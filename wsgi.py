"""
Минимальное WSGI-приложение: форма, валидация, сохранение в MariaDB/MySQL (prepared statements).
"""
from __future__ import annotations

import html
import os
import re
import sys
from datetime import date, datetime
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs

try:
    import mysql.connector
except ImportError:  # pragma: no cover
    mysql = None  # type: ignore
else:
    mysql = mysql.connector

BASE_DIR = Path(__file__).resolve().parent
TEMPLATE_PATH = BASE_DIR / "index.html"
STATIC_DIR = BASE_DIR / "static"

LANGUAGE_CODES = (
    "pascal",
    "c",
    "cpp",
    "javascript",
    "php",
    "python",
    "java",
    "haskell",
    "clojure",
    "prolog",
    "scala",
    "go",
)
ALLOWED_LANGUAGES = frozenset(LANGUAGE_CODES)
ALLOWED_GENDER = frozenset({"male", "female", "other"})

FIO_PATTERN = re.compile(r"^[A-Za-zА-Яа-яЁё]+(?:\s+[A-Za-zА-Яа-яЁё]+)*$")
EMAIL_PATTERN = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")


def _template() -> str:
    return TEMPLATE_PATH.read_text(encoding="utf-8")


def _render(
    *,
    error_block: str = "",
    success_block: str = "",
    full_name_value: str = "",
    phone_value: str = "",
    email_value: str = "",
    birth_date_value: str = "",
    gender: str | None = None,
    languages_selected: frozenset[str] | None = None,
    biography_value: str = "",
    contract_accepted: bool = False,
) -> str:
    languages_selected = languages_selected or frozenset()
    gender_male_checked = " checked" if gender == "male" else ""
    gender_female_checked = " checked" if gender == "female" else ""
    gender_other_checked = " checked" if gender == "other" else ""
    contract_checked = " checked" if contract_accepted else ""

    chk: dict[str, str] = {f"chk_{code}": (" checked" if code in languages_selected else "") for code in LANGUAGE_CODES}

    mapping = {
        "{error_block}": error_block,
        "{success_block}": success_block,
        "{full_name_value}": html.escape(full_name_value, quote=True),
        "{phone_value}": html.escape(phone_value, quote=True),
        "{email_value}": html.escape(email_value, quote=True),
        "{birth_date_value}": html.escape(birth_date_value, quote=True),
        "{gender_male_checked}": gender_male_checked,
        "{gender_female_checked}": gender_female_checked,
        "{gender_other_checked}": gender_other_checked,
        "{biography_value}": html.escape(biography_value, quote=False),
        "{contract_checked}": contract_checked,
    }
    mapping.update({f"{{{k}}}": v for k, v in chk.items()})

    out = _template()
    # Длинные ключи первыми, чтобы не пересечься с частичными совпадениями (не наш случай)
    for key, val in mapping.items():
        out = out.replace(key, val)
    return out


def _first(params: dict[str, list[str]], key: str, default: str = "") -> str:
    vals = params.get(key, [])
    if not vals:
        return default
    return vals[0]


def _validate(params: dict[str, list[str]]) -> tuple[dict[str, Any], list[str]]:
    errors: list[str] = []
    raw_name = _first(params, "full_name").strip()
    raw_phone = _first(params, "phone").strip()
    raw_email = _first(params, "email").strip()
    raw_birth = _first(params, "birth_date")
    raw_gender = _first(params, "gender")
    raw_bio = _first(params, "biography").replace("\r\n", "\n").replace("\r", "\n")
    langs = params.get("languages", [])
    contract_vals = params.get("contract", [])

    values: dict[str, Any] = {
        "full_name": raw_name,
        "phone": raw_phone,
        "email": raw_email,
        "birth_date_raw": raw_birth,
        "gender": raw_gender if raw_gender in ALLOWED_GENDER else None,
        "languages": [],
        "biography": raw_bio,
        "contract_accepted": "yes" in contract_vals,
    }

    if not raw_name:
        errors.append("ФИО: поле не заполнено.")
    elif len(raw_name) > 150:
        errors.append("ФИО: не более 150 символов.")
    elif not FIO_PATTERN.fullmatch(raw_name):
        errors.append("ФИО: допустимы только буквы и пробелы между словами.")

    if not raw_phone:
        errors.append("Телефон: поле не заполнено.")
    else:
        digits = re.sub(r"\D", "", raw_phone)
        if len(digits) < 10 or len(digits) > 15:
            errors.append("Телефон: укажите от 10 до 15 цифр (можно с + в начале).")

    if not raw_email:
        errors.append("E-mail: поле не заполнено.")
    elif len(raw_email) > 255:
        errors.append("E-mail: слишком длинный адрес.")
    elif not EMAIL_PATTERN.match(raw_email):
        errors.append("E-mail: некорректный формат.")

    birth_d: date | None = None
    if not raw_birth:
        errors.append("Дата рождения: поле не заполнено.")
    else:
        try:
            birth_d = datetime.strptime(raw_birth, "%Y-%m-%d").date()
        except ValueError:
            errors.append("Дата рождения: укажите корректную дату.")
        else:
            today = date.today()
            if birth_d > today:
                errors.append("Дата рождения: не может быть в будущем.")
            if birth_d < date(1900, 1, 1):
                errors.append("Дата рождения: слишком ранняя дата.")
    values["birth_date"] = birth_d

    if not raw_gender:
        errors.append("Пол: выберите значение.")
    elif raw_gender not in ALLOWED_GENDER:
        errors.append("Пол: недопустимое значение.")

    if not langs:
        errors.append("Языки программирования: выберите хотя бы один.")
    else:
        unknown = sorted({x for x in langs if x not in ALLOWED_LANGUAGES})
        if unknown:
            errors.append("Языки программирования: содержатся недопустимые значения.")
        values["languages"] = list(dict.fromkeys(x for x in langs if x in ALLOWED_LANGUAGES))

    bio_stripped = raw_bio.strip()
    if not bio_stripped:
        errors.append("Биография: поле не заполнено.")
    elif len(bio_stripped) > 5000:
        errors.append("Биография: не более 5000 символов.")
    values["biography_stripped"] = bio_stripped

    if "yes" not in contract_vals:
        errors.append("Необходимо подтвердить ознакомление с контрактом.")

    return values, errors


def _error_html(messages: list[str]) -> str:
    if not messages:
        return ""
    items = "".join(f"<li>{html.escape(m, quote=False)}</li>" for m in messages)
    return f'<div class="alert alert--errors" role="alert"><strong>Исправьте ошибки:</strong><ul>{items}</ul></div>'


def _success_html() -> str:
    return (
        '<div class="alert alert--success" role="status">'
        "Данные успешно сохранены."
        "</div>"
    )


def _get_db_connection():
    if mysql is None:
        raise RuntimeError("Установите пакет mysql-connector-python: pip install mysql-connector-python")
    host = os.environ.get("MYSQL_HOST", "localhost")
    user = os.environ.get("MYSQL_USER", "root")
    password = os.environ.get("MYSQL_PASSWORD", "")
    database = os.environ.get("MYSQL_DATABASE", "form_app")
    return mysql.connect(
        host=host,
        user=user,
        password=password,
        database=database,
        charset="utf8mb4",
    )


def _save_submission(values: dict[str, Any], language_codes: list[str]) -> None:
    conn = _get_db_connection()
    cursor = None
    try:
        conn.start_transaction()
        cursor = conn.cursor()
        codes_unique = list(dict.fromkeys(language_codes))
        placeholders = ",".join(["%s"] * len(codes_unique))
        cursor.execute(
            f"SELECT id, code FROM programming_languages WHERE code IN ({placeholders})",
            codes_unique,
        )
        rows = cursor.fetchall()
        id_by_code = {r[1]: r[0] for r in rows}
        if len(id_by_code) != len(codes_unique):
            raise ValueError("Справочник языков в БД не совпадает с ожидаемым.")

        cursor.execute(
            """
            INSERT INTO form_submissions
              (full_name, phone, email, birth_date, gender, biography, contract_accepted)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            """,
            (
                values["full_name"],
                values["phone"],
                values["email"],
                values["birth_date"],
                values["gender"],
                values["biography_stripped"],
                1,
            ),
        )
        submission_id = cursor.lastrowid
        lang_rows = [(submission_id, id_by_code[c]) for c in codes_unique]
        cursor.executemany(
            """
            INSERT INTO submission_programming_languages (submission_id, language_id)
            VALUES (%s, %s)
            """,
            lang_rows,
        )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        if cursor is not None:
            cursor.close()
        conn.close()


def _read_body(environ: dict) -> bytes:
    try:
        size = int(environ.get("CONTENT_LENGTH", "0") or "0")
    except ValueError:
        size = 0
    if size <= 0:
        return b""
    return environ["wsgi.input"].read(size)


def _serve_static(path: str) -> tuple[str | None, bytes]:
    if not path.startswith("/static/"):
        return None, b""
    rel = path[len("/static/") :].lstrip("/")
    if ".." in rel or rel.startswith("/"):
        return "404 Not Found", b"Not found"
    full = STATIC_DIR / rel
    if not full.is_file():
        return "404 Not Found", b"Not found"
    data = full.read_bytes()
    if rel.endswith(".css"):
        ctype = "text/css; charset=utf-8"
    else:
        ctype = "application/octet-stream"
    return ctype, data


def application(environ: dict, start_response):
    """Точка входа WSGI."""
    method = environ.get("REQUEST_METHOD", "GET").upper()
    path = environ.get("PATH_INFO", "") or "/"
    if path != "/" and path.startswith("/static/"):
        ctype_or_status, data = _serve_static(path)
        if isinstance(ctype_or_status, str) and ctype_or_status.startswith("404"):
            start_response("404 Not Found", [("Content-Type", "text/plain; charset=utf-8")])
            return [data]
        start_response("200 OK", [("Content-Type", ctype_or_status or "application/octet-stream")])
        return [data]

    if path not in ("/", ""):
        start_response("404 Not Found", [("Content-Type", "text/plain; charset=utf-8")])
        return [b"Not found"]

    if method == "GET":
        body = _render()
        start_response("200 OK", [("Content-Type", "text/html; charset=utf-8")])
        return [body.encode("utf-8")]

    if method != "POST":
        start_response("405 Method Not Allowed", [("Allow", "GET, POST"), ("Content-Type", "text/plain; charset=utf-8")])
        return [b"Method not allowed"]

    raw = _read_body(environ)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = raw.decode("utf-8", errors="replace")
    params = parse_qs(text, keep_blank_values=True)

    values, errors = _validate(params)

    if errors:
        err_html = _error_html(errors)
        body = _render(
            error_block=err_html,
            full_name_value=values["full_name"],
            phone_value=values["phone"],
            email_value=values["email"],
            birth_date_value=values["birth_date_raw"],
            gender=values["gender"],
            languages_selected=frozenset(values["languages"]),
            biography_value=values["biography"],
            contract_accepted=values["contract_accepted"],
        )
        start_response("200 OK", [("Content-Type", "text/html; charset=utf-8")])
        return [body.encode("utf-8")]

    try:
        _save_submission(values, values["languages"])
    except Exception as exc:  # noqa: BLE001
        msg = "Не удалось сохранить данные. Проверьте настройки БД и что выполнен schema.sql."
        if os.environ.get("WSGI_DEBUG", "").lower() in ("1", "true", "yes"):
            msg += f" ({exc!r})"
        err_html = _error_html([msg])
        body = _render(
            error_block=err_html,
            full_name_value=values["full_name"],
            phone_value=values["phone"],
            email_value=values["email"],
            birth_date_value=values["birth_date_raw"],
            gender=values["gender"],
            languages_selected=frozenset(values["languages"]),
            biography_value=values["biography"],
            contract_accepted=values["contract_accepted"],
        )
        start_response("200 OK", [("Content-Type", "text/html; charset=utf-8")])
        return [body.encode("utf-8")]

    body = _render(success_block=_success_html())
    start_response("200 OK", [("Content-Type", "text/html; charset=utf-8")])
    return [body.encode("utf-8")]


# Запуск: gunicorn wsgi:application или mod_wsgi
if __name__ == "__main__":  # pragma: no cover
    from wsgiref.simple_server import make_server

    port = int(os.environ.get("PORT", "8000"))
    print(f"Serving http://127.0.0.1:{port}/ (WSGI development server)", file=sys.stderr)
    make_server("127.0.0.1", port, application).serve_forever()

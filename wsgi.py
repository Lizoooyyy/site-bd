"""
WSGI-приложение для заданий 4-7:
- форма с серверной валидацией и cookies;
- учетка пользователя (логин/пароль) + сессии в БД;
- админка с HTTP Basic Auth;
- базовые меры защиты (XSS/SQLi/CSRF/Info disclosure).
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import html
import os
import re
import secrets
import sys
from datetime import date, datetime, timedelta, timezone
from http.cookies import SimpleCookie
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, quote, unquote

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
PHONE_PATTERN = re.compile(r"^(?=(?:\D*\d){10,15}\D*$)\+?[0-9\s\-\(\)]+$")
BIRTH_DATE_PATTERN = re.compile(r"^(19\d{2}|20\d{2})-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])$")
GENDER_PATTERN = re.compile(r"^(male|female|other)$")
BIOGRAPHY_PATTERN = re.compile(r"^[^\x00-\x08\x0B\x0C\x0E-\x1F\x7F]*$")
_LANG_RE = re.compile(r"^(?:" + "|".join(re.escape(x) for x in LANGUAGE_CODES) + r")$")

COOKIE_PREFIX_OLD = "form_old_"
COOKIE_PREFIX_ERR = "form_err_"
COOKIE_PREFIX_SAVED = "form_saved_"
COOKIE_FLASH_SUCCESS = "form_flash_success"
COOKIE_FLASH_CREDS = "form_flash_creds"
COOKIE_SESSION_ID = "session_id"
COOKIE_GUEST_CSRF = "guest_csrf"
COOKIE_ADMIN_CSRF = "admin_csrf"

ONE_YEAR_SECONDS = 60 * 60 * 24 * 365
SESSION_SECONDS = 60 * 60 * 24 * 7
PBKDF2_ITERS = 200_000


def _template() -> str:
    return TEMPLATE_PATH.read_text(encoding="utf-8")


def _h(s: str) -> str:
    return html.escape(s, quote=True)


def _error_html(messages: list[str]) -> str:
    if not messages:
        return ""
    items = "".join(f"<li>{html.escape(m, quote=False)}</li>" for m in messages)
    return f'<div class="alert alert--errors" role="alert"><strong>Исправьте ошибки:</strong><ul>{items}</ul></div>'


def _success_html(text: str = "Данные успешно сохранены.") -> str:
    return f'<div class="alert alert--success" role="status">{html.escape(text, quote=False)}</div>'


def _nav_html(active: str) -> str:
    items = (
        ("home", "/", "Анкета"),
        ("login", "/login", "Вход"),
        ("admin", "/admin", "Админка"),
    )
    parts: list[str] = []
    for key, href, label in items:
        cls = "site-nav__link site-nav__link--active" if key == active else "site-nav__link"
        parts.append(f'<a class="{cls}" href="{href}">{html.escape(label)}</a>')
    return f'<nav class="site-nav" aria-label="Разделы сайта">{"".join(parts)}</nav>'


def _html_shell(*, title: str, inner: str, wide: bool = False) -> str:
    page_cls = "page page--wide" if wide else "page"
    return f"""<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>{_h(title)}</title>
  <link rel="stylesheet" href="/static/style.css" />
</head>
<body>
  <div class="{page_cls}">
    <main class="card" role="main">
{inner}
    </main>
  </div>
</body>
</html>"""


def _render_main(
    *,
    error_block: str = "",
    success_block: str = "",
    credentials_block: str = "",
    auth_block: str = "",
    csrf_token_value: str = "",
    submit_caption: str = "Сохранить",
    full_name_value: str = "",
    phone_value: str = "",
    email_value: str = "",
    birth_date_value: str = "",
    gender: str | None = None,
    languages_selected: frozenset[str] | None = None,
    biography_value: str = "",
    contract_accepted: bool = False,
    field_errors: dict[str, str] | None = None,
) -> str:
    field_errors = field_errors or {}
    languages_selected = languages_selected or frozenset()
    gender_male_checked = " checked" if gender == "male" else ""
    gender_female_checked = " checked" if gender == "female" else ""
    gender_other_checked = " checked" if gender == "other" else ""
    contract_checked = " checked" if contract_accepted else ""
    chk: dict[str, str] = {f"chk_{code}": (" checked" if code in languages_selected else "") for code in LANGUAGE_CODES}

    def err(name: str) -> str:
        return html.escape(field_errors.get(name, ""), quote=False)

    def invalid_class(name: str) -> str:
        return "is-invalid" if name in field_errors else ""

    def aria_invalid(name: str) -> str:
        return "true" if name in field_errors else "false"

    mapping = {
        "{nav_block}": _nav_html("home"),
        "{error_block}": error_block,
        "{success_block}": success_block,
        "{credentials_block}": credentials_block,
        "{auth_block}": auth_block,
        "{csrf_token_value}": _h(csrf_token_value),
        "{submit_caption}": html.escape(submit_caption, quote=False),
        "{full_name_value}": _h(full_name_value),
        "{phone_value}": _h(phone_value),
        "{email_value}": _h(email_value),
        "{birth_date_value}": _h(birth_date_value),
        "{gender_male_checked}": gender_male_checked,
        "{gender_female_checked}": gender_female_checked,
        "{gender_other_checked}": gender_other_checked,
        "{biography_value}": html.escape(biography_value, quote=False),
        "{contract_checked}": contract_checked,
        "{full_name_error}": err("full_name"),
        "{phone_error}": err("phone"),
        "{email_error}": err("email"),
        "{birth_date_error}": err("birth_date"),
        "{gender_error}": err("gender"),
        "{languages_error}": err("languages"),
        "{biography_error}": err("biography"),
        "{contract_error}": err("contract"),
        "{full_name_invalid_class}": invalid_class("full_name"),
        "{phone_invalid_class}": invalid_class("phone"),
        "{email_invalid_class}": invalid_class("email"),
        "{birth_date_invalid_class}": invalid_class("birth_date"),
        "{gender_invalid_class}": invalid_class("gender"),
        "{languages_invalid_class}": invalid_class("languages"),
        "{biography_invalid_class}": invalid_class("biography"),
        "{contract_invalid_class}": invalid_class("contract"),
        "{full_name_aria_invalid}": aria_invalid("full_name"),
        "{phone_aria_invalid}": aria_invalid("phone"),
        "{email_aria_invalid}": aria_invalid("email"),
        "{birth_date_aria_invalid}": aria_invalid("birth_date"),
        "{biography_aria_invalid}": aria_invalid("biography"),
    }
    mapping.update({f"{{{k}}}": v for k, v in chk.items()})

    out = _template()
    for key, val in mapping.items():
        out = out.replace(key, val)
    return out


def _render_login_page(*, error_text: str = "", csrf_token: str = "", login_value: str = "") -> str:
    err = f'<div class="alert alert--errors" role="alert">{html.escape(error_text, quote=False)}</div>' if error_text else ""
    inner = f"""
      {_nav_html("login")}
      <h1>Вход для редактирования заявки</h1>
      <p class="lead">Войдите с логином и паролем, которые выдаются после первой успешной отправки анкеты.</p>
      {err}
      <form method="post" action="/login" accept-charset="UTF-8" novalidate>
        <input type="hidden" name="csrf_token" value="{_h(csrf_token)}" />
        <div class="field">
          <label class="field__label" for="login">Логин</label>
          <input type="text" id="login" name="login" value="{_h(login_value)}" autocomplete="username" required />
        </div>
        <div class="field">
          <label class="field__label" for="password">Пароль</label>
          <input type="password" id="password" name="password" autocomplete="current-password" required />
        </div>
        <div class="actions">
          <button type="submit">Войти</button>
        </div>
      </form>
    """
    return _html_shell(title="Вход", inner=inner, wide=False)


def _render_admin_page(*, rows: list[dict[str, Any]], stats: list[dict[str, Any]], csrf_token: str) -> str:
    table_rows = []
    for row in rows:
        row_id = int(row["id"])
        gender_map = {"male": "Мужской", "female": "Женский", "other": "Другое"}
        langs = row.get("languages", "")
        table_rows.append(
            "<tr>"
            f"<td>{row_id}</td>"
            f"<td>{_h(row['user_login'])}</td>"
            f"<td>{_h(row['full_name'])}</td>"
            f"<td>{_h(row['phone'])}</td>"
            f"<td>{_h(row['email'])}</td>"
            f"<td>{_h(str(row['birth_date']))}</td>"
            f"<td>{_h(gender_map.get(row['gender'], row['gender']))}</td>"
            f"<td>{_h(langs)}</td>"
            f"<td class=\"admin-table__bio\">{html.escape(row['biography'], quote=False)}</td>"
            f"<td>{'Да' if int(row['contract_accepted']) else 'Нет'}</td>"
            "<td class=\"admin-table__actions\">"
            f"<a class=\"text-link\" href=\"/admin/edit?id={row_id}\">Изменить</a>"
            f"<form class=\"admin-inline-form\" method=\"post\" action=\"/admin/delete?id={row_id}\">"
            f"<input type=\"hidden\" name=\"csrf_token\" value=\"{_h(csrf_token)}\" />"
            "<button class=\"btn-danger\" type=\"submit\">Удалить</button>"
            "</form>"
            "</td>"
            "</tr>"
        )
    stats_rows = "".join(
        f"<li><span class=\"stats__name\">{_h(str(x['display_name']))}</span>"
        f"<span class=\"stats__cnt\">{int(x['cnt'])}</span></li>"
        for x in stats
    )
    inner = f"""
      {_nav_html("admin")}
      <h1>Админ-панель</h1>
      <p class="lead">Доступ по HTTP Basic Auth (логин и пароль администратора из базы). Ниже — все заявки и статистика по языкам.</p>
      <section class="section-block" aria-labelledby="stats-heading">
        <h2 class="section-block__title" id="stats-heading">Статистика: сколько заявок указали язык</h2>
        <ul class="stats-list">{stats_rows}</ul>
      </section>
      <section class="section-block" aria-labelledby="table-heading">
        <h2 class="section-block__title" id="table-heading">Все заявки</h2>
        <div class="table-wrap">
          <table class="admin-table">
            <thead>
              <tr>
                <th>ID</th><th>Логин</th><th>ФИО</th><th>Телефон</th><th>Email</th><th>Дата</th><th>Пол</th><th>Языки</th><th>Биография</th><th>Контракт</th><th>Действия</th>
              </tr>
            </thead>
            <tbody>
              {''.join(table_rows)}
            </tbody>
          </table>
        </div>
      </section>
    """
    return _html_shell(title="Админ-панель", inner=inner, wide=True)


def _render_admin_edit_page(
    *,
    sub_id: int,
    values: dict[str, Any],
    field_errors: dict[str, str] | None,
    csrf_token: str,
) -> str:
    field_errors = field_errors or {}
    languages = frozenset(values.get("languages", []))
    checks = {k: (" checked" if k in languages else "") for k in LANGUAGE_CODES}
    err_block = _error_html(list(field_errors.values()))
    inner = f"""
      {_nav_html("admin")}
      <h1>Редактирование заявки #{sub_id}</h1>
      <p class="lead"><a class="text-link" href="/admin">← К списку заявок</a></p>
      {err_block}
      <form method="post" action="/admin/edit?id={sub_id}" accept-charset="UTF-8" novalidate>
        <input type="hidden" name="csrf_token" value="{_h(csrf_token)}" />
        <div class="field">
          <label class="field__label" for="adm_full_name">ФИО</label>
          <input type="text" id="adm_full_name" name="full_name" value="{_h(values.get('full_name', ''))}" />
        </div>
        <div class="field">
          <label class="field__label" for="adm_phone">Телефон</label>
          <input type="text" id="adm_phone" name="phone" value="{_h(values.get('phone', ''))}" />
        </div>
        <div class="field">
          <label class="field__label" for="adm_email">E-mail</label>
          <input type="text" id="adm_email" name="email" value="{_h(values.get('email', ''))}" />
        </div>
        <div class="field">
          <label class="field__label" for="adm_birth">Дата рождения</label>
          <input type="date" id="adm_birth" name="birth_date" value="{_h(values.get('birth_date_raw', ''))}" />
        </div>
        <fieldset class="field field--plain">
          <legend class="field__label">Пол</legend>
          <div class="inline-group">
            <label><input type="radio" name="gender" value="male"{' checked' if values.get('gender') == 'male' else ''}/> Мужской</label>
            <label><input type="radio" name="gender" value="female"{' checked' if values.get('gender') == 'female' else ''}/> Женский</label>
            <label><input type="radio" name="gender" value="other"{' checked' if values.get('gender') == 'other' else ''}/> Другое</label>
          </div>
        </fieldset>
        <div class="field">
          <span class="field__label" id="adm-lang">Языки программирования</span>
          <div class="lang-grid" role="group" aria-labelledby="adm-lang">
            <label><input type="checkbox" name="languages" value="pascal"{checks['pascal']} /> Pascal</label>
            <label><input type="checkbox" name="languages" value="c"{checks['c']} /> C</label>
            <label><input type="checkbox" name="languages" value="cpp"{checks['cpp']} /> C++</label>
            <label><input type="checkbox" name="languages" value="javascript"{checks['javascript']} /> JavaScript</label>
            <label><input type="checkbox" name="languages" value="php"{checks['php']} /> PHP</label>
            <label><input type="checkbox" name="languages" value="python"{checks['python']} /> Python</label>
            <label><input type="checkbox" name="languages" value="java"{checks['java']} /> Java</label>
            <label><input type="checkbox" name="languages" value="haskell"{checks['haskell']} /> Haskel</label>
            <label><input type="checkbox" name="languages" value="clojure"{checks['clojure']} /> Clojure</label>
            <label><input type="checkbox" name="languages" value="prolog"{checks['prolog']} /> Prolog</label>
            <label><input type="checkbox" name="languages" value="scala"{checks['scala']} /> Scala</label>
            <label><input type="checkbox" name="languages" value="go"{checks['go']} /> Go</label>
          </div>
        </div>
        <div class="field">
          <label class="field__label" for="adm_bio">Биография</label>
          <textarea id="adm_bio" name="biography">{html.escape(values.get('biography', ''), quote=False)}</textarea>
        </div>
        <div class="field field--contract">
          <label><input type="checkbox" name="contract" value="yes"{' checked' if values.get('contract_accepted') else ''}/> С контрактом ознакомлен(а)</label>
        </div>
        <div class="actions">
          <button type="submit">Сохранить изменения</button>
        </div>
      </form>
    """
    return _html_shell(title=f"Заявка #{sub_id}", inner=inner, wide=False)


def _first(params: dict[str, list[str]], key: str, default: str = "") -> str:
    vals = params.get(key, [])
    return vals[0] if vals else default


def _parse_cookies(environ: dict) -> dict[str, str]:
    raw = environ.get("HTTP_COOKIE", "") or ""
    jar = SimpleCookie()
    jar.load(raw)
    out: dict[str, str] = {}
    for k, morsel in jar.items():
        out[k] = morsel.value
    return out


def _set_cookie_header(
    *,
    name: str,
    value: str,
    max_age: int | None = None,
    path: str = "/",
    same_site: str = "Lax",
    http_only: bool = False,
) -> str:
    v = quote(value, safe="")
    parts = [f"{name}={v}", f"Path={path}", f"SameSite={same_site}"]
    if max_age is not None:
        parts.append(f"Max-Age={max_age}")
    if http_only:
        parts.append("HttpOnly")
    return "; ".join(parts)


def _delete_cookie_header(*, name: str, path: str = "/") -> str:
    return f"{name}=; Path={path}; Max-Age=0; SameSite=Lax"


def _get_db_connection():
    if mysql is None:
        raise RuntimeError("Установите пакет mysql-connector-python: pip install mysql-connector-python")
    try:
        port = int(os.environ.get("MYSQL_PORT", "3306"))
    except ValueError:
        port = 3306
    # autocommit=True: иначе DELETE в _get_current_user оставляет транзакцию открытой
    # и следующий start_transaction() (вход, форма) падает с «Transaction already in progress».
    return mysql.connect(
        host=os.environ.get("MYSQL_HOST", "localhost"),
        port=port,
        user=os.environ.get("MYSQL_USER", "root"),
        password=os.environ.get("MYSQL_PASSWORD", ""),
        database=os.environ.get("MYSQL_DATABASE", "form_app"),
        charset="utf8mb4",
        autocommit=True,
    )


def _hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), PBKDF2_ITERS).hex()
    return f"pbkdf2_sha256${PBKDF2_ITERS}${salt}${digest}"


def _verify_password(password: str, stored: str) -> bool:
    if stored.startswith("pbkdf2_sha256$"):
        try:
            _, iters_s, salt, digest = stored.split("$", 3)
            iters = int(iters_s)
        except (ValueError, TypeError):
            return False
        check = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), iters).hex()
        return hmac.compare_digest(check, digest)
    check_sha = hashlib.sha256(password.encode("utf-8")).hexdigest()
    return hmac.compare_digest(check_sha, stored)


def _gen_user_login(conn) -> str:
    cursor = conn.cursor()
    try:
        while True:
            candidate = "user" + secrets.token_hex(4)
            cursor.execute("SELECT 1 FROM form_submissions WHERE user_login=%s LIMIT 1", (candidate,))
            if cursor.fetchone() is None:
                return candidate
    finally:
        cursor.close()


def _gen_password() -> str:
    return secrets.token_urlsafe(10)


def _validate(params: dict[str, list[str]]) -> tuple[dict[str, Any], dict[str, str], list[str]]:
    field_errors: dict[str, str] = {}
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
        field_errors["full_name"] = "Поле обязательно."
        errors.append("ФИО: поле не заполнено.")
    elif len(raw_name) > 150:
        field_errors["full_name"] = "Не более 150 символов."
        errors.append("ФИО: не более 150 символов.")
    elif not FIO_PATTERN.fullmatch(raw_name):
        msg = "Допустимы только буквы русского/латинского алфавита и пробелы."
        field_errors["full_name"] = msg
        errors.append(f"ФИО: {msg}")

    if not raw_phone:
        field_errors["phone"] = "Поле обязательно."
        errors.append("Телефон: поле не заполнено.")
    elif len(raw_phone) > 64:
        field_errors["phone"] = "Слишком длинное значение."
        errors.append("Телефон: слишком длинное значение.")
    elif not PHONE_PATTERN.fullmatch(raw_phone):
        msg = "Допустимы цифры, пробелы, '+', '(', ')', '-' (цифр 10-15)."
        field_errors["phone"] = msg
        errors.append(f"Телефон: {msg}")

    if not raw_email:
        field_errors["email"] = "Поле обязательно."
        errors.append("E-mail: поле не заполнено.")
    elif len(raw_email) > 255:
        field_errors["email"] = "Слишком длинный адрес."
        errors.append("E-mail: слишком длинный адрес.")
    elif not EMAIL_PATTERN.fullmatch(raw_email):
        msg = "Допустимы латиница, цифры и . _ % + - (пример: name@example.com)."
        field_errors["email"] = msg
        errors.append(f"E-mail: {msg}")

    birth_d: date | None = None
    if not raw_birth:
        field_errors["birth_date"] = "Поле обязательно."
        errors.append("Дата рождения: поле не заполнено.")
    elif not BIRTH_DATE_PATTERN.fullmatch(raw_birth):
        msg = "Допустим формат YYYY-MM-DD."
        field_errors["birth_date"] = msg
        errors.append(f"Дата рождения: {msg}")
    else:
        try:
            birth_d = datetime.strptime(raw_birth, "%Y-%m-%d").date()
        except ValueError:
            field_errors["birth_date"] = "Укажите корректную дату."
            errors.append("Дата рождения: укажите корректную дату.")
        else:
            today = date.today()
            if birth_d > today:
                field_errors["birth_date"] = "Дата не может быть в будущем."
                errors.append("Дата рождения: не может быть в будущем.")
            elif birth_d < date(1900, 1, 1):
                field_errors["birth_date"] = "Слишком ранняя дата."
                errors.append("Дата рождения: слишком ранняя дата.")
    values["birth_date"] = birth_d

    if not raw_gender:
        field_errors["gender"] = "Выберите значение."
        errors.append("Пол: выберите значение.")
    elif not GENDER_PATTERN.fullmatch(raw_gender):
        field_errors["gender"] = "Недопустимое значение."
        errors.append("Пол: недопустимое значение.")

    if not langs:
        field_errors["languages"] = "Выберите хотя бы один язык."
        errors.append("Языки программирования: выберите хотя бы один.")
    else:
        unknown = sorted({x for x in langs if not _LANG_RE.fullmatch(x)})
        if unknown:
            msg = "Допустимы только варианты из списка на странице."
            field_errors["languages"] = msg
            errors.append(f"Языки программирования: {msg}")
        values["languages"] = list(dict.fromkeys(x for x in langs if _LANG_RE.fullmatch(x)))

    bio_stripped = raw_bio.strip()
    if not bio_stripped:
        field_errors["biography"] = "Поле обязательно."
        errors.append("Биография: поле не заполнено.")
    elif len(bio_stripped) > 5000:
        field_errors["biography"] = "Не более 5000 символов."
        errors.append("Биография: не более 5000 символов.")
    elif not BIOGRAPHY_PATTERN.fullmatch(raw_bio):
        msg = "Допустим обычный текст, пробелы и переносы строк."
        field_errors["biography"] = msg
        errors.append(f"Биография: {msg}")
    values["biography_stripped"] = bio_stripped

    if "yes" not in contract_vals:
        field_errors["contract"] = "Необходимо подтвердить."
        errors.append("Необходимо подтвердить ознакомление с контрактом.")

    return values, field_errors, errors


def _load_submission_languages(conn, submission_id: int) -> list[str]:
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(
            """
            SELECT pl.code
            FROM submission_programming_languages spl
            JOIN programming_languages pl ON pl.id = spl.language_id
            WHERE spl.submission_id=%s
            ORDER BY pl.id
            """,
            (submission_id,),
        )
        return [str(x["code"]) for x in cursor.fetchall()]
    finally:
        cursor.close()


def _upsert_submission_languages(conn, submission_id: int, language_codes: list[str]) -> None:
    codes_unique = list(dict.fromkeys(language_codes))
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("DELETE FROM submission_programming_languages WHERE submission_id=%s", (submission_id,))
        if not codes_unique:
            return
        placeholders = ",".join(["%s"] * len(codes_unique))
        cursor.execute(f"SELECT id, code FROM programming_languages WHERE code IN ({placeholders})", codes_unique)
        rows = cursor.fetchall()
        id_by_code = {str(r["code"]): int(r["id"]) for r in rows}
        if len(id_by_code) != len(codes_unique):
            raise ValueError("Справочник языков в БД не совпадает с ожидаемым.")
        cursor.executemany(
            "INSERT INTO submission_programming_languages (submission_id, language_id) VALUES (%s, %s)",
            [(submission_id, id_by_code[c]) for c in codes_unique],
        )
    finally:
        cursor.close()


def _insert_submission(conn, values: dict[str, Any], login: str, password_hash: str) -> int:
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            INSERT INTO form_submissions
            (full_name, phone, email, birth_date, gender, biography, user_login, password_hash, contract_accepted)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                values["full_name"],
                values["phone"],
                values["email"],
                values["birth_date"],
                values["gender"],
                values["biography_stripped"],
                login,
                password_hash,
                1 if values["contract_accepted"] else 0,
            ),
        )
        return int(cursor.lastrowid)
    finally:
        cursor.close()


def _update_submission(conn, submission_id: int, values: dict[str, Any]) -> None:
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            UPDATE form_submissions
            SET full_name=%s, phone=%s, email=%s, birth_date=%s, gender=%s, biography=%s, contract_accepted=%s
            WHERE id=%s
            """,
            (
                values["full_name"],
                values["phone"],
                values["email"],
                values["birth_date"],
                values["gender"],
                values["biography_stripped"],
                1 if values["contract_accepted"] else 0,
                submission_id,
            ),
        )
    finally:
        cursor.close()


def _submission_to_values(sub: dict[str, Any], langs: list[str]) -> dict[str, Any]:
    return {
        "full_name": str(sub["full_name"]),
        "phone": str(sub["phone"]),
        "email": str(sub["email"]),
        "birth_date_raw": str(sub["birth_date"]),
        "birth_date": sub["birth_date"],
        "gender": str(sub["gender"]),
        "languages": langs,
        "biography": str(sub["biography"]),
        "biography_stripped": str(sub["biography"]),
        "contract_accepted": bool(sub["contract_accepted"]),
    }


def _session_now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _create_user_session(conn, submission_id: int) -> tuple[str, str]:
    session_id = secrets.token_hex(32)
    csrf_token = secrets.token_hex(32)
    expires = _session_now() + timedelta(seconds=SESSION_SECONDS)
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            INSERT INTO user_sessions (session_id, submission_id, csrf_token, expires_at)
            VALUES (%s, %s, %s, %s)
            """,
            (session_id, submission_id, csrf_token, expires),
        )
    finally:
        cursor.close()
    return session_id, csrf_token


def _get_current_user(conn, cookies: dict[str, str]) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    sid = unquote(cookies.get(COOKIE_SESSION_ID, "") or "")
    if not sid:
        return None, None
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("DELETE FROM user_sessions WHERE expires_at <= NOW()")
        cursor.execute(
            """
            SELECT us.session_id, us.submission_id, us.csrf_token, us.expires_at,
                   fs.id, fs.user_login, fs.full_name, fs.phone, fs.email, fs.birth_date, fs.gender, fs.biography, fs.contract_accepted
            FROM user_sessions us
            JOIN form_submissions fs ON fs.id = us.submission_id
            WHERE us.session_id=%s AND us.expires_at > NOW()
            LIMIT 1
            """,
            (sid,),
        )
        row = cursor.fetchone()
        if row is None:
            return None, None
        session_data = {"session_id": row["session_id"], "csrf_token": row["csrf_token"], "submission_id": int(row["submission_id"])}
        submission = {
            "id": int(row["id"]),
            "user_login": str(row["user_login"]),
            "full_name": str(row["full_name"]),
            "phone": str(row["phone"]),
            "email": str(row["email"]),
            "birth_date": row["birth_date"],
            "gender": str(row["gender"]),
            "biography": str(row["biography"]),
            "contract_accepted": bool(row["contract_accepted"]),
        }
        return session_data, submission
    finally:
        cursor.close()


def _destroy_session(conn, session_id: str) -> None:
    cursor = conn.cursor()
    try:
        cursor.execute("DELETE FROM user_sessions WHERE session_id=%s", (session_id,))
    finally:
        cursor.close()


def _load_defaults_from_saved_cookies(cookies: dict[str, str]) -> dict[str, Any]:
    def get_saved(key: str) -> str:
        v = cookies.get(COOKIE_PREFIX_SAVED + key, "")
        return unquote(v) if v else ""

    langs_raw = get_saved("languages")
    langs = frozenset(x for x in langs_raw.split(",") if x in ALLOWED_LANGUAGES)
    gender = get_saved("gender") or None
    if gender not in ALLOWED_GENDER:
        gender = None
    contract = get_saved("contract") == "yes"
    return {
        "full_name": get_saved("full_name"),
        "phone": get_saved("phone"),
        "email": get_saved("email"),
        "birth_date": get_saved("birth_date"),
        "gender": gender,
        "languages": langs,
        "biography": get_saved("biography"),
        "contract_accepted": contract,
    }


def _load_old_and_errors_from_session_cookies(cookies: dict[str, str]) -> tuple[dict[str, str], dict[str, str]]:
    old: dict[str, str] = {}
    errs: dict[str, str] = {}
    for k, v in cookies.items():
        if k.startswith(COOKIE_PREFIX_OLD):
            old[k[len(COOKIE_PREFIX_OLD) :]] = unquote(v)
        elif k.startswith(COOKIE_PREFIX_ERR):
            errs[k[len(COOKIE_PREFIX_ERR) :]] = unquote(v)
    return old, errs


def _session_cookie_headers_for_errors(values: dict[str, Any], field_errors: dict[str, str]) -> list[tuple[str, str]]:
    headers: list[tuple[str, str]] = []
    headers.append(("Set-Cookie", _set_cookie_header(name=COOKIE_PREFIX_OLD + "full_name", value=values.get("full_name", ""))))
    headers.append(("Set-Cookie", _set_cookie_header(name=COOKIE_PREFIX_OLD + "phone", value=values.get("phone", ""))))
    headers.append(("Set-Cookie", _set_cookie_header(name=COOKIE_PREFIX_OLD + "email", value=values.get("email", ""))))
    headers.append(("Set-Cookie", _set_cookie_header(name=COOKIE_PREFIX_OLD + "birth_date", value=values.get("birth_date_raw", ""))))
    headers.append(("Set-Cookie", _set_cookie_header(name=COOKIE_PREFIX_OLD + "gender", value=values.get("gender") or "")))
    headers.append(("Set-Cookie", _set_cookie_header(name=COOKIE_PREFIX_OLD + "languages", value=",".join(values.get("languages") or []))))
    headers.append(("Set-Cookie", _set_cookie_header(name=COOKIE_PREFIX_OLD + "biography", value=values.get("biography", ""))))
    headers.append(("Set-Cookie", _set_cookie_header(name=COOKIE_PREFIX_OLD + "contract", value="yes" if values.get("contract_accepted") else "")))
    for field, msg in field_errors.items():
        headers.append(("Set-Cookie", _set_cookie_header(name=COOKIE_PREFIX_ERR + field, value=msg)))
    return headers


def _delete_session_error_cookies_headers(old: dict[str, str], errs: dict[str, str]) -> list[tuple[str, str]]:
    headers: list[tuple[str, str]] = []
    for k in old.keys():
        headers.append(("Set-Cookie", _delete_cookie_header(name=COOKIE_PREFIX_OLD + k)))
    for k in errs.keys():
        headers.append(("Set-Cookie", _delete_cookie_header(name=COOKIE_PREFIX_ERR + k)))
    return headers


def _success_cookies_headers(values: dict[str, Any]) -> list[tuple[str, str]]:
    headers: list[tuple[str, str]] = []
    headers.append(("Set-Cookie", _set_cookie_header(name=COOKIE_PREFIX_SAVED + "full_name", value=values["full_name"], max_age=ONE_YEAR_SECONDS)))
    headers.append(("Set-Cookie", _set_cookie_header(name=COOKIE_PREFIX_SAVED + "phone", value=values["phone"], max_age=ONE_YEAR_SECONDS)))
    headers.append(("Set-Cookie", _set_cookie_header(name=COOKIE_PREFIX_SAVED + "email", value=values["email"], max_age=ONE_YEAR_SECONDS)))
    headers.append(("Set-Cookie", _set_cookie_header(name=COOKIE_PREFIX_SAVED + "birth_date", value=values["birth_date_raw"], max_age=ONE_YEAR_SECONDS)))
    headers.append(("Set-Cookie", _set_cookie_header(name=COOKIE_PREFIX_SAVED + "gender", value=values["gender"], max_age=ONE_YEAR_SECONDS)))
    headers.append(("Set-Cookie", _set_cookie_header(name=COOKIE_PREFIX_SAVED + "languages", value=",".join(values["languages"]), max_age=ONE_YEAR_SECONDS)))
    headers.append(("Set-Cookie", _set_cookie_header(name=COOKIE_PREFIX_SAVED + "biography", value=values["biography"], max_age=ONE_YEAR_SECONDS)))
    headers.append(("Set-Cookie", _set_cookie_header(name=COOKIE_PREFIX_SAVED + "contract", value="yes", max_age=ONE_YEAR_SECONDS)))
    headers.append(("Set-Cookie", _set_cookie_header(name=COOKIE_FLASH_SUCCESS, value="1")))
    return headers


def _parse_post(environ: dict) -> dict[str, list[str]]:
    try:
        size = int(environ.get("CONTENT_LENGTH", "0") or "0")
    except ValueError:
        size = 0
    raw = environ["wsgi.input"].read(size) if size > 0 else b""
    text = raw.decode("utf-8", errors="replace")
    return parse_qs(text, keep_blank_values=True)


def _parse_query(environ: dict) -> dict[str, list[str]]:
    return parse_qs(environ.get("QUERY_STRING", "") or "", keep_blank_values=True)


def _csrf_valid(posted: str, cookie_value: str) -> bool:
    if not posted or not cookie_value:
        return False
    return hmac.compare_digest(posted, cookie_value)


def _auth_block_for_user(is_auth: bool, login: str, csrf_token: str) -> str:
    if is_auth:
        return (
            '<div class="alert alert--success auth-banner">'
            f'<p class="auth-banner__text">Вы вошли как <strong>{_h(login)}</strong>. Можно менять свою заявку ниже.</p>'
            '<form class="auth-banner__form" method="post" action="/logout">'
            f'<input type="hidden" name="csrf_token" value="{_h(csrf_token)}" />'
            '<button type="submit" class="btn-secondary">Выйти</button></form></div>'
        )
    return (
        '<div class="alert auth-banner auth-banner--guest">'
        '<a class="text-link" href="/login">Вход по логину и паролю из письма после отправки анкеты</a>'
        "</div>"
    )


def _credentials_block_from_cookie(cookies: dict[str, str]) -> tuple[str, list[tuple[str, str]]]:
    raw = cookies.get(COOKIE_FLASH_CREDS, "")
    if not raw:
        return "", []
    decoded = unquote(raw)
    login, sep, password = decoded.partition("\t")
    if not sep:
        return "", [("Set-Cookie", _delete_cookie_header(name=COOKIE_FLASH_CREDS))]
    block = (
        '<div class="alert alert--success"><strong>Ваш логин и пароль (показываются один раз):</strong><br>'
        f'Логин: <code>{_h(login)}</code><br>'
        f'Пароль: <code>{_h(password)}</code><br>'
        "Сохраните их, они нужны для входа и редактирования заявки."
        "</div>"
    )
    return block, [("Set-Cookie", _delete_cookie_header(name=COOKIE_FLASH_CREDS))]


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


def _admin_unauthorized(start_response):
    start_response(
        "401 Unauthorized",
        [("Content-Type", "text/plain; charset=utf-8"), ("WWW-Authenticate", 'Basic realm="Admin area"')],
    )
    return [b"Unauthorized"]


def _admin_auth_ok(conn, environ: dict) -> bool:
    auth = environ.get("HTTP_AUTHORIZATION", "") or ""
    if not auth.startswith("Basic "):
        return False
    try:
        decoded = base64.b64decode(auth[6:].encode("ascii"), validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError):
        return False
    login, sep, password = decoded.partition(":")
    if not sep:
        return False
    cur = conn.cursor(dictionary=True)
    try:
        cur.execute("SELECT password_hash FROM admins WHERE login=%s LIMIT 1", (login,))
        row = cur.fetchone()
        if row is None:
            return False
        return _verify_password(password, str(row["password_hash"]))
    finally:
        cur.close()


def application(environ: dict, start_response):
    method = (environ.get("REQUEST_METHOD", "GET") or "GET").upper()
    path = environ.get("PATH_INFO", "") or "/"

    if path != "/" and path.startswith("/static/"):
        ctype_or_status, data = _serve_static(path)
        if isinstance(ctype_or_status, str) and ctype_or_status.startswith("404"):
            start_response("404 Not Found", [("Content-Type", "text/plain; charset=utf-8")])
            return [data]
        start_response("200 OK", [("Content-Type", ctype_or_status or "application/octet-stream")])
        return [data]

    try:
        conn = _get_db_connection()
    except Exception as exc:  # noqa: BLE001
        msg = "Ошибка подключения к БД."
        if os.environ.get("WSGI_DEBUG", "").lower() in ("1", "true", "yes"):
            msg += f" {exc!r}"
        start_response("500 Internal Server Error", [("Content-Type", "text/plain; charset=utf-8")])
        return [msg.encode("utf-8")]

    try:
        cookies = _parse_cookies(environ)
        session_data, session_submission = _get_current_user(conn, cookies)

        if path in ("/", "") and method == "GET":
            headers: list[tuple[str, str]] = [("Content-Type", "text/html; charset=utf-8")]
            field_errs: dict[str, str] = {}
            error_block = ""
            success_block = ""
            credentials_block = ""

            guest_csrf = unquote(cookies.get(COOKIE_GUEST_CSRF, "") or "")
            if not guest_csrf:
                guest_csrf = secrets.token_hex(32)
                headers.append(("Set-Cookie", _set_cookie_header(name=COOKIE_GUEST_CSRF, value=guest_csrf)))

            csrf_token = guest_csrf
            if session_data is not None:
                csrf_token = str(session_data["csrf_token"])

            if session_data is not None and session_submission is not None:
                langs = _load_submission_languages(conn, int(session_submission["id"]))
                values = _submission_to_values(session_submission, langs)
                submit_caption = "Сохранить изменения"
            else:
                defaults = _load_defaults_from_saved_cookies(cookies)
                old, field_errs = _load_old_and_errors_from_session_cookies(cookies)
                values = {
                    "full_name": old.get("full_name", defaults["full_name"]),
                    "phone": old.get("phone", defaults["phone"]),
                    "email": old.get("email", defaults["email"]),
                    "birth_date_raw": old.get("birth_date", defaults["birth_date"]),
                    "gender": old.get("gender", defaults["gender"]),
                    "languages": defaults["languages"],
                    "biography": old.get("biography", defaults["biography"]),
                    "contract_accepted": old.get("contract", "yes" if defaults["contract_accepted"] else "") == "yes",
                }
                langs_raw = old.get("languages", "")
                if langs_raw:
                    values["languages"] = frozenset(x for x in langs_raw.split(",") if x in ALLOWED_LANGUAGES)
                if field_errs:
                    error_block = _error_html(list(field_errs.values()))
                    headers.extend(_delete_session_error_cookies_headers(old, field_errs))
                submit_caption = "Сохранить"

            if cookies.get(COOKIE_FLASH_SUCCESS) == "1":
                success_block = _success_html()
                headers.append(("Set-Cookie", _delete_cookie_header(name=COOKIE_FLASH_SUCCESS)))

            creds_block, creds_headers = _credentials_block_from_cookie(cookies)
            credentials_block = creds_block
            headers.extend(creds_headers)

            auth_login = str(session_submission["user_login"]) if session_submission is not None else ""
            auth_block = _auth_block_for_user(session_data is not None, auth_login, csrf_token)
            body = _render_main(
                error_block=error_block,
                success_block=success_block,
                credentials_block=credentials_block,
                auth_block=auth_block,
                csrf_token_value=csrf_token,
                submit_caption=submit_caption,
                full_name_value=str(values["full_name"]),
                phone_value=str(values["phone"]),
                email_value=str(values["email"]),
                birth_date_value=str(values["birth_date_raw"]),
                gender=(values["gender"] if values["gender"] in ALLOWED_GENDER else None),
                languages_selected=frozenset(values["languages"]),
                biography_value=str(values["biography"]),
                contract_accepted=bool(values["contract_accepted"]),
                field_errors=field_errs,
            )
            start_response("200 OK", headers)
            return [body.encode("utf-8")]

        if path in ("/", "") and method == "POST":
            params = _parse_post(environ)
            csrf_posted = _first(params, "csrf_token")

            if session_data is not None and session_submission is not None:
                if not _csrf_valid(csrf_posted, str(session_data["csrf_token"])):
                    start_response("403 Forbidden", [("Content-Type", "text/plain; charset=utf-8")])
                    return [b"CSRF token mismatch"]
                values, field_errors, errors = _validate(params)
                if errors:
                    body = _render_main(
                        error_block=_error_html(errors),
                        auth_block=_auth_block_for_user(True, str(session_submission["user_login"]), str(session_data["csrf_token"])),
                        csrf_token_value=str(session_data["csrf_token"]),
                        submit_caption="Сохранить изменения",
                        full_name_value=values["full_name"],
                        phone_value=values["phone"],
                        email_value=values["email"],
                        birth_date_value=values["birth_date_raw"],
                        gender=values["gender"],
                        languages_selected=frozenset(values["languages"]),
                        biography_value=values["biography"],
                        contract_accepted=values["contract_accepted"],
                        field_errors=field_errors,
                    )
                    start_response("200 OK", [("Content-Type", "text/html; charset=utf-8")])
                    return [body.encode("utf-8")]
                try:
                    conn.start_transaction()
                    _update_submission(conn, int(session_submission["id"]), values)
                    _upsert_submission_languages(conn, int(session_submission["id"]), values["languages"])
                    conn.commit()
                except Exception:
                    conn.rollback()
                    raise
                start_response(
                    "303 See Other",
                    [("Location", "/"), ("Set-Cookie", _set_cookie_header(name=COOKIE_FLASH_SUCCESS, value="1"))],
                )
                return [b""]

            guest_csrf = unquote(cookies.get(COOKIE_GUEST_CSRF, "") or "")
            if not _csrf_valid(csrf_posted, guest_csrf):
                start_response("403 Forbidden", [("Content-Type", "text/plain; charset=utf-8")])
                return [b"CSRF token mismatch"]

            values, field_errors, errors = _validate(params)
            if errors:
                headers = _session_cookie_headers_for_errors(values, field_errors)
                headers.append(("Location", "/"))
                start_response("303 See Other", headers)
                return [b""]

            try:
                conn.start_transaction()
                login = _gen_user_login(conn)
                password = _gen_password()
                password_hash = _hash_password(password)
                submission_id = _insert_submission(conn, values, login, password_hash)
                _upsert_submission_languages(conn, submission_id, values["languages"])
                conn.commit()
            except Exception:
                conn.rollback()
                raise

            headers = _success_cookies_headers(values)
            headers.append(("Set-Cookie", _set_cookie_header(name=COOKIE_FLASH_CREDS, value=f"{login}\t{password}")))
            headers.append(("Location", "/"))
            start_response("303 See Other", headers)
            return [b""]

        if path == "/login" and method == "GET":
            guest_csrf = unquote(cookies.get(COOKIE_GUEST_CSRF, "") or "")
            headers = [("Content-Type", "text/html; charset=utf-8")]
            if not guest_csrf:
                guest_csrf = secrets.token_hex(32)
                headers.append(("Set-Cookie", _set_cookie_header(name=COOKIE_GUEST_CSRF, value=guest_csrf)))
            body = _render_login_page(csrf_token=guest_csrf)
            start_response("200 OK", headers)
            return [body.encode("utf-8")]

        if path == "/login" and method == "POST":
            params = _parse_post(environ)
            guest_csrf = unquote(cookies.get(COOKIE_GUEST_CSRF, "") or "")
            if not _csrf_valid(_first(params, "csrf_token"), guest_csrf):
                start_response("403 Forbidden", [("Content-Type", "text/plain; charset=utf-8")])
                return [b"CSRF token mismatch"]
            login = _first(params, "login").strip()
            password = _first(params, "password")
            if not login or not password:
                body = _render_login_page(error_text="Укажите логин и пароль.", csrf_token=guest_csrf, login_value=login)
                start_response("200 OK", [("Content-Type", "text/html; charset=utf-8")])
                return [body.encode("utf-8")]
            cur = conn.cursor(dictionary=True)
            try:
                cur.execute("SELECT id, password_hash FROM form_submissions WHERE user_login=%s LIMIT 1", (login,))
                row = cur.fetchone()
            finally:
                cur.close()
            if row is None or not _verify_password(password, str(row["password_hash"])):
                body = _render_login_page(error_text="Неверный логин или пароль.", csrf_token=guest_csrf, login_value=login)
                start_response("200 OK", [("Content-Type", "text/html; charset=utf-8")])
                return [body.encode("utf-8")]
            sid, _ = _create_user_session(conn, int(row["id"]))
            start_response(
                "303 See Other",
                [
                    ("Location", "/"),
                    ("Set-Cookie", _set_cookie_header(name=COOKIE_SESSION_ID, value=sid, http_only=True, max_age=SESSION_SECONDS)),
                ],
            )
            return [b""]

        if path == "/logout" and method == "POST":
            if session_data is None:
                start_response("303 See Other", [("Location", "/")])
                return [b""]
            params = _parse_post(environ)
            if not _csrf_valid(_first(params, "csrf_token"), str(session_data["csrf_token"])):
                start_response("403 Forbidden", [("Content-Type", "text/plain; charset=utf-8")])
                return [b"CSRF token mismatch"]
            _destroy_session(conn, str(session_data["session_id"]))
            start_response(
                "303 See Other",
                [("Location", "/"), ("Set-Cookie", _delete_cookie_header(name=COOKIE_SESSION_ID))],
            )
            return [b""]

        if path == "/admin" and method == "GET":
            if not _admin_auth_ok(conn, environ):
                return _admin_unauthorized(start_response)
            admin_csrf = unquote(cookies.get(COOKIE_ADMIN_CSRF, "") or "")
            headers = [("Content-Type", "text/html; charset=utf-8")]
            if not admin_csrf:
                admin_csrf = secrets.token_hex(32)
                headers.append(("Set-Cookie", _set_cookie_header(name=COOKIE_ADMIN_CSRF, value=admin_csrf)))
            cur = conn.cursor(dictionary=True)
            try:
                cur.execute(
                    """
                    SELECT fs.id, fs.user_login, fs.full_name, fs.phone, fs.email, fs.birth_date, fs.gender, fs.biography, fs.contract_accepted,
                           GROUP_CONCAT(pl.display_name ORDER BY pl.id SEPARATOR ', ') AS languages
                    FROM form_submissions fs
                    LEFT JOIN submission_programming_languages spl ON spl.submission_id = fs.id
                    LEFT JOIN programming_languages pl ON pl.id = spl.language_id
                    GROUP BY fs.id
                    ORDER BY fs.id DESC
                    """
                )
                rows = cur.fetchall()
                cur.execute(
                    """
                    SELECT pl.display_name, COUNT(spl.submission_id) AS cnt
                    FROM programming_languages pl
                    LEFT JOIN submission_programming_languages spl ON spl.language_id = pl.id
                    GROUP BY pl.id, pl.display_name
                    ORDER BY pl.id
                    """
                )
                stats = cur.fetchall()
            finally:
                cur.close()
            body = _render_admin_page(rows=rows, stats=stats, csrf_token=admin_csrf)
            start_response("200 OK", headers)
            return [body.encode("utf-8")]

        if path == "/admin/delete" and method == "POST":
            if not _admin_auth_ok(conn, environ):
                return _admin_unauthorized(start_response)
            params = _parse_post(environ)
            admin_csrf = unquote(cookies.get(COOKIE_ADMIN_CSRF, "") or "")
            if not _csrf_valid(_first(params, "csrf_token"), admin_csrf):
                start_response("403 Forbidden", [("Content-Type", "text/plain; charset=utf-8")])
                return [b"CSRF token mismatch"]
            q = _parse_query(environ)
            try:
                sub_id = int(_first(q, "id"))
            except ValueError:
                start_response("400 Bad Request", [("Content-Type", "text/plain; charset=utf-8")])
                return [b"Bad id"]
            cur = conn.cursor()
            try:
                cur.execute("DELETE FROM form_submissions WHERE id=%s", (sub_id,))
            finally:
                cur.close()
            conn.commit()
            start_response("303 See Other", [("Location", "/admin")])
            return [b""]

        if path == "/admin/edit" and method in ("GET", "POST"):
            if not _admin_auth_ok(conn, environ):
                return _admin_unauthorized(start_response)
            q = _parse_query(environ)
            try:
                sub_id = int(_first(q, "id"))
            except ValueError:
                start_response("400 Bad Request", [("Content-Type", "text/plain; charset=utf-8")])
                return [b"Bad id"]
            admin_csrf = unquote(cookies.get(COOKIE_ADMIN_CSRF, "") or "")
            headers = [("Content-Type", "text/html; charset=utf-8")]
            if not admin_csrf:
                admin_csrf = secrets.token_hex(32)
                headers.append(("Set-Cookie", _set_cookie_header(name=COOKIE_ADMIN_CSRF, value=admin_csrf)))

            if method == "POST":
                params = _parse_post(environ)
                if not _csrf_valid(_first(params, "csrf_token"), admin_csrf):
                    start_response("403 Forbidden", [("Content-Type", "text/plain; charset=utf-8")])
                    return [b"CSRF token mismatch"]
                values, field_errors, errors = _validate(params)
                if errors:
                    body = _render_admin_edit_page(sub_id=sub_id, values=values, field_errors=field_errors, csrf_token=admin_csrf)
                    start_response("200 OK", headers)
                    return [body.encode("utf-8")]
                try:
                    conn.start_transaction()
                    _update_submission(conn, sub_id, values)
                    _upsert_submission_languages(conn, sub_id, values["languages"])
                    conn.commit()
                except Exception:
                    conn.rollback()
                    raise
                start_response("303 See Other", [("Location", "/admin")])
                return [b""]

            cur = conn.cursor(dictionary=True)
            try:
                cur.execute(
                    """
                    SELECT id, full_name, phone, email, birth_date, gender, biography, contract_accepted
                    FROM form_submissions
                    WHERE id=%s
                    LIMIT 1
                    """,
                    (sub_id,),
                )
                row = cur.fetchone()
            finally:
                cur.close()
            if row is None:
                start_response("404 Not Found", [("Content-Type", "text/plain; charset=utf-8")])
                return [b"Not found"]
            langs = _load_submission_languages(conn, sub_id)
            values = _submission_to_values(row, langs)
            body = _render_admin_edit_page(sub_id=sub_id, values=values, field_errors=None, csrf_token=admin_csrf)
            start_response("200 OK", headers)
            return [body.encode("utf-8")]

        start_response("404 Not Found", [("Content-Type", "text/plain; charset=utf-8")])
        return [b"Not found"]
    except Exception as exc:  # noqa: BLE001
        msg = "Внутренняя ошибка сервера."
        if os.environ.get("WSGI_DEBUG", "").lower() in ("1", "true", "yes"):
            msg += f" ({exc!r})"
        start_response("500 Internal Server Error", [("Content-Type", "text/plain; charset=utf-8")])
        return [msg.encode("utf-8")]
    finally:
        conn.close()


if __name__ == "__main__":  # pragma: no cover
    from wsgiref.simple_server import make_server

    port = int(os.environ.get("PORT", "8000"))
    print(f"Serving http://127.0.0.1:{port}/", file=sys.stderr)
    make_server("127.0.0.1", port, application).serve_forever()


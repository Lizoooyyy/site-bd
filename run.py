"""
Локальный запуск для проверки: python run.py
Перед запуском задайте переменные окружения (или создайте .env и экспортируйте вручную).
"""
import os

from wsgiref.simple_server import make_server

from wsgi import application


def main() -> None:
    env_path = os.path.join(os.path.dirname(__file__), ".env")
    if os.path.isfile(env_path):
        with open(env_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, _, v = line.partition("=")
                k, v = k.strip(), v.strip().strip('"').strip("'")
                if k and k not in os.environ:
                    os.environ[k] = v
    port = int(os.environ.get("PORT", "8000"))
    srv = make_server("127.0.0.1", port, application)
    print(f"http://127.0.0.1:{port}/")
    srv.serve_forever()


if __name__ == "__main__":
    main()

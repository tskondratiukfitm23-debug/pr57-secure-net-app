"""Налаштування сервера (усе через змінні середовища, жодних секретів у коді)."""
import os
import secrets
import sys


def _int(name, default):
    return int(os.environ.get(name, default))


APP_ENV = os.environ.get("APP_ENV", "dev")

JWT_SECRET = os.environ.get("JWT_SECRET")
if not JWT_SECRET:
    if APP_ENV == "prod":
        sys.exit("JWT_SECRET is required in prod")
    # dev: ефемерний секрет на час життя процесу (токени стають недійсними після перезапуску)
    JWT_SECRET = secrets.token_urlsafe(48)
    JWT_SECRET_SOURCE = "ephemeral"  # nosec B105
else:
    JWT_SECRET_SOURCE = "env"  # nosec B105
if len(JWT_SECRET) < 32:
    sys.exit("JWT_SECRET must be at least 32 characters")

JWT_ALG = "HS256"
JWT_ISS = os.environ.get("JWT_ISS", "secure-net-app")
JWT_AUD = os.environ.get("JWT_AUD", "secure-net-clients")
ACCESS_TTL = _int("ACCESS_TTL", 900)          # 15 хв
REFRESH_TTL = _int("REFRESH_TTL", 8 * 3600)   # 8 год
MFA_TOKEN_TTL = _int("MFA_TOKEN_TTL", 300)    # 5 хв на введення OTP

USERS_PATH = os.environ.get("USERS_PATH", os.path.join(os.path.dirname(__file__), "users.json"))
LOG_PATH = os.environ.get("APP_LOG", os.path.join(os.path.dirname(__file__), "logs", "app.jsonl"))

# Rate limit / brute force
LOGIN_MAX_FAILS = _int("LOGIN_MAX_FAILS", 5)       # невдалих спроб до блокування
LOGIN_WINDOW = _int("LOGIN_WINDOW", 300)           # вікно підрахунку, с
LOCKOUT_BASE = _int("LOCKOUT_BASE", 60)            # перше блокування, с (далі x2, макс 1 год)
LOGIN_IP_RPM = _int("LOGIN_IP_RPM", 20)            # спроб логіну з одного IP за хвилину
RATE_CAPACITY = _int("RATE_CAPACITY", 30)          # token bucket на IP: розмір
RATE_REFILL = float(os.environ.get("RATE_REFILL", 15))  # токенів/с

# Порти: HTTP_PORTS — плейн-текст лише для /health і /echo-http (Завдання 2)
HTTP_PORTS = {int(p) for p in os.environ.get("HTTP_PORTS", "8080").split(",") if p}

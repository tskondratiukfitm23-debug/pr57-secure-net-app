"""Структуровані JSON-логи (JSONL) з маскуванням секретів.

Формат рядка:
{"ts":"2026-11-25T20:00:00.123Z","level":"WARNING","event":"auth.fail","category":"auth",
 "ip":"10.0.0.2","user":"alice","request_id":"…","reason":"bad_password"}
"""
import json
import logging
import os
import time

from server import config

SENSITIVE = {"password", "pwd", "token", "access_token", "refresh_token", "otp", "secret",
             "totp_secret", "authorization", "jwt", "mfa_token"}

# event -> category (для фільтрації за типом)
CATEGORIES = {"http": "request", "auth": "auth", "mfa": "auth", "token": "session",  # nosec B105
              "access": "access", "rate": "security", "lockout": "security", "tls": "security",
              "server": "system", "error": "error", "admin": "admin"}


def mask(obj):
    if isinstance(obj, dict):
        return {k: ("***" if k.lower() in SENSITIVE else mask(v)) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [mask(v) for v in obj]
    return obj


class JSONFormatter(logging.Formatter):
    def format(self, record):
        ms = int((record.created % 1) * 1000)
        event = record.getMessage()
        data = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created)) + f".{ms:03d}Z",
                "level": record.levelname, "event": event,
                "category": CATEGORIES.get(event.split(".")[0], "other")}
        fields = getattr(record, "fields", None)
        if isinstance(fields, dict):
            data.update(mask(fields))
        return json.dumps(data, ensure_ascii=False)


def get_logger(path: str = None) -> logging.Logger:
    path = path or config.LOG_PATH
    logger = logging.getLogger("secure-net-app")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    current = getattr(logger, "_path", None)
    if current != path:
        for h in list(logger.handlers):
            logger.removeHandler(h)
            h.close()
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        fh = logging.FileHandler(path, encoding="utf-8")
        fh.setFormatter(JSONFormatter())
        logger.addHandler(fh)
        logger._path = path
    return logger


def log(event: str, level: int = logging.INFO, **fields):
    get_logger().log(level, event, extra={"fields": fields})

"""Паролі (bcrypt), JWT (HS256, iss/aud/exp/jti), ролі, відкликання токенів, TOTP-MFA."""
import json
import os
import threading
import time
import uuid
from typing import Optional

import bcrypt
import jwt
import pyotp

from server import config

BCRYPT_ROUNDS = int(os.environ.get("BCRYPT_ROUNDS", 12))
ROLES = {"user": {"echo", "whoami", "mfa"}, "admin": {"echo", "whoami", "mfa", "admin"}}
_lock = threading.RLock()
# фіктивний хеш для вирівнювання часу відповіді, якщо користувача не існує (захист від енумерації)
_DUMMY_HASH = bcrypt.hashpw(b"dummy-password-for-timing", bcrypt.gensalt(BCRYPT_ROUNDS))


# ------------------------------------------------------------------ users store
class UserStore:
    def __init__(self, path: str = None):
        self.path = path or config.USERS_PATH
        self.reload()

    def reload(self):
        with _lock:
            if os.path.exists(self.path):
                with open(self.path, "r", encoding="utf-8") as f:
                    self.users = json.load(f)
            else:
                self.users = {}

    def save(self):
        with _lock:
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self.users, f, ensure_ascii=False, indent=2)
            os.replace(tmp, self.path)

    def get(self, username: str) -> Optional[dict]:
        return self.users.get(username)

    def add(self, username: str, password: str, role: str = "user"):
        check_password_policy(password)
        if role not in ROLES:
            raise ValueError("unknown role")
        with _lock:
            if username in self.users:
                raise ValueError("user exists")
            self.users[username] = {"pwd": hash_password(password), "role": role,
                                    "totp_secret": None, "mfa_enabled": False, "totp_last": 0}
            self.save()

    def public(self):
        return [{"username": u, "role": d["role"], "mfa_enabled": d.get("mfa_enabled", False)}
                for u, d in self.users.items()]


def check_password_policy(pwd: str):
    problems = []
    if len(pwd) < 12:
        problems.append("мінімум 12 символів")
    if not any(c.isdigit() for c in pwd):
        problems.append("потрібна цифра")
    if not any(c.isupper() for c in pwd) or not any(c.islower() for c in pwd):
        problems.append("потрібні великі та малі літери")
    if problems:
        raise ValueError("Слабкий пароль: " + ", ".join(problems))


def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt(BCRYPT_ROUNDS)).decode()


def verify_password(plain: str, hashed: Optional[str]) -> bool:
    if not hashed:
        bcrypt.checkpw(plain.encode("utf-8"), _DUMMY_HASH)  # однаковий час
        return False
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode())
    except ValueError:
        return False


# ------------------------------------------------------------------ JWT
class TokenError(Exception):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class Denylist:
    """Відкликані jti (logout, ротація refresh). У проді — Redis з TTL."""

    def __init__(self):
        self._d = {}

    def add(self, jti: str, exp: int):
        with _lock:
            self._d[jti] = exp
            now = time.time()
            for k in [k for k, v in self._d.items() if v < now]:
                del self._d[k]

    def __contains__(self, jti):
        return jti in self._d


DENYLIST = Denylist()


def create_token(sub: str, role: str, typ: str = "access", ttl: int = None) -> str:
    now = int(time.time())
    ttl = ttl or {"access": config.ACCESS_TTL, "refresh": config.REFRESH_TTL, "mfa": config.MFA_TOKEN_TTL}[typ]
    payload = {"sub": sub, "role": role, "typ": typ, "iat": now, "nbf": now, "exp": now + ttl,
               "iss": config.JWT_ISS, "aud": config.JWT_AUD, "jti": uuid.uuid4().hex}
    return jwt.encode(payload, config.JWT_SECRET, algorithm=config.JWT_ALG)


def decode_token(tok: str, expected_typ: str = "access") -> dict:
    try:
        payload = jwt.decode(tok, config.JWT_SECRET, algorithms=[config.JWT_ALG],
                             audience=config.JWT_AUD, issuer=config.JWT_ISS,
                             options={"require": ["exp", "iat", "sub", "jti", "typ", "iss", "aud"]})
    except jwt.ExpiredSignatureError:
        raise TokenError("expired")
    except jwt.InvalidSignatureError:
        raise TokenError("bad_signature")
    except jwt.InvalidAlgorithmError:
        raise TokenError("bad_algorithm")
    except jwt.InvalidAudienceError:
        raise TokenError("bad_audience")
    except jwt.InvalidIssuerError:
        raise TokenError("bad_issuer")
    except jwt.MissingRequiredClaimError as e:
        raise TokenError(f"missing_claim:{e.claim}")
    except jwt.InvalidTokenError:
        raise TokenError("malformed")
    if payload.get("typ") != expected_typ:
        raise TokenError("wrong_type")
    if payload["jti"] in DENYLIST:
        raise TokenError("revoked")
    if payload.get("role") not in ROLES:
        raise TokenError("bad_role")
    return payload


def revoke(payload: dict):
    DENYLIST.add(payload["jti"], payload["exp"])


def has_permission(role: str, perm: str) -> bool:
    return perm in ROLES.get(role, set())


# ------------------------------------------------------------------ TOTP (RFC 6238)
def mfa_begin(store: UserStore, username: str) -> dict:
    """Генерує новий секрет (ще не активний, поки не підтверджено кодом)."""
    with _lock:
        u = store.get(username)
        secret = pyotp.random_base32()
        u["totp_pending"] = secret
        store.save()
    uri = pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name="SecureNetApp")
    return {"secret": secret, "otpauth_uri": uri}


def mfa_confirm(store: UserStore, username: str, otp: str) -> bool:
    with _lock:
        u = store.get(username)
        secret = u.get("totp_pending")
        if not secret:
            return False
        totp = pyotp.TOTP(secret)
        if not totp.verify(otp, valid_window=1):
            return False
        u["totp_secret"], u["mfa_enabled"] = secret, True
        u["totp_last"] = totp.timecode(time.time())
        u.pop("totp_pending", None)
        store.save()
    return True


def verify_totp(store: UserStore, username: str, otp: str) -> str:
    """Повертає 'ok' | 'invalid' | 'replay'. Код приймається з вікном ±1 крок (30 с)."""
    with _lock:
        u = store.get(username)
        secret = u.get("totp_secret") if u else None
        if not secret:
            return "invalid"
        totp = pyotp.TOTP(secret)
        now = time.time()
        for drift in (0, -1, 1):
            step = totp.timecode(now) + drift
            if pyotp.utils.strings_equal(str(otp), totp.generate_otp(step)):
                if step <= u.get("totp_last", 0):
                    return "replay"
                u["totp_last"] = step
                store.save()
                return "ok"
    return "invalid"

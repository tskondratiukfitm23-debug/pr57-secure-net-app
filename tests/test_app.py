import json
import os
import time

import jwt
import pyotp

from server import config, security
from tests.conftest import login


# ---------- Завдання 2: протокол запит-відповідь / plaintext
def test_health_and_echo_plain(http_client):
    assert http_client.get("/health").json()["tls"] is False
    r = http_client.post("/echo-http", json={"msg": "hi"})
    assert r.status_code == 200 and r.json()["echo"] == "hi" and r.json()["len"] == 2


def test_plaintext_auth_forbidden(http_client):
    r = http_client.post("/auth/login", json={"username": "alice", "password": "x"})
    assert r.status_code == 403 and "TLS required" in r.json()["detail"]


def test_security_headers(client):
    r = client.get("/health")
    assert r.headers["Strict-Transport-Security"].startswith("max-age=")
    assert r.headers["X-Content-Type-Options"] == "nosniff"


def test_validation_422(client):
    assert client.post("/echo-http", json={"msg": ""}).status_code == 422
    assert client.post("/auth/login", json={"username": "a b'--", "password": "x"}).status_code == 422


# ---------- Завдання 4: облікові записи, bcrypt, ролі
def test_passwords_hashed_with_bcrypt(client):
    data = json.load(open(os.environ["USERS_PATH"]))
    for u in data.values():
        assert u["pwd"].startswith("$2b$") and "Passw0rd" not in u["pwd"]
    assert data["alice"]["pwd"] != data["admin"]["pwd"]


def test_login_ok_and_bad(client):
    assert login(client)["role"] == "user"
    r = client.post("/auth/login", json={"username": "alice", "password": "wrong"})
    assert r.status_code == 401
    r = client.post("/auth/login", json={"username": "nobody", "password": "wrong"})
    assert r.status_code == 401 and r.json()["detail"] == "Invalid credentials"


def test_password_policy(client):
    tok = login(client, "admin")["access_token"]
    h = {"Authorization": f"Bearer {tok}"}
    assert client.post("/admin/users", headers=h, json={"username": "eve", "password": "short"}).status_code == 422
    assert client.post("/admin/users", headers=h,
                       json={"username": "eve", "password": "alllowercaseletters"}).status_code == 400
    assert client.post("/admin/users", headers=h,
                       json={"username": "eve", "password": "Eve-Passw0rd-2026"}).status_code == 201


def test_roles(client):
    user = {"Authorization": "Bearer " + login(client)["access_token"]}
    admin = {"Authorization": "Bearer " + login(client, "admin")["access_token"]}
    assert client.get("/admin/users", headers=user).status_code == 403
    assert client.get("/admin/users", headers=admin).status_code == 200
    assert client.post("/echo-https", headers=user, json={"msg": "x"}).json()["user"] == "alice"


# ---------- Завдання 5: JWT
def test_missing_and_garbage_token(client):
    assert client.get("/whoami").status_code == 401
    assert client.get("/whoami", headers={"Authorization": "Bearer abc.def.ghi"}).status_code == 401


def test_expired_token(client):
    tok = security.create_token("alice", "user", "access", ttl=1)
    time.sleep(2.1)
    r = client.get("/whoami", headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 401 and r.json()["detail"] == "Token expired"


def test_forged_tokens_rejected(client):
    now = int(time.time())
    base = {"sub": "alice", "role": "admin", "typ": "access", "iat": now, "nbf": now, "exp": now + 600,
            "iss": config.JWT_ISS, "aud": config.JWT_AUD, "jti": "x"}
    forged = [
        jwt.encode(base, "wrong-secret-wrong-secret-wrong-secret", algorithm="HS256"),  # інший ключ
        jwt.encode(base, None, algorithm="none"),                                       # alg=none
        jwt.encode({**base, "aud": "other"}, config.JWT_SECRET, algorithm="HS256"),
        jwt.encode({**base, "typ": "refresh"}, config.JWT_SECRET, algorithm="HS256"),
    ]
    for t in forged:
        assert client.get("/admin/users", headers={"Authorization": f"Bearer {t}"}).status_code == 401


def test_role_from_db_not_token(client):
    # навіть валідно підписаний токен із role=admin для alice не дає адмін-доступу
    tok = security.create_token("alice", "admin", "access")
    assert client.get("/admin/users", headers={"Authorization": f"Bearer {tok}"}).status_code == 403


def test_refresh_rotation_and_logout(client):
    pair = login(client)
    r = client.post("/auth/refresh", json={"refresh_token": pair["refresh_token"]})
    assert r.status_code == 200
    assert client.post("/auth/refresh", json={"refresh_token": pair["refresh_token"]}).status_code == 401
    new = r.json()
    h = {"Authorization": f"Bearer {new['access_token']}"}
    assert client.post("/auth/logout", headers=h, json={"refresh_token": new["refresh_token"]}).status_code == 200
    assert client.get("/whoami", headers=h).status_code == 401
    assert client.post("/auth/refresh", json={"refresh_token": new["refresh_token"]}).status_code == 401


def test_access_token_not_usable_as_refresh(client):
    pair = login(client)
    assert client.post("/auth/refresh", json={"refresh_token": pair["access_token"]}).status_code == 401


# ---------- Завдання 8: MFA TOTP
def _enable_mfa(client):
    h = {"Authorization": "Bearer " + login(client)["access_token"]}
    setup = client.post("/auth/mfa/setup", headers=h).json()
    assert setup["otpauth_uri"].startswith("otpauth://totp/SecureNetApp:alice")
    assert client.post("/auth/mfa/confirm", headers=h, json={"otp": "000000"}).status_code in (400,)
    totp = pyotp.TOTP(setup["secret"])
    assert client.post("/auth/mfa/confirm", headers=h, json={"otp": totp.now()}).status_code == 200
    return totp


def test_mfa_flow_and_replay(client):
    totp = _enable_mfa(client)
    r = client.post("/auth/login", json={"username": "alice", "password": "Alice-Passw0rd!"})
    body = r.json()
    assert body["mfa_required"] is True and "access_token" not in body
    mfa_tok = body["mfa_token"]
    # mfa_token не є access-токеном
    assert client.get("/whoami", headers={"Authorization": f"Bearer {mfa_tok}"}).status_code == 401
    # код, вже використаний при підтвердженні, -> replay
    assert client.post("/auth/login/otp", json={"mfa_token": mfa_tok, "otp": totp.now()}).status_code == 401
    nxt = totp.generate_otp(totp.timecode(time.time()) + 1)
    r = client.post("/auth/login/otp", json={"mfa_token": mfa_tok, "otp": nxt})
    assert r.status_code == 200 and "access_token" in r.json()
    # повтор того ж коду / того ж mfa_token
    assert client.post("/auth/login/otp", json={"mfa_token": mfa_tok, "otp": nxt}).status_code == 401


# ---------- Завдання 7: brute force / rate limit
def test_lockout_after_failures(client):
    for _ in range(3):
        assert client.post("/auth/login", json={"username": "alice", "password": "bad"}).status_code == 401
    r = client.post("/auth/login", json={"username": "alice", "password": "Alice-Passw0rd!"})
    assert r.status_code == 429 and int(r.headers["Retry-After"]) > 0
    # інший користувач не заблокований
    assert login(client, "admin")["role"] == "admin"


def test_token_bucket(client):
    from server import app as app_module
    from server.ratelimit import TokenBucket
    app_module.bucket = TokenBucket(capacity=5, refill=0.01)
    codes = [client.get("/health").status_code for _ in range(8)]
    assert codes[:5] == [200] * 5 and codes[-1] == 429


# ---------- Завдання 6: журнали
def test_logs_written_filtered_and_masked(client):
    client.post("/auth/login", json={"username": "alice", "password": "S3cret-should-not-leak"})
    raw = open(os.environ["APP_LOG"], encoding="utf-8").read()
    assert "S3cret-should-not-leak" not in raw
    h = {"Authorization": "Bearer " + login(client, "admin")["access_token"]}
    r = client.get("/admin/logs", headers=h, params={"event": "auth.fail", "user": "alice", "since": "10m"})
    ev = r.json()["events"]
    assert r.status_code == 200 and ev and all(e["event"] == "auth.fail" and e["user"] == "alice" for e in ev)
    assert client.get("/admin/logs", headers=h, params={"since": "bad"}).status_code == 400

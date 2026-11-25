"""Тестове оточення: змінні середовища ДО імпорту server.*"""
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
_tmp = tempfile.mkdtemp(prefix="sna-test-")
os.environ.update({
    "JWT_SECRET": "test-secret-0123456789-abcdefghijklmnop",
    "USERS_PATH": os.path.join(_tmp, "users.json"),
    "APP_LOG": os.path.join(_tmp, "app.jsonl"),
    "BCRYPT_ROUNDS": "4",
    "LOGIN_MAX_FAILS": "3",
    "LOGIN_IP_RPM": "1000",
    "RATE_CAPACITY": "1000",
    "RATE_REFILL": "1000",
})

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from server import app as app_module, security  # noqa: E402

USERS = {"alice": ("Alice-Passw0rd!", "user"), "admin": ("Admin-Passw0rd!", "admin")}


@pytest.fixture()
def client():
    if os.path.exists(os.environ["USERS_PATH"]):
        os.remove(os.environ["USERS_PATH"])
    store = app_module.store
    store.reload()
    for u, (p, r) in USERS.items():
        store.add(u, p, r)
    app_module.reset_state()
    security.DENYLIST.__init__()
    return TestClient(app_module.app, base_url="https://testserver")


@pytest.fixture()
def http_client():
    return TestClient(app_module.app, base_url="http://testserver")


def login(c, user="alice"):
    r = c.post("/auth/login", json={"username": user, "password": USERS[user][0]})
    assert r.status_code == 200, r.text
    return r.json()

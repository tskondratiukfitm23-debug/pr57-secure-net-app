"""Створює демо-БД користувачів з bcrypt-хешами (cost 12).

python -m server.scripts.create_users            # демо-користувачі alice/bob/admin
python -m server.scripts.create_users --user carol --role user   # пароль запитується інтерактивно
"""
import argparse
import getpass
import json
import os

from server import config, security

DEMO = [("alice", "Alice-Passw0rd!", "user"),
        ("bob", "Bob-Passw0rd-2026", "user"),
        ("admin", "Admin-Passw0rd!", "admin")]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--path", default=config.USERS_PATH)
    ap.add_argument("--user")
    ap.add_argument("--role", default="user", choices=["user", "admin"])
    ap.add_argument("--reset", action="store_true", help="перезаписати БД демо-користувачами")
    a = ap.parse_args()
    if a.reset or not os.path.exists(a.path):
        with open(a.path, "w", encoding="utf-8") as f:
            json.dump({}, f)
    store = security.UserStore(a.path)
    if a.user:
        pwd = getpass.getpass(f"Пароль для {a.user}: ")
        store.add(a.user, pwd, a.role)
        print(f"Створено {a.user} ({a.role})")
        return
    for u, p, r in DEMO:
        if not store.get(u):
            store.add(u, p, r)
            print(f"Створено {u:<6} роль={r:<5} hash={store.get(u)['pwd'][:29]}…")


if __name__ == "__main__":
    main()

"""CLI-клієнт Secure Net App.

Адреса сервера: --host (або env SNA_HOST, за замовч. 127.0.0.1), порти --http-port/--https-port.
Довіра: --ca server/certs/ca.crt (перевірка ланцюжка + імені хоста). Перевірку НЕ вимкнено ніде.
Токени зберігаються у client/.tokens.json (gitignored) і ніколи не друкуються повністю.
"""
import argparse
import base64
import concurrent.futures as cf
import hashlib
import hmac
import json
import os
import socket
import ssl
import sys
import time

import requests

TOK_FILE = os.environ.get("SNA_TOKENS", os.path.join(os.path.dirname(__file__), ".tokens.json"))


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def short(tok: str) -> str:
    return tok[:16] + "…" + tok[-6:] if tok else "-"


class Client:
    def __init__(self, a):
        self.a = a
        self.http = f"http://{a.host}:{a.http_port}"
        self.https = f"https://{a.host}:{a.https_port}"
        self.verify = a.ca if a.ca else True

    # ---- helpers
    def req(self, method, path, tls=True, token=None, **kw):
        url = (self.https if tls else self.http) + path
        h = kw.pop("headers", {})
        if token:
            h["Authorization"] = f"Bearer {token}"
        t = time.perf_counter()
        r = requests.request(method, url, headers=h, timeout=10, verify=self.verify if tls else True, **kw)
        ms = (time.perf_counter() - t) * 1000
        return r, ms

    @staticmethod
    def show(r, ms=None, hide=("access_token", "refresh_token", "mfa_token")):
        try:
            body = r.json()
            if isinstance(body, dict):
                body = {k: (short(v) if k in hide and isinstance(v, str) else v) for k, v in body.items()}
            txt = json.dumps(body, ensure_ascii=False)
        except ValueError:
            txt = r.text[:300]
        extra = f"  ({ms:.1f} ms)" if ms is not None else ""
        print(f"HTTP {r.status_code} {r.reason}{extra}\n  {txt}")
        if r.headers.get("Retry-After"):
            print(f"  Retry-After: {r.headers['Retry-After']} s")

    @staticmethod
    def save_tokens(d):
        with open(TOK_FILE, "w") as f:
            json.dump(d, f)
        os.chmod(TOK_FILE, 0o600)

    @staticmethod
    def tokens():
        if not os.path.exists(TOK_FILE):
            sys.exit("Немає збережених токенів — спочатку виконайте login")
        with open(TOK_FILE) as f:
            return json.load(f)


# ------------------------------------------------------------------ commands
def cmd_echo(c, a):
    if a.http:
        print(f"→ POST {c.http}/echo-http  (БЕЗ шифрування)")
        r, ms = c.req("POST", "/echo-http", tls=False, json={"msg": a.msg})
    else:
        print(f"→ POST {c.https}/echo-http  (TLS, CA={a.ca})")
        r, ms = c.req("POST", "/echo-http", json={"msg": a.msg})
    c.show(r, ms)


def cmd_plain_auth(c, a):
    print(f"→ POST {c.http}/auth/login  (спроба логіну по HTTP)")
    r, ms = c.req("POST", "/auth/login", tls=False, json={"username": "alice", "password": "x"})
    c.show(r, ms)


def cmd_tls_info(c, a):
    ctx = ssl.create_default_context(cafile=a.ca) if a.ca else ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    sni = a.sni or a.host
    print(f"→ TLS handshake з {a.host}:{a.https_port} (SNI/hostname={sni}, CA={a.ca or 'системне сховище'})")
    try:
        with socket.create_connection((a.host, a.https_port), timeout=5) as raw:
            with ctx.wrap_socket(raw, server_hostname=sni) as s:
                cert = s.getpeercert()
                name, ver, bits = s.cipher()
                print(f"  Версія протоколу : {s.version()}")
                print(f"  Cipher suite     : {name} ({bits} біт)")
                print(f"  ALPN             : {s.selected_alpn_protocol()}")
                subj = dict(x[0] for x in cert["subject"])
                iss = dict(x[0] for x in cert["issuer"])
                print(f"  Subject CN       : {subj.get('commonName')}")
                print(f"  Issuer CN        : {iss.get('commonName')}")
                print(f"  SAN              : {', '.join(f'{t}:{v}' for t, v in cert.get('subjectAltName', []))}")
                print(f"  Дійсний          : {cert['notBefore']}  →  {cert['notAfter']}")
                der = s.getpeercert(binary_form=True)
                print(f"  SHA-256 відбиток : {hashlib.sha256(der).hexdigest()[:47]}…")
                print("  Перевірка        : ✔ ланцюжок до CA валідний, ім'я хоста збігається з SAN")
    except ssl.SSLCertVerificationError as e:
        print(f"  ✘ ПЕРЕВІРКУ СЕРТИФІКАТА НЕ ПРОЙДЕНО: {e.verify_message} (код {e.verify_code})")
        print("  З'єднання розірвано клієнтом — дані не передавались.")
        sys.exit(3)


def _login_flow(c, user, password, otp=None):
    r, ms = c.req("POST", "/auth/login", json={"username": user, "password": password})
    c.show(r, ms)
    if r.status_code != 200:
        return None
    body = r.json()
    if body.get("mfa_required"):
        if not otp:
            print("  ⚠ Увімкнено MFA: повторіть з --otp <6 цифр>")
            return None
        print(f"→ POST /auth/login/otp  (другий фактор, OTP={otp})")
        r, ms = c.req("POST", "/auth/login/otp", json={"mfa_token": body["mfa_token"], "otp": otp})
        c.show(r, ms)
        if r.status_code != 200:
            return None
        body = r.json()
    return body


def cmd_login(c, a):
    print(f"→ POST {c.https}/auth/login  user={a.user}")
    body = _login_flow(c, a.user, a.password, a.otp)
    if body:
        c.save_tokens({"access": body["access_token"], "refresh": body["refresh_token"], "user": a.user})
        print(f"  ✔ Токени збережено у {os.path.relpath(TOK_FILE)} (роль={body['role']}, access діє {body['expires_in']} с)")


def cmd_whoami(c, a):
    r, ms = c.req("GET", "/whoami", token=a.token or c.tokens()["access"])
    c.show(r, ms)


def cmd_secure_echo(c, a):
    r, ms = c.req("POST", "/echo-https", token=c.tokens()["access"], json={"msg": a.msg})
    c.show(r, ms)


def cmd_admin(c, a):
    t = c.tokens()
    print(f"→ GET /admin/users  від імені {t['user']}")
    r, ms = c.req("GET", "/admin/users", token=t["access"])
    c.show(r, ms)


def cmd_logs(c, a):
    params = {k: v for k, v in {"event": a.event, "user": a.user, "since": a.since, "category": a.category,
                                "limit": a.limit}.items() if v}
    r, ms = c.req("GET", "/admin/logs", token=c.tokens()["access"], params=params)
    if r.status_code != 200:
        return c.show(r, ms)
    d = r.json()
    print(f"HTTP 200 — знайдено {d['count']} подій (показано {len(d['events'])})")
    for e in d["events"]:
        print(f"  {e['ts']} {e['level']:<7} {e['event']:<16} user={e.get('user')} ip={e.get('ip')} "
              f"{e.get('reason') or e.get('path') or ''}")


def cmd_refresh(c, a):
    t = c.tokens()
    r, ms = c.req("POST", "/auth/refresh", json={"refresh_token": t["refresh"]})
    c.show(r, ms)
    if r.status_code == 200:
        old = t["refresh"]
        t.update(access=r.json()["access_token"], refresh=r.json()["refresh_token"], old_refresh=old)
        c.save_tokens(t)
        print("→ Повторне використання СТАРОГО refresh-токена:")
        r, ms = c.req("POST", "/auth/refresh", json={"refresh_token": old})
        c.show(r, ms)


def cmd_logout(c, a):
    t = c.tokens()
    r, ms = c.req("POST", "/auth/logout", token=t["access"], json={"refresh_token": t["refresh"]})
    c.show(r, ms)
    print("→ Той самий access-токен після logout:")
    r, ms = c.req("GET", "/whoami", token=t["access"])
    c.show(r, ms)


def cmd_mfa_setup(c, a):
    r, ms = c.req("POST", "/auth/mfa/setup", token=c.tokens()["access"])
    if r.status_code != 200:
        return c.show(r, ms)
    d = r.json()
    print(f"HTTP 200 OK\n  secret      : {d['secret']}\n  otpauth URI : {d['otpauth_uri']}")
    try:
        import qrcode
        out = os.path.join(os.path.dirname(__file__), "mfa_qr.png")
        qrcode.make(d["otpauth_uri"]).save(out)
        print(f"  QR-код      : {os.path.relpath(out)} — відскануйте в Google Authenticator / Microsoft Authenticator")
    except ImportError:
        pass
    print("  Далі: client.py mfa-confirm --otp <код з застосунку>")


def cmd_mfa_confirm(c, a):
    r, ms = c.req("POST", "/auth/mfa/confirm", token=c.tokens()["access"], json={"otp": a.otp})
    c.show(r, ms)


def cmd_totp(c, a):
    """Імітація застосунку-автентифікатора (лише для демо/тестів)."""
    import pyotp
    t = pyotp.TOTP(a.secret)
    print(t.now())
    if a.verbose:
        print(f"  (дійсний ще {30 - int(time.time()) % 30} с)", file=sys.stderr)


def cmd_brute(c, a):
    print(f"Атака перебором на '{a.user}': {a.wrong} неправильних паролів")
    codes = {}
    for i in range(1, a.wrong + 1):
        r, ms = c.req("POST", "/auth/login", json={"username": a.user, "password": f"guess{i:04d}"})
        codes[r.status_code] = codes.get(r.status_code, 0) + 1
        extra = f" Retry-After={r.headers.get('Retry-After')}s" if r.status_code == 429 else ""
        print(f"  спроба {i:>2}: HTTP {r.status_code} {r.json().get('detail')}{extra}")
    print(f"Підсумок: {codes}")
    if a.then_password:
        print(f"→ Тепер ПРАВИЛЬНИЙ пароль для '{a.user}' під час блокування:")
        r, ms = c.req("POST", "/auth/login", json={"username": a.user, "password": a.then_password})
        c.show(r, ms)


def cmd_flood(c, a):
    print(f"DoS-імітація: {a.n} запитів GET /health, {a.workers} потоків")
    s = requests.Session()
    s.verify = c.verify

    def one(_):
        try:
            return s.get(c.https + "/health", timeout=5).status_code
        except requests.RequestException:
            return 0
    t = time.perf_counter()
    with cf.ThreadPoolExecutor(a.workers) as ex:
        codes = list(ex.map(one, range(a.n)))
    dt = time.perf_counter() - t
    summary = {k: codes.count(k) for k in sorted(set(codes))}
    print(f"  за {dt:.2f} с ({a.n / dt:.0f} req/s): {summary}")
    print(f"  пропущено {summary.get(200, 0)}, відхилено 429: {summary.get(429, 0)}")


def cmd_bypass(c, a):
    """Спроби обійти контроль доступу. Очікується 401/403 у кожному випадку."""
    t = c.tokens()
    acc = t["access"]
    h, p, sig = acc.split(".")
    payload = json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
    esc = dict(payload, role="admin", sub="admin")

    def forge(header, body, key=None):
        seg = b64u(json.dumps(header, separators=(",", ":")).encode()) + "." + b64u(json.dumps(body, separators=(",", ":")).encode())
        if key is None:
            return seg + "."
        return seg + "." + b64u(hmac.new(key, seg.encode(), hashlib.sha256).digest())

    cases = [
        ("Без токена", "/whoami", None),
        ("Сміття замість токена", "/whoami", "abc.def.ghi"),
        ("alg=none + role=admin", "/admin/users", forge({"alg": "none", "typ": "JWT"}, esc)),
        ("Змінений payload (role=admin), старий підпис", "/admin/users",
         b64u(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode()) + "." +
         b64u(json.dumps(esc, separators=(",", ":")).encode()) + "." + sig),
        ("Підроблений підпис (вгаданий секрет)", "/admin/users", forge({"alg": "HS256", "typ": "JWT"}, esc, b"secret")),
        ("Прострочений токен (exp у минулому)", "/whoami",
         forge({"alg": "HS256", "typ": "JWT"}, dict(payload, exp=1), b"secret")),
        ("refresh-токен замість access", "/whoami", t["refresh"]),
        (f"Легітимний токен {t['user']} → адмін-ендпоінт", "/admin/users", acc),
    ]
    print(f"{'#':<2} {'Сценарій':<46} {'Ендпоінт':<13} Результат")
    for i, (name, path, tok) in enumerate(cases, 1):
        r, _ = c.req("GET", path, token=tok)
        why = r.headers.get("WWW-Authenticate", "")
        why = why.split('error_description="')[1].rstrip('"') if "error_description" in why else r.json().get("detail")
        mark = "✔ заблоковано" if r.status_code in (401, 403) else "✘ ДОСТУП ОТРИМАНО"
        print(f"{i:<2} {name:<46} {path:<13} HTTP {r.status_code} {mark} ({why})")


def main():
    ap = argparse.ArgumentParser(description="Secure Net App client")
    ap.add_argument("--host", default=os.environ.get("SNA_HOST", "127.0.0.1"))
    ap.add_argument("--http-port", type=int, default=int(os.environ.get("SNA_HTTP_PORT", 8080)))
    ap.add_argument("--https-port", type=int, default=int(os.environ.get("SNA_HTTPS_PORT", 8443)))
    ap.add_argument("--ca", default=os.environ.get("SNA_CA"))
    sp = ap.add_subparsers(dest="cmd", required=True)
    p = sp.add_parser("echo"); g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--http", action="store_true"); g.add_argument("--https", action="store_true")
    p.add_argument("--msg", required=True)
    sp.add_parser("plain-auth")
    p = sp.add_parser("tls-info"); p.add_argument("--sni")
    p = sp.add_parser("login"); p.add_argument("--user", required=True); p.add_argument("--password", required=True); p.add_argument("--otp")
    p = sp.add_parser("whoami"); p.add_argument("--token")
    p = sp.add_parser("secure-echo"); p.add_argument("--msg", required=True)
    sp.add_parser("admin-users")
    p = sp.add_parser("logs"); p.add_argument("--event"); p.add_argument("--user"); p.add_argument("--since")
    p.add_argument("--category"); p.add_argument("--limit", type=int, default=20)
    sp.add_parser("refresh"); sp.add_parser("logout")
    sp.add_parser("mfa-setup")
    p = sp.add_parser("mfa-confirm"); p.add_argument("--otp", required=True)
    p = sp.add_parser("totp"); p.add_argument("--secret", required=True); p.add_argument("-v", "--verbose", action="store_true")
    p = sp.add_parser("brute"); p.add_argument("--user", required=True); p.add_argument("--wrong", type=int, default=8)
    p.add_argument("--then-password")
    p = sp.add_parser("flood"); p.add_argument("--n", type=int, default=200); p.add_argument("--workers", type=int, default=20)
    sp.add_parser("bypass")
    a = ap.parse_args()
    c = Client(a)
    fn = globals()["cmd_" + a.cmd.replace("-", "_")]
    try:
        fn(c, a)
    except requests.exceptions.SSLError as e:
        print(f"✘ TLS-помилка: {e.__class__.__name__}: перевірка сертифіката не пройдена")
        sys.exit(3)
    except requests.exceptions.ConnectionError:
        print("✘ Немає з'єднання з сервером")
        sys.exit(2)


if __name__ == "__main__":
    main()

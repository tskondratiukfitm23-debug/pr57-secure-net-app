"""Secure Net App — FastAPI-сервер (ПР №5-7).

Запуск (два слухачі одного застосунку):
  HTTP  (Завдання 2, тільки /health і /echo-http):
      uvicorn server.app:app --host 0.0.0.0 --port 8080
  HTTPS (Завдання 3+):
      uvicorn server.app:app --host 0.0.0.0 --port 8443 \
          --ssl-keyfile server/certs/server.key --ssl-certfile server/certs/server.crt
"""
import logging
import time
import uuid
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from server import config, security
from server.logfilter import filter_events, read_events
from server.logger_setup import log
from server.models import (EchoIn, LoginIn, MfaConfirmIn, MfaRequiredOut, OtpIn, RefreshIn,
                           TokenOut, UserCreateIn)
from server.ratelimit import LoginGuard, TokenBucket

VERSION = "1.0.0"
PLAINTEXT_ALLOWED = {"/health", "/echo-http"}

app = FastAPI(title="Secure Net App", version=VERSION)
store = security.UserStore()
guard = LoginGuard()
bucket = TokenBucket()


def client_ip(req: Request) -> str:
    return req.client.host if req.client else "unknown"


def reset_state():
    """Для тестів: свіжі лімітатори та перечитана БД користувачів."""
    global guard, bucket
    guard, bucket = LoginGuard(), TokenBucket()
    store.reload()


# ------------------------------------------------------------------ middleware
@app.middleware("http")
async def security_middleware(request: Request, call_next):
    rid = uuid.uuid4().hex[:12]
    request.state.rid, request.state.user = rid, None
    ip, path = client_ip(request), request.url.path
    tls = request.url.scheme == "https"
    t0 = time.perf_counter()

    ok, retry = bucket.allow(ip)
    if not ok:
        log("rate.limit", logging.WARNING, ip=ip, path=path, scope="ip_bucket", request_id=rid)
        resp = JSONResponse({"detail": "Too many requests"}, status_code=429,
                            headers={"Retry-After": str(int(retry) + 1)})
    elif not tls and path not in PLAINTEXT_ALLOWED:
        log("tls.required", logging.WARNING, ip=ip, path=path, request_id=rid)
        resp = JSONResponse({"detail": "TLS required: use https://…:8443"}, status_code=403)
    else:
        try:
            resp = await call_next(request)
        except Exception as e:  # noqa: BLE001 — будь-яка непередбачена помилка
            log("error.unhandled", logging.ERROR, ip=ip, path=path, request_id=rid, error=type(e).__name__)
            resp = JSONResponse({"detail": "Internal error", "request_id": rid}, status_code=500)

    resp.headers["X-Request-ID"] = rid
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["X-Frame-Options"] = "DENY"
    if tls:
        resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    lvl = logging.WARNING if resp.status_code >= 400 else logging.INFO
    log("http.request", lvl, ip=ip, method=request.method, path=path, status=resp.status_code,
        ms=round((time.perf_counter() - t0) * 1000, 2), tls=tls, user=request.state.user, request_id=rid)
    return resp


@app.exception_handler(RequestValidationError)
async def validation_handler(request: Request, exc: RequestValidationError):
    log("error.validation", logging.WARNING, ip=client_ip(request), path=request.url.path,
        fields=[".".join(map(str, e["loc"])) for e in exc.errors()])
    return JSONResponse({"detail": "Invalid request", "errors": [e["msg"] for e in exc.errors()]}, status_code=422)


# ------------------------------------------------------------------ auth dependencies
def require_token(req: Request) -> dict:
    auth = req.headers.get("Authorization", "")
    ip = client_ip(req)
    if not auth.startswith("Bearer "):
        log("access.denied", logging.WARNING, ip=ip, path=req.url.path, reason="missing_token")
        raise HTTPException(401, "Missing token", headers={"WWW-Authenticate": "Bearer"})
    try:
        payload = security.decode_token(auth[7:].strip(), "access")
    except security.TokenError as e:
        log("token.invalid", logging.WARNING, ip=ip, path=req.url.path, reason=e.reason)
        detail = "Token expired" if e.reason == "expired" else "Invalid token"
        raise HTTPException(401, detail, headers={"WWW-Authenticate": f'Bearer error="invalid_token", error_description="{e.reason}"'})
    if not store.get(payload["sub"]):
        raise HTTPException(401, "Invalid token")
    req.state.user = payload["sub"]
    return payload


def require_perm(perm: str):
    def dep(req: Request, payload: dict = Depends(require_token)) -> dict:
        # роль беремо з БД, а не з токена — зміна ролі діє одразу
        role = store.get(payload["sub"])["role"]
        if not security.has_permission(role, perm):
            log("access.forbidden", logging.WARNING, ip=client_ip(req), user=payload["sub"],
                role=role, path=req.url.path, need=perm)
            raise HTTPException(403, "Forbidden: insufficient role")
        return payload
    return dep


def issue_pair(user: str, role: str) -> TokenOut:
    return TokenOut(access_token=security.create_token(user, role, "access"),
                    refresh_token=security.create_token(user, role, "refresh"),
                    expires_in=config.ACCESS_TTL, role=role)


# ------------------------------------------------------------------ public
@app.get("/health")
def health(req: Request):
    return {"ok": True, "ts": int(time.time()), "tls": req.url.scheme == "https", "version": VERSION}


@app.post("/echo-http")
def echo_http(e: EchoIn, req: Request):
    """Мінімальний протокол запит-відповідь (Завдання 2). Доступний і по HTTP, і по HTTPS."""
    return {"echo": e.msg, "len": len(e.msg), "tls": req.url.scheme == "https", "ts": int(time.time())}


# ------------------------------------------------------------------ authentication
@app.post("/auth/login", response_model=TokenOut | MfaRequiredOut)
def login(req: Request, data: LoginIn):
    ip, user = client_ip(req), data.username
    allowed, reason, retry = guard.check(ip, user)
    if not allowed:
        log("rate.limit" if reason == "ip_rate" else "lockout.active", logging.WARNING,
            ip=ip, user=user, scope=reason, retry_after=retry)
        raise HTTPException(429, "Too many attempts, try later", headers={"Retry-After": str(retry)})
    u = store.get(user)
    if not security.verify_password(data.password, u["pwd"] if u else None):
        n, lock = guard.fail(user)
        log("auth.fail", logging.WARNING, ip=ip, user=user, reason="bad_credentials", fails=n)
        if lock:
            log("lockout.start", logging.WARNING, ip=ip, user=user, seconds=lock)
        raise HTTPException(401, "Invalid credentials")
    if u.get("mfa_enabled"):
        log("auth.password_ok", ip=ip, user=user, next="otp")
        return MfaRequiredOut(mfa_token=security.create_token(user, u["role"], "mfa"),
                              expires_in=config.MFA_TOKEN_TTL)
    guard.success(user)
    req.state.user = user
    log("auth.ok", ip=ip, user=user, role=u["role"], mfa=False)
    return issue_pair(user, u["role"])


@app.post("/auth/login/otp", response_model=TokenOut)
def login_otp(req: Request, data: OtpIn):
    ip = client_ip(req)
    try:
        p = security.decode_token(data.mfa_token, "mfa")
    except security.TokenError as e:
        log("mfa.fail", logging.WARNING, ip=ip, reason="mfa_token_" + e.reason)
        raise HTTPException(401, "MFA session invalid or expired, login again")
    user = p["sub"]
    allowed, reason, retry = guard.check(ip, user)
    if not allowed:
        log("lockout.active", logging.WARNING, ip=ip, user=user, scope=reason)
        raise HTTPException(429, "Too many attempts, try later", headers={"Retry-After": str(retry)})
    res = security.verify_totp(store, user, data.otp)
    if res != "ok":
        n, lock = guard.fail(user)
        log("mfa.fail", logging.WARNING, ip=ip, user=user, reason=res, fails=n)
        if lock:
            log("lockout.start", logging.WARNING, ip=ip, user=user, seconds=lock)
        raise HTTPException(401, "OTP invalid" if res == "invalid" else "OTP already used")
    security.revoke(p)  # mfa_token одноразовий
    guard.success(user)
    req.state.user = user
    role = store.get(user)["role"]
    log("auth.ok", ip=ip, user=user, role=role, mfa=True)
    return issue_pair(user, role)


@app.post("/auth/refresh", response_model=TokenOut)
def refresh(req: Request, data: RefreshIn):
    ip = client_ip(req)
    try:
        p = security.decode_token(data.refresh_token, "refresh")
    except security.TokenError as e:
        log("token.refresh_fail", logging.WARNING, ip=ip, reason=e.reason)
        raise HTTPException(401, "Invalid refresh token")
    security.revoke(p)  # ротація: старий refresh більше не діє
    u = store.get(p["sub"])
    if not u:
        raise HTTPException(401, "Invalid refresh token")
    log("token.refresh", ip=ip, user=p["sub"])
    return issue_pair(p["sub"], u["role"])


@app.post("/auth/logout")
def logout(req: Request, data: Optional[RefreshIn] = None, payload: dict = Depends(require_token)):
    security.revoke(payload)
    if data:
        try:
            security.revoke(security.decode_token(data.refresh_token, "refresh"))
        except security.TokenError:
            pass
    log("token.revoked", ip=client_ip(req), user=payload["sub"], reason="logout")
    return {"ok": True}


# ------------------------------------------------------------------ MFA
@app.post("/auth/mfa/setup")
def mfa_setup(req: Request, payload: dict = Depends(require_perm("mfa"))):
    res = security.mfa_begin(store, payload["sub"])
    log("mfa.setup", ip=client_ip(req), user=payload["sub"])
    return res


@app.post("/auth/mfa/confirm")
def mfa_confirm(req: Request, data: MfaConfirmIn, payload: dict = Depends(require_perm("mfa"))):
    if not security.mfa_confirm(store, payload["sub"], data.otp):
        log("mfa.fail", logging.WARNING, ip=client_ip(req), user=payload["sub"], reason="confirm_invalid")
        raise HTTPException(400, "OTP invalid — MFA not enabled")
    log("mfa.enabled", ip=client_ip(req), user=payload["sub"])
    return {"mfa_enabled": True}


# ------------------------------------------------------------------ protected
@app.get("/whoami")
def whoami(payload: dict = Depends(require_token)):
    u = store.get(payload["sub"])
    return {"sub": payload["sub"], "role": u["role"], "mfa_enabled": u.get("mfa_enabled", False),
            "exp": payload["exp"], "expires_in": payload["exp"] - int(time.time())}


@app.post("/echo-https")
def echo_https(e: EchoIn, payload: dict = Depends(require_perm("echo"))):
    return {"user": payload["sub"], "echo": e.msg, "tls": True}


@app.get("/admin/users")
def admin_users(req: Request, payload: dict = Depends(require_perm("admin"))):
    log("admin.list_users", ip=client_ip(req), user=payload["sub"])
    return {"users": store.public(), "locked": guard.status()}


@app.post("/admin/users", status_code=201)
def admin_create(req: Request, data: UserCreateIn, payload: dict = Depends(require_perm("admin"))):
    try:
        store.add(data.username, data.password, data.role)
    except ValueError as e:
        raise HTTPException(400, str(e))
    log("admin.create_user", ip=client_ip(req), user=payload["sub"], target=data.username, role=data.role)
    return {"created": data.username, "role": data.role}


@app.get("/admin/logs")
def admin_logs(req: Request, payload: dict = Depends(require_perm("admin")),
               event: Optional[str] = None, category: Optional[str] = None, user: Optional[str] = None,
               ip: Optional[str] = None, since: Optional[str] = None, until: Optional[str] = None,
               limit: int = Query(50, ge=1, le=500)):
    try:
        res = list(filter_events(read_events(config.LOG_PATH), event=event, category=category,
                                 user=user, ip=ip, since=since, until=until))
    except ValueError:
        raise HTTPException(400, "Bad time format")
    log("admin.read_logs", ip=client_ip(req), user=payload["sub"], filter_event=event, filter_user=user)
    return {"count": len(res), "events": res[-limit:]}

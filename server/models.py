from typing import Optional

from pydantic import BaseModel, Field


class EchoIn(BaseModel):
    msg: str = Field(min_length=1, max_length=4096)


class LoginIn(BaseModel):
    username: str = Field(min_length=3, max_length=32, pattern=r"^[a-zA-Z0-9_.-]+$")
    password: str = Field(min_length=1, max_length=128)


class OtpIn(BaseModel):
    mfa_token: str
    otp: str = Field(pattern=r"^\d{6}$")


class MfaConfirmIn(BaseModel):
    otp: str = Field(pattern=r"^\d{6}$")


class RefreshIn(BaseModel):
    refresh_token: str


class TokenOut(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    role: str


class MfaRequiredOut(BaseModel):
    mfa_required: bool = True
    mfa_token: str
    expires_in: int


class UserCreateIn(BaseModel):
    username: str = Field(min_length=3, max_length=32, pattern=r"^[a-zA-Z0-9_.-]+$")
    password: str = Field(min_length=12, max_length=128)
    role: str = Field(default="user", pattern=r"^(user|admin)$")


class Health(BaseModel):
    ok: bool
    ts: int
    tls: bool
    version: Optional[str] = None

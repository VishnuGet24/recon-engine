"""JWT helper utilities for the /api (JWT-authenticated) surface."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
from flask import current_app


@dataclass(frozen=True)
class TokenPair:
    access_token: str
    refresh_token: str
    expires_in: int


class JwtError(Exception):
    pass


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _issuer() -> str:
    return current_app.config.get("JWT_ISSUER", "sf-recon-engine")


def _secret() -> str:
    return current_app.config.get("JWT_SECRET", current_app.config.get("SECRET_KEY", ""))


def _algorithm() -> str:
    return current_app.config.get("JWT_ALGORITHM", "HS256")


def _access_ttl_seconds() -> int:
    return int(current_app.config.get("JWT_ACCESS_TTL_SECONDS", 3600))


def _refresh_ttl_seconds() -> int:
    return int(current_app.config.get("JWT_REFRESH_TTL_SECONDS", 30 * 24 * 3600))


def issue_tokens(*, user_id: int, permissions: list[str]) -> TokenPair:
    now = _utc_now()
    expires_in = _access_ttl_seconds()

    access_payload = {
        "iss": _issuer(),
        "sub": str(user_id),
        "typ": "access",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=expires_in)).timestamp()),
        "permissions": permissions,
    }

    refresh_payload = {
        "iss": _issuer(),
        "sub": str(user_id),
        "typ": "refresh",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=_refresh_ttl_seconds())).timestamp()),
    }

    access_token = jwt.encode(access_payload, _secret(), algorithm=_algorithm())
    refresh_token = jwt.encode(refresh_payload, _secret(), algorithm=_algorithm())
    return TokenPair(access_token=access_token, refresh_token=refresh_token, expires_in=expires_in)


def decode_token(token: str, *, expected_type: str) -> dict[str, Any]:
    try:
        payload = jwt.decode(
            token,
            _secret(),
            algorithms=[_algorithm()],
            issuer=_issuer(),
            options={"require": ["exp", "iat", "iss", "sub", "typ"]},
        )
    except jwt.ExpiredSignatureError as exc:
        raise JwtError("Token expired") from exc
    except jwt.InvalidTokenError as exc:
        raise JwtError("Invalid token") from exc

    if payload.get("typ") != expected_type:
        raise JwtError("Invalid token type")

    return payload


def access_expiry_iso(payload: dict[str, Any]) -> str | None:
    exp = payload.get("exp")
    if not isinstance(exp, (int, float)):
        return None
    return datetime.fromtimestamp(float(exp), tz=timezone.utc).isoformat()


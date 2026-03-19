"""Authentication business logic."""

from __future__ import annotations

import re

import bcrypt
from flask import session
from sqlalchemy import func, or_

from config import Config
from models import User


_USERNAME_RE = re.compile(r"^[a-zA-Z0-9_.-]{3,64}$")


def validate_username(username: str) -> str:
    normalized = (username or "").strip()
    if not _USERNAME_RE.match(normalized):
        raise ValueError("Username must be 3-64 chars and contain only letters, digits, _, ., -")
    return normalized


def validate_password_policy(password: str) -> None:
    if len(password) < 12:
        raise ValueError("Password must be at least 12 characters")
    if not any(ch.islower() for ch in password):
        raise ValueError("Password must include a lowercase letter")
    if not any(ch.isupper() for ch in password):
        raise ValueError("Password must include an uppercase letter")
    if not any(ch.isdigit() for ch in password):
        raise ValueError("Password must include a number")
    if not any(ch in "!@#$%^&*()-_=+[]{};:,.?/" for ch in password):
        raise ValueError("Password must include a special character")


def hash_password(plain_password: str) -> str:
    validate_password_policy(plain_password)
    hashed = bcrypt.hashpw(
        plain_password.encode("utf-8"),
        bcrypt.gensalt(rounds=Config.BCRYPT_LOG_ROUNDS),
    )
    return hashed.decode("utf-8")


def verify_password(plain_password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(plain_password.encode("utf-8"), password_hash.encode("utf-8"))
    except ValueError:
        return False


def get_user_by_identity(identity: str) -> User | None:
    normalized = (identity or "").strip().lower()
    if not normalized:
        return None

    return User.query.filter(
        or_(func.lower(User.username) == normalized, func.lower(User.email) == normalized)
    ).first()


def authenticate_user(identity: str, password: str) -> User | None:
    user = get_user_by_identity(identity)
    if user is None or not user.is_active:
        return None

    if not verify_password(password, user.password_hash):
        return None

    return user


def establish_session(user: User) -> None:
    # Avoid session fixation by clearing any pre-auth state.
    session.clear()
    session.permanent = True
    session["user_id"] = user.id


def clear_session() -> None:
    session.clear()

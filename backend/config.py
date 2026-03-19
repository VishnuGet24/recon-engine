"""Application configuration loaded from environment variables."""

from __future__ import annotations

import os
from datetime import timedelta
from pathlib import Path
from urllib.parse import quote_plus

from dotenv import load_dotenv


BASE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BASE_DIR.parent

# Load env files deterministically so CLI and app server use the same settings.
load_dotenv(BASE_DIR / ".env", override=False)
load_dotenv(PROJECT_ROOT / ".env", override=False)


def _first_env(*keys: str, default: str = "") -> str:
    for key in keys:
        value = os.getenv(key)
        if value is not None and value != "":
            return value
    return default


def _to_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _to_int(value: str | None, default: int) -> int:
    if value is None or value.strip() == "":
        return default
    return int(value)


def _to_list(value: str | None, default: list[str]) -> list[str]:
    if value is None or value.strip() == "":
        return default
    return [item.strip() for item in value.split(",") if item.strip()]


def _build_db_uri() -> str:
    explicit_uri = os.getenv("DATABASE_URL")
    if explicit_uri:
        return explicit_uri

    user = _first_env("DB_USER", "MYSQL_USER", default="root")
    password = _first_env("DB_PASSWORD", "MYSQL_PASSWORD", "MYSQL_ROOT_PASSWORD", default="")
    host = _first_env("DB_HOST", "MYSQL_HOST", default="127.0.0.1")
    port = _first_env("DB_PORT", "MYSQL_PORT", default="3306")
    name = _first_env("DB_NAME", "MYSQL_DATABASE", default="scanner_db")
    password_escaped = quote_plus(password)

    return f"mysql+pymysql://{user}:{password_escaped}@{host}:{port}/{name}?charset=utf8mb4"


class Config:
    APP_ENV = os.getenv("APP_ENV", "development")
    DEBUG = _to_bool(os.getenv("FLASK_DEBUG"), default=False)

    SECRET_KEY = os.getenv("SECRET_KEY", "replace-this-in-production")

    SQLALCHEMY_DATABASE_URI = _build_db_uri()
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    if SQLALCHEMY_DATABASE_URI.startswith("sqlite:"):
        SQLALCHEMY_ENGINE_OPTIONS = {
            "connect_args": {"check_same_thread": False},
        }
    else:
        SQLALCHEMY_ENGINE_OPTIONS = {
            "pool_pre_ping": True,
            "pool_recycle": _to_int(os.getenv("DB_POOL_RECYCLE"), default=280),
            "pool_size": _to_int(os.getenv("DB_POOL_SIZE"), default=10),
            "max_overflow": _to_int(os.getenv("DB_MAX_OVERFLOW"), default=20),
            "pool_timeout": _to_int(os.getenv("DB_POOL_TIMEOUT"), default=30),
        }

    SESSION_COOKIE_NAME = "recon_session"
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SECURE = _to_bool(
        os.getenv("SESSION_COOKIE_SECURE"),
        default=APP_ENV.lower() == "production",
    )
    SESSION_COOKIE_SAMESITE = os.getenv(
        "SESSION_COOKIE_SAMESITE",
        "None" if SESSION_COOKIE_SECURE else "Lax",
    )
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=_to_int(os.getenv("SESSION_TTL_MINUTES"), default=30))

    CSRF_HEADER_NAME = os.getenv("CSRF_HEADER_NAME", "X-CSRF-Token")
    CSRF_TOKEN_BYTES = _to_int(os.getenv("CSRF_TOKEN_BYTES"), default=32)

    CORS_ORIGINS = _to_list(os.getenv("CORS_ORIGINS"), default=["http://127.0.0.1:5173", "http://localhost:5173"])

    BCRYPT_LOG_ROUNDS = _to_int(os.getenv("BCRYPT_LOG_ROUNDS"), default=12)
    MAX_CONTENT_LENGTH = _to_int(os.getenv("MAX_CONTENT_LENGTH"), default=1048576)
    ALLOW_PRIVATE_TARGETS = _to_bool(os.getenv("ALLOW_PRIVATE_TARGETS"), default=False)

    LOGIN_RATE_LIMIT = _to_int(os.getenv("LOGIN_RATE_LIMIT"), default=10)
    LOGIN_RATE_WINDOW_SEC = _to_int(os.getenv("LOGIN_RATE_WINDOW_SEC"), default=300)
    SCAN_RATE_LIMIT = _to_int(os.getenv("SCAN_RATE_LIMIT"), default=30)
    SCAN_RATE_WINDOW_SEC = _to_int(os.getenv("SCAN_RATE_WINDOW_SEC"), default=300)

    ENABLE_DB_CREATE_ALL = _to_bool(os.getenv("ENABLE_DB_CREATE_ALL"), default=False)

    FRONTEND_DIST = os.getenv("FRONTEND_DIST", str(PROJECT_ROOT / "recon_frontend" / "dist"))

    LOG_DIR = os.getenv("LOG_DIR", str(BASE_DIR / "logs"))
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

    # JWT /api auth configuration (used by routes/api_routes.py)
    JWT_ISSUER = os.getenv("JWT_ISSUER", "sf-recon-engine")
    JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
    JWT_SECRET = os.getenv("JWT_SECRET", SECRET_KEY)
    JWT_ACCESS_TTL_SECONDS = _to_int(os.getenv("JWT_ACCESS_TTL_SECONDS"), default=3600)
    JWT_REFRESH_TTL_SECONDS = _to_int(os.getenv("JWT_REFRESH_TTL_SECONDS"), default=30 * 24 * 3600)

    WAIT_FOR_DB = _to_bool(os.getenv("WAIT_FOR_DB"), default=False)
    WAIT_FOR_DB_TIMEOUT_SECONDS = _to_int(os.getenv("WAIT_FOR_DB_TIMEOUT_SECONDS"), default=60)
    WAIT_FOR_DB_INTERVAL_SECONDS = _to_int(os.getenv("WAIT_FOR_DB_INTERVAL_SECONDS"), default=2)

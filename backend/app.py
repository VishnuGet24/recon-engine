"""Application entrypoint for secure session-authenticated recon backend."""

from __future__ import annotations

import logging
import logging.config
import os
import time
from logging.handlers import RotatingFileHandler
from pathlib import Path

import click
from flask import Flask, abort, g, jsonify, send_from_directory, session
from flask_cors import CORS
from sqlalchemy import text
from sqlalchemy.exc import OperationalError, SQLAlchemyError
from werkzeug.middleware.proxy_fix import ProxyFix

from config import Config
from extensions import db
from models import User
from routes import register_blueprints
from security import init_security_controls
from services.auth_service import hash_password, validate_username
from services.rbac_service import seed_rbac_data


def _configure_logging(app: Flask) -> None:
    log_config_file = os.getenv("LOG_CONFIG_FILE", "")
    if log_config_file and os.path.exists(log_config_file):
        logging.config.fileConfig(log_config_file, disable_existing_loggers=False)
        return

    os.makedirs(app.config["LOG_DIR"], exist_ok=True)
    log_file = os.path.join(app.config["LOG_DIR"], "backend.log")

    level = getattr(logging, app.config.get("LOG_LEVEL", "INFO").upper(), logging.INFO)
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")

    app.logger.handlers.clear()
    app.logger.setLevel(level)

    file_handler = RotatingFileHandler(log_file, maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8")
    file_handler.setFormatter(formatter)
    file_handler.setLevel(level)

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    stream_handler.setLevel(level)

    app.logger.addHandler(file_handler)
    app.logger.addHandler(stream_handler)


def _register_hooks(app: Flask) -> None:
    @app.before_request
    def load_session_user() -> None:
        g.current_user = None
        user_id = session.get("user_id")
        if not user_id:
            return

        user = db.session.get(User, user_id)
        if user is None or not user.is_active:
            session.clear()
            return

        g.current_user = user

    @app.after_request
    def apply_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'; form-action 'self'"
        response.headers["Cache-Control"] = "no-store"
        if app.config.get("SESSION_COOKIE_SECURE"):
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response


def _register_error_handlers(app: Flask) -> None:
    @app.errorhandler(400)
    def bad_request(error):
        return jsonify({"error": "Bad request", "detail": str(error)}), 400

    @app.errorhandler(401)
    def unauthorized(error):
        return jsonify({"error": "Unauthorized", "detail": str(error)}), 401

    @app.errorhandler(403)
    def forbidden(error):
        return jsonify({"error": "Forbidden", "detail": str(error)}), 403

    @app.errorhandler(404)
    def not_found(error):
        return jsonify({"error": "Not found", "detail": str(error)}), 404

    @app.errorhandler(429)
    def too_many(error):
        return jsonify({"error": "Too many requests", "detail": str(error)}), 429

    @app.errorhandler(500)
    def internal_error(error):
        return jsonify({"error": "Internal server error", "detail": str(error)}), 500

    @app.errorhandler(SQLAlchemyError)
    def handle_sqlalchemy_error(error):
        db.session.rollback()
        app.logger.exception("Database error")
        if isinstance(error, OperationalError):
            return (
                jsonify(
                    {
                        "error": "Database unavailable. Check MySQL credentials in backend/.env",
                        "hint": "Set DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME",
                    }
                ),
                503,
            )
        return jsonify({"error": "Database operation failed"}), 500


def _register_frontend_routes(app: Flask) -> None:
    frontend_dist = Path(app.config["FRONTEND_DIST"]).resolve()
    reserved_paths = {"admin", "api", "auth", "csrf", "healthz", "login", "logout", "me", "readyz", "scan", "scans"}

    def _try_serve_asset(path: str):
        candidate = (frontend_dist / path).resolve()
        try:
            candidate.relative_to(frontend_dist)
        except ValueError:
            abort(404)

        if candidate.is_file():
            return send_from_directory(frontend_dist, path)

        return None

    @app.get("/", defaults={"path": ""})
    @app.get("/<path:path>")
    def frontend_app(path: str):
        if not frontend_dist.exists():
            return (
                jsonify(
                    {
                        "error": "Frontend bundle not found",
                        "detail": f"Build recon_frontend into {frontend_dist}",
                    }
                ),
                503,
            )

        if path:
            top_level = path.split("/", 1)[0]
            if top_level in reserved_paths:
                abort(404)

            asset_response = _try_serve_asset(path)
            if asset_response is not None:
                return asset_response

        return send_from_directory(frontend_dist, "index.html")


def _register_cli_commands(app: Flask) -> None:
    @app.cli.command("seed-rbac")
    def seed_rbac_command() -> None:
        """Create or update default RBAC roles and permissions."""
        seed_rbac_data()
        click.echo("RBAC data seeded successfully.")

    @app.cli.command("create-admin")
    @click.option("--username", prompt=True)
    @click.option("--email", prompt=True)
    @click.option("--password", prompt=True, hide_input=True, confirmation_prompt=True)
    def create_admin_command(username: str, email: str, password: str) -> None:
        """Create an admin user."""
        seed_rbac_data()
        from models import Role

        try:
            username = validate_username(username.strip())
        except ValueError as exc:
            click.echo(f"Invalid username: {exc}")
            return

        email = email.strip().lower()
        if "@" not in email:
            click.echo("Invalid email format.")
            return

        existing = User.query.filter((User.username == username) | (User.email == email)).first()
        if existing is not None:
            click.echo("User already exists.")
            return

        admin_role = Role.query.filter_by(name="admin").first()
        if admin_role is None:
            click.echo("Admin role not found. Run seed-rbac first.")
            return

        user = User(
            username=username,
            email=email,
            password_hash=hash_password(password),
            is_active=True,
        )
        user.roles = [admin_role]
        db.session.add(user)
        db.session.commit()
        click.echo(f"Admin user created with id={user.id}")


def create_app() -> Flask:
    app = Flask(__name__)
    app.config.from_object(Config)

    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)

    _configure_logging(app)

    CORS(
        app,
        resources={r"/*": {"origins": app.config["CORS_ORIGINS"]}},
        supports_credentials=True,
        allow_headers=["Content-Type", "X-CSRF-Token", "X-XSRF-TOKEN", "Authorization"],
        expose_headers=[app.config["CSRF_HEADER_NAME"]],
        methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    )

    db.init_app(app)

    if app.config.get("WAIT_FOR_DB"):
        deadline = time.time() + int(app.config.get("WAIT_FOR_DB_TIMEOUT_SECONDS", 60))
        interval = int(app.config.get("WAIT_FOR_DB_INTERVAL_SECONDS", 2))
        while True:
            try:
                with app.app_context():
                    db.session.execute(text("SELECT 1"))
                break
            except OperationalError:
                if time.time() >= deadline:
                    raise
                app.logger.warning("Waiting for database to become ready...")
                time.sleep(max(1, interval))

    with app.app_context():
        if app.config.get("ENABLE_DB_CREATE_ALL"):
            db.create_all()

    _register_hooks(app)
    init_security_controls(app)
    _register_error_handlers(app)
    _register_cli_commands(app)
    register_blueprints(app)
    _register_frontend_routes(app)

    @app.get("/healthz")
    def healthcheck():
        return jsonify({"status": "ok"})

    @app.get("/readyz")
    def readiness():
        db.session.execute(text("SELECT 1"))
        return jsonify({"status": "ready"})

    return app


app = create_app()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)

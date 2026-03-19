from __future__ import annotations

import os
from getpass import getpass

from app import create_app
from extensions import db
from models import Role, User
from services.auth_service import hash_password, validate_username
from services.rbac_service import seed_rbac_data


def _prompt(label: str, env_key: str) -> str:
    value = (os.getenv(env_key) or "").strip()
    if value:
        return value
    return input(f"{label}: ").strip()


def main() -> int:
    app = create_app()
    with app.app_context():
        seed_rbac_data()

        username = validate_username(_prompt("Username", "ADMIN_USERNAME"))
        email = _prompt("Email", "ADMIN_EMAIL").lower()
        if "@" not in email:
            raise SystemExit("Invalid email format.")

        password = os.getenv("ADMIN_PASSWORD") or ""
        if not password:
            password = getpass("Password: ")

        existing = User.query.filter((User.username == username) | (User.email == email)).first()
        if existing is not None:
            print("User already exists.")
            return 0

        admin_role = Role.query.filter_by(name="admin").first()
        if admin_role is None:
            raise SystemExit("Admin role not found (seed-rbac did not run).")

        user = User(
            username=username,
            email=email,
            password_hash=hash_password(password),
            is_active=True,
        )
        user.roles = [admin_role]
        db.session.add(user)
        db.session.commit()
        print(f"Admin user created with id={user.id}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())


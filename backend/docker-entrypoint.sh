#!/bin/sh
set -eu

if [ "${WAIT_FOR_DB:-1}" = "1" ]; then
  python - <<'PY'
import os
import time

from sqlalchemy import text
from sqlalchemy.exc import OperationalError

os.environ["WAIT_FOR_DB"] = "0"
os.environ["ENABLE_DB_CREATE_ALL"] = "0"

from app import create_app
from extensions import db

timeout = int(os.getenv("WAIT_FOR_DB_TIMEOUT_SECONDS", "60"))
interval = int(os.getenv("WAIT_FOR_DB_INTERVAL_SECONDS", "2"))
deadline = time.time() + timeout

app = create_app()
with app.app_context():
    while True:
        try:
            db.session.execute(text("SELECT 1"))
            break
        except OperationalError:
            if time.time() >= deadline:
                raise
            print("Waiting for database to become ready...")
            time.sleep(max(1, interval))
PY
fi

if [ "${DB_AUTO_INIT:-1}" = "1" ]; then
  python - <<'PY'
import os

os.environ["WAIT_FOR_DB"] = "0"
os.environ["ENABLE_DB_CREATE_ALL"] = "0"

from app import create_app
from extensions import db
from services.rbac_service import seed_rbac_data

app = create_app()
with app.app_context():
    db.create_all()
    seed_rbac_data()
    print("Database tables ensured and RBAC seeded.")

    admin_email = (os.getenv("ADMIN_EMAIL") or "").strip().lower()
    admin_password = os.getenv("ADMIN_PASSWORD") or ""
    admin_username = (os.getenv("ADMIN_USERNAME") or "admin").strip()
    if admin_email and admin_password:
        from models import Role, User
        from services.auth_service import hash_password
        existing = User.query.filter((User.username == admin_username) | (User.email == admin_email)).first()
        if not existing:
            admin_role = Role.query.filter_by(name="admin").first()
            user = User(
                username=admin_username,
                email=admin_email,
                password_hash=hash_password(admin_password),
                is_active=True,
            )
            if admin_role:
                user.roles = [admin_role]
            db.session.add(user)
            db.session.commit()
            print(f"Default admin user created: {admin_username} ({admin_email})")
PY
fi

export WAIT_FOR_DB=0
export ENABLE_DB_CREATE_ALL=0

exec gunicorn -c gunicorn_conf.py app:app

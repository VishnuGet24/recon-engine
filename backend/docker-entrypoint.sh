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

app = create_app()
with app.app_context():
    db.create_all()
print("Database tables ensured (create_all).")
PY
fi

export WAIT_FOR_DB=0
export ENABLE_DB_CREATE_ALL=0

exec gunicorn -c gunicorn_conf.py app:app

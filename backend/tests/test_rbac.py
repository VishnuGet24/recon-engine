"""Unit tests for RBAC role and permission enforcement."""

from __future__ import annotations

import sys
from pathlib import Path
import unittest
from flask import session

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import create_app
from extensions import db
from models import Role, User
from services.auth_service import hash_password
from services.rbac_service import seed_rbac_data


class TestRBACPermissions(unittest.TestCase):
    """Test RBAC permission enforcement across scan endpoints."""

    def setUp(self):
        self.app = create_app(
            {
                "TESTING": True,
                "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
                "APP_ENV": "development",
                "SECRET_KEY": "test-secret-key-for-unit-testing",
                "JWT_SECRET": "test-jwt-secret-for-unit-testing",
                "WAIT_FOR_DB": False,
                "ENABLE_DB_CREATE_ALL": False,
            }
        )
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()
        seed_rbac_data()

        # Create basic user (permission: scan:passive)
        basic_role = Role.query.filter_by(name="basic").first()
        self.basic_user = User(
            username="basicuser",
            email="basic@example.com",
            password_hash=hash_password("Password123!@#"),
            is_active=True,
        )
        self.basic_user.roles = [basic_role]
        db.session.add(self.basic_user)

        # Create authorized user (permissions: scan:passive, scan:active)
        authorized_role = Role.query.filter_by(name="authorized").first()
        self.auth_user = User(
            username="authuser",
            email="auth@example.com",
            password_hash=hash_password("Password123!@#"),
            is_active=True,
        )
        self.auth_user.roles = [authorized_role]
        db.session.add(self.auth_user)

        db.session.commit()
        self.client = self.app.test_client()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def _login_session(self, user_id: int):
        with self.client.session_transaction() as sess:
            sess["user_id"] = user_id
            sess["csrf_token"] = "test-csrf-token-12345"

    def test_unauthenticated_request_rejected(self):
        with self.client.session_transaction() as sess:
            sess["csrf_token"] = "valid-csrf-token"
        response = self.client.post(
            "/scans/active",
            json={"target": "example.com"},
            headers={"X-CSRF-Token": "valid-csrf-token"},
        )
        self.assertEqual(response.status_code, 401)

    def test_basic_user_cannot_access_active_scan(self):
        self._login_session(self.basic_user.id)
        response = self.client.post(
            "/scans/active",
            json={"target": "example.com"},
            headers={"X-CSRF-Token": "test-csrf-token-12345"},
        )
        self.assertEqual(response.status_code, 403)
        data = response.get_json()
        self.assertIn("Forbidden", data.get("error", ""))

    def test_basic_user_cannot_request_full_scan_on_general_endpoint(self):
        self._login_session(self.basic_user.id)
        response = self.client.post(
            "/scans",
            json={"target": "example.com", "scan_mode": "full"},
            headers={"X-CSRF-Token": "test-csrf-token-12345"},
        )
        self.assertEqual(response.status_code, 403)

    def test_authorized_user_can_access_active_scan(self):
        self._login_session(self.auth_user.id)
        response = self.client.post(
            "/scans/active",
            json={"target": "example.com"},
            headers={"X-CSRF-Token": "test-csrf-token-12345"},
        )
        # Should be authorized (status 200/201 or accepted, definitely not 401 or 403)
        self.assertNotIn(response.status_code, [401, 403])


if __name__ == "__main__":
    unittest.main()

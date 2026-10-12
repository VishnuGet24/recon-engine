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
from utils.jwt_utils import issue_tokens


class TestRBACPermissions(unittest.TestCase):
    """Test RBAC permission enforcement across scan and user management endpoints."""

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

        # Create admin user
        admin_role = Role.query.filter_by(name="admin").first()
        self.admin_user = User(
            username="adminuser",
            email="admin@example.com",
            password_hash=hash_password("Password123!@#"),
            is_active=True,
        )
        self.admin_user.roles = [admin_role]
        db.session.add(self.admin_user)

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

        # Create privileged user (permissions: scan:passive, scan:active, scan:full)
        privileged_role = Role.query.filter_by(name="privileged").first()
        self.auth_user = User(
            username="authuser",
            email="auth@example.com",
            password_hash=hash_password("Password123!@#"),
            is_active=True,
        )
        self.auth_user.roles = [privileged_role]
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

    def _jwt_headers(self, user: User) -> dict[str, str]:
        tokens = issue_tokens(user_id=user.id, permissions=sorted(user.permission_names))
        return {
            "Authorization": f"Bearer {tokens.access_token}",
            "Content-Type": "application/json",
        }

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
        self.assertNotIn(response.status_code, [401, 403])

    def test_admin_can_create_basic_user(self):
        headers = self._jwt_headers(self.admin_user)
        response = self.client.post(
            "/api/users",
            headers=headers,
            json={
                "username": "newbasic",
                "email": "newbasic@example.com",
                "password": "Password123!@#",
                "role": "basic",
            },
        )
        self.assertEqual(response.status_code, 201)
        data = response.get_json()
        self.assertEqual(data["user"]["role"], "basic")
        self.assertEqual(data["user"]["username"], "newbasic")

    def test_admin_can_create_privileged_user(self):
        headers = self._jwt_headers(self.admin_user)
        response = self.client.post(
            "/api/users",
            headers=headers,
            json={
                "username": "newpriv",
                "email": "newpriv@example.com",
                "password": "Password123!@#",
                "role": "privileged",
            },
        )
        self.assertEqual(response.status_code, 201)
        data = response.get_json()
        self.assertEqual(data["user"]["role"], "privileged")

    def test_privileged_user_cannot_create_users(self):
        headers = self._jwt_headers(self.auth_user)
        response = self.client.post(
            "/api/users",
            headers=headers,
            json={
                "username": "unauthorizedcreate",
                "email": "unauth@example.com",
                "password": "Password123!@#",
                "role": "basic",
            },
        )
        self.assertEqual(response.status_code, 403)

    def test_basic_user_cannot_create_users(self):
        headers = self._jwt_headers(self.basic_user)
        response = self.client.post(
            "/api/users",
            headers=headers,
            json={
                "username": "unauthorizedcreate2",
                "email": "unauth2@example.com",
                "password": "Password123!@#",
                "role": "basic",
            },
        )
        self.assertEqual(response.status_code, 403)

    def test_basic_user_cannot_create_active_scan_via_api(self):
        headers = self._jwt_headers(self.basic_user)
        response = self.client.post(
            "/api/scans",
            headers=headers,
            json={
                "targets": ["example.com"],
                "scanType": "custom_scan",  # active scan
            },
        )
        self.assertEqual(response.status_code, 403)
        data = response.get_json()
        self.assertIn("locked for Basic users", data.get("error", {}).get("message", ""))

    def test_basic_user_cannot_create_full_scan_via_api(self):
        headers = self._jwt_headers(self.basic_user)
        response = self.client.post(
            "/api/scans",
            headers=headers,
            json={
                "targets": ["example.com"],
                "scanType": "full_scan",
            },
        )
        self.assertEqual(response.status_code, 403)

    def test_privileged_user_can_create_active_and_full_scan_via_api(self):
        headers = self._jwt_headers(self.auth_user)
        response = self.client.post(
            "/api/scans",
            headers=headers,
            json={
                "targets": ["example.com"],
                "scanType": "custom_scan",  # active scan
            },
        )
        self.assertEqual(response.status_code, 201)

        response_full = self.client.post(
            "/api/scans",
            headers=headers,
            json={
                "targets": ["example.com"],
                "scanType": "full_scan",  # full scan
            },
        )
        self.assertEqual(response_full.status_code, 201)

    def test_basic_user_can_create_passive_scan_via_api(self):
        headers = self._jwt_headers(self.basic_user)
        response = self.client.post(
            "/api/scans",
            headers=headers,
            json={
                "targets": ["example.com"],
                "scanType": "quick_scan",  # passive scan
            },
        )
        self.assertEqual(response.status_code, 201)


if __name__ == "__main__":
    unittest.main()

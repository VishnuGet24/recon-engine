"""Integration tests for end-to-end passive scan execution and database persistence."""

from __future__ import annotations

import sys
from pathlib import Path
import unittest
from datetime import datetime, timezone

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import create_app
from extensions import db
from models import Finding, Role, Scan, User
from services.auth_service import hash_password
from services.rbac_service import seed_rbac_data
from services.scan_service import generate_findings, run_passive_scan


class TestScanIntegration(unittest.TestCase):
    """Integration test suite for scan execution, persistence, and findings generation."""

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

        admin_role = Role.query.filter_by(name="admin").first()
        self.user = User(
            username="testscanner",
            email="scanner@example.com",
            password_hash=hash_password("Password123!@#"),
            is_active=True,
        )
        self.user.roles = [admin_role]
        db.session.add(self.user)
        db.session.commit()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def test_passive_scan_creates_scan_and_findings(self):
        target = "example.com"

        # 1. Run passive scan execution
        results = run_passive_scan(target=target, allow_private_targets=True)
        self.assertIsInstance(results, dict)
        self.assertIn("modules", results)
        self.assertEqual(results.get("target"), target)

        # 2. Persist the Scan in the database
        scan = Scan(
            user_id=self.user.id,
            target=target,
            scan_mode="passive",
            status="completed",
            risk_score=2.0,
            overall_risk="Low",
            confidence_score=80.0,
            results_json=results,
            completed_at=datetime.now(timezone.utc),
        )
        db.session.add(scan)
        db.session.commit()

        # Assert scan row is created
        persisted_scan = db.session.get(Scan, scan.id)
        self.assertIsNotNone(persisted_scan)
        self.assertEqual(persisted_scan.status, "completed")
        self.assertEqual(persisted_scan.target, target)
        self.assertEqual(persisted_scan.scan_mode, "passive")

        # 3. Generate findings from scan results
        finding_payloads = generate_findings(scan_id=scan.id, target=target, results=results)
        self.assertIsInstance(finding_payloads, list)
        self.assertGreater(len(finding_payloads), 0, "Passive scan should generate at least one discovery/finding row")

        # 4. Persist findings
        for item in finding_payloads:
            finding = Finding(
                id=item["id"],
                scan_id=scan.id,
                severity=item.get("severity", "low"),
                title=item.get("title", "Finding"),
                description=item.get("description", ""),
                category=item.get("category", "reconnaissance"),
                asset_name=item.get("asset_name", target),
                asset_type=item.get("asset_type", "domain"),
                status="open",
            )
            db.session.add(finding)
        db.session.commit()

        # 5. Query and assert findings in database
        saved_findings = Finding.query.filter_by(scan_id=scan.id).all()
        self.assertGreater(len(saved_findings), 0)

        first_finding = saved_findings[0]
        self.assertIsNotNone(first_finding.id)
        self.assertIsNotNone(first_finding.title)
        self.assertEqual(first_finding.scan_id, scan.id)

        # 6. Verify serialization to API dict
        api_dict = first_finding.to_api_dict()
        self.assertEqual(api_dict["id"], str(first_finding.id))
        self.assertIn("severity", api_dict)
        self.assertIn("title", api_dict)


if __name__ == "__main__":
    unittest.main()

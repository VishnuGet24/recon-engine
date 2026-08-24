"""Unit tests for target validation and SSRF policy enforcement."""

from __future__ import annotations

import sys
from pathlib import Path
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from services.scan_service import enforce_target_policy, normalize_target, validate_target


class TestTargetValidation(unittest.TestCase):
    """Test suite for domain/IP validation rules."""

    def test_valid_domain_names(self):
        valid_targets = [
            "example.com",
            "sub.example.com",
            "deep.nested.sub.domain.org",
            "test-domain.co.uk",
            "domain123.io",
        ]
        for target in valid_targets:
            with self.subTest(target=target):
                # Should not raise any ValueError
                validate_target(target)

    def test_valid_ip_addresses(self):
        valid_ips = [
            "8.8.8.8",
            "1.1.1.1",
            "93.184.216.34",
            "2001:4860:4860::8888",
        ]
        for ip in valid_ips:
            with self.subTest(ip=ip):
                validate_target(ip)

    def test_invalid_target_formats(self):
        invalid_targets = [
            "",
            "   ",
            "-invalid.com",
            "invalid..com",
            ".invalid.com",
            "http://example.com",  # raw target must be normalized first
            "example.com/path",
            "example",
            "256.256.256.256",
            "invalid_char$.com",
            "invalid domain.com",
            "domain.c",  # TLD must be at least 2 chars
        ]
        for target in invalid_targets:
            with self.subTest(target=target):
                with self.assertRaises(ValueError):
                    validate_target(target)

    def test_normalize_target(self):
        self.assertEqual(normalize_target("https://example.com/some/path"), "example.com")
        self.assertEqual(normalize_target("http://sub.example.com:8080/"), "sub.example.com")
        self.assertEqual(normalize_target("  EXAMPLE.COM  "), "example.com")
        self.assertEqual(normalize_target("example.com."), "example.com")
        self.assertEqual(normalize_target(""), "")


class TestSSRFPolicyEnforcement(unittest.TestCase):
    """Test suite for SSRF guard and private network policy enforcement."""

    def test_private_ip_blocked_by_default(self):
        private_ips = [
            "127.0.0.1",
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.100",
            "169.254.169.254",  # AWS/Cloud metadata service
            "::1",
        ]
        for ip in private_ips:
            with self.subTest(ip=ip):
                with self.assertRaises(ValueError) as ctx:
                    enforce_target_policy(ip, allow_private_targets=False)
                self.assertIn("private or reserved", str(ctx.exception).lower())

    def test_private_ip_allowed_when_explicitly_configured(self):
        private_ips = ["127.0.0.1", "10.0.0.1", "192.168.1.1"]
        for ip in private_ips:
            with self.subTest(ip=ip):
                resolved = enforce_target_policy(ip, allow_private_targets=True)
                self.assertIsInstance(resolved, list)

    @patch("services.scan_service.resolve_target_ips")
    def test_domain_resolving_to_private_ip_blocked(self, mock_resolve):
        mock_resolve.return_value = ["127.0.0.1"]
        with self.assertRaises(ValueError) as ctx:
            enforce_target_policy("internal.corp.local", allow_private_targets=False)
        self.assertIn("resolves to private or reserved", str(ctx.exception).lower())

    @patch("services.scan_service.resolve_target_ips")
    def test_public_domain_allowed(self, mock_resolve):
        mock_resolve.return_value = ["93.184.216.34"]
        resolved = enforce_target_policy("example.com", allow_private_targets=False)
        self.assertEqual(resolved, ["93.184.216.34"])


if __name__ == "__main__":
    unittest.main()

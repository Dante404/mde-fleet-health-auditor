from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from mde_health_auditor.models import DeviceRecord
from mde_health_auditor.policy import (
    AuditPolicy,
    PolicyError,
    audit_devices,
    evaluate_device,
)

NOW = datetime(2026, 9, 9, 12, 0, tzinfo=timezone.utc)


def healthy_device(**changes):
    values = {
        "device_id": "device-a",
        "computer_dns_name": "host-a.example.invalid",
        "last_seen": "2026-09-09T08:00:00Z",
        "os_platform": "Windows11",
        "health_status": "Active",
        "onboarding_status": "Onboarded",
        "risk_score": "None",
        "exposure_level": "Low",
    }
    values.update(changes)
    return DeviceRecord(**values)


class AuditPolicyTests(unittest.TestCase):
    def test_healthy_device_has_no_issues(self):
        finding = evaluate_device(healthy_device(), AuditPolicy(), now=NOW)
        self.assertEqual(finding.issues, [])
        self.assertEqual(finding.max_severity, "none")

    def test_stale_and_health_problems_are_reported(self):
        device = healthy_device(
            last_seen="2026-07-01T00:00:00Z",
            health_status="ImpairedCommunication",
            onboarding_status="CanBeOnboarded",
            risk_score="High",
            exposure_level="Medium",
            sensor_health_state="NoSensorData",
            update_failure_count=3,
        )

        finding = evaluate_device(device, AuditPolicy(), now=NOW)
        codes = {issue.code for issue in finding.issues}

        self.assertEqual(finding.max_severity, "high")
        self.assertTrue(
            {
                "device_stale",
                "unhealthy_device",
                "onboarding_problem",
                "elevated_risk",
                "elevated_exposure",
                "unhealthy_sensor",
                "update_failures",
            }.issubset(codes)
        )

    def test_generic_platform_version_baseline(self):
        policy = AuditPolicy(minimum_client_versions={"Windows": "10.20.3.0"})
        old = healthy_device(client_version="10.19.9.9")
        current = healthy_device(device_id="device-b", client_version="10.20.3")

        old_finding = evaluate_device(old, policy, now=NOW)
        current_finding = evaluate_device(current, policy, now=NOW)

        self.assertIn("outdated_client", {issue.code for issue in old_finding.issues})
        self.assertNotIn(
            "outdated_client",
            {issue.code for issue in current_finding.issues},
        )

    def test_audit_order_is_deterministic(self):
        findings = audit_devices(
            [
                healthy_device(device_id="b", computer_dns_name="z-host"),
                healthy_device(device_id="a", computer_dns_name="A-host"),
            ],
            AuditPolicy(),
            now=NOW,
        )
        self.assertEqual(
            [finding.device.device_id for finding in findings],
            ["a", "b"],
        )

    def test_policy_file_rejects_unknown_settings(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "policy.toml"
            path.write_text("[audit]\nunknown = 5\n", encoding="utf-8")
            with self.assertRaisesRegex(PolicyError, "unknown audit setting"):
                AuditPolicy.from_toml(path)

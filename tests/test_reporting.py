from __future__ import annotations

import csv
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from mde_health_auditor.models import DeviceRecord
from mde_health_auditor.policy import AuditPolicy, audit_devices
from mde_health_auditor.reporting import build_report, write_csv, write_json


class ReportingTests(unittest.TestCase):
    def test_findings_only_and_report_files(self):
        policy = AuditPolicy()
        now = datetime(2026, 9, 9, tzinfo=timezone.utc)
        devices = [
            DeviceRecord(
                device_id="healthy",
                last_seen="2026-09-09T00:00:00Z",
                health_status="Active",
                onboarding_status="Onboarded",
                risk_score="None",
                exposure_level="Low",
            ),
            DeviceRecord(
                device_id="stale",
                computer_dns_name="stale.example.invalid",
                last_seen="2026-01-01T00:00:00Z",
                health_status="Inactive",
                onboarding_status="Onboarded",
            ),
        ]
        report = build_report(
            audit_devices(devices, policy, now=now),
            policy,
            source="test",
            generated_at=now,
        )

        self.assertEqual(report["device_count"], 2)
        self.assertEqual(report["finding_count"], 1)
        self.assertEqual(len(report["devices"]), 1)

        with tempfile.TemporaryDirectory() as temp_dir:
            json_path = write_json(report, Path(temp_dir) / "report.json")
            csv_path = write_csv(report, Path(temp_dir) / "report.csv")

            loaded = json.loads(json_path.read_text(encoding="utf-8"))
            self.assertEqual(loaded["devices"][0]["device_id"], "stale")
            with csv_path.open(encoding="utf-8", newline="") as handle:
                rows = list(csv.DictReader(handle))
            self.assertEqual(rows[0]["device_id"], "stale")
            self.assertIn("device_stale", rows[0]["issue_codes"])

from __future__ import annotations

import unittest

from mde_health_auditor.hunting import enrich_devices
from mde_health_auditor.models import DeviceRecord


class DeviceRecordTests(unittest.TestCase):
    def test_machine_fields_are_normalized(self):
        record = DeviceRecord.from_machine(
            {
                "id": "device-a",
                "computerDnsName": "HOST.EXAMPLE",
                "lastSeen": "2026-09-01T00:00:00Z",
                "osPlatform": "Windows11",
                "osArchitecture": "64-bit",
                "healthStatus": "Active",
                "onboardingstatus": "onboarded",
                "machineTags": ["z", "a"],
                "isAadJoined": True,
            }
        )

        self.assertEqual(record.device_id, "device-a")
        self.assertEqual(record.onboarding_status, "onboarded")
        self.assertEqual(record.machine_tags, ["a", "z"])
        self.assertTrue(record.is_aad_joined)

    def test_hunting_rows_enrich_by_case_insensitive_id(self):
        device = DeviceRecord(device_id="DEVICE-A")

        enrich_devices(
            [device],
            [
                {
                    "DeviceId": "device-a",
                    "ClientVersion": "10.1.2.3",
                    "SensorHealthState": "Healthy",
                    "UpdateFailureCount": "2",
                    "LatestUpdateFailure": "2026-09-01T00:00:00Z",
                }
            ],
        )

        self.assertEqual(device.client_version, "10.1.2.3")
        self.assertEqual(device.update_failure_count, 2)

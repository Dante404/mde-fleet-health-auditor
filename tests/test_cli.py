from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from mde_health_auditor.cli import main

ROOT = Path(__file__).resolve().parents[1]


class CliTests(unittest.TestCase):
    def test_offline_sample_writes_both_formats(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            result = main(
                [
                    "--machines-file",
                    str(ROOT / "examples" / "sample-machines.json"),
                    "--hunting-file",
                    str(ROOT / "examples" / "sample-hunting.json"),
                    "--config",
                    str(ROOT / "config.example.toml"),
                    "--output-dir",
                    temp_dir,
                    "--output-prefix",
                    "test-report",
                    "--format",
                    "both",
                ]
            )

            self.assertEqual(result, 0)
            self.assertTrue((Path(temp_dir) / "test-report.json").exists())
            self.assertTrue((Path(temp_dir) / "test-report.csv").exists())

    def test_fail_on_high_returns_one_after_writing_report(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            result = main(
                [
                    "--machines-file",
                    str(ROOT / "examples" / "sample-machines.json"),
                    "--output-dir",
                    temp_dir,
                    "--output-prefix",
                    "threshold",
                    "--format",
                    "json",
                    "--fail-on",
                    "high",
                ]
            )

            self.assertEqual(result, 1)
            self.assertTrue((Path(temp_dir) / "threshold.json").exists())

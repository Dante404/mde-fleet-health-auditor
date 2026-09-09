"""Deterministic CSV, JSON, and console reporting."""

from __future__ import annotations

import csv
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .models import Finding
from .policy import AuditPolicy

CSV_FIELDS = [
    "device_id",
    "computer_dns_name",
    "last_seen",
    "days_since_seen",
    "os_platform",
    "os_version",
    "os_build",
    "os_architecture",
    "client_version",
    "health_status",
    "sensor_health_state",
    "onboarding_status",
    "risk_score",
    "exposure_level",
    "group_name",
    "aad_device_id",
    "is_aad_joined",
    "machine_tags",
    "update_failure_count",
    "latest_update_failure",
    "max_severity",
    "issue_codes",
    "issue_details",
]


def finding_to_dict(finding: Finding) -> dict[str, Any]:
    device = finding.device
    return {
        "device_id": device.device_id,
        "computer_dns_name": device.computer_dns_name,
        "last_seen": device.last_seen,
        "days_since_seen": (
            round(finding.days_since_seen, 2)
            if finding.days_since_seen is not None
            else None
        ),
        "os_platform": device.os_platform,
        "os_version": device.os_version,
        "os_build": device.os_build,
        "os_architecture": device.os_architecture,
        "client_version": device.client_version,
        "health_status": device.health_status,
        "sensor_health_state": device.sensor_health_state,
        "onboarding_status": device.onboarding_status,
        "risk_score": device.risk_score,
        "exposure_level": device.exposure_level,
        "group_name": device.group_name,
        "aad_device_id": device.aad_device_id,
        "is_aad_joined": device.is_aad_joined,
        "machine_tags": list(device.machine_tags),
        "update_failure_count": device.update_failure_count,
        "latest_update_failure": device.latest_update_failure,
        "max_severity": finding.max_severity,
        "issues": [
            {
                "code": issue.code,
                "severity": issue.severity,
                "message": issue.message,
            }
            for issue in finding.issues
        ],
    }


def build_report(
    findings: list[Finding],
    policy: AuditPolicy,
    *,
    source: str,
    include_healthy: bool = False,
    generated_at: datetime | None = None,
) -> dict[str, Any]:
    generated_at = (generated_at or datetime.now(timezone.utc)).astimezone(timezone.utc)
    included = findings if include_healthy else [item for item in findings if item.issues]
    return {
        "generated_at": generated_at.isoformat().replace("+00:00", "Z"),
        "source": source,
        "device_count": len(findings),
        "finding_count": sum(bool(item.issues) for item in findings),
        "reported_device_count": len(included),
        "severity_counts": {
            severity: sum(item.max_severity == severity for item in findings)
            for severity in ("high", "medium", "low")
        },
        "policy": policy.as_dict(),
        "devices": [finding_to_dict(item) for item in included],
    }


def write_json(report: dict[str, Any], path: str | Path) -> Path:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps(report, indent=2, sort_keys=False) + "\n",
        encoding="utf-8",
    )
    return destination


def write_csv(report: dict[str, Any], path: str | Path) -> Path:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_FIELDS)
        writer.writeheader()
        for item in report["devices"]:
            row = {field: item.get(field, "") for field in CSV_FIELDS}
            row["machine_tags"] = ";".join(item["machine_tags"])
            row["issue_codes"] = ";".join(issue["code"] for issue in item["issues"])
            row["issue_details"] = " | ".join(
                f"{issue['severity']}:{issue['code']}:{issue['message']}"
                for issue in item["issues"]
            )
            writer.writerow(row)
    return destination


def format_summary(report: dict[str, Any]) -> str:
    counts = report["severity_counts"]
    return (
        f"Audited {report['device_count']} device(s); "
        f"{report['finding_count']} with findings "
        f"(high={counts['high']}, medium={counts['medium']}, low={counts['low']})."
    )

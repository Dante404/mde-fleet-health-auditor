"""Configurable fleet-health rules."""

from __future__ import annotations

import re
import tomllib
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .models import DeviceRecord, Finding, Issue


class PolicyError(ValueError):
    """Raised when a policy file is invalid."""


@dataclass(slots=True)
class AuditPolicy:
    stale_after_days: int = 7
    critical_stale_after_days: int = 30
    update_failure_critical_count: int = 3
    minimum_client_versions: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.stale_after_days < 1:
            raise PolicyError("stale_after_days must be at least 1")
        if self.critical_stale_after_days < self.stale_after_days:
            raise PolicyError(
                "critical_stale_after_days must be greater than or equal to stale_after_days"
            )
        if self.update_failure_critical_count < 1:
            raise PolicyError("update_failure_critical_count must be at least 1")
        for platform, version in self.minimum_client_versions.items():
            if not str(platform).strip():
                raise PolicyError("minimum_client_versions contains an empty platform name")
            _version_tuple(str(version))

    @classmethod
    def from_toml(cls, path: str | Path) -> "AuditPolicy":
        with Path(path).open("rb") as handle:
            raw = tomllib.load(handle)
        audit = raw.get("audit", {})
        baselines = raw.get("minimum_client_versions", {})
        if not isinstance(audit, dict) or not isinstance(baselines, dict):
            raise PolicyError(
                "[audit] and [minimum_client_versions] must be TOML tables"
            )
        allowed = {
            "stale_after_days",
            "critical_stale_after_days",
            "update_failure_critical_count",
        }
        unknown = sorted(set(audit) - allowed)
        if unknown:
            raise PolicyError(f"unknown audit setting(s): {', '.join(unknown)}")
        try:
            return cls(
                stale_after_days=int(audit.get("stale_after_days", 7)),
                critical_stale_after_days=int(
                    audit.get("critical_stale_after_days", 30)
                ),
                update_failure_critical_count=int(
                    audit.get("update_failure_critical_count", 3)
                ),
                minimum_client_versions={
                    str(platform): str(version)
                    for platform, version in baselines.items()
                },
            )
        except (TypeError, ValueError) as exc:
            raise PolicyError(f"invalid policy value: {exc}") from exc

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def _parse_datetime(raw: str) -> datetime:
    text = raw.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _normalized(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.casefold())


def _version_tuple(value: str) -> tuple[int, ...]:
    parts = re.findall(r"\d+", value)
    if not parts:
        raise PolicyError(f"client version has no numeric components: {value!r}")
    return tuple(int(part) for part in parts)


def _version_is_older(current: str, minimum: str) -> bool:
    left = _version_tuple(current)
    right = _version_tuple(minimum)
    width = max(len(left), len(right))
    return left + (0,) * (width - len(left)) < right + (0,) * (width - len(right))


def _baseline_for(device: DeviceRecord, policy: AuditPolicy) -> str | None:
    platform = _normalized(device.os_platform)
    matches = {
        _normalized(name): version
        for name, version in policy.minimum_client_versions.items()
    }
    if platform in matches:
        return matches[platform]
    for generic in ("windows", "linux", "macos"):
        if platform.startswith(generic) and generic in matches:
            return matches[generic]
    return matches.get("default")


def evaluate_device(
    device: DeviceRecord,
    policy: AuditPolicy,
    *,
    now: datetime | None = None,
) -> Finding:
    now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    issues: list[Issue] = []
    days_since_seen: float | None = None

    if not device.device_id:
        issues.append(Issue("missing_device_id", "high", "Inventory row has no device ID"))

    if not device.last_seen:
        issues.append(Issue("missing_last_seen", "high", "No last-seen timestamp is available"))
    else:
        try:
            days_since_seen = (now - _parse_datetime(device.last_seen)).total_seconds() / 86_400
            if days_since_seen < -1:
                issues.append(
                    Issue(
                        "last_seen_in_future",
                        "medium",
                        "Last-seen timestamp is more than one day in the future",
                    )
                )
            elif days_since_seen >= policy.critical_stale_after_days:
                issues.append(
                    Issue(
                        "device_stale",
                        "high",
                        f"No full device report for {days_since_seen:.1f} days",
                    )
                )
            elif days_since_seen >= policy.stale_after_days:
                issues.append(
                    Issue(
                        "device_stale",
                        "medium",
                        f"No full device report for {days_since_seen:.1f} days",
                    )
                )
        except ValueError:
            issues.append(
                Issue("invalid_last_seen", "high", "Last-seen timestamp is not valid ISO 8601")
            )

    health = _normalized(device.health_status)
    if not health:
        issues.append(Issue("missing_health_status", "medium", "Health status is unavailable"))
    elif health != "active":
        severity = (
            "high"
            if health
            in {
                "impairedcommunication",
                "nosensordata",
                "nosensordataimpairedcommunication",
            }
            else "medium"
        )
        issues.append(
            Issue(
                "unhealthy_device",
                severity,
                f"Device health status is {device.health_status}",
            )
        )

    onboarding = _normalized(device.onboarding_status)
    if not onboarding:
        issues.append(
            Issue("missing_onboarding_status", "medium", "Onboarding status is unavailable")
        )
    elif onboarding != "onboarded":
        severity = {
            "canbeonboarded": "high",
            "insufficientinfo": "medium",
            "unsupported": "low",
        }.get(onboarding, "high")
        issues.append(
            Issue(
                "onboarding_problem",
                severity,  # type: ignore[arg-type]
                f"Onboarding status is {device.onboarding_status}",
            )
        )

    risk = _normalized(device.risk_score)
    if risk in {"high", "medium"}:
        issues.append(
            Issue(
                "elevated_risk",
                risk,  # type: ignore[arg-type]
                f"Defender risk score is {device.risk_score}",
            )
        )

    exposure = _normalized(device.exposure_level)
    if exposure in {"high", "medium"}:
        issues.append(
            Issue(
                "elevated_exposure",
                exposure,  # type: ignore[arg-type]
                f"Defender exposure level is {device.exposure_level}",
            )
        )

    sensor = _normalized(device.sensor_health_state)
    if sensor and sensor not in {"active", "healthy"}:
        severity = (
            "high"
            if sensor
            in {
                "impairedcommunication",
                "nosensordata",
                "nosensordataimpairedcommunication",
                "unhealthy",
            }
            else "medium"
        )
        issues.append(
            Issue(
                "unhealthy_sensor",
                severity,
                f"EDR sensor health is {device.sensor_health_state}",
            )
        )

    minimum = _baseline_for(device, policy)
    if minimum:
        if not device.client_version:
            issues.append(
                Issue(
                    "missing_client_version",
                    "medium",
                    f"No client version is available; minimum for {device.os_platform} is {minimum}",
                )
            )
        else:
            try:
                if _version_is_older(device.client_version, minimum):
                    issues.append(
                        Issue(
                            "outdated_client",
                            "high",
                            f"Client {device.client_version} is below minimum {minimum}",
                        )
                    )
            except PolicyError:
                issues.append(
                    Issue(
                        "unparseable_client_version",
                        "medium",
                        f"Could not compare client version {device.client_version!r}",
                    )
                )

    if device.update_failure_count:
        severity = (
            "high"
            if device.update_failure_count >= policy.update_failure_critical_count
            else "medium"
        )
        latest = (
            f"; latest at {device.latest_update_failure}"
            if device.latest_update_failure
            else ""
        )
        issues.append(
            Issue(
                "update_failures",
                severity,
                f"{device.update_failure_count} Defender update failure(s){latest}",
            )
        )

    return Finding(device=device, issues=issues, days_since_seen=days_since_seen)


def audit_devices(
    devices: list[DeviceRecord],
    policy: AuditPolicy,
    *,
    now: datetime | None = None,
) -> list[Finding]:
    return [
        evaluate_device(device, policy, now=now)
        for device in sorted(
            devices,
            key=lambda item: (item.computer_dns_name.casefold(), item.device_id.casefold()),
        )
    ]

"""Domain models and API response normalization."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

Severity = Literal["low", "medium", "high"]
SEVERITY_RANK: dict[str, int] = {"none": 0, "low": 1, "medium": 2, "high": 3}


def _first(mapping: dict[str, Any], *keys: str, default: Any = "") -> Any:
    for key in keys:
        if key in mapping and mapping[key] is not None:
            return mapping[key]
    return default


@dataclass(slots=True)
class DeviceRecord:
    device_id: str
    computer_dns_name: str = ""
    first_seen: str = ""
    last_seen: str = ""
    os_platform: str = ""
    os_version: str = ""
    os_build: str = ""
    os_architecture: str = ""
    health_status: str = ""
    onboarding_status: str = ""
    group_name: str = ""
    risk_score: str = ""
    exposure_level: str = ""
    is_aad_joined: bool | None = None
    aad_device_id: str = ""
    machine_tags: list[str] = field(default_factory=list)
    client_version: str = ""
    sensor_health_state: str = ""
    update_failure_count: int = 0
    latest_update_failure: str = ""

    @classmethod
    def from_machine(cls, raw: dict[str, Any]) -> "DeviceRecord":
        tags = _first(raw, "machineTags", "MachineTags", default=[])
        if isinstance(tags, str):
            tags = [tags]
        elif not isinstance(tags, list):
            tags = []

        joined = _first(raw, "isAadJoined", "IsAadJoined", default=None)
        if not isinstance(joined, bool):
            joined = None

        return cls(
            device_id=str(_first(raw, "id", "DeviceId")),
            computer_dns_name=str(_first(raw, "computerDnsName", "DeviceName")),
            first_seen=str(_first(raw, "firstSeen", "FirstSeen")),
            last_seen=str(_first(raw, "lastSeen", "LastSeen")),
            os_platform=str(_first(raw, "osPlatform", "OSPlatform")),
            os_version=str(_first(raw, "version", "OSVersion")),
            os_build=str(_first(raw, "osBuild", "OSBuild")),
            os_architecture=str(
                _first(raw, "osArchitecture", "OSArchitecture", "osProcessor")
            ),
            health_status=str(_first(raw, "healthStatus", "HealthStatus")),
            onboarding_status=str(
                _first(raw, "onboardingStatus", "onboardingstatus", "OnboardingStatus")
            ),
            group_name=str(_first(raw, "rbacGroupName", "MachineGroup")),
            risk_score=str(_first(raw, "riskScore", "RiskScore")),
            exposure_level=str(_first(raw, "exposureLevel", "ExposureLevel")),
            is_aad_joined=joined,
            aad_device_id=str(_first(raw, "aadDeviceId", "AadDeviceId")),
            machine_tags=sorted(str(tag) for tag in tags),
        )

    def apply_hunting_row(self, raw: dict[str, Any]) -> None:
        self.client_version = str(_first(raw, "ClientVersion", "clientVersion"))
        self.sensor_health_state = str(
            _first(raw, "SensorHealthState", "sensorHealthState")
        )
        hunting_onboarding = str(
            _first(
                raw,
                "HuntingOnboardingStatus",
                "huntingOnboardingStatus",
                "OnboardingStatus",
            )
        )
        if hunting_onboarding and not self.onboarding_status:
            self.onboarding_status = hunting_onboarding
        count = _first(raw, "UpdateFailureCount", "updateFailureCount", default=0)
        try:
            self.update_failure_count = max(0, int(count))
        except (TypeError, ValueError):
            self.update_failure_count = 0
        self.latest_update_failure = str(
            _first(raw, "LatestUpdateFailure", "latestUpdateFailure")
        )


@dataclass(frozen=True, slots=True)
class Issue:
    code: str
    severity: Severity
    message: str


@dataclass(slots=True)
class Finding:
    device: DeviceRecord
    issues: list[Issue]
    days_since_seen: float | None

    @property
    def max_severity(self) -> str:
        if not self.issues:
            return "none"
        return max(self.issues, key=lambda item: SEVERITY_RANK[item.severity]).severity

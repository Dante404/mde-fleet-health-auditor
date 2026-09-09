"""Advanced hunting enrichment for client and update health."""

from __future__ import annotations

from typing import Any

from .models import DeviceRecord

FLEET_ENRICHMENT_QUERY = r"""
let LatestDeviceInfo =
    DeviceInfo
    | summarize arg_max(Timestamp, ClientVersion, SensorHealthState, OnboardingStatus) by DeviceId;
let UpdateFailures =
    DeviceEvents
    | where ActionType in~ ("MpSignatureUpdateFailed", "MpPlatformUpdateFailed", "MpEngineUpdateFailed")
        or (ActionType =~ "AntivirusSignatureUpdate" and tolower(AdditionalFields) contains "failed")
    | summarize UpdateFailureCount=count(), LatestUpdateFailure=max(Timestamp) by DeviceId;
LatestDeviceInfo
| join kind=leftouter UpdateFailures on DeviceId
| project DeviceId,
          ClientVersion,
          SensorHealthState,
          HuntingOnboardingStatus=OnboardingStatus,
          UpdateFailureCount=coalesce(UpdateFailureCount, 0),
          LatestUpdateFailure
""".strip()


def enrich_devices(
    devices: list[DeviceRecord],
    hunting_rows: list[dict[str, Any]],
) -> None:
    by_id = {device.device_id.casefold(): device for device in devices if device.device_id}
    for row in hunting_rows:
        raw_id = row.get("DeviceId", row.get("deviceId", ""))
        device = by_id.get(str(raw_id).casefold())
        if device is not None:
            device.apply_hunting_row(row)

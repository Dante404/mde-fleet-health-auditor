# Health rules

The auditor normalizes MDE inventory and optional Graph hunting data into one
device record. A device can have more than one issue; its maximum severity is
used in summary counts and --fail-on evaluation.

| Rule | Condition | Severity |
| --- | --- | --- |
| Missing last seen | No timestamp | High |
| Stale device | At or above stale_after_days | Medium |
| Critically stale | At or above critical_stale_after_days | High |
| Device health | Anything except Active | Medium or high for impaired/no-sensor states |
| Onboarding | CanBeOnboarded | High |
| Onboarding | InsufficientInfo | Medium |
| Onboarding | Unsupported | Low |
| Risk score | Medium or High | Matching severity |
| Exposure level | Medium or High | Matching severity |
| Sensor health | Nonhealthy hunting value | Medium or high for impaired/no-sensor states |
| Client version | Below a configured platform baseline | High |
| Update failures | One or more during hunting lookback | Medium, or high at configured count |

## Last-seen interpretation

Microsoft defines the machine resource lastSeen value as the time of the last
full device report, normally sent every 24 hours. It does not correspond
exactly to the similarly named value shown in the Defender portal. Choose a
threshold that fits sleep, travel, server, and ephemeral-device behavior in
your environment.

## Client version baselines

The List machines response does not expose endpoint ClientVersion. That field
comes from the DeviceInfo advanced hunting table, so outdated-client checks
require --include-hunting or --hunting-file.

Baselines are not built into the project because current approved versions
change and rings can intentionally differ. Put numeric values in
[minimum_client_versions]. Matching ignores punctuation and letter case.
Exact OSPlatform names win; generic Windows, Linux, macOS, and default keys are
fallbacks.

## Update failures

The built-in enrichment query counts these DeviceEvents patterns:

- MpSignatureUpdateFailed
- MpPlatformUpdateFailed
- MpEngineUpdateFailed
- AntivirusSignatureUpdate when AdditionalFields contains failed

Microsoft advises using the in-portal schema reference for supported ActionType
values. Validate these values against your tenant if product telemetry changes.
The Graph API applies its own query time, row, and resource quotas; the default
lookback is 30 days.

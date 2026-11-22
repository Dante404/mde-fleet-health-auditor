# MDE Fleet Health Auditor

[![Validation](https://github.com/Dante404/mde-fleet-health-auditor/actions/workflows/validate.yml/badge.svg)](https://github.com/Dante404/mde-fleet-health-auditor/actions/workflows/validate.yml)

A read-only command-line tool for reviewing Microsoft Defender for Endpoint
device health. It finds stale inventory, unhealthy sensors, onboarding
problems, elevated risk or exposure, old client versions, and recent Defender
update failures, then writes deterministic CSV and JSON reports.

## What it does

- Retrieves every visible machine with supported paging and throttling retries.
- Applies configurable health thresholds without changing a device or tenant.
- Optionally enriches inventory through Microsoft Graph advanced hunting.
- Supports saved JSON responses for offline analysis and reproducible testing.
- Keeps access tokens in memory and never accepts a client secret.
- Can return a nonzero status at a chosen severity for scheduled checks.

The normal inventory audit requires only the delegated Machine.Read permission.
Advanced hunting is optional and separately requires the delegated
ThreatHunting.Read.All permission.

## Quick start with sample data

Python 3.11 or newer is required.

~~~bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -e .

mde-health-audit \
  --machines-file examples/sample-machines.json \
  --hunting-file examples/sample-hunting.json \
  --config config.example.toml \
  --output-dir reports
~~~

The command prints a short summary and creates timestamped CSV and JSON files.
Reports contain findings only unless --all-devices is supplied.

### Windows PowerShell quick start (offline sample)

From PowerShell on Windows, with Python 3.11 or newer installed:

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\mde-health-audit.exe --machines-file examples/sample-machines.json --hunting-file examples/sample-hunting.json --config config.example.toml --output-dir reports
```

The offline example uses synthetic device records. It does not sign in, call Microsoft APIs, or alter endpoint configuration. Inspect the generated CSV and JSON in `reports/` (which is ignored by Git). Use the live-audit instructions below only when you have the appropriate Entra registration, permissions and authorization.

## Live audit

Create a public-client app registration as described in
[docs/authentication.md](docs/authentication.md), then set the tenant and
application IDs. These values identify the app; they are not secrets.

~~~bash
export MDE_TENANT_ID="00000000-0000-0000-0000-000000000000"
export MDE_CLIENT_ID="00000000-0000-0000-0000-000000000000"

mde-health-audit --config config.example.toml
~~~

The tool displays Microsoft's device-code sign-in instructions. Authentication
supports the controls applied to the signing-in user, including MFA and
Conditional Access.

To include endpoint client versions, EDR sensor state, and update failures:

~~~bash
mde-health-audit \
  --config config.example.toml \
  --include-hunting
~~~

This requests a separate Microsoft Graph token. Add ThreatHunting.Read.All to
the app registration only when that enrichment is needed.

For a tenant using a regional MDE endpoint, choose a documented region such as
--api-region eu. The default is the global endpoint.

## Health policy

Copy config.example.toml and adjust the thresholds. Minimum client versions are
intentionally empty because an approved version baseline varies by operating
system and environment.

~~~toml
[audit]
stale_after_days = 7
critical_stale_after_days = 30
update_failure_critical_count = 3

[minimum_client_versions]
Windows11 = "10.9000.1000.0"
Linux = "101.25000.0000"
~~~

Version values above are format examples only. Use baselines approved for your
own environment. Exact OSPlatform keys are matched first; Windows, Linux,
macOS, and default can act as generic fallbacks.

See [docs/health-rules.md](docs/health-rules.md) for rule behavior and caveats.

## Useful options

| Option | Purpose |
| --- | --- |
| --machines-file PATH | Audit a saved MDE response without signing in |
| --include-hunting | Query current Graph advanced hunting enrichment |
| --hunting-file PATH | Enrich from a saved Graph response |
| --all-devices | Include devices with no findings |
| --format csv, json, or both | Select report format |
| --fail-on high | Exit 1 when a high-severity finding exists |
| --api-region eu | Use a documented regional MDE API endpoint |
| --page-size N | Set page size from 1 through 10,000 |

Run mde-health-audit --help for the complete interface.

## Exit status

| Code | Meaning |
| --- | --- |
| 0 | Audit completed and the selected failure threshold was not reached |
| 1 | Audit completed and --fail-on was reached |
| 2 | Configuration, authentication, input, or API error |

## Read-only design

The inventory client calls GET /api/machines. The optional hunting client calls
POST /v1.0/security/runHuntingQuery, but that operation executes a read-only
KQL query and uses a read-only Graph permission. Pagination links are accepted
only from the configured MDE HTTPS origin, preventing a bearer token from being
forwarded to an unexpected host. Responses to HTTP 429 and transient server
errors respect Retry-After and use bounded backoff.

No credential, token cache, live report, or environment file is committed.
See [SECURITY.md](SECURITY.md) for safe handling guidance.

## Tests

~~~bash
PYTHONPATH=src python -m unittest discover -s tests -v
~~~

Tests use fake transports and fixed sample data; they do not contact Microsoft.
GitHub Actions also compiles the package and runs an offline command smoke test.

## API references

- [List machines — Microsoft Defender for Endpoint](https://learn.microsoft.com/en-us/defender-endpoint/api/get-machines)
- [Machine resource type](https://learn.microsoft.com/en-us/defender-endpoint/api/machine)
- [Native app authentication for Defender for Endpoint](https://learn.microsoft.com/en-us/defender-endpoint/api/exposed-apis-create-app-nativeapp)
- [Microsoft Graph runHuntingQuery](https://learn.microsoft.com/en-us/graph/api/security-security-runhuntingquery?view=graph-rest-1.0)
- [DeviceInfo advanced hunting table](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table)
- [DeviceEvents advanced hunting table](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceevents-table)

## License

MIT

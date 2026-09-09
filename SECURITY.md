# Security

## Credential handling

This tool is designed for delegated device-code authentication. Do not create a
client secret for it and do not paste access tokens into command-line
arguments, configuration files, issues, or logs.

Tenant IDs and client IDs are identifiers, not credentials. Access tokens are
held only in process memory. The project does not write an MSAL token cache.

Generated reports can contain device names, IDs, groups, tags, risk levels, and
health information. Store and share them according to your organization's data
handling requirements. The reports directory and common environment or token
cache files are ignored by Git.

## Permissions

Grant only delegated Machine.Read for the base inventory audit. Add delegated
ThreatHunting.Read.All only if Graph enrichment is required. The signed-in
user's Defender roles and device-group scope still determine visible data.

Review tenant consent and app access periodically and remove permissions that
are no longer needed.

## Reporting a vulnerability

Open a private security advisory in this repository. Do not include live
credentials, access tokens, tenant data, or unredacted reports.

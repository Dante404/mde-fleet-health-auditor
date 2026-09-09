# Authentication setup

MDE Fleet Health Auditor uses delegated device-code authentication. It is a
public client and does not need a client secret.

## Create the app registration

1. Open Microsoft Entra admin center and go to App registrations.
2. Create a new single-tenant registration.
3. Copy the Directory (tenant) ID and Application (client) ID.
4. Under Authentication, enable Allow public client flows.
5. Under API permissions, add Microsoft Defender for Endpoint
   (WindowsDefenderATP) as a delegated permission and select Machine.Read.
6. If advanced hunting enrichment will be used, also add the Microsoft Graph
   delegated permission ThreatHunting.Read.All.
7. Grant admin consent when your tenant policy requires it.

Do not add a secret or certificate. This application signs in a user
interactively and does not use application-only access.

## Run

~~~bash
export MDE_TENANT_ID="your-tenant-id"
export MDE_CLIENT_ID="your-application-id"
mde-health-audit --config config.example.toml
~~~

The terminal prints a Microsoft verification URL and a short code. Complete
sign-in in the browser. For optional enrichment, the app obtains a
resource-specific Microsoft Graph token and might ask for consent or sign-in
again.

## Permission boundaries

Machine.Read can read machine profiles, including commands previously sent to a
machine, but cannot run response actions or modify machines. The signed-in user
must have permission to view Defender data and sees only device groups allowed
by role-based access control.

ThreatHunting.Read.All can query hunting data visible to the signed-in user. The
tool uses it only for the built-in fleet enrichment query. Omit
--include-hunting and leave this permission unconfigured when client/update
enrichment is not needed.

The MDE API endpoint is api.security.microsoft.com, while Microsoft currently
documents the token scope for this API under the legacy
api.securitycenter.microsoft.com resource. The implementation follows that
documented audience split.

"""Interactive, secretless authentication for Microsoft APIs."""

from __future__ import annotations

import sys
from collections.abc import Sequence
from typing import Any, TextIO

MDE_SCOPES = ("https://api.securitycenter.microsoft.com/.default",)
GRAPH_SCOPES = ("https://graph.microsoft.com/.default",)


class AuthenticationError(RuntimeError):
    """Raised when Microsoft identity platform authentication fails."""


class DeviceCodeCredential:
    """Acquire delegated tokens through MSAL's device-code flow.

    No client secret is accepted or stored. MSAL's in-memory cache is shared
    between resource-specific token requests for the lifetime of this process.
    """

    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        *,
        output: TextIO = sys.stderr,
        app: Any | None = None,
    ) -> None:
        if not tenant_id.strip() or not client_id.strip():
            raise ValueError("tenant_id and client_id are required")

        self.output = output
        self._tokens: dict[tuple[str, ...], str] = {}
        if app is not None:
            self._app = app
            return

        try:
            import msal
        except ImportError as exc:  # pragma: no cover - depends on installation
            raise AuthenticationError(
                "MSAL is not installed. Run: python -m pip install -e ."
            ) from exc

        authority = f"https://login.microsoftonline.com/{tenant_id.strip()}"
        self._app = msal.PublicClientApplication(
            client_id.strip(),
            authority=authority,
        )

    def get_token(self, scopes: Sequence[str]) -> str:
        key = tuple(sorted(scopes))
        if key in self._tokens:
            return self._tokens[key]

        result: dict[str, Any] | None = None
        for account in self._app.get_accounts():
            result = self._app.acquire_token_silent(list(scopes), account=account)
            if result and result.get("access_token"):
                return self._remember(key, result["access_token"])

        flow = self._app.initiate_device_flow(scopes=list(scopes))
        if "user_code" not in flow:
            detail = flow.get("error_description") or flow.get("error") or "unknown error"
            raise AuthenticationError(f"Could not start device-code authentication: {detail}")

        print(flow.get("message", "Follow the Microsoft sign-in instructions."), file=self.output)
        result = self._app.acquire_token_by_device_flow(flow)
        if result and result.get("access_token"):
            return self._remember(key, result["access_token"])

        detail = (result or {}).get("error_description") or (result or {}).get("error")
        raise AuthenticationError(f"Authentication failed: {detail or 'no access token returned'}")

    def _remember(self, key: tuple[str, ...], token: str) -> str:
        self._tokens[key] = token
        return token

from __future__ import annotations

import io
import unittest

from mde_health_auditor.auth import AuthenticationError, DeviceCodeCredential


class FakeApp:
    def __init__(self, *, result=None, flow=None):
        self.result = result or {"access_token": "device-token"}
        self.flow = flow or {"user_code": "ABCD", "message": "Sign in now"}
        self.device_calls = 0

    def get_accounts(self):
        return []

    def acquire_token_silent(self, scopes, account):
        return None

    def initiate_device_flow(self, scopes):
        return self.flow

    def acquire_token_by_device_flow(self, flow):
        self.device_calls += 1
        return self.result


class DeviceCodeCredentialTests(unittest.TestCase):
    def test_device_flow_token_is_cached_per_scope(self):
        app = FakeApp()
        output = io.StringIO()
        credential = DeviceCodeCredential(
            "tenant",
            "client",
            output=output,
            app=app,
        )

        first = credential.get_token(["scope/.default"])
        second = credential.get_token(["scope/.default"])

        self.assertEqual(first, "device-token")
        self.assertEqual(second, "device-token")
        self.assertEqual(app.device_calls, 1)
        self.assertIn("Sign in now", output.getvalue())

    def test_device_flow_start_error_is_clear(self):
        app = FakeApp(flow={"error": "invalid_client"})
        credential = DeviceCodeCredential("tenant", "client", app=app)

        with self.assertRaisesRegex(AuthenticationError, "invalid_client"):
            credential.get_token(["scope/.default"])

from __future__ import annotations

import unittest

from mde_health_auditor.client import ApiError, GraphHuntingClient, MDEClient


class FakeResponse:
    def __init__(self, status_code, payload, *, headers=None, text=""):
        self.status_code = status_code
        self.payload = payload
        self.headers = headers or {}
        self.text = text

    def json(self):
        return self.payload


class FakeSession:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        if not self.responses:
            raise AssertionError("Unexpected HTTP request")
        return self.responses.pop(0)


class MDEClientTests(unittest.TestCase):
    def test_skip_pagination_reads_every_page(self):
        session = FakeSession(
            [
                FakeResponse(200, {"value": [{"id": "a"}, {"id": "b"}]}),
                FakeResponse(200, {"value": [{"id": "c"}]}),
            ]
        )
        client = MDEClient(lambda: "token", session=session, sleep=lambda _: None)

        machines = client.list_machines(page_size=2)

        self.assertEqual([item["id"] for item in machines], ["a", "b", "c"])
        self.assertEqual(session.calls[0][2]["params"], {"$top": 2, "$skip": 0})
        self.assertEqual(session.calls[1][2]["params"], {"$top": 2, "$skip": 2})
        self.assertEqual(
            session.calls[0][2]["headers"]["Authorization"],
            "Bearer token",
        )

    def test_same_origin_next_link_is_followed(self):
        next_link = "https://api.security.microsoft.com/api/machines?$skip=1"
        session = FakeSession(
            [
                FakeResponse(
                    200,
                    {"value": [{"id": "a"}], "@odata.nextLink": next_link},
                ),
                FakeResponse(200, {"value": []}),
            ]
        )
        client = MDEClient(lambda: "token", session=session, sleep=lambda _: None)

        self.assertEqual([item["id"] for item in client.list_machines()], ["a"])
        self.assertEqual(session.calls[1][1], next_link)
        self.assertIsNone(session.calls[1][2]["params"])

    def test_cross_origin_next_link_is_rejected(self):
        session = FakeSession(
            [
                FakeResponse(
                    200,
                    {
                        "value": [{"id": "a"}],
                        "@odata.nextLink": "https://example.invalid/steal",
                    },
                )
            ]
        )
        client = MDEClient(lambda: "token", session=session, sleep=lambda _: None)

        with self.assertRaisesRegex(ApiError, "unexpected pagination host"):
            client.list_machines()
        self.assertEqual(len(session.calls), 1)

    def test_retry_after_is_honored(self):
        delays = []
        session = FakeSession(
            [
                FakeResponse(429, {}, headers={"Retry-After": "0.25"}),
                FakeResponse(200, {"value": []}),
            ]
        )
        client = MDEClient(
            lambda: "token",
            session=session,
            sleep=delays.append,
            max_retries=1,
        )

        self.assertEqual(client.list_machines(), [])
        self.assertEqual(delays, [0.25])


class GraphHuntingClientTests(unittest.TestCase):
    def test_posts_query_and_timespan(self):
        session = FakeSession([FakeResponse(200, {"results": [{"DeviceId": "a"}]})])
        client = GraphHuntingClient(
            lambda: "graph-token",
            session=session,
            sleep=lambda _: None,
        )

        rows = client.run("DeviceInfo | take 1", timespan="P7D")

        self.assertEqual(rows, [{"DeviceId": "a"}])
        method, url, kwargs = session.calls[0]
        self.assertEqual(method, "POST")
        self.assertEqual(
            url,
            "https://graph.microsoft.com/v1.0/security/runHuntingQuery",
        )
        self.assertEqual(
            kwargs["json"],
            {"Query": "DeviceInfo | take 1", "Timespan": "P7D"},
        )

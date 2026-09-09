"""HTTP clients for read-only Defender and Microsoft Graph endpoints."""

from __future__ import annotations

import email.utils
import time
from collections.abc import Callable, Iterator
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

MDE_REGION_URLS = {
    "global": "https://api.security.microsoft.com",
    "eu": "https://eu.api.security.microsoft.com",
    "us": "https://us.api.security.microsoft.com",
    "uk": "https://uk.api.security.microsoft.com",
    "au": "https://au.api.security.microsoft.com",
    "swa": "https://swa.api.security.microsoft.com",
    "ina": "https://ina.api.security.microsoft.com",
    "aea": "https://aea.api.security.microsoft.com",
}

RETRYABLE_STATUS = {429, 500, 502, 503, 504}


class ApiError(RuntimeError):
    """Raised when an API call cannot be completed safely."""


def _default_session() -> Any:
    try:
        import requests
    except ImportError as exc:  # pragma: no cover - depends on installation
        raise ApiError("requests is not installed. Run: python -m pip install -e .") from exc
    return requests.Session()


def _retry_delay(response: Any, attempt: int) -> float:
    raw = response.headers.get("Retry-After") if getattr(response, "headers", None) else None
    if raw:
        try:
            return max(0.0, min(float(raw), 120.0))
        except ValueError:
            try:
                retry_at = email.utils.parsedate_to_datetime(raw)
                if retry_at.tzinfo is None:
                    retry_at = retry_at.replace(tzinfo=timezone.utc)
                return max(
                    0.0,
                    min((retry_at - datetime.now(timezone.utc)).total_seconds(), 120.0),
                )
            except (TypeError, ValueError):
                pass
    return min(2.0**attempt, 30.0)


class JsonApiClient:
    def __init__(
        self,
        token_provider: Callable[[], str],
        *,
        session: Any | None = None,
        timeout: float = 30.0,
        max_retries: int = 4,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.token_provider = token_provider
        self.session = session or _default_session()
        self.timeout = timeout
        self.max_retries = max_retries
        self.sleep = sleep

    def request_json(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        json: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {self.token_provider()}",
            "User-Agent": "mde-fleet-health-auditor/0.1",
        }
        if json is not None:
            headers["Content-Type"] = "application/json; charset=utf-8"

        last_error: Exception | None = None
        for attempt in range(self.max_retries + 1):
            try:
                response = self.session.request(
                    method,
                    url,
                    params=params,
                    json=json,
                    headers=headers,
                    timeout=self.timeout,
                )
            except Exception as exc:  # transport implementations vary
                last_error = exc
                if attempt >= self.max_retries:
                    raise ApiError(f"{method} {url} failed after retries: {exc}") from exc
                self.sleep(min(2.0**attempt, 30.0))
                continue

            if response.status_code in RETRYABLE_STATUS and attempt < self.max_retries:
                self.sleep(_retry_delay(response, attempt))
                continue

            if not 200 <= response.status_code < 300:
                request_id = response.headers.get("request-id", "unknown")
                body = (getattr(response, "text", "") or "").strip().replace("\n", " ")
                if len(body) > 500:
                    body = body[:497] + "..."
                raise ApiError(
                    f"{method} {url} returned HTTP {response.status_code} "
                    f"(request-id: {request_id}): {body or 'empty response'}"
                )

            try:
                payload = response.json()
            except (TypeError, ValueError) as exc:
                raise ApiError(f"{method} {url} returned invalid JSON") from exc
            if not isinstance(payload, dict):
                raise ApiError(f"{method} {url} returned a non-object JSON response")
            return payload

        raise ApiError(f"{method} {url} failed: {last_error or 'unknown error'}")


class MDEClient:
    """Read machine inventory from Microsoft Defender for Endpoint."""

    def __init__(
        self,
        token_provider: Callable[[], str],
        *,
        base_url: str = MDE_REGION_URLS["global"],
        session: Any | None = None,
        timeout: float = 30.0,
        max_retries: int = 4,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        parsed = urlparse(self.base_url)
        if parsed.scheme != "https" or not parsed.netloc:
            raise ValueError("MDE base_url must be an absolute HTTPS URL")
        self._origin = (parsed.scheme, parsed.netloc)
        self.http = JsonApiClient(
            token_provider,
            session=session,
            timeout=timeout,
            max_retries=max_retries,
            sleep=sleep,
        )

    def iter_machines(self, *, page_size: int = 10_000) -> Iterator[dict[str, Any]]:
        if not 1 <= page_size <= 10_000:
            raise ValueError("page_size must be between 1 and 10000")

        url = f"{self.base_url}/api/machines"
        params: dict[str, Any] | None = {"$top": page_size, "$skip": 0}
        seen_urls: set[str] = set()

        while True:
            payload = self.http.request_json("GET", url, params=params)
            values = payload.get("value")
            if not isinstance(values, list):
                raise ApiError("List machines response is missing a JSON 'value' array")
            for machine in values:
                if isinstance(machine, dict):
                    yield machine

            next_link = payload.get("@odata.nextLink")
            if next_link:
                if not isinstance(next_link, str):
                    raise ApiError("@odata.nextLink must be a string")
                self._validate_next_link(next_link)
                if next_link in seen_urls:
                    raise ApiError("Pagination loop detected in @odata.nextLink")
                seen_urls.add(next_link)
                url, params = next_link, None
                continue

            if len(values) < page_size:
                break
            assert params is not None
            params = {"$top": page_size, "$skip": int(params["$skip"]) + page_size}

    def list_machines(self, *, page_size: int = 10_000) -> list[dict[str, Any]]:
        return list(self.iter_machines(page_size=page_size))

    def _validate_next_link(self, next_link: str) -> None:
        parsed = urlparse(next_link)
        if (parsed.scheme, parsed.netloc) != self._origin:
            raise ApiError("Refusing to send an access token to an unexpected pagination host")
        if not parsed.path.startswith("/api/machines"):
            raise ApiError("Unexpected pagination path returned by the MDE API")


class GraphHuntingClient:
    """Run read-only advanced hunting queries through Microsoft Graph."""

    endpoint = "https://graph.microsoft.com/v1.0/security/runHuntingQuery"

    def __init__(
        self,
        token_provider: Callable[[], str],
        *,
        session: Any | None = None,
        timeout: float = 190.0,
        max_retries: int = 4,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.http = JsonApiClient(
            token_provider,
            session=session,
            timeout=timeout,
            max_retries=max_retries,
            sleep=sleep,
        )

    def run(self, query: str, *, timespan: str = "P30D") -> list[dict[str, Any]]:
        payload = self.http.request_json(
            "POST",
            self.endpoint,
            json={"Query": query, "Timespan": timespan},
        )
        results = payload.get("results")
        if not isinstance(results, list):
            raise ApiError("Advanced hunting response is missing a JSON 'results' array")
        return [row for row in results if isinstance(row, dict)]

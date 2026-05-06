"""Sync + async clients for the InjectShield REST API.

The SDK is intentionally thin — one method per endpoint, no magical retries
or caching. Build on top with the abstractions your agent needs.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Literal, Optional

import httpx

DEFAULT_BASE_URL = "https://api.injectshield.dev"
USER_AGENT = "injectshield-python/0.1.0"

ContextKind = Literal[
    "git_commit",
    "web_content",
    "user_input",
    "file_content",
    "email",
    "tool_output",
    "unknown",
]
Sensitivity = Literal["low", "medium", "high"]


# ---- exceptions ----

class InjectShieldError(Exception):
    """Base class for all SDK errors."""
    def __init__(self, code: str, message: str, status: int | None = None):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message
        self.status = status


class AuthError(InjectShieldError):
    """Missing / invalid / revoked API key."""


class RateLimitError(InjectShieldError):
    """Per-second rate limit hit (100 req/s)."""


class QuotaExceededError(InjectShieldError):
    """Monthly request quota exhausted — upgrade tier."""


# ---- result type ----

@dataclass
class ScanResult:
    safe: bool
    confidence: float
    threat_type: str
    patterns_matched: list[str] = field(default_factory=list)
    cleaned_text: Optional[str] = None
    semantic_score: Optional[float] = None
    semantic_label: Optional[str] = None
    notes: list[str] = field(default_factory=list)
    request_id: str = ""

    @classmethod
    def _from_json(cls, obj: dict[str, Any]) -> "ScanResult":
        return cls(
            safe=bool(obj.get("safe")),
            confidence=float(obj.get("confidence", 0)),
            threat_type=str(obj.get("threat_type", "none")),
            patterns_matched=list(obj.get("patterns_matched", [])),
            cleaned_text=obj.get("cleaned_text"),
            semantic_score=obj.get("semantic_score"),
            semantic_label=obj.get("semantic_label"),
            notes=list(obj.get("notes", [])),
            request_id=str(obj.get("request_id", "")),
        )


def _raise_for_error(status: int, body: Any) -> None:
    if isinstance(body, dict) and "error" in body:
        err = body["error"] or {}
        code = str(err.get("code") or f"http_{status}")
        msg = str(err.get("message") or "Unknown error.")
    else:
        code = f"http_{status}"
        msg = str(body)[:200]
    if status == 401:
        raise AuthError(code, msg, status)
    if status == 402:
        raise QuotaExceededError(code, msg, status)
    if status == 429:
        raise RateLimitError(code, msg, status)
    raise InjectShieldError(code, msg, status)


def _build_scan_body(
    text: str,
    context: ContextKind,
    sensitivity: Sensitivity,
    return_cleaned: bool,
) -> dict[str, Any]:
    return {
        "text": text,
        "context": context,
        "options": {
            "sensitivity": sensitivity,
            "return_cleaned": return_cleaned,
        },
    }


# ---- sync client ----

class InjectShield:
    """Synchronous InjectShield client.

    Args:
        api_key: API key (`is_live_*`). Get one at https://injectshield.dev
        base_url: Override the API endpoint (e.g. for self-hosted deployments).
        timeout: Per-request timeout in seconds. Default 15.
    """

    def __init__(
        self,
        api_key: str,
        *,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = 15.0,
    ):
        if not api_key:
            raise ValueError("api_key is required")
        self._base = base_url.rstrip("/")
        self._client = httpx.Client(
            timeout=timeout,
            headers={
                "authorization": f"Bearer {api_key}",
                "user-agent": USER_AGENT,
            },
        )

    def __enter__(self) -> "InjectShield":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def close(self) -> None:
        self._client.close()

    # ---- methods ----

    def scan(
        self,
        text: str,
        *,
        context: ContextKind = "unknown",
        sensitivity: Sensitivity = "medium",
        return_cleaned: bool = True,
    ) -> ScanResult:
        """Scan a string for prompt-injection. Returns a ScanResult."""
        r = self._client.post(
            self._base + "/v1/scan",
            json=_build_scan_body(text, context, sensitivity, return_cleaned),
        )
        body = _safe_json(r)
        if r.status_code >= 400:
            _raise_for_error(r.status_code, body)
        return ScanResult._from_json(body)

    def scan_many(
        self,
        texts: Iterable[str],
        *,
        context: ContextKind = "unknown",
        sensitivity: Sensitivity = "medium",
        return_cleaned: bool = True,
    ) -> list[ScanResult]:
        """Convenience: scan a list serially. Use `AsyncInjectShield` for parallelism."""
        return [
            self.scan(t, context=context, sensitivity=sensitivity, return_cleaned=return_cleaned)
            for t in texts
        ]

    def usage(self) -> dict[str, Any]:
        """Current-month usage for the bearer key."""
        r = self._client.get(self._base + "/v1/usage")
        body = _safe_json(r)
        if r.status_code >= 400:
            _raise_for_error(r.status_code, body)
        return body

    def me(self) -> dict[str, Any]:
        """Key metadata (email, tier, monthly_limit, used_this_month)."""
        r = self._client.get(self._base + "/v1/keys/me")
        body = _safe_json(r)
        if r.status_code >= 400:
            _raise_for_error(r.status_code, body)
        return body

    def patterns(self) -> dict[str, Any]:
        """Public list of supported categories / contexts / sensitivities."""
        r = self._client.get(self._base + "/v1/patterns")
        body = _safe_json(r)
        if r.status_code >= 400:
            _raise_for_error(r.status_code, body)
        return body


# ---- async client ----

class AsyncInjectShield:
    """Asynchronous InjectShield client. Same API as `InjectShield`, awaitable."""

    def __init__(
        self,
        api_key: str,
        *,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = 15.0,
    ):
        if not api_key:
            raise ValueError("api_key is required")
        self._base = base_url.rstrip("/")
        self._client = httpx.AsyncClient(
            timeout=timeout,
            headers={
                "authorization": f"Bearer {api_key}",
                "user-agent": USER_AGENT,
            },
        )

    async def __aenter__(self) -> "AsyncInjectShield":
        return self

    async def __aexit__(self, *exc) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._client.aclose()

    async def scan(
        self,
        text: str,
        *,
        context: ContextKind = "unknown",
        sensitivity: Sensitivity = "medium",
        return_cleaned: bool = True,
    ) -> ScanResult:
        r = await self._client.post(
            self._base + "/v1/scan",
            json=_build_scan_body(text, context, sensitivity, return_cleaned),
        )
        body = _safe_json(r)
        if r.status_code >= 400:
            _raise_for_error(r.status_code, body)
        return ScanResult._from_json(body)

    async def usage(self) -> dict[str, Any]:
        r = await self._client.get(self._base + "/v1/usage")
        body = _safe_json(r)
        if r.status_code >= 400:
            _raise_for_error(r.status_code, body)
        return body

    async def me(self) -> dict[str, Any]:
        r = await self._client.get(self._base + "/v1/keys/me")
        body = _safe_json(r)
        if r.status_code >= 400:
            _raise_for_error(r.status_code, body)
        return body

    async def patterns(self) -> dict[str, Any]:
        r = await self._client.get(self._base + "/v1/patterns")
        body = _safe_json(r)
        if r.status_code >= 400:
            _raise_for_error(r.status_code, body)
        return body


def _safe_json(r: httpx.Response) -> Any:
    try:
        return r.json()
    except Exception:
        return {"error": {"code": f"http_{r.status_code}", "message": r.text[:200]}}

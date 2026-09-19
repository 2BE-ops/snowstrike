"""
SnowStrike AI v7.0 - Ghidra MCP HTTP Client

Thin HTTP client for communicating with a ghidra-mcp server.
Translates tool calls into REST requests and wraps responses as ToolResult
objects so the downstream execution pipeline (event bus, compaction, logging)
works unchanged.
"""

import logging
import os
import time
from dataclasses import field

import httpx

from tools.executor import ToolResult

logger = logging.getLogger(__name__)

# Default ghidra-mcp server URL (overridden by GHIDRA_MCP_URL env var)
_DEFAULT_URL = "http://ghidra-mcp:8089"

# Timeouts (seconds)
_DEFAULT_TIMEOUT = 120
_CONNECT_TIMEOUT = 10
_HEALTH_CHECK_RETRIES = 3
_HEALTH_CHECK_DELAY = 2.0


class GhidraMCPClient:
    """HTTP client for ghidra-mcp REST API.

    Usage:
        client = GhidraMCPClient()
        result = client.call("/decompile_function", "GET", {"name": "main"})
    """

    def __init__(self, base_url: str | None = None):
        self.base_url = (
            base_url
            or os.environ.get("GHIDRA_MCP_URL")
            or _DEFAULT_URL
        ).rstrip("/")
        self._client = httpx.Client(
            base_url=self.base_url,
            timeout=httpx.Timeout(_DEFAULT_TIMEOUT, connect=_CONNECT_TIMEOUT),
        )
        self._connected = False

    def close(self):
        """Close the underlying HTTP connection pool."""
        self._client.close()

    # ------------------------------------------------------------------
    # Health check
    # ------------------------------------------------------------------

    def check_connection(self, retries: int = _HEALTH_CHECK_RETRIES) -> bool:
        """Verify ghidra-mcp service is reachable.

        Returns True if /check_connection responds with 200, False otherwise.
        Retries with exponential backoff.
        """
        for attempt in range(1, retries + 1):
            try:
                resp = self._client.get(
                    "/check_connection",
                    timeout=httpx.Timeout(_CONNECT_TIMEOUT),
                )
                if resp.status_code == 200:
                    self._connected = True
                    logger.info("ghidra-mcp connected: %s", resp.text[:120])
                    return True
                logger.warning(
                    "ghidra-mcp health check attempt %d/%d: HTTP %d",
                    attempt, retries, resp.status_code,
                )
            except httpx.HTTPError as exc:
                logger.warning(
                    "ghidra-mcp health check attempt %d/%d failed: %s",
                    attempt, retries, exc,
                )
            if attempt < retries:
                time.sleep(_HEALTH_CHECK_DELAY * attempt)

        self._connected = False
        return False

    @property
    def is_connected(self) -> bool:
        return self._connected

    # ------------------------------------------------------------------
    # Core RPC call
    # ------------------------------------------------------------------

    def call(
        self,
        endpoint: str,
        method: str = "GET",
        params: dict | None = None,
        timeout: int | None = None,
    ) -> ToolResult:
        """Make an HTTP request to ghidra-mcp and wrap the response as a ToolResult.

        Args:
            endpoint: REST path (e.g. "/decompile_function").
            method: HTTP method ("GET" or "POST").
            params: Query params (GET) or form/JSON body (POST).
            timeout: Per-call timeout in seconds (default: _DEFAULT_TIMEOUT).

        Returns:
            ToolResult with stdout=response body, return_code mapped from HTTP status.
        """
        params = params or {}
        effective_timeout = httpx.Timeout(
            timeout or _DEFAULT_TIMEOUT, connect=_CONNECT_TIMEOUT,
        )
        tool_name = f"ghidra_{endpoint.strip('/').replace('/', '_')}"
        command_display = f"{method} {self.base_url}{endpoint}"
        start = time.monotonic()

        try:
            if method.upper() == "POST":
                resp = self._client.post(
                    endpoint,
                    data=params,
                    timeout=effective_timeout,
                )
            else:
                resp = self._client.get(
                    endpoint,
                    params=params,
                    timeout=effective_timeout,
                )

            duration = time.monotonic() - start
            body = resp.text

            # Map HTTP status to return code
            if 200 <= resp.status_code < 300:
                return_code = 0
                success = True
                stderr = ""
            elif 400 <= resp.status_code < 500:
                return_code = 1
                success = False
                stderr = f"HTTP {resp.status_code}: client error"
            else:
                return_code = 2
                success = False
                stderr = f"HTTP {resp.status_code}: server error"

            return ToolResult(
                tool_name=tool_name,
                command=command_display,
                stdout=body,
                stderr=stderr,
                return_code=return_code,
                duration_seconds=round(duration, 2),
                success=success,
                timed_out=False,
            )

        except httpx.TimeoutException as exc:
            duration = time.monotonic() - start
            return ToolResult(
                tool_name=tool_name,
                command=command_display,
                stdout="",
                stderr=f"Request timed out after {timeout or _DEFAULT_TIMEOUT}s: {exc}",
                return_code=124,
                duration_seconds=round(duration, 2),
                success=False,
                timed_out=True,
            )
        except httpx.HTTPError as exc:
            duration = time.monotonic() - start
            return ToolResult(
                tool_name=tool_name,
                command=command_display,
                stdout="",
                stderr=f"HTTP error: {exc}",
                return_code=1,
                duration_seconds=round(duration, 2),
                success=False,
                timed_out=False,
            )


# ---------------------------------------------------------------------------
# Module-level singleton (lazy-initialized)
# ---------------------------------------------------------------------------

_instance: GhidraMCPClient | None = None


def get_ghidra_client() -> GhidraMCPClient:
    """Return (and lazily create) the module-level GhidraMCPClient singleton."""
    global _instance
    if _instance is None:
        _instance = GhidraMCPClient()
    return _instance

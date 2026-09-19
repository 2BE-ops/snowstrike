"""Handler for http_request flow steps."""

from __future__ import annotations

import logging
import re
import time
from urllib.parse import urlparse

from flows.schema import StepDefinition, StepResult, StepStatus

logger = logging.getLogger(__name__)

_MAX_RESPONSE_SIZE = 10 * 1024 * 1024  # 10MB
_DEFAULT_TIMEOUT = 30

# Blocked URL patterns (cloud metadata, internal abuse)
_BLOCKED_HOSTS = {
    "169.254.169.254",
    "metadata.google.internal",
    "metadata.internal",
}

_BLOCKED_HOST_PATTERNS = [
    re.compile(r"^169\.254\."),
    re.compile(r"^fd[0-9a-f]{2}:"),  # IPv6 link-local
]


def _is_url_allowed(url: str) -> tuple[bool, str]:
    """Check if URL is allowed. Returns (allowed, reason)."""
    try:
        parsed = urlparse(url)
        host = parsed.hostname or ""
    except Exception:
        return False, "Invalid URL"

    if host in _BLOCKED_HOSTS:
        return False, f"Blocked host: {host} (cloud metadata endpoint)"

    for pattern in _BLOCKED_HOST_PATTERNS:
        if pattern.match(host):
            return False, f"Blocked host pattern: {host}"

    if not parsed.scheme or parsed.scheme not in ("http", "https"):
        return False, f"Invalid scheme: {parsed.scheme} (must be http or https)"

    return True, ""


class HttpRequestStepHandler:
    """Execute HTTP requests with security restrictions."""

    def execute(
        self,
        step: StepDefinition,
        context: dict,
        workspace: str,
        engagement_id: int = 0,
    ) -> StepResult:
        from flows.template_env import render_template
        import httpx

        t0 = time.monotonic()

        # Render URL and body templates
        try:
            rendered_url = render_template(step.url, context)
            rendered_body = render_template(step.body, context) if step.body else None
            rendered_headers = {}
            for k, v in step.headers.items():
                rendered_headers[k] = render_template(str(v), context) if isinstance(v, str) else str(v)
        except Exception as exc:
            elapsed = time.monotonic() - t0
            return StepResult(
                step_id=step.id,
                status=StepStatus.FAILED.value,
                success=False,
                duration_seconds=elapsed,
                errors=[f"Template render failed: {exc}"],
            )

        # URL allowlist check
        allowed, reason = _is_url_allowed(rendered_url)
        if not allowed:
            elapsed = time.monotonic() - t0
            return StepResult(
                step_id=step.id,
                status=StepStatus.FAILED.value,
                success=False,
                duration_seconds=elapsed,
                errors=[f"URL blocked: {reason}"],
            )

        # Execute request
        timeout = step.timeout or _DEFAULT_TIMEOUT
        try:
            with httpx.Client(timeout=timeout, follow_redirects=True, verify=True) as client:
                response = client.request(
                    method=step.method.upper(),
                    url=rendered_url,
                    headers=rendered_headers,
                    content=rendered_body,
                )
        except Exception as exc:
            elapsed = time.monotonic() - t0
            return StepResult(
                step_id=step.id,
                status=StepStatus.FAILED.value,
                success=False,
                duration_seconds=elapsed,
                errors=[f"HTTP request failed: {exc}"],
            )

        elapsed = time.monotonic() - t0

        # Check response size
        body_text = ""
        if step.capture_response:
            body_bytes = response.content
            if len(body_bytes) > _MAX_RESPONSE_SIZE:
                body_text = body_bytes[:_MAX_RESPONSE_SIZE].decode("utf-8", errors="replace")
            else:
                body_text = response.text

        # Check expected status
        expected = step.expected_status or [200, 201, 204]
        success = response.status_code in expected

        output = {
            "status_code": response.status_code,
            "body": body_text,
            "headers": dict(response.headers),
            "url": str(response.url),
            "method": step.method.upper(),
        }

        errors = []
        if not success:
            errors.append(f"Unexpected status {response.status_code} (expected {expected})")

        return StepResult(
            step_id=step.id,
            status=StepStatus.COMPLETED.value if success else StepStatus.FAILED.value,
            success=success,
            output=output,
            duration_seconds=elapsed,
            errors=errors,
        )

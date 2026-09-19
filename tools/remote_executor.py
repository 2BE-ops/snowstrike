"""
RemoteToolExecutor — HTTP proxy to the privileged tool-runner service.

Same public interface as ToolExecutor so callers can use either transparently.
Forwards run() calls to the tool-runner's POST /execute endpoint.
"""

import logging
import os
import shlex
from typing import Callable, Optional

import httpx

from tools.executor import ToolResult

logger = logging.getLogger(__name__)


class RemoteToolExecutor:
    """Execute security tools via the remote tool-runner HTTP service.

    Drop-in replacement for ToolExecutor — same run() signature and return type.
    The on_output streaming callback is not supported over HTTP and is silently
    ignored (the tool-runner executes synchronously and returns the full result).
    """

    def __init__(
        self,
        tool_runner_url: str,
        default_timeout: int = 300,
        max_output_bytes: int = 10 * 1024 * 1024,
    ):
        self.tool_runner_url = tool_runner_url.rstrip("/")
        self.default_timeout = default_timeout
        self.max_output_bytes = max_output_bytes
        self._auth_token = os.environ.get("TOOL_RUNNER_AUTH_TOKEN", "")
        if not self._auth_token:
            logger.warning("TOOL_RUNNER_AUTH_TOKEN not set — requests will be rejected by tool-runner")

    def run(
        self,
        tool_name: str,
        args: list[str],
        timeout: Optional[int] = None,
        cwd: Optional[str] = None,
        env: Optional[dict] = None,
        stdin_data: Optional[str] = None,
        on_output: Optional[Callable[[str], None]] = None,
    ) -> ToolResult:
        """
        Execute a tool via the remote tool-runner service.

        Same interface as ToolExecutor.run(). The on_output callback is not
        supported over HTTP and is silently ignored.
        """
        effective_timeout = timeout if timeout is not None else self.default_timeout

        payload = {
            "tool_name": tool_name,
            "args": args,
            "timeout": effective_timeout,
            "cwd": cwd,
            "env": env,
            "stdin_data": stdin_data,
        }

        logger.info(
            "Remote execute: %s %s (timeout=%ds)",
            tool_name, shlex.join(args), effective_timeout,
        )

        # HTTP timeout = tool timeout + 30s grace for network overhead
        http_timeout = effective_timeout + 30
        headers = {}
        if self._auth_token:
            headers["Authorization"] = f"Bearer {self._auth_token}"

        try:
            with httpx.Client(timeout=http_timeout) as client:
                resp = client.post(
                    f"{self.tool_runner_url}/execute",
                    json=payload,
                    headers=headers,
                )
                resp.raise_for_status()
                data = resp.json()

            result = ToolResult(
                tool_name=data["tool_name"],
                command=data["command"],
                stdout=data["stdout"],
                stderr=data["stderr"],
                return_code=data["return_code"],
                duration_seconds=data["duration_seconds"],
                success=data["success"],
                timed_out=data["timed_out"],
                attempt=data.get("attempt", 1),
                max_attempts=data.get("max_attempts", 1),
                metadata=data.get("metadata", {}),
                outcome_kind=data.get("outcome_kind", ""),
                signal_detected=data.get("signal_detected", False),
            )

            log_fn = logger.info if result.success else logger.warning
            log_fn(
                "Remote tool %s %s in %.2fs (exit=%d)",
                tool_name,
                "completed" if result.success else "failed",
                result.duration_seconds,
                result.return_code,
            )

            return result

        except httpx.TimeoutException:
            logger.error("Remote tool %s timed out (HTTP timeout=%ds)", tool_name, http_timeout)
            return ToolResult(
                tool_name=tool_name,
                command=shlex.join([tool_name] + args),
                stdout="",
                stderr=f"Tool runner HTTP request timed out after {http_timeout}s",
                return_code=-1,
                duration_seconds=float(http_timeout),
                success=False,
                timed_out=True,
            )

        except httpx.HTTPStatusError as exc:
            logger.error("Remote tool %s HTTP error: %s", tool_name, exc)
            return ToolResult(
                tool_name=tool_name,
                command=shlex.join([tool_name] + args),
                stdout="",
                stderr=f"Tool runner HTTP error: {exc.response.status_code} {exc.response.text[:500]}",
                return_code=-1,
                duration_seconds=0.0,
                success=False,
            )

        except Exception as exc:
            logger.error("Remote tool %s connection error: %s", tool_name, exc)
            return ToolResult(
                tool_name=tool_name,
                command=shlex.join([tool_name] + args),
                stdout="",
                stderr=f"Tool runner connection error: {exc}",
                return_code=-1,
                duration_seconds=0.0,
                success=False,
            )

    def check_available(self, tool_name: str) -> bool:
        """Check if the tool-runner service is reachable."""
        try:
            with httpx.Client(timeout=5) as client:
                resp = client.get(f"{self.tool_runner_url}/health")
                return resp.status_code == 200
        except Exception:
            return False

    def check_tools_status(self, tool_names: list[str]) -> dict[str, bool]:
        """Remote availability check — returns True for all if service is up."""
        service_up = self.check_available("")
        return {name: service_up for name in tool_names}

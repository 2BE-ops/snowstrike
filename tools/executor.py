"""
Direct subprocess tool executor for security tools.
No Flask, no HTTP. Just subprocess calls with timeout, retry, and logging.

v7.1: Streaming execution via Popen with live line-by-line output to event bus.
v7.2: Richer outcome classification (OutcomeKind) and signal detection.
"""

import logging
import os
import re
import select
import shlex
import shutil
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Outcome classification
# ---------------------------------------------------------------------------

class OutcomeKind(str, Enum):
    """Rich outcome classification for tool executions.

    success           – clean exit (rc=0), output present
    partial_success   – nonzero exit but actionable output was produced
    timeout_with_signal – timed out but produced useful output before deadline
    empty_result      – completed but produced no actionable output
    wrapper_error     – command-build or flag mismatch (usage error from binary)
    env_error         – binary not found, permission denied, OS error
    interactive_hang  – tool appears to be waiting for interactive input
    target_refused    – target explicitly refused connection / unreachable
    skipped           – pre-execution gate blocked the run
    """
    SUCCESS = "success"
    PARTIAL_SUCCESS = "partial_success"
    TIMEOUT_WITH_SIGNAL = "timeout_with_signal"
    EMPTY_RESULT = "empty_result"
    WRAPPER_ERROR = "wrapper_error"
    ENV_ERROR = "env_error"
    INTERACTIVE_HANG = "interactive_hang"
    TARGET_REFUSED = "target_refused"
    SKIPPED = "skipped"


# Patterns that indicate a usage/flag mismatch from the binary
_WRAPPER_ERROR_PATTERNS = [
    re.compile(r"unknown flag|unknown option|unrecognized option", re.I),
    re.compile(r"unrecognized arguments", re.I),
    re.compile(r"invalid.*flag|invalid.*option", re.I),
    re.compile(r"error:.*usage|usage:", re.I),
    re.compile(r"bad option|illegal option", re.I),
    re.compile(r"flag provided but not defined", re.I),
    re.compile(r"cannot use\s+[-\w]+\s+twice", re.I),
]

# Patterns that indicate the tool produced actionable security signal
_SIGNAL_PATTERNS = [
    re.compile(r"\d+/tcp\s+open", re.I),           # nmap port open
    re.compile(r"status:\s*\d{3}", re.I),           # HTTP status code
    re.compile(r"\[2\d{2}\]|\[3\d{2}\]", re.I),    # [200], [301], etc
    re.compile(r"^[123]\d{2}\s+(GET|POST|PUT|HEAD)", re.M),  # feroxbuster/gobuster HTTP lines
    re.compile(r"OSVDB-|CVE-\d{4}", re.I),          # nikto/nuclei findings
    re.compile(r"[1-9]\d*\s+host(?:s)?\s+up", re.I),  # nmap hosts up (positive count only)
    re.compile(r"\bdirectory listing\b", re.I),       # explicit directory exposure
    re.compile(r"\b(?:discovered|found)\b.{0,40}\b(?:subdomain|vhost|directory|endpoint)\b", re.I),
    re.compile(r"\b(?:valid|confirmed|cracked|dumped|discovered|found)\b.{0,60}\b(?:credential|credentials|password|hash(?:es)?)\b", re.I),
    re.compile(r"\b(?:credential|credentials|password|hash(?:es)?)\b.{0,60}\b(?:valid|confirmed|cracked|dumped|discovered|found)\b", re.I),
    re.compile(r"-----BEGIN", re.I),                  # certificate/key material
    re.compile(r"SQL injection|XSS|SSTI|LFI|RFI", re.I),  # vuln types
]

# Patterns that indicate empty/no-signal output
_NO_SIGNAL_PATTERNS = [
    re.compile(r"0 host(?:s)? up", re.I),
    re.compile(r"no results", re.I),
    re.compile(r"nothing found", re.I),
    re.compile(r"^$"),
]

# Patterns indicating target-side refusal
_TARGET_REFUSED_PATTERNS = [
    re.compile(r"connection refused", re.I),
    re.compile(r"host unreachable|no route to host", re.I),
    re.compile(r"name or service not known", re.I),
    re.compile(r"ssl.*handshake.*fail", re.I),
]


def classify_outcome(result: "ToolResult") -> OutcomeKind:
    """Classify a ToolResult into a rich outcome kind.

    Called automatically after execution to set result.outcome_kind.
    """
    combined = (result.stdout or "") + "\n" + (result.stderr or "")

    # Env errors: binary not found, permission denied
    if result.return_code == 127:
        return OutcomeKind.ENV_ERROR
    if result.return_code == 126:
        return OutcomeKind.ENV_ERROR

    # Check for wrapper/flag mismatch errors
    if result.return_code != 0:
        for pat in _WRAPPER_ERROR_PATTERNS:
            if pat.search(combined):
                return OutcomeKind.WRAPPER_ERROR

    # Detect signal presence
    has_signal = any(pat.search(combined) for pat in _SIGNAL_PATTERNS)
    has_no_signal = (
        not result.stdout.strip()
        or any(pat.search(combined) for pat in _NO_SIGNAL_PATTERNS)
    )
    target_refused = any(pat.search(combined) for pat in _TARGET_REFUSED_PATTERNS)

    # Check for interactive hang patterns BEFORE timeout classification
    # so msfconsole/gdb prompts don't fall through to empty_result
    interactive_markers = [
        "msf>", "msf6>", "msf6 >", "meterpreter>", "(gdb)",
        "pdb>", ">>> ", "mysql>", "psql>", "irb(",
    ]
    lower_combined = combined.lower()
    looks_interactive = any(m.lower() in lower_combined for m in interactive_markers)
    if (result.timed_out or result.duration_seconds > 60) and looks_interactive:
        return OutcomeKind.INTERACTIVE_HANG

    # Timeout handling
    if result.timed_out:
        return OutcomeKind.TIMEOUT_WITH_SIGNAL if has_signal else OutcomeKind.EMPTY_RESULT

    # Explicit target-side refusal with no useful findings
    if target_refused and not has_signal:
        return OutcomeKind.TARGET_REFUSED

    # Clean exit
    if result.return_code == 0:
        if has_signal:
            return OutcomeKind.SUCCESS
        if has_no_signal:
            return OutcomeKind.EMPTY_RESULT
        if result.stdout.strip():
            return OutcomeKind.SUCCESS
        return OutcomeKind.EMPTY_RESULT

    # Nonzero exit but produced useful output
    if has_signal:
        return OutcomeKind.PARTIAL_SUCCESS

    # Secondary interactive hang check for tools with no output at all
    if result.duration_seconds > 60 and not result.stdout.strip():
        return OutcomeKind.INTERACTIVE_HANG

    # Empty/no-signal with nonzero exit
    if has_no_signal:
        return OutcomeKind.EMPTY_RESULT

    # Generic failure — leave as partial if there's any output
    if result.stdout.strip():
        return OutcomeKind.PARTIAL_SUCCESS

    return OutcomeKind.EMPTY_RESULT


def detect_signal(result: "ToolResult") -> bool:
    """Return True if the tool output contains actionable security signal."""
    combined = (result.stdout or "") + "\n" + (result.stderr or "")
    return any(pat.search(combined) for pat in _SIGNAL_PATTERNS)


@dataclass
class ToolResult:
    """Structured result from a tool execution.

    v7.2: Added outcome_kind and signal_detected for richer classification.
    """
    tool_name: str
    command: str
    stdout: str
    stderr: str
    return_code: int
    duration_seconds: float
    success: bool
    timed_out: bool = False
    attempt: int = 1
    max_attempts: int = 1
    metadata: dict = field(default_factory=dict)
    outcome_kind: str = ""         # Set by classify_outcome() after execution
    signal_detected: bool = False  # Set by detect_signal() after execution

    def __post_init__(self):
        """Auto-classify outcome if not already set."""
        if not self.outcome_kind:
            self.outcome_kind = classify_outcome(self).value
        if not self.signal_detected:
            self.signal_detected = detect_signal(self)

    def to_dict(self) -> dict:
        """Serialize to dictionary for JSON output."""
        return {
            "tool_name": self.tool_name,
            "command": self.command,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "return_code": self.return_code,
            "duration_seconds": round(self.duration_seconds, 3),
            "success": self.success,
            "timed_out": self.timed_out,
            "attempt": self.attempt,
            "max_attempts": self.max_attempts,
            "metadata": self.metadata,
            "outcome_kind": self.outcome_kind,
            "signal_detected": self.signal_detected,
        }

    @property
    def output(self) -> str:
        """Return stdout if available, otherwise stderr."""
        return self.stdout.strip() if self.stdout.strip() else self.stderr.strip()


class ToolExecutor:
    """Execute security tools via subprocess with timeout, retry, and logging.

    Requires root privileges. All tool subprocesses inherit elevated permissions
    so raw sockets, packet capture, and privileged operations work without fallbacks.

    v7.1: Supports streaming execution with live output via on_output callback
    and event bus integration.
    """

    def __init__(self, default_timeout: int = 300, max_output_bytes: int = 10 * 1024 * 1024):
        self.default_timeout = default_timeout
        self.max_output_bytes = max_output_bytes

    def _prepare_command(self, tool_name: str, args: list[str]) -> tuple[list[str], str]:
        """Prepare the command list and apply nmap unprivileged fixups."""
        if tool_name == "nmap" and os.geteuid() != 0:
            if "--unprivileged" not in args:
                args = ["--unprivileged"] + args
            raw_flags = {"-O", "-sU", "-sA", "-sF", "-sX", "-sN", "-sM", "--traceroute", "-sS"}
            args = [a for a in args if a not in raw_flags]
            if "-sT" not in args:
                args = ["-sT"] + args

        cmd = [tool_name] + args
        return cmd, shlex.join(cmd)

    # Environment variables that must never leak to tool subprocesses
    _STRIPPED_ENV_KEYS = {
        "ANTHROPIC_API_KEY", "XAI_API_KEY", "OPENAI_API_KEY",
        "TOOL_RUNNER_AUTH_TOKEN", "AWS_SECRET_ACCESS_KEY",
        "AZURE_CLIENT_SECRET", "GCP_SERVICE_ACCOUNT_KEY",
    }
    # Variables that callers may not override via the env parameter
    _DENIED_OVERRIDE_KEYS = {
        "LD_PRELOAD", "LD_LIBRARY_PATH", "PYTHONPATH", "PYTHONSTARTUP",
    }

    def _prepare_env(self, env: Optional[dict]) -> dict:
        """Build a sanitised environment for tool subprocesses.

        - Always strips API keys and secrets from the inherited environment.
        - Rejects dangerous overrides (LD_PRELOAD, etc.) from caller-supplied env.
        """
        run_env = os.environ.copy()
        # Strip secrets from inherited environment
        for key in self._STRIPPED_ENV_KEYS:
            run_env.pop(key, None)
        if env:
            denied = set(env.keys()) & self._DENIED_OVERRIDE_KEYS
            if denied:
                logger.warning("Rejected dangerous env overrides: %s", denied)
            run_env.update({k: v for k, v in env.items() if k not in self._DENIED_OVERRIDE_KEYS})
        return run_env

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
        Execute a tool with optional live streaming output.

        Args:
            tool_name: Name/path of the binary to execute.
            args: List of command-line arguments.
            timeout: Timeout in seconds (overrides default_timeout).
            cwd: Working directory for the command.
            env: Environment variables (merged with current env if provided).
            stdin_data: Optional string to pass to the process via stdin.
            on_output: Callback invoked with each line of stdout as it arrives.
                       Enables real-time streaming to event bus / UI.

        Returns:
            ToolResult with execution details.
        """
        effective_timeout = timeout if timeout is not None else self.default_timeout
        cmd, cmd_str = self._prepare_command(tool_name, args)
        run_env = self._prepare_env(env)

        logger.info("Executing: %s (timeout=%ds, streaming=%s)", cmd_str, effective_timeout, bool(on_output))

        start_time = time.monotonic()

        # Use streaming (Popen) when on_output callback is provided
        if on_output and stdin_data is None:
            return self._run_streaming(
                cmd, cmd_str, tool_name, effective_timeout, cwd, run_env, on_output, start_time
            )

        # Fallback: blocking subprocess.run (for stdin_data or no streaming)
        return self._run_blocking(
            cmd, cmd_str, tool_name, effective_timeout, cwd, run_env, stdin_data, start_time
        )

    def _run_streaming(
        self,
        cmd: list[str],
        cmd_str: str,
        tool_name: str,
        timeout: int,
        cwd: Optional[str],
        env: Optional[dict],
        on_output: Callable[[str], None],
        start_time: float,
    ) -> ToolResult:
        """Execute with Popen, streaming stdout line-by-line via on_output callback."""
        stdout_lines = []
        stderr_data = ""
        return_code = -1
        timed_out = False

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=cwd,
                env=env,
                bufsize=1,  # line-buffered
                start_new_session=True,  # enables process-group kill on timeout
            )

            # Read stderr in a background thread to prevent deadlocks
            stderr_chunks = []
            def _read_stderr():
                try:
                    data = proc.stderr.read()
                    if data:
                        stderr_chunks.append(data[:self.max_output_bytes])
                except Exception:
                    pass

            stderr_thread = threading.Thread(target=_read_stderr, daemon=True)
            stderr_thread.start()

            # Stream stdout line by line
            total_bytes = 0
            deadline = start_time + timeout

            for line in proc.stdout:
                total_bytes += len(line)
                if total_bytes > self.max_output_bytes:
                    stdout_lines.append("... (output truncated)")
                    break

                stripped = line.rstrip("\n\r")
                stdout_lines.append(stripped)

                # Fire the streaming callback
                try:
                    on_output(stripped)
                except Exception as e:
                    logger.debug("on_output callback error: %s", e)

                # Check timeout
                if time.monotonic() > deadline:
                    timed_out = True
                    logger.warning("Tool %s timed out after %ds (streaming)", tool_name, timeout)
                    proc.kill()
                    break

            # Wait for process to finish (with a grace period)
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                # Kill the entire process group to clean up child processes
                try:
                    os.killpg(os.getpgid(proc.pid), 9)
                except (ProcessLookupError, PermissionError):
                    proc.kill()
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    logger.error("Process %d could not be killed — potential zombie", proc.pid)
                timed_out = True

            stderr_thread.join(timeout=3)
            return_code = proc.returncode if proc.returncode is not None else -1
            stderr_data = "".join(stderr_chunks)

        except FileNotFoundError:
            stderr_data = f"Tool binary not found: {tool_name}"
            return_code = 127
            logger.error("Tool binary not found: %s", tool_name)

        except PermissionError:
            stderr_data = f"Permission denied executing: {tool_name}"
            return_code = 126
            logger.error("Permission denied: %s", tool_name)

        except OSError as exc:
            stderr_data = f"OS error executing {tool_name}: {exc}"
            return_code = -1
            logger.error("OS error executing %s: %s", tool_name, exc)

        duration = time.monotonic() - start_time
        success = return_code == 0 and not timed_out
        stdout = "\n".join(stdout_lines)

        result = ToolResult(
            tool_name=tool_name, command=cmd_str,
            stdout=stdout, stderr=stderr_data,
            return_code=return_code, duration_seconds=duration,
            success=success, timed_out=timed_out,
        )

        log_fn = logger.info if success else logger.warning
        log_fn("Tool %s %s in %.2fs (exit=%d, streamed=%d lines)",
               tool_name, "completed" if success else "failed",
               duration, return_code, len(stdout_lines))

        return result

    def _run_blocking(
        self,
        cmd: list[str],
        cmd_str: str,
        tool_name: str,
        timeout: int,
        cwd: Optional[str],
        env: Optional[dict],
        stdin_data: Optional[str],
        start_time: float,
    ) -> ToolResult:
        """Execute with blocking subprocess.run (original behavior)."""
        timed_out = False
        stdout = ""
        stderr = ""
        return_code = -1

        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=timeout, cwd=cwd, env=env, input=stdin_data,
            )
            stdout = proc.stdout[:self.max_output_bytes] if proc.stdout else ""
            stderr = proc.stderr[:self.max_output_bytes] if proc.stderr else ""
            return_code = proc.returncode

        except subprocess.TimeoutExpired as exc:
            timed_out = True
            stdout = exc.stdout.decode("utf-8", errors="replace") if exc.stdout else ""
            stderr = exc.stderr.decode("utf-8", errors="replace") if exc.stderr else ""
            stdout = stdout[:self.max_output_bytes]
            stderr = stderr[:self.max_output_bytes]
            return_code = -1
            logger.warning("Tool %s timed out after %ds", tool_name, timeout)

        except FileNotFoundError:
            stderr = f"Tool binary not found: {tool_name}"
            return_code = 127
            logger.error("Tool binary not found: %s", tool_name)

        except PermissionError:
            stderr = f"Permission denied executing: {tool_name}"
            return_code = 126
            logger.error("Permission denied: %s", tool_name)

        except OSError as exc:
            stderr = f"OS error executing {tool_name}: {exc}"
            return_code = -1
            logger.error("OS error executing %s: %s", tool_name, exc)

        duration = time.monotonic() - start_time
        success = return_code == 0 and not timed_out

        result = ToolResult(
            tool_name=tool_name, command=cmd_str,
            stdout=stdout, stderr=stderr,
            return_code=return_code, duration_seconds=duration,
            success=success, timed_out=timed_out,
        )

        log_fn = logger.info if success else logger.warning
        log_fn("Tool %s %s in %.2fs (exit=%d, timed_out=%s)",
               tool_name, "completed" if success else "failed",
               duration, return_code, timed_out)

        return result

    def run_parallel(
        self,
        tasks: list[dict],
        max_workers: int = 4,
    ) -> list[ToolResult]:
        """Execute multiple tools concurrently.

        Args:
            tasks: List of dicts with keys: tool_name, args, and optionally
                   timeout, cwd, env, on_output.
            max_workers: Maximum concurrent tool executions.

        Returns:
            List of ToolResults in the same order as input tasks.
        """
        results = [None] * len(tasks)

        def _run_one(index: int, task: dict) -> tuple[int, ToolResult]:
            result = self.run(
                tool_name=task["tool_name"],
                args=task.get("args", []),
                timeout=task.get("timeout"),
                cwd=task.get("cwd"),
                env=task.get("env"),
                on_output=task.get("on_output"),
            )
            return index, result

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(_run_one, i, task): i
                for i, task in enumerate(tasks)
            }
            for future in as_completed(futures):
                try:
                    idx, result = future.result()
                    results[idx] = result
                except Exception as e:
                    idx = futures[future]
                    task = tasks[idx]
                    results[idx] = ToolResult(
                        tool_name=task.get("tool_name", "unknown"),
                        command="",
                        stdout="",
                        stderr=f"Parallel execution error: {e}",
                        return_code=-1,
                        duration_seconds=0,
                        success=False,
                    )

        return results

    def run_with_retry(
        self,
        tool_name: str,
        args: list[str],
        max_retries: int = 2,
        timeout: Optional[int] = None,
        cwd: Optional[str] = None,
        env: Optional[dict] = None,
        retry_delay: float = 2.0,
        retry_on_timeout: bool = True,
    ) -> ToolResult:
        """Execute with automatic retry on failure."""
        total_attempts = 1 + max_retries
        last_result = None

        for attempt in range(1, total_attempts + 1):
            logger.info("Attempt %d/%d for %s", attempt, total_attempts, tool_name)

            result = self.run(
                tool_name=tool_name, args=args,
                timeout=timeout, cwd=cwd, env=env,
            )
            result.attempt = attempt
            result.max_attempts = total_attempts
            last_result = result

            if result.success:
                return result

            if result.timed_out and not retry_on_timeout:
                logger.info("Not retrying %s after timeout (retry_on_timeout=False)", tool_name)
                return result

            if result.return_code in (126, 127):
                logger.info("Not retrying %s (exit code %d is not retryable)", tool_name, result.return_code)
                return result

            if attempt < total_attempts:
                logger.info("Retrying %s in %.1fs...", tool_name, retry_delay)
                time.sleep(retry_delay)

        return last_result

    def check_available(self, tool_name: str) -> bool:
        """Check if a tool binary exists on PATH using shutil.which."""
        return shutil.which(tool_name) is not None

    def check_tools_status(self, tool_names: list[str]) -> dict[str, bool]:
        """Check availability of multiple tools."""
        return {name: self.check_available(name) for name in tool_names}

    def run_pipeline(
        self,
        steps: list[dict],
        stop_on_failure: bool = True,
    ) -> list[ToolResult]:
        """Run a sequence of tool commands."""
        results = []
        for i, step in enumerate(steps):
            logger.info("Pipeline step %d/%d: %s", i + 1, len(steps), step.get("tool_name"))
            result = self.run(
                tool_name=step["tool_name"],
                args=step.get("args", []),
                timeout=step.get("timeout"),
                cwd=step.get("cwd"),
                env=step.get("env"),
            )
            results.append(result)
            if not result.success and stop_on_failure:
                logger.warning("Pipeline stopped at step %d due to failure", i + 1)
                break
        return results


# ---------------------------------------------------------------------------
# Factory — returns RemoteToolExecutor when SNOWSTRIKE_TOOL_RUNNER_URL is set,
# otherwise returns the local ToolExecutor.
# ---------------------------------------------------------------------------

def create_executor(**kwargs) -> "ToolExecutor":
    """Create the appropriate executor based on environment configuration.

    If SNOWSTRIKE_TOOL_RUNNER_URL is set, returns a RemoteToolExecutor that
    proxies tool calls to the privileged tool-runner container over HTTP.
    Otherwise, returns a local ToolExecutor for direct subprocess execution.
    """
    tool_runner_url = os.environ.get("SNOWSTRIKE_TOOL_RUNNER_URL", "")
    if tool_runner_url:
        from tools.remote_executor import RemoteToolExecutor
        logger.info("Using RemoteToolExecutor → %s", tool_runner_url)
        return RemoteToolExecutor(tool_runner_url=tool_runner_url, **kwargs)
    logger.info("Using local ToolExecutor")
    return ToolExecutor(**kwargs)

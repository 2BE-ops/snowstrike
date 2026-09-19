"""
SnowStrike Tool Runner — Privileged FastAPI service wrapping ToolExecutor.

Runs inside the privileged container, receives execution requests from the
unprivileged orchestrator container over HTTP, and delegates to the local
ToolExecutor (which calls subprocess.Popen on security tool binaries).

Usage:
    python -m tool_runner.server
    python -m tool_runner.server --port 9090
"""

import argparse
import hmac
import logging
import os
import secrets
import shlex
import sys

# Ensure project root is on path so `tools.executor` is importable
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from fastapi import FastAPI, Request, HTTPException
from pydantic import BaseModel
from typing import Optional

from tools.executor import ToolExecutor, ToolResult

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler()],
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Authentication — require a shared bearer token set via environment variable.
# If TOOL_RUNNER_AUTH_TOKEN is not set, generate a random one and log it once
# so the operator can configure the orchestrator side.
# ---------------------------------------------------------------------------
AUTH_TOKEN: str = os.environ.get("TOOL_RUNNER_AUTH_TOKEN", "")
if not AUTH_TOKEN:
    AUTH_TOKEN = secrets.token_urlsafe(32)
    logger.warning(
        "TOOL_RUNNER_AUTH_TOKEN not set — generated ephemeral token: %s", AUTH_TOKEN
    )

app = FastAPI(title="SnowStrike Tool Runner", version="1.0.0")


@app.middleware("http")
async def _auth_middleware(request: Request, call_next):
    """Reject requests without a valid Bearer token (except /health)."""
    if request.url.path == "/health":
        return await call_next(request)
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing Bearer token")
    token = auth_header[len("Bearer "):]
    if not hmac.compare_digest(token, AUTH_TOKEN):
        raise HTTPException(status_code=403, detail="Invalid Bearer token")
    return await call_next(request)


# ---------------------------------------------------------------------------
# Tool-name allowlist — only permit known security tool binaries.
# ---------------------------------------------------------------------------
_ALLOWED_TOOLS: set[str] = {
    # Recon & enumeration
    "nmap", "masscan", "rustscan", "enum4linux", "enum4linux-ng", "rpcclient",
    "smbclient", "smbmap", "crackmapexec", "netexec", "nbtscan", "onesixtyone",
    "snmpwalk", "snmpcheck", "ldapsearch", "dnsrecon", "dnsenum", "dig",
    "fierce", "amass", "subfinder", "assetfinder", "httprobe", "httpx",
    "whatweb", "wafw00f", "wpscan", "droopescan", "joomscan",
    # Web scanning
    "nikto", "nuclei", "feroxbuster", "gobuster", "dirb", "dirsearch",
    "ffuf", "wfuzz", "sqlmap", "dalfox", "xsstrike", "arjun",
    "commix", "ssrfmap", "tplmap",
    # Exploitation
    "msfconsole", "msfvenom", "searchsploit", "hydra", "medusa",
    "john", "hashcat", "cewl", "crunch",
    # Post-exploitation
    "impacket-smbexec", "impacket-wmiexec", "impacket-psexec",
    "impacket-atexec", "impacket-dcomexec", "impacket-secretsdump",
    "impacket-getTGT", "impacket-getST", "impacket-GetNPUsers",
    "impacket-GetUserSPNs", "impacket-ntlmrelayx", "impacket-smbserver",
    "evil-winrm", "bloodhound-python", "certipy",
    # Network
    "responder", "tcpdump", "wireshark", "tshark", "netcat", "nc",
    "socat", "proxychains", "chisel", "ligolo-ng",
    # Cloud
    "aws", "az", "gcloud", "kubectl", "prowler", "scoutsuite",
    # OSINT
    "theharvester", "spiderfoot", "recon-ng", "sherlock", "holehe",
    # Forensics & binary
    "volatility3", "vol3", "foremost", "binwalk", "exiftool", "testdisk",
    "strings", "file", "objdump", "readelf", "radare2", "r2",
    # Utilities
    "curl", "wget", "python3", "python", "bash", "sh",
    "cat", "grep", "awk", "sed", "head", "tail", "sort", "uniq",
    "cut", "tr", "wc", "find", "xargs", "base64", "xxd", "openssl",
    "ssh", "scp", "ftp", "telnet", "whois", "host", "nslookup",
}

# Single shared executor instance
_executor = ToolExecutor()


class ExecuteRequest(BaseModel):
    tool_name: str
    args: list[str] = []
    timeout: Optional[int] = None
    cwd: Optional[str] = None
    env: Optional[dict[str, str]] = None
    stdin_data: Optional[str] = None


class ExecuteResponse(BaseModel):
    tool_name: str
    command: str
    stdout: str
    stderr: str
    return_code: int
    duration_seconds: float
    success: bool
    timed_out: bool
    attempt: int
    max_attempts: int
    metadata: dict
    outcome_kind: str
    signal_detected: bool


@app.post("/execute", response_model=ExecuteResponse)
async def execute_tool(req: ExecuteRequest):
    """Execute a security tool via the local ToolExecutor."""
    # --- Tool-name allowlist ---
    tool_basename = os.path.basename(req.tool_name)
    if "/" in req.tool_name or ".." in req.tool_name:
        raise HTTPException(
            status_code=400,
            detail=f"tool_name must not contain path separators: {req.tool_name!r}",
        )
    if tool_basename not in _ALLOWED_TOOLS:
        raise HTTPException(
            status_code=403,
            detail=f"Tool not in allowlist: {tool_basename!r}",
        )

    # --- cwd validation: must be under /tmp, engagement dirs, or common work dirs ---
    allowed_cwd_prefixes = ("/tmp", "/home", "/opt/snowstrike", "/engagements", "/root")
    if req.cwd:
        real_cwd = os.path.realpath(req.cwd)
        if not any(real_cwd.startswith(p) for p in allowed_cwd_prefixes):
            raise HTTPException(
                status_code=400,
                detail=f"cwd not in allowed paths: {req.cwd!r}",
            )

    # --- env sanitization: strip dangerous variables ---
    _DENIED_ENV_KEYS = {
        "LD_PRELOAD", "LD_LIBRARY_PATH", "PYTHONPATH", "PYTHONSTARTUP",
        "ANTHROPIC_API_KEY", "XAI_API_KEY", "OPENAI_API_KEY",
        "TOOL_RUNNER_AUTH_TOKEN", "AWS_SECRET_ACCESS_KEY",
    }
    sanitized_env = None
    if req.env:
        sanitized_env = {
            k: v for k, v in req.env.items() if k not in _DENIED_ENV_KEYS
        }
        denied = set(req.env.keys()) & _DENIED_ENV_KEYS
        if denied:
            logger.warning("Stripped denied env vars from request: %s", denied)

    logger.info("Execute request: %s %s", req.tool_name, req.args)

    result: ToolResult = _executor.run(
        tool_name=req.tool_name,
        args=req.args,
        timeout=req.timeout,
        cwd=req.cwd,
        env=sanitized_env,
        stdin_data=req.stdin_data,
        # on_output not supported over HTTP — streaming would require websockets
    )

    return ExecuteResponse(**result.to_dict())


@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "ok", "service": "tool-runner"}


def main():
    parser = argparse.ArgumentParser(description="SnowStrike Tool Runner")
    parser.add_argument("--port", "-p", type=int, default=9090)
    parser.add_argument("--host", default="127.0.0.1")
    args = parser.parse_args()

    import uvicorn

    logger.info("Tool Runner starting on %s:%d", args.host, args.port)
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")


if __name__ == "__main__":
    main()

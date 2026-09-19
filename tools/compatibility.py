"""
Startup compatibility probe for security tool binaries.

Runs once at agent/engagement init to build a capability profile per tool:
- Binary path (shutil.which)
- Version/help output
- Variant detection (e.g., Python httpx vs ProjectDiscovery httpx)
- Normalized capability profile with supported flags

The result is a dict keyed by tool_name with compatibility status that acts
as a hard pre-execution gate: if a tool is present but incompatible, it will
be skipped cleanly rather than discovered by failure at runtime.

v7.2
"""

import logging
import os
import re
import shlex
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Capability profile dataclass
# ---------------------------------------------------------------------------

@dataclass
class ToolProfile:
    """Capability profile for a single tool binary."""
    tool_name: str
    binary_name: str
    binary_path: Optional[str] = None
    available: bool = False
    compatible: bool = True
    version: str = "unknown"
    variant: str = "unknown"      # e.g. "projectdiscovery", "python", "kali"
    reason: str = ""
    capabilities: dict = field(default_factory=dict)  # flag -> supported bool

    def to_dict(self) -> dict:
        return {
            "tool_name": self.tool_name,
            "binary_name": self.binary_name,
            "binary_path": self.binary_path,
            "available": self.available,
            "compatible": self.compatible,
            "version": self.version,
            "variant": self.variant,
            "reason": self.reason,
            "capabilities": self.capabilities,
        }


# ---------------------------------------------------------------------------
# Version/help capture helper
# ---------------------------------------------------------------------------

def _capture_output(cmd: list[str], timeout: int = 10) -> tuple[str, str, int]:
    """Run a command and capture stdout+stderr. Returns (stdout, stderr, returncode)."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env={**os.environ, "LANG": "C"},
        )
        return result.stdout, result.stderr, result.returncode
    except FileNotFoundError:
        return "", "binary not found", 127
    except subprocess.TimeoutExpired:
        return "", "timeout during probe", -1
    except Exception as e:
        return "", str(e), -1


def _get_version_text(binary: str) -> str:
    """Try common version flags and return the first successful output."""
    for flag in ["--version", "-version", "-V", "--help", "-h"]:
        stdout, stderr, rc = _capture_output([binary, flag])
        combined = (stdout + "\n" + stderr).strip()
        if combined and rc != 127:
            return combined[:2000]  # Cap output
    return ""


# ---------------------------------------------------------------------------
# Per-tool probe functions
# ---------------------------------------------------------------------------

def _probe_httpx(binary_path: str) -> ToolProfile:
    """Detect if httpx is ProjectDiscovery (Go) or Python httpx CLI."""
    profile = ToolProfile(
        tool_name="httpx_probe",
        binary_name="httpx",
        binary_path=binary_path,
        available=True,
    )
    version_text = _get_version_text(binary_path)
    profile.version = _extract_version(version_text)

    # ProjectDiscovery httpx has flags like -sc, -title, -tech-detect
    # Python httpx CLI uses subcommands and different syntax
    if any(kw in version_text.lower() for kw in ["projectdiscovery", "pd", "-tech-detect", "-sc"]):
        profile.variant = "projectdiscovery"
        profile.compatible = True
        profile.capabilities = {
            "-sc": True, "-title": True, "-tech-detect": True,
            "-follow-redirects": True, "-threads": True, "-l": True,
        }
    elif any(kw in version_text.lower() for kw in ["python", "httpx/", "encode/httpx"]):
        profile.variant = "python"
        profile.compatible = False
        profile.reason = "python_httpx_cli_not_projectdiscovery"
        profile.capabilities = {
            "-sc": False, "-title": False, "-tech-detect": False,
            "-follow-redirects": False, "-threads": False,
        }
    else:
        # Try a direct flag probe: -sc is PD-specific
        stdout, stderr, rc = _capture_output([binary_path, "-sc", "-silent", "-version"])
        combined = stdout + stderr
        if rc != 127 and ("projectdiscovery" in combined.lower() or "-tech-detect" in combined.lower()):
            profile.variant = "projectdiscovery"
            profile.compatible = True
            profile.capabilities = {
                "-sc": True, "-title": True, "-tech-detect": True,
                "-follow-redirects": True, "-threads": True,
            }
        else:
            # Probe help output for PD-style flags
            stdout, stderr, rc = _capture_output([binary_path, "-h"])
            help_text = stdout + stderr
            is_pd = "-tech-detect" in help_text or "-status-code" in help_text
            profile.variant = "projectdiscovery" if is_pd else "python"
            profile.compatible = is_pd
            if not is_pd:
                profile.reason = "python_httpx_cli_not_projectdiscovery"
                profile.capabilities = {"-sc": False, "-title": False, "-tech-detect": False}
            else:
                profile.capabilities = {
                    "-sc": True, "-title": True, "-tech-detect": True,
                    "-follow-redirects": True, "-threads": True,
                }

    return profile


def _probe_katana(binary_path: str) -> ToolProfile:
    """Probe katana for supported flags."""
    profile = ToolProfile(
        tool_name="katana_crawl",
        binary_name="katana",
        binary_path=binary_path,
        available=True,
    )
    version_text = _get_version_text(binary_path)
    profile.version = _extract_version(version_text)

    # Get help text to check supported flags
    stdout, stderr, _ = _capture_output([binary_path, "-h"])
    help_text = stdout + stderr

    profile.variant = "projectdiscovery"
    profile.compatible = True

    # Check individual flags
    profile.capabilities = {
        "-u": "-u" in help_text,
        "-d": bool(re.search(r'\s-d[\s,]', help_text)),
        "-headless": "-headless" in help_text,
        "-js-crawl": "-js-crawl" in help_text,
        "-jc": "-jc" in help_text,         # newer alias for -js-crawl
        "-cs": "-cs" in help_text,           # crawl scope
        "-crawl-scope": "-crawl-scope" in help_text,  # older name
        "-jsonl": "-jsonl" in help_text,
        "-json": "-json" in help_text,       # alternative
        "-f": bool(re.search(r'\s-f[\s,]', help_text)),
        "-H": "-H" in help_text,
    }

    # If -js-crawl is gone, check for -jc as replacement
    if not profile.capabilities.get("-js-crawl") and profile.capabilities.get("-jc"):
        profile.capabilities["js_crawl_flag"] = "-jc"
    elif profile.capabilities.get("-js-crawl"):
        profile.capabilities["js_crawl_flag"] = "-js-crawl"
    else:
        profile.capabilities["js_crawl_flag"] = None

    # If -cs is gone, check for -crawl-scope
    if not profile.capabilities.get("-cs") and profile.capabilities.get("-crawl-scope"):
        profile.capabilities["scope_flag"] = "-crawl-scope"
    elif profile.capabilities.get("-cs"):
        profile.capabilities["scope_flag"] = "-cs"
    else:
        profile.capabilities["scope_flag"] = None

    # JSON output flag
    if profile.capabilities.get("-jsonl"):
        profile.capabilities["json_flag"] = "-jsonl"
    elif profile.capabilities.get("-json"):
        profile.capabilities["json_flag"] = "-json"
    else:
        profile.capabilities["json_flag"] = None

    return profile


def _probe_nikto(binary_path: str) -> ToolProfile:
    """Probe nikto for version and capabilities."""
    profile = ToolProfile(
        tool_name="nikto_scan",
        binary_name="nikto",
        binary_path=binary_path,
        available=True,
    )
    version_text = _get_version_text(binary_path)
    profile.version = _extract_version(version_text)
    profile.variant = "standard"
    profile.compatible = True
    profile.capabilities = {
        "-h": True,
        "-p": True,
        "-ssl": True,
        "-Tuning": True,
        "-Plugins": True,
        "-maxtime": "-maxtime" in version_text,
    }
    return profile


def _probe_gobuster(binary_path: str) -> ToolProfile:
    """Probe gobuster for version and flag support."""
    profile = ToolProfile(
        tool_name="gobuster_scan",
        binary_name="gobuster",
        binary_path=binary_path,
        available=True,
    )
    version_text = _get_version_text(binary_path)
    profile.version = _extract_version(version_text)

    # Get dir-mode help
    stdout, stderr, _ = _capture_output([binary_path, "dir", "--help"])
    help_text = stdout + stderr

    profile.variant = "standard"
    profile.compatible = True
    profile.capabilities = {
        "-u": "-u" in help_text,
        "-w": "-w" in help_text,
        "-x": "-x" in help_text,
        "-t": "-t" in help_text,
        "-s": "-s" in help_text,                          # status codes (include)
        "--status-codes": "--status-codes" in help_text,  # long form
        "-b": "-b" in help_text,                          # status codes (exclude) - newer
        "--exclude-status-codes": "--exclude-status-codes" in help_text,
        "--exclude-length": "--exclude-length" in help_text,
        "--no-status": "--no-status" in help_text,
    }

    # Detect if this version uses -s (include) vs --status-codes-blacklist
    # Newer gobuster removed -s and uses -b for blacklist by default
    if not profile.capabilities.get("-s") and profile.capabilities.get("-b"):
        profile.capabilities["status_code_mode"] = "exclude_only"
    else:
        profile.capabilities["status_code_mode"] = "include"

    return profile


def _probe_arjun(binary_path: str) -> ToolProfile:
    """Probe arjun for version and flag support."""
    profile = ToolProfile(
        tool_name="arjun_scan",
        binary_name="arjun",
        binary_path=binary_path,
        available=True,
    )
    version_text = _get_version_text(binary_path)
    profile.version = _extract_version(version_text)

    stdout, stderr, _ = _capture_output([binary_path, "-h"])
    help_text = stdout + stderr

    profile.variant = "standard"
    profile.compatible = True
    profile.capabilities = {
        "-u": "-u" in help_text,
        "-m": "-m" in help_text,
        "--headers": "--headers" in help_text,
        "-w": "-w" in help_text,
        "-t": "-t" in help_text,
        "-k": "-k" in help_text or "--insecure" in help_text,
        "--stable": "--stable" in help_text,
    }
    return profile


def _probe_nmap(binary_path: str) -> ToolProfile:
    """Probe nmap for version."""
    profile = ToolProfile(
        tool_name="nmap_advanced",
        binary_name="nmap",
        binary_path=binary_path,
        available=True,
    )
    version_text = _get_version_text(binary_path)
    profile.version = _extract_version(version_text)
    profile.variant = "standard"
    profile.compatible = True
    return profile


def _probe_feroxbuster(binary_path: str) -> ToolProfile:
    """Probe feroxbuster for version and capabilities."""
    profile = ToolProfile(
        tool_name="feroxbuster_scan",
        binary_name="feroxbuster",
        binary_path=binary_path,
        available=True,
    )
    version_text = _get_version_text(binary_path)
    profile.version = _extract_version(version_text)
    profile.variant = "standard"
    profile.compatible = True

    stdout, stderr, _ = _capture_output([binary_path, "--help"])
    help_text = stdout + stderr
    profile.capabilities = {
        "-u": "-u" in help_text,
        "-w": "-w" in help_text,
        "-x": "-x" in help_text,
        "-t": "-t" in help_text,
        "-d": "-d" in help_text,
        "-s": "-s" in help_text,
        "-C": "-C" in help_text,
        "-S": "-S" in help_text,
        "-H": "-H" in help_text,
        "-k": "-k" in help_text or "--insecure" in help_text,
    }
    return profile


def _probe_testssl(binary_path: str) -> ToolProfile:
    """Probe testssl for version."""
    profile = ToolProfile(
        tool_name="testssl_scan",
        binary_name="testssl.sh",
        binary_path=binary_path,
        available=True,
    )
    version_text = _get_version_text(binary_path)
    profile.version = _extract_version(version_text)
    profile.variant = "standard"
    profile.compatible = True
    return profile


# ---------------------------------------------------------------------------
# Generic probe (for tools without a dedicated prober)
# ---------------------------------------------------------------------------

def _probe_generic(tool_name: str, binary_name: str, binary_path: str) -> ToolProfile:
    """Basic probe: just check availability and capture version."""
    profile = ToolProfile(
        tool_name=tool_name,
        binary_name=binary_name,
        binary_path=binary_path,
        available=True,
    )
    version_text = _get_version_text(binary_path)
    profile.version = _extract_version(version_text)
    profile.variant = "standard"
    profile.compatible = True
    return profile


# ---------------------------------------------------------------------------
# Version extraction helper
# ---------------------------------------------------------------------------

def _extract_version(text: str) -> str:
    """Pull a version string (e.g. 2.1.0, v3.4.5) from version output."""
    if not text:
        return "unknown"
    m = re.search(r'v?(\d+\.\d+(?:\.\d+)?(?:[-+]\S+)?)', text)
    return m.group(0) if m else "unknown"


# ---------------------------------------------------------------------------
# Probe registry: tool_name -> dedicated prober
# ---------------------------------------------------------------------------

_PROBE_REGISTRY: dict[str, callable] = {
    "httpx_probe": ("httpx", _probe_httpx),
    "katana_crawl": ("katana", _probe_katana),
    "nikto_scan": ("nikto", _probe_nikto),
    "gobuster_scan": ("gobuster", _probe_gobuster),
    "arjun_scan": ("arjun", _probe_arjun),
    "nmap_advanced": ("nmap", _probe_nmap),
    "nmap_scan": ("nmap", _probe_nmap),
    "feroxbuster_scan": ("feroxbuster", _probe_feroxbuster),
    "testssl_scan": ("testssl.sh", _probe_testssl),
}


# ---------------------------------------------------------------------------
# Main probe API
# ---------------------------------------------------------------------------

class CompatibilityProbe:
    """
    Run once at startup to build a compatibility map for all registered tools.

    Usage:
        probe = CompatibilityProbe()
        results = probe.run()               # probe all registered tools
        results = probe.run(["httpx_probe"]) # probe specific tools

        # Check before execution
        if not probe.is_compatible("httpx_probe"):
            skip(...)
    """

    def __init__(self):
        self._profiles: dict[str, ToolProfile] = {}

    def run(self, tool_names: Optional[list[str]] = None) -> dict[str, dict]:
        """
        Probe tools and return compatibility map.

        Args:
            tool_names: If provided, only probe these tools. Otherwise probe all
                        tools in the probe registry.

        Returns:
            Dict of tool_name -> profile dict.
        """
        from tools.registry import get_binary_for_tool, TOOL_REGISTRY

        targets = tool_names or list(_PROBE_REGISTRY.keys())

        for tool_name in targets:
            entry = _PROBE_REGISTRY.get(tool_name)
            if entry:
                binary_name, prober = entry
            else:
                # Use registry to find binary name, apply generic probe
                binary_name = get_binary_for_tool(tool_name)
                if not binary_name:
                    self._profiles[tool_name] = ToolProfile(
                        tool_name=tool_name,
                        binary_name="",
                        available=False,
                        compatible=False,
                        reason="no_binary_mapping",
                    )
                    continue
                prober = None

            binary_path = shutil.which(binary_name)
            if not binary_path:
                self._profiles[tool_name] = ToolProfile(
                    tool_name=tool_name,
                    binary_name=binary_name,
                    available=False,
                    compatible=False,
                    reason="binary_missing",
                )
                logger.warning("Tool %s: binary '%s' not found on PATH", tool_name, binary_name)
                continue

            try:
                if prober:
                    profile = prober(binary_path)
                else:
                    profile = _probe_generic(tool_name, binary_name, binary_path)
                self._profiles[tool_name] = profile
                if not profile.compatible:
                    logger.warning(
                        "Tool %s: incompatible (variant=%s, reason=%s)",
                        tool_name, profile.variant, profile.reason,
                    )
                else:
                    logger.info(
                        "Tool %s: OK (binary=%s, version=%s, variant=%s)",
                        tool_name, binary_path, profile.version, profile.variant,
                    )
            except Exception as e:
                logger.error("Probe failed for %s: %s", tool_name, e)
                self._profiles[tool_name] = ToolProfile(
                    tool_name=tool_name,
                    binary_name=binary_name,
                    binary_path=binary_path,
                    available=True,
                    compatible=False,
                    reason=f"probe_error: {e}",
                )

        return {name: p.to_dict() for name, p in self._profiles.items()}

    def get_profile(self, tool_name: str) -> Optional[ToolProfile]:
        """Get cached profile for a tool."""
        return self._profiles.get(tool_name)

    def is_compatible(self, tool_name: str) -> bool:
        """Check if a tool passed the compatibility probe.

        Tools not in the profile cache are assumed compatible (they weren't
        probed, so no evidence of incompatibility).
        """
        profile = self._profiles.get(tool_name)
        if profile is None:
            return True  # Not probed = no evidence of incompatibility
        return profile.compatible

    def is_available(self, tool_name: str) -> bool:
        """Check if a tool binary exists."""
        profile = self._profiles.get(tool_name)
        if profile is None:
            return True
        return profile.available

    def get_skip_reason(self, tool_name: str) -> Optional[str]:
        """Get the reason a tool would be skipped, or None if compatible."""
        profile = self._profiles.get(tool_name)
        if profile is None:
            return None
        if not profile.available:
            return f"binary_missing ({profile.binary_name})"
        if not profile.compatible:
            return profile.reason
        return None

    def get_capability(self, tool_name: str, flag: str) -> Optional[bool]:
        """Check if a specific flag/capability is supported for a tool."""
        profile = self._profiles.get(tool_name)
        if profile is None:
            return None
        return profile.capabilities.get(flag)

    def to_shared_state_format(self) -> dict:
        """Export profiles in the format expected by shared_state.tool_compatibility."""
        tools = {}
        for name, profile in self._profiles.items():
            tools[name] = {
                "compatible": profile.compatible,
                "available": profile.available,
                "version": profile.version,
                "variant": profile.variant,
                "reason": profile.reason,
                "capabilities": profile.capabilities,
            }
        return {"tools": tools}


# ---------------------------------------------------------------------------
# Convenience: run probes and persist to shared state
# ---------------------------------------------------------------------------

def probe_and_persist(shared_state, tool_names: Optional[list[str]] = None) -> CompatibilityProbe:
    """
    Run compatibility probes and write results to shared state.

    Args:
        shared_state: SharedState instance to persist results.
        tool_names: Optional list of specific tools to probe.

    Returns:
        The CompatibilityProbe instance (for further queries).
    """
    probe = CompatibilityProbe()
    probe.run(tool_names)
    try:
        shared_state.update_section("tool_compatibility", probe.to_shared_state_format())
        logger.info("Compatibility probe results persisted to shared state")
    except Exception as e:
        logger.error("Failed to persist compatibility probe results: %s", e)
    return probe

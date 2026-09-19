"""
SnowStrike AI v7.0 - Configuration

Central configuration for API keys, model selection, and system defaults.
"""

import os
import sys
from pathlib import Path


# ============================================================================
# Privilege Enforcement
# ============================================================================

def require_root():
    """Ensure the process is running as root (UID 0). Exit immediately if not.

    Deprecated: In container deployments, the orchestrator runs unprivileged and
    tool execution is delegated to the privileged tool-runner container. This
    function is retained only for non-container CLI use (snowstrike_cli.py).

    Many security tools (nmap SYN scan, masscan, arp-scan, responder, etc.)
    require raw-socket or CAP_NET_RAW privileges. Running as root guarantees
    all agents and their tool subprocesses inherit the necessary permissions.
    """
    if os.geteuid() != 0:
        print(
            "\033[91m[FATAL] SnowStrike AI must be run as root (sudo).\n"
            "       Security tools require elevated privileges for raw sockets,\n"
            "       packet capture, and low-level network access.\n"
            "       Usage: sudo python3 <script>\033[0m",
            file=sys.stderr,
        )
        sys.exit(1)


# ============================================================================
# Container / Service URLs
# ============================================================================

# When set, tools/executor.py uses RemoteToolExecutor to proxy tool calls
# to the privileged tool-runner container over HTTP.
SNOWSTRIKE_TOOL_RUNNER_URL = os.environ.get("SNOWSTRIKE_TOOL_RUNNER_URL", "")

# ============================================================================
# API Configuration
# ============================================================================

ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
XAI_API_KEY = os.environ.get("XAI_API_KEY", "")

# OSINT / third-party tool API keys (optional — tools degrade gracefully without them)
TOOL_API_KEYS = {
    "SHODAN_API_KEY": os.environ.get("SHODAN_API_KEY", ""),
    "CENSYS_API_ID": os.environ.get("CENSYS_API_ID", ""),
    "CENSYS_API_SECRET": os.environ.get("CENSYS_API_SECRET", ""),
    "SPIDERFOOT_API_KEY": os.environ.get("SPIDERFOOT_API_KEY", ""),
    "VIRUSTOTAL_API_KEY": os.environ.get("VIRUSTOTAL_API_KEY", ""),
}

def get_tool_env() -> dict:
    """Return non-empty API keys as env vars for tool subprocesses."""
    return {k: v for k, v in TOOL_API_KEYS.items() if v}

# Tiered model selection for different purposes
# "planning" is an alias that resolves to "orchestrator"
MODELS = {
    "orchestrator": os.environ.get("SNOWSTRIKE_ORCHESTRATOR_MODEL", "claude-opus-4-20250514"),
    "tool_calling": os.environ.get("SNOWSTRIKE_TOOL_CALLING_MODEL", "claude-sonnet-4-20250514"),
    "compaction": os.environ.get("SNOWSTRIKE_COMPACTION_MODEL", "kimi-k2-0711-preview"),
    "planning": os.environ.get("SNOWSTRIKE_PLANNING_MODEL", "claude-opus-4-20250514"),  # alias to orchestrator
}

# ============================================================================
# Available Models Registry
# ============================================================================
# Each model declares its provider so the framework knows which client to use.
# "anthropic" = native Anthropic SDK, "openai" = OpenAI-compatible endpoint.

AVAILABLE_MODELS = {
    # --- Anthropic ---
    "claude-sonnet-4-20250514": {
        "label": "Claude Sonnet 4",
        "provider": "anthropic",
        "api_key_env": "ANTHROPIC_API_KEY",
    },
    "claude-opus-4-20250514": {
        "label": "Claude Opus 4",
        "provider": "anthropic",
        "api_key_env": "ANTHROPIC_API_KEY",
    },
    "claude-haiku-4-5-20251001": {
        "label": "Claude Haiku 4.5",
        "provider": "anthropic",
        "api_key_env": "ANTHROPIC_API_KEY",
    },
    # Anthropic 4.6 generation (latest)
    "claude-opus-4-6": {
        "label": "Claude Opus 4.6",
        "provider": "anthropic",
        "api_key_env": "ANTHROPIC_API_KEY",
    },
    "claude-sonnet-4-6": {
        "label": "Claude Sonnet 4.6",
        "provider": "anthropic",
        "api_key_env": "ANTHROPIC_API_KEY",
    },
    # --- OpenAI ---
    "gpt-5.2": {
        "label": "GPT-5.2",
        "provider": "openai",
        "base_url": "https://api.openai.com/v1",
        "api_key_env": "OPENAI_API_KEY",
    },
    "gpt-5": {
        "label": "GPT-5",
        "provider": "openai",
        "base_url": "https://api.openai.com/v1",
        "api_key_env": "OPENAI_API_KEY",
    },
    "gpt-5-mini": {
        "label": "GPT-5 Mini",
        "provider": "openai",
        "base_url": "https://api.openai.com/v1",
        "api_key_env": "OPENAI_API_KEY",
    },
    "gpt-4.1": {
        "label": "GPT-4.1",
        "provider": "openai",
        "base_url": "https://api.openai.com/v1",
        "api_key_env": "OPENAI_API_KEY",
    },
    "gpt-4.1-nano": {
        "label": "GPT-4.1 Nano",
        "provider": "openai",
        "base_url": "https://api.openai.com/v1",
        "api_key_env": "OPENAI_API_KEY",
    },
    "o4-mini": {
        "label": "o4-mini",
        "provider": "openai",
        "base_url": "https://api.openai.com/v1",
        "api_key_env": "OPENAI_API_KEY",
    },
    "o3": {
        "label": "o3",
        "provider": "openai",
        "base_url": "https://api.openai.com/v1",
        "api_key_env": "OPENAI_API_KEY",
    },
    # --- xAI / Grok ---
    "grok-4": {
        "label": "Grok 4",
        "provider": "grok",
        "api_key_env": "XAI_API_KEY",
    },
    "grok-4-fast": {
        "label": "Grok 4 Fast",
        "provider": "grok",
        "api_key_env": "XAI_API_KEY",
    },
    "grok-4-1-fast": {
        "label": "Grok 4.1 Fast",
        "provider": "grok",
        "api_key_env": "XAI_API_KEY",
    },
    "grok-4-fast-non-reasoning": {
        "label": "Grok 4 Fast (Non-Reasoning)",
        "provider": "grok",
        "api_key_env": "XAI_API_KEY",
    },
    "grok-4-1-fast-non-reasoning": {
        "label": "Grok 4.1 Fast (Non-Reasoning)",
        "provider": "grok",
        "api_key_env": "XAI_API_KEY",
    },
    "grok-4.20-reasoning": {
        "label": "Grok 4.20 Reasoning",
        "provider": "grok",
        "api_key_env": "XAI_API_KEY",
    },
    "grok-4.20-multi-agent": {
        "label": "Grok 4.20 Multi-Agent",
        "provider": "grok",
        "api_key_env": "XAI_API_KEY",
    },
    # --- Kimi / Moonshot AI (OpenAI-compatible) ---
    "kimi-k2-0711-preview": {
        "label": "Kimi K2",
        "provider": "openai",
        "base_url": "https://api.moonshot.ai/v1",
        "api_key_env": "MOONSHOT_API_KEY",
    },
    "kimi-k2.5": {
        "label": "Kimi K2.5",
        "provider": "openai",
        "base_url": "https://api.moonshot.ai/v1",
        "api_key_env": "MOONSHOT_API_KEY",
    },
    "kimi-k2-turbo": {
        "label": "Kimi K2 Turbo",
        "provider": "openai",
        "base_url": "https://api.moonshot.ai/v1",
        "api_key_env": "MOONSHOT_API_KEY",
    },
    # --- Claude Code CLI (subscription-based, no API key needed) ---
    "claude-code-opus": {
        "label": "Claude Opus (Code CLI)",
        "provider": "claude_code",
        "api_key_env": "",
        "cli_model": "claude-opus-4-6",
    },
    "claude-code-sonnet": {
        "label": "Claude Sonnet (Code CLI)",
        "provider": "claude_code",
        "api_key_env": "",
        "cli_model": "claude-sonnet-4-6",
    },
    "claude-code-haiku": {
        "label": "Claude Haiku (Code CLI)",
        "provider": "claude_code",
        "api_key_env": "",
        "cli_model": "claude-haiku-4-5-20251001",
    },
}

# Per-million-token pricing (USD). Used by the cost tracker.
# Loaded from config/model_costs.yaml when available, with hardcoded fallback.

def _load_model_pricing() -> dict:
    """Load pricing from config/model_costs.yaml, falling back to hardcoded defaults."""
    yaml_path = Path(__file__).parent / "model_costs.yaml"
    if yaml_path.exists():
        try:
            import yaml
            with open(yaml_path) as f:
                data = yaml.safe_load(f)
            pricing = {}
            for model_id, info in data.get("models", {}).items():
                pricing[model_id] = {
                    "input": info.get("input_cost_per_mtok", 0.0),
                    "output": info.get("output_cost_per_mtok", 0.0),
                    "provider": info.get("provider", "unknown"),
                }
            if pricing:
                return pricing
        except Exception:
            pass  # Fall through to hardcoded defaults

    return {
        "claude-opus-4-20250514":    {"input": 15.00, "output": 75.00, "provider": "anthropic"},
        "claude-sonnet-4-20250514":  {"input":  3.00, "output": 15.00, "provider": "anthropic"},
        "claude-haiku-4-5-20251001": {"input":  1.00, "output":  5.00, "provider": "anthropic"},
        "claude-opus-4-6":           {"input":  5.00, "output": 25.00, "provider": "anthropic"},
        "claude-sonnet-4-6":         {"input":  3.00, "output": 15.00, "provider": "anthropic"},
        "gpt-5.2":                   {"input":  1.75, "output": 14.00, "provider": "openai"},
        "gpt-5":                     {"input":  1.25, "output": 10.00, "provider": "openai"},
        "gpt-5-mini":                {"input":  0.25, "output":  2.00, "provider": "openai"},
        "gpt-4.1":                   {"input":  2.00, "output":  8.00, "provider": "openai"},
        "gpt-4.1-nano":              {"input":  0.10, "output":  0.40, "provider": "openai"},
        "o4-mini":                   {"input":  1.10, "output":  4.40, "provider": "openai"},
        "o3":                        {"input": 10.00, "output": 40.00, "provider": "openai"},
        "kimi-k2-0711-preview":      {"input":  0.55, "output":  2.20, "provider": "moonshot"},
        "kimi-k2.5":                 {"input":  0.60, "output":  2.50, "provider": "moonshot"},
        "kimi-k2-turbo":             {"input":  0.40, "output":  1.60, "provider": "moonshot"},
        "grok-4":                    {"input":  2.00, "output": 10.00, "provider": "xai"},
        "grok-4-fast":               {"input":  1.00, "output":  4.00, "provider": "xai"},
        "grok-4-1-fast":             {"input":  1.00, "output":  4.00, "provider": "xai"},
        "grok-4-fast-non-reasoning": {"input":  0.80, "output":  3.00, "provider": "xai"},
        "grok-4-1-fast-non-reasoning": {"input": 0.80, "output": 3.00, "provider": "xai"},
        "grok-4.20-reasoning":       {"input":  3.00, "output": 15.00, "provider": "xai"},
        "grok-4.20-multi-agent":     {"input":  5.00, "output": 25.00, "provider": "xai"},
        # Claude Code CLI — subscription-based, $0 marginal cost
        "claude-code-opus":          {"input":  0.00, "output":  0.00, "provider": "claude_code"},
        "claude-code-sonnet":        {"input":  0.00, "output":  0.00, "provider": "claude_code"},
        "claude-code-haiku":         {"input":  0.00, "output":  0.00, "provider": "claude_code"},
    }

MODEL_PRICING = _load_model_pricing()


def _load_model_context_windows() -> dict:
    """Load model context windows from config/model_costs.yaml with fallback."""
    yaml_path = Path(__file__).parent / "model_costs.yaml"
    if yaml_path.exists():
        try:
            import yaml
            with open(yaml_path) as f:
                data = yaml.safe_load(f)
            windows = {}
            for model_id, info in data.get("models", {}).items():
                context_window = info.get("context_window")
                if context_window:
                    windows[model_id] = int(context_window)
            if windows:
                return windows
        except Exception:
            pass

    return {
        "claude-opus-4-6": 1_000_000,
        "claude-sonnet-4-6": 1_000_000,
        "claude-opus-4-20250514": 200_000,
        "claude-sonnet-4-20250514": 200_000,
        "claude-haiku-4-5-20251001": 200_000,
        "gpt-5.2": 400_000,
        "gpt-5": 128_000,
        "gpt-5-mini": 128_000,
        "gpt-4.1": 1_000_000,
        "gpt-4.1-nano": 1_000_000,
        "o4-mini": 200_000,
        "o3": 200_000,
        "kimi-k2-0711-preview": 128_000,
        "kimi-k2.5": 128_000,
        "kimi-k2-turbo": 128_000,
        "grok-4": 2_000_000,
        "grok-4-fast": 2_000_000,
        "grok-4-1-fast": 2_000_000,
        "grok-4-fast-non-reasoning": 2_000_000,
        "grok-4-1-fast-non-reasoning": 2_000_000,
        "grok-4.20-reasoning": 2_000_000,
        "grok-4.20-multi-agent": 2_000_000,
        # Claude Code CLI — inherit from underlying models
        "claude-code-opus": 1_000_000,
        "claude-code-sonnet": 1_000_000,
        "claude-code-haiku": 200_000,
    }


MODEL_CONTEXT_WINDOWS = _load_model_context_windows()


def get_model_context_window(model_id: str, default: int = 150_000) -> int:
    """Return configured context window for a model."""
    try:
        return int(MODEL_CONTEXT_WINDOWS.get(model_id, default))
    except Exception:
        return default

# Tier presets for quick model configuration
TIER_PRESETS = {
    "default": {
        "orchestrator": "claude-opus-4-20250514",
        "tool_calling": "claude-sonnet-4-20250514",
        "compaction": "kimi-k2-0711-preview",
    },
    "openai_mid": {
        "orchestrator": "claude-opus-4-20250514",
        "tool_calling": "gpt-5.2",
        "compaction": "gpt-5.2",
    },
    "hybrid": {
        "orchestrator": "claude-opus-4-20250514",
        "tool_calling": "gpt-5.2",
        "compaction": "kimi-k2-0711-preview",
    },
    "grok": {
        "orchestrator": "grok-4.20-reasoning",
        "tool_calling": "grok-4-1-fast",
        "compaction": "grok-4-fast-non-reasoning",
    },
    "grok_full": {
        "orchestrator": "grok-4.20-reasoning",
        "tool_calling": "grok-4",
        "compaction": "grok-4-fast-non-reasoning",
    },
    "grok_hybrid": {
        "orchestrator": "claude-opus-4-20250514",
        "tool_calling": "grok-4-1-fast",
        "compaction": "grok-4-fast-non-reasoning",
    },
    "claude_code": {
        "orchestrator": "claude-code-opus",
        "tool_calling": "claude-code-sonnet",
        "compaction": "claude-code-haiku",
    },
    "claude_code_hybrid": {
        "orchestrator": "claude-code-opus",
        "tool_calling": "claude-code-sonnet",
        "compaction": "kimi-k2-0711-preview",
    },
}

# Agent roles and tiers that can have model overrides (used by dashboard)
CONFIGURABLE_ROLES = [
    # Tiers
    {"key": "orchestrator", "label": "Orchestrator Tier"},
    {"key": "tool_calling", "label": "Tool Calling Tier"},
    {"key": "compaction", "label": "Compaction Tier"},
    # Individual agents
    {"key": "recon", "label": "Recon Agent"},
    {"key": "webapp", "label": "WebApp Agent"},
    {"key": "browser", "label": "Browser Agent"},
    {"key": "attack", "label": "Attack Agent"},
    {"key": "binary", "label": "Binary/RE Agent"},
    {"key": "cloud", "label": "Cloud Agent"},
    {"key": "forensics", "label": "Forensics Agent"},
    {"key": "osint", "label": "OSINT Agent"},
    {"key": "ghidra", "label": "Ghidra Agent"},
    {"key": "reporting", "label": "Reporting Agent"},
]

# ============================================================================
# Paths
# ============================================================================

PROJECT_ROOT = Path(__file__).parent.parent
ENGAGEMENTS_DIR = PROJECT_ROOT / "engagements"
EXPERIMENTS_DB_PATH = ENGAGEMENTS_DIR / "experiments.db"
AGENTS_PROMPTS_DIR = PROJECT_ROOT / "agents" / "prompts"
AGENT_CONFIG_DIR = Path(os.environ.get("AGENT_CONFIG_DIR", str(PROJECT_ROOT / "agent-configs"))).resolve()
TOOL_CATALOG_DIR = Path(os.environ.get("TOOL_CATALOG_DIR", str(PROJECT_ROOT / "tools" / "catalog"))).resolve()


def _bounded_int(env_var: str, default: int, lo: int, hi: int) -> int:
    """Read an integer from an env var, clamping to [lo, hi]."""
    return max(lo, min(hi, int(os.environ.get(env_var, str(default)))))


# ============================================================================
# Agent Configuration
# ============================================================================

# Maximum tool_use turns per sub-agent before forced stop
MAX_AGENT_TURNS = _bounded_int("SNOWSTRIKE_MAX_TURNS", 30, 1, 200)

# Maximum concurrent sub-agents in a wave
MAX_PARALLEL_AGENTS = _bounded_int("SNOWSTRIKE_MAX_PARALLEL", 4, 1, 16)

# Default tool execution timeout (seconds)
DEFAULT_TOOL_TIMEOUT = _bounded_int("SNOWSTRIKE_TOOL_TIMEOUT", 300, 10, 3600)

# Long-running tool timeout (autorecon, masscan, etc.)
LONG_TOOL_TIMEOUT = _bounded_int("SNOWSTRIKE_LONG_TIMEOUT", 900, 60, 7200)

# Maximum raw output size to store (bytes) - larger outputs truncated in raw log
MAX_RAW_OUTPUT_SIZE = _bounded_int("SNOWSTRIKE_MAX_RAW_SIZE", 10 * 1024 * 1024, 1024, 100 * 1024 * 1024)

# Maximum orchestrator decision iterations before forced stop
MAX_ORCHESTRATOR_ITERATIONS = _bounded_int("SNOWSTRIKE_MAX_ITERATIONS", 30, 1, 200)

# Token budget for the intelligence brief (approx tokens, 1 token ≈ 4 chars)
INTELLIGENCE_BRIEF_TOKEN_BUDGET = _bounded_int("SNOWSTRIKE_BRIEF_TOKEN_BUDGET", 4000, 500, 50000)

# ============================================================================
# Database
# ============================================================================

DB_FILENAME = "snowstrike.db"

# ============================================================================
# Engagement Defaults
# ============================================================================

DEFAULT_METHODOLOGY = "standard"  # standard, webapp, network, cloud, ctf

# Agent types for orchestration
AGENT_TYPES = [
    "recon", "webapp", "browser",
    "attack", "binary", "cloud", "forensics", "osint", "ghidra", "reporting",
]

# Initial objectives by engagement type (orchestrator refines these dynamically)
OBJECTIVE_TEMPLATES = {
    "standard": [
        "Map the complete attack surface (hosts, services, versions)",
        "Identify and confirm exploitable vulnerabilities",
        "Obtain initial access to target systems",
        "Escalate privileges to maximum level",
        "Document all findings for reporting",
    ],
    "webapp": [
        "Map web application attack surface (endpoints, parameters, technologies)",
        "Identify and confirm web vulnerabilities (SQLi, XSS, SSRF, etc.)",
        "Exploit confirmed vulnerabilities for access or data extraction",
        "Document all findings for reporting",
    ],
    "network": [
        "Map the complete network attack surface",
        "Identify credential-based and exploit-based attack vectors",
        "Obtain initial access and escalate privileges",
        "Identify lateral movement paths",
        "Document all findings for reporting",
    ],
    "ctf": [
        "Map the attack surface quickly",
        "Identify the intended vulnerability or attack chain",
        "Exploit and capture flags",
    ],
    "cloud": [
        "Enumerate cloud infrastructure and IAM configuration",
        "Identify misconfigurations and excessive permissions",
        "Test for privilege escalation paths",
        "Document all findings for reporting",
    ],
}

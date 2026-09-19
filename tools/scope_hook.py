"""
Scope enforcement hook for SnowStrike tool execution.

Blocks tool calls that target out-of-scope hosts by inspecting tool arguments
for target-like fields and validating them against the engagement's
ScopeValidator. Registered at priority 1 (highest) so scope checks run
before any other hook.

See docs/APPLIED_ARCHITECTURE_REPORT.md Section 2 for design rationale.
"""

import logging
import re
from typing import Optional

from memory.scope_validator import ScopeValidator
from memory.shared_state import SharedState
from tools.hooks import (
    HookAction,
    HookEvent,
    HookMatcher,
    HookRule,
    get_hook_registry,
)

logger = logging.getLogger(__name__)

# Argument names that may contain target hosts, IPs, domains, or URLs.
# Derived from tools/definitions.py tool schemas.
TARGET_ARG_NAMES = frozenset({
    "target",
    "targets",
    "host",
    "hosts",
    "ip",
    "url",
    "domain",
    "rhost",
    "rhosts",
    "target_ip",
    "target_host",
    "target_url",
    "address",
    "server",
    "endpoint",
    "uri",
    "base_url",
    "dest",
    "destination",
    "remote_host",
    "peer",
})

# Tools that should be exempt from scope enforcement (non-targeting tools).
_EXEMPT_TOOLS = frozenset({
    "save_finding",
    "read_shared_state",
    "update_shared_state",
    "add_to_network_map",
    "log_message",
    "get_raw_output",
    "query_tool_history",
    "report_finding",
    "hashcat_brute",
    "git_secret_scan",
})

_URL_RE = re.compile(r"^https?://", re.I)


def _extract_host(value: str) -> Optional[str]:
    """Extract a hostname/IP from a value that might be a URL or bare host."""
    value = value.strip()
    if not value:
        return None
    # Strip protocol and path/port for URL-style values
    host = re.sub(r"^https?://", "", value, flags=re.I)
    host = re.sub(r"[:/].*$", "", host)
    return host if host else None


class ScopeEnforcementMatcher(HookMatcher):
    """Matches tool executions that target out-of-scope hosts.

    Inspects tool arguments for target-like fields (target, host, ip, url,
    domain, rhost, rhosts) and validates them against engagement scope.
    Returns True (= should block) if ANY target arg is out of scope.
    """

    def __init__(self, validator: ScopeValidator):
        self._validator = validator

    @property
    def name(self) -> str:
        return "scope_enforcement"

    def match(self, event: HookEvent) -> bool:
        # Skip exempt tools
        if event.tool_name in _EXEMPT_TOOLS:
            return False

        for arg_name, arg_value in event.tool_args.items():
            if arg_name not in TARGET_ARG_NAMES:
                continue

            # Normalize to a list of string values
            values: list[str] = []
            if isinstance(arg_value, str) and arg_value.strip():
                values = [arg_value]
            elif isinstance(arg_value, list):
                values = [str(v) for v in arg_value if v]

            for val in values:
                # Handle comma-separated or space-separated target lists
                targets = re.split(r"[,\s]+", val.strip())
                for raw_target in targets:
                    host = _extract_host(raw_target)
                    if not host:
                        continue

                    if not self._validator.is_in_scope(host):
                        logger.warning(
                            "[ScopeHook] Out-of-scope target detected: "
                            "tool=%s arg=%s value=%r host=%r",
                            event.tool_name, arg_name, raw_target, host,
                        )
                        return True  # Should block

        return False


def register_scope_enforcement(engagement_dir: str) -> None:
    """Register scope enforcement hook using engagement's scope config.

    Reads target/scope/out_of_scope from SharedState, creates a
    ScopeValidator, and registers a BLOCK rule at priority 1 (highest).
    """
    shared_state = SharedState(engagement_dir)
    state = shared_state.read()
    engagement = state.get("engagement", {})

    target = engagement.get("target", "")
    scope = engagement.get("scope", [])
    out_of_scope = engagement.get("out_of_scope", [])

    if not target and not scope:
        logger.info("[ScopeHook] No scope defined — skipping enforcement registration")
        return

    validator = ScopeValidator(target, scope, out_of_scope)
    matcher = ScopeEnforcementMatcher(validator)

    rule = HookRule(
        matcher=matcher,
        action=HookAction.BLOCK,
        priority=1,  # Highest — scope enforcement before all other hooks
        name="scope_enforcement",
    )

    registry = get_hook_registry()
    # Remove any existing scope enforcement rule before re-registering
    registry.remove_rule("scope_enforcement")
    registry.add_rule(rule)

    logger.info(
        "[ScopeHook] Scope enforcement registered for target=%s "
        "(%d scope entries, %d out-of-scope entries)",
        target, len(scope), len(out_of_scope),
    )

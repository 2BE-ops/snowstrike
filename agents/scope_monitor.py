"""
Parallel scope monitor that validates tool executions against engagement scope.

Runs as an event bus subscriber (not an LLM agent). Processes TOOL_START events
and emits SCOPE_BLOCK / SCOPE_NEEDS_REVIEW events when out-of-scope targets
are detected. In-scope targets pass silently.
"""

import ipaddress
import logging
import re
import threading
import time
from typing import Optional

from memory.event_bus import Event, EventType, get_event_bus
from memory.scope_validator import ScopeValidator
from memory.shared_state import SharedState

logger = logging.getLogger(__name__)

# Keys in tool args that typically contain target-like values
_TARGET_ARG_KEYS = frozenset({
    "target", "targets", "host", "ip", "url", "domain", "hostname",
    "rhost", "rhosts", "address", "uri", "endpoint",
    "dest", "destination", "server", "remote_host",
    "target_ip", "target_host", "base_url",
})

# Regex to extract host-like values from command strings
_HOST_PATTERN = re.compile(
    r"(?:^|\s)(?:https?://)?([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*)"
)

_IP_PATTERN = re.compile(
    r"(?:^|\s)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
)

# IPv6 pattern: matches both bare and bracket-enclosed forms
_IPV6_PATTERN = re.compile(
    r"(?:^|\s)\[?([0-9a-fA-F:]{2,39}(?:::[0-9a-fA-F:]{0,37})?)\]?"
)


class ScopeMonitor:
    """Parallel monitor that validates all tool executions against engagement scope.

    Runs as an event bus subscriber (not an LLM agent). Processes tool execution
    events and emits BLOCK events when out-of-scope targets are detected.

    Classification:
    - ALLOW: Target is in scope
    - BLOCK: Target is clearly out of scope (auto-blocked)
    - NEEDS_REVIEW: Target is ambiguous (log for human review)
    """

    def __init__(self, engagement_dir: str):
        self._engagement_dir = engagement_dir
        self._shared_state = SharedState(engagement_dir)
        self._event_bus = get_event_bus()

        # Load scope from shared state
        self._scope_validator = self._load_scope_validator()

        # Thread-safe stats and violations
        self._lock = threading.Lock()
        self._violations: list[dict] = []
        self._stats = {"allow": 0, "block": 0, "review": 0}

        # Unsubscribe handle
        self._unsubscribe: Optional[callable] = None

    def _load_scope_validator(self) -> Optional[ScopeValidator]:
        """Load engagement scope and create a ScopeValidator."""
        try:
            state = self._shared_state.read()
            engagement = state.get("engagement", {})
            target = engagement.get("target", "")
            scope = engagement.get("scope", [])
            out_of_scope = engagement.get("out_of_scope", [])
            if target:
                return ScopeValidator(target, scope, out_of_scope)
        except Exception as e:
            logger.debug("ScopeMonitor: failed to load scope: %s", e)
        return None

    def start(self) -> None:
        """Subscribe to tool execution events on the event bus."""
        self._unsubscribe = self._event_bus.subscribe(self._on_tool_event)
        logger.info("ScopeMonitor started — subscribed to event bus")

    def stop(self) -> None:
        """Unsubscribe from the event bus."""
        if self._unsubscribe:
            self._unsubscribe()
            self._unsubscribe = None
            logger.info("ScopeMonitor stopped")

    def _on_tool_event(self, event: Event) -> None:
        """Main handler — filter for TOOL_START events and validate targets."""
        if event.type != EventType.TOOL_START:
            return

        if self._scope_validator is None:
            return

        data = event.data or {}
        tool_name = data.get("tool", "")
        command = data.get("command", "")
        agent_name = event.source or ""

        # Extract target-like values from the command/args
        targets = self._extract_targets(command, data)

        for target_value in targets:
            if self._scope_validator.is_in_scope(target_value):
                with self._lock:
                    self._stats["allow"] += 1
            elif self._is_ambiguous(target_value):
                self._handle_needs_review(tool_name, target_value, agent_name, event)
            else:
                self._handle_block(tool_name, target_value, agent_name, event)

    def _extract_targets(self, command: str, data: dict) -> list[str]:
        """Extract target-like values from tool event data."""
        targets = []

        # Check known arg keys
        for key in _TARGET_ARG_KEYS:
            val = data.get(key)
            if val and isinstance(val, str):
                targets.append(val.strip())

        # Extract IPs and hostnames from command string
        if command:
            for match in _IP_PATTERN.finditer(command):
                ip_str = match.group(1)
                try:
                    ipaddress.ip_address(ip_str)
                    targets.append(ip_str)
                except ValueError:
                    pass

            # Extract IPv6 addresses
            for match in _IPV6_PATTERN.finditer(command):
                ip6_str = match.group(1)
                try:
                    ipaddress.ip_address(ip6_str)
                    targets.append(ip6_str)
                except ValueError:
                    pass

            for match in _HOST_PATTERN.finditer(command):
                host = match.group(1)
                # Filter out common non-target strings
                if "." in host and len(host) > 3 and not host.endswith(".py"):
                    targets.append(host)

        # Deduplicate while preserving order
        seen = set()
        unique = []
        for t in targets:
            t_lower = t.lower()
            if t_lower not in seen:
                seen.add(t_lower)
                unique.append(t)

        return unique

    def _is_ambiguous(self, value: str) -> bool:
        """Check if a target value is ambiguous (not clearly in or out of scope).

        Private IPs and localhost are considered ambiguous rather than blocked,
        since they may be part of an internal pivot chain.
        """
        cleaned = re.sub(r"^https?://", "", value.strip().lower())
        cleaned = re.sub(r"[:/].*$", "", cleaned)
        try:
            addr = ipaddress.ip_address(cleaned)
            if addr.is_private or addr.is_loopback:
                return True
        except ValueError:
            pass
        return False

    def _handle_block(self, tool_name: str, target: str, agent_name: str, event: Event) -> None:
        """Handle an out-of-scope target: emit SCOPE_BLOCK, log, record violation."""
        data = event.data or {}
        violation = {
            "tool_name": tool_name,
            "target": target,
            "agent_name": agent_name,
            "timestamp": time.time(),
            "action_taken": "BLOCK",
            "command": data.get("command", "")[:500],
            "event_data_keys": list(data.keys()),
        }

        with self._lock:
            self._violations.append(violation)
            self._stats["block"] += 1

        logger.warning(
            "ScopeMonitor BLOCK: agent=%s tool=%s target=%s",
            agent_name, tool_name, target,
        )

        # Emit block event
        self._event_bus.emit(Event(
            type=EventType.SCOPE_BLOCK,
            source="scope_monitor",
            data={
                "tool_name": tool_name,
                "target": target,
                "agent_name": agent_name,
                "action": "BLOCK",
            },
            engagement_id=event.engagement_id,
        ))

        # Write violation to shared state
        self._write_violation_to_state(violation)

    def _handle_needs_review(self, tool_name: str, target: str, agent_name: str, event: Event) -> None:
        """Handle an ambiguous target: emit SCOPE_NEEDS_REVIEW, log."""
        data = event.data or {}
        violation = {
            "tool_name": tool_name,
            "target": target,
            "agent_name": agent_name,
            "timestamp": time.time(),
            "action_taken": "NEEDS_REVIEW",
            "command": data.get("command", "")[:500],
            "event_data_keys": list(data.keys()),
        }

        with self._lock:
            self._violations.append(violation)
            self._stats["review"] += 1

        logger.info(
            "ScopeMonitor NEEDS_REVIEW: agent=%s tool=%s target=%s",
            agent_name, tool_name, target,
        )

        # Emit review event
        self._event_bus.emit(Event(
            type=EventType.SCOPE_NEEDS_REVIEW,
            source="scope_monitor",
            data={
                "tool_name": tool_name,
                "target": target,
                "agent_name": agent_name,
                "action": "NEEDS_REVIEW",
            },
            engagement_id=event.engagement_id,
        ))

        # Write to shared state for reporting
        self._write_violation_to_state(violation)

    def _write_violation_to_state(self, violation: dict) -> None:
        """Append a violation record to the scope_violations list in shared state."""
        try:
            self._shared_state.append_to_list("scope_violations", violation)
        except Exception as e:
            logger.debug("ScopeMonitor: failed to write violation to state: %s", e)

    def get_violations(self) -> list[dict]:
        """Returns all blocked/review events for reporting."""
        with self._lock:
            return list(self._violations)

    def get_stats(self) -> dict:
        """Counts of allow/block/review decisions."""
        with self._lock:
            return dict(self._stats)

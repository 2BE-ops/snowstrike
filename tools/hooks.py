"""
Hook-based tool interception layer for SnowStrike.

Provides PreToolUse/PostToolUse hook evaluation around tool execution.
Hooks can BLOCK, MODIFY_ARGS, or LOG tool calls. The HookRegistry is a
thread-safe singleton; rules are evaluated in priority order with
first-BLOCK-wins semantics.

See docs/APPLIED_ARCHITECTURE_REPORT.md Section 2 for design rationale.
"""

import logging
import re
import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)


class HookEventType(str, Enum):
    PRE_TOOL_USE = "pre_tool_use"
    POST_TOOL_USE = "post_tool_use"
    PRE_HANDOFF = "pre_handoff"
    POST_HANDOFF = "post_handoff"
    PRE_STATE_WRITE = "pre_state_write"
    POST_TOOL_FAILURE = "post_tool_failure"
    ORCHESTRATOR_DECISION = "orchestrator_decision"
    # Flow lifecycle hooks
    PRE_FLOW_TRIGGER = "pre_flow_trigger"
    PRE_FLOW_STEP = "pre_flow_step"
    POST_FLOW_STEP = "post_flow_step"
    POST_FLOW_COMPLETE = "post_flow_complete"


@dataclass
class HookEvent:
    """Context for a hook evaluation."""
    event_type: HookEventType
    tool_name: str
    tool_args: dict
    agent_name: str
    engagement_id: int
    tool_result: Any = None       # Only populated for POST_TOOL_USE / POST_TOOL_FAILURE
    tool_category: str = ""       # Tool category (e.g. "recon", "exploit")
    state_section: str = ""       # SharedState section name (PRE_STATE_WRITE)
    state_value: Any = None       # Value being written (PRE_STATE_WRITE)
    # Flow-specific fields (PRE_FLOW_*, POST_FLOW_*)
    flow_name: str = ""
    flow_run_id: str = ""
    step_id: str = ""
    step_type: str = ""
    trigger_type: str = ""
    step_result: Any = None       # Only populated for POST_FLOW_STEP


class HookAction(str, Enum):
    ALLOW = "allow"
    BLOCK = "block"
    DEFER = "defer"
    MODIFY_ARGS = "modify_args"
    INJECT = "inject"
    LOG_ONLY = "log_only"


class HookMatcher(ABC):
    """Base class for hook matchers."""

    @property
    @abstractmethod
    def name(self) -> str: ...

    @abstractmethod
    def match(self, event: HookEvent) -> bool: ...


class ToolNameMatcher(HookMatcher):
    """Match if event.tool_name is in the given set of tool names."""

    def __init__(self, tool_names: set[str]):
        self._tool_names = tool_names

    @property
    def name(self) -> str:
        return f"tool:{','.join(sorted(self._tool_names))}"

    def match(self, event: HookEvent) -> bool:
        return event.tool_name in self._tool_names


class AgentTypeMatcher(HookMatcher):
    """Match if event.agent_name is in the given set of agent names."""

    def __init__(self, agent_names: set[str]):
        self._agent_names = agent_names

    @property
    def name(self) -> str:
        return f"agent:{','.join(sorted(self._agent_names))}"

    def match(self, event: HookEvent) -> bool:
        return event.agent_name in self._agent_names


class ArgPatternMatcher(HookMatcher):
    """Match if tool_args[arg_name] matches a regex pattern."""

    def __init__(self, arg_name: str, pattern: str):
        self._arg_name = arg_name
        self._pattern = re.compile(pattern)

    @property
    def name(self) -> str:
        return f"arg:{self._arg_name}~{self._pattern.pattern}"

    def match(self, event: HookEvent) -> bool:
        value = event.tool_args.get(self._arg_name)
        if value is None:
            return False
        return bool(self._pattern.search(str(value)))


class CompoundMatcher(HookMatcher):
    """Match when ALL sub-matchers match (AND logic)."""

    def __init__(self, matchers: list[HookMatcher]):
        self._matchers = matchers

    @property
    def name(self) -> str:
        return " AND ".join(m.name for m in self._matchers)

    def match(self, event: HookEvent) -> bool:
        return all(m.match(event) for m in self._matchers)


class FlowMatcher(HookMatcher):
    """Match on flow name and/or step type."""

    def __init__(self, flow_names: set[str] | None = None, step_types: set[str] | None = None):
        self._flow_names = flow_names or set()
        self._step_types = step_types or set()

    @property
    def name(self) -> str:
        parts = []
        if self._flow_names:
            parts.append(f"flows={self._flow_names}")
        if self._step_types:
            parts.append(f"step_types={self._step_types}")
        return " ".join(parts) or "FlowMatcher(*)"

    def match(self, event: HookEvent) -> bool:
        if self._flow_names and event.flow_name not in self._flow_names:
            return False
        if self._step_types and event.step_type not in self._step_types:
            return False
        return True


@dataclass
class HookRule:
    """A registered hook: matcher + action + optional arg/inject modifier."""
    matcher: HookMatcher
    action: HookAction
    priority: int = 100  # lower = higher priority
    name: str = ""
    modify_fn: Optional[Callable[[HookEvent], dict]] = None
    inject_fn: Optional[Callable[[HookEvent], str]] = None


class HookRegistry:
    """Thread-safe registry for hook rules.

    Rules are pre-sorted by priority. evaluate() walks them in order:
    first BLOCK short-circuits, first MODIFY_ARGS wins, LOG_ONLY is
    noted, default is ALLOW.
    """

    def __init__(self):
        self._rules: list[HookRule] = []
        self._lock = threading.Lock()

    def add_rule(self, rule: HookRule) -> None:
        """Add a rule, maintaining priority sort order."""
        with self._lock:
            self._rules.append(rule)
            self._rules.sort(key=lambda r: r.priority)
        logger.debug("Hook registered: %s (priority=%d, action=%s)",
                      rule.name, rule.priority, rule.action.value)

    def remove_rule(self, name: str) -> None:
        """Remove all rules with the given name."""
        with self._lock:
            self._rules = [r for r in self._rules if r.name != name]
        logger.debug("Hook removed: %s", name)

    def evaluate(self, event: HookEvent) -> tuple[HookAction, Optional[HookRule], str]:
        """Evaluate all matching rules and return (action, matched_rule, inject_context).

        Priority order: BLOCK > DEFER > MODIFY_ARGS > INJECT > LOG_ONLY > ALLOW.
        For INJECT, all matching inject_fn results are concatenated.
        Returns (ALLOW, None, "") when no rule matches or no rule blocks/modifies.
        """
        with self._lock:
            matching = [r for r in self._rules if r.matcher.match(event)]
        if not matching:
            return HookAction.ALLOW, None, ""
        # BLOCK — first wins
        for rule in matching:
            if rule.action == HookAction.BLOCK:
                logger.info("[Hook] BLOCK %s on %s by '%s'",
                            event.tool_name, event.event_type.value, rule.name)
                return HookAction.BLOCK, rule, ""
        # DEFER — first wins
        for rule in matching:
            if rule.action == HookAction.DEFER:
                logger.info("[Hook] DEFER %s on %s by '%s'",
                            event.tool_name, event.event_type.value, rule.name)
                return HookAction.DEFER, rule, ""
        # MODIFY_ARGS — first wins
        for rule in matching:
            if rule.action == HookAction.MODIFY_ARGS and rule.modify_fn is not None:
                try:
                    rule.modify_fn(event)
                    logger.info("[Hook] MODIFY_ARGS %s by '%s'",
                                event.tool_name, rule.name)
                    return HookAction.MODIFY_ARGS, rule, ""
                except Exception as e:
                    logger.warning("[Hook] modify_fn error in '%s': %s", rule.name, e)
        # INJECT — accumulate all injection strings
        inject_parts: list[str] = []
        first_inject_rule: Optional[HookRule] = None
        for rule in matching:
            if rule.action == HookAction.INJECT and rule.inject_fn is not None:
                try:
                    ctx = rule.inject_fn(event)
                    if ctx:
                        inject_parts.append(ctx)
                        if first_inject_rule is None:
                            first_inject_rule = rule
                        logger.info("[Hook] INJECT %s by '%s'",
                                    event.tool_name, rule.name)
                except Exception as e:
                    logger.warning("[Hook] inject_fn error in '%s': %s", rule.name, e)
        if inject_parts:
            return HookAction.INJECT, first_inject_rule, "\n".join(inject_parts)
        # LOG_ONLY
        for rule in matching:
            if rule.action == HookAction.LOG_ONLY:
                logger.info("[Hook] LOG_ONLY %s by '%s'", event.tool_name, rule.name)
        return HookAction.ALLOW, None, ""

    def clear(self) -> None:
        """Remove all rules (for testing)."""
        with self._lock:
            self._rules.clear()


_hook_registry: Optional[HookRegistry] = None
_registry_lock = threading.Lock()


def get_hook_registry() -> HookRegistry:
    """Return the global HookRegistry singleton."""
    global _hook_registry
    if _hook_registry is None:
        with _registry_lock:
            if _hook_registry is None:
                _hook_registry = HookRegistry()
    return _hook_registry

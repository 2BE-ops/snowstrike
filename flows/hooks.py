"""Flow-specific hook evaluation helpers.

Provides convenience functions for evaluating hooks at flow lifecycle points:
pre-trigger, pre-step, post-step, post-complete.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

logger = logging.getLogger(__name__)


def evaluate_pre_flow_trigger(
    flow_name: str,
    trigger_type: str,
    engagement_id: int = 0,
) -> tuple[str, str]:
    """Evaluate PRE_FLOW_TRIGGER hooks. Returns (action, message)."""
    try:
        from tools.hooks import HookEventType, HookEvent, HookAction, get_hook_registry
        registry = get_hook_registry()
        event = HookEvent(
            event_type=HookEventType.PRE_FLOW_TRIGGER,
            tool_name="",
            tool_args={},
            agent_name="",
            engagement_id=engagement_id,
            flow_name=flow_name,
            trigger_type=trigger_type,
        )
        action, rule, _ = registry.evaluate(event)
        if action == HookAction.BLOCK:
            msg = f"Blocked by hook '{rule.name}'" if rule else "Blocked by hook"
            logger.info("Flow '%s' trigger blocked: %s", flow_name, msg)
            return "block", msg
        return "allow", ""
    except Exception as exc:
        logger.debug("Hook evaluation error (pre_flow_trigger): %s", exc)
        return "allow", ""


def evaluate_pre_flow_step(
    flow_name: str,
    flow_run_id: str,
    step_id: str,
    step_type: str,
    engagement_id: int = 0,
) -> tuple[str, str]:
    """Evaluate PRE_FLOW_STEP hooks. Returns (action, message)."""
    try:
        from tools.hooks import HookEventType, HookEvent, HookAction, get_hook_registry
        registry = get_hook_registry()
        event = HookEvent(
            event_type=HookEventType.PRE_FLOW_STEP,
            tool_name="",
            tool_args={},
            agent_name="",
            engagement_id=engagement_id,
            flow_name=flow_name,
            flow_run_id=flow_run_id,
            step_id=step_id,
            step_type=step_type,
        )
        action, rule, _ = registry.evaluate(event)
        if action == HookAction.BLOCK:
            msg = f"Blocked by hook '{rule.name}'" if rule else "Blocked by hook"
            logger.info("Flow step '%s.%s' blocked: %s", flow_name, step_id, msg)
            return "block", msg
        return "allow", ""
    except Exception as exc:
        logger.debug("Hook evaluation error (pre_flow_step): %s", exc)
        return "allow", ""


def evaluate_post_flow_step(
    flow_name: str,
    flow_run_id: str,
    step_id: str,
    step_type: str,
    step_result: Any = None,
    engagement_id: int = 0,
) -> None:
    """Evaluate POST_FLOW_STEP hooks (informational only)."""
    try:
        from tools.hooks import HookEventType, HookEvent, get_hook_registry
        registry = get_hook_registry()
        event = HookEvent(
            event_type=HookEventType.POST_FLOW_STEP,
            tool_name="",
            tool_args={},
            agent_name="",
            engagement_id=engagement_id,
            flow_name=flow_name,
            flow_run_id=flow_run_id,
            step_id=step_id,
            step_type=step_type,
            step_result=step_result,
        )
        registry.evaluate(event)
    except Exception as exc:
        logger.debug("Hook evaluation error (post_flow_step): %s", exc)


def evaluate_post_flow_complete(
    flow_name: str,
    flow_run_id: str,
    status: str,
    engagement_id: int = 0,
) -> None:
    """Evaluate POST_FLOW_COMPLETE hooks (informational only)."""
    try:
        from tools.hooks import HookEventType, HookEvent, get_hook_registry
        registry = get_hook_registry()
        event = HookEvent(
            event_type=HookEventType.POST_FLOW_COMPLETE,
            tool_name="",
            tool_args={},
            agent_name="",
            engagement_id=engagement_id,
            flow_name=flow_name,
            flow_run_id=flow_run_id,
        )
        registry.evaluate(event)
    except Exception as exc:
        logger.debug("Hook evaluation error (post_flow_complete): %s", exc)

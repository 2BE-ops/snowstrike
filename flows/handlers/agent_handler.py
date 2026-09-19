"""Handler for agent_dispatch flow steps."""

from __future__ import annotations

import logging
import time
from pathlib import Path

from flows.schema import StepDefinition, StepResult, StepStatus

logger = logging.getLogger(__name__)


class AgentStepHandler:
    """Execute agent_dispatch steps by instantiating and running an agent."""

    def execute(
        self,
        step: StepDefinition,
        context: dict,
        workspace: str,
        engagement_id: int = 0,
    ) -> StepResult:
        from flows.template_env import render_template

        # Render the task template
        rendered_task = render_template(step.task, context)

        # Look up agent class
        try:
            from agents.orchestrator import AGENT_CLASSES, _agent_registry
        except ImportError:
            from agents.registry import AgentRegistry

            config_dir = Path(__file__).parent.parent.parent / "agent-configs"
            registry = AgentRegistry(config_dir)
            registry.load_all()
            AGENT_CLASSES = registry.get_agent_classes()
            _agent_registry = registry

        agent_class = AGENT_CLASSES.get(step.agent)
        if not agent_class:
            return StepResult(
                step_id=step.id,
                status=StepStatus.FAILED.value,
                success=False,
                errors=[f"Unknown agent type: {step.agent}"],
            )

        # Get YAML config if registry available
        agent_yaml_config = None
        try:
            if _agent_registry is not None:
                agent_yaml_config = _agent_registry.get_config(step.agent)
        except Exception:
            pass

        # Instantiate agent
        model_override = step.model_override or ""
        t0 = time.monotonic()

        try:
            agent = agent_class(
                engagement_dir=workspace,
                engagement_id=engagement_id,
                model_override=model_override,
                agent_config=agent_yaml_config,
            )
            result = agent.execute(rendered_task)
        except Exception as exc:
            elapsed = time.monotonic() - t0
            logger.error("Agent dispatch failed for step '%s': %s", step.id, exc)
            return StepResult(
                step_id=step.id,
                status=StepStatus.FAILED.value,
                success=False,
                duration_seconds=elapsed,
                errors=[str(exc)],
            )

        elapsed = time.monotonic() - t0

        # Map AgentResult -> StepResult output
        output = {
            "summary": getattr(result, "summary", ""),
            "findings": getattr(result, "findings", {}),
            "tools_used": getattr(result, "tools_used", []),
            "suggested_next_steps": getattr(result, "suggested_next_steps", ""),
            "duration": getattr(result, "duration_seconds", elapsed),
        }

        return StepResult(
            step_id=step.id,
            status=StepStatus.COMPLETED.value if result.success else StepStatus.FAILED.value,
            success=result.success,
            output=output,
            duration_seconds=elapsed,
            errors=getattr(result, "errors", []) or [],
        )

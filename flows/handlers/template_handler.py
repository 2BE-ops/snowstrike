"""Handler for template_render flow steps."""

from __future__ import annotations

import logging
import time
from pathlib import Path

from flows.schema import StepDefinition, StepResult, StepStatus

logger = logging.getLogger(__name__)

_DEFINITIONS_DIR = Path(__file__).parent.parent / "definitions"


class TemplateRenderStepHandler:
    """Render a Jinja2 template file with flow context."""

    def execute(
        self,
        step: StepDefinition,
        context: dict,
        workspace: str,
        engagement_id: int = 0,
    ) -> StepResult:
        from flows.template_env import create_flow_template_env

        t0 = time.monotonic()

        # Resolve template path (relative to definitions dir)
        template_path = _DEFINITIONS_DIR / step.template
        if not template_path.exists():
            # Try relative to workspace
            template_path = Path(workspace) / step.template
        if not template_path.exists():
            elapsed = time.monotonic() - t0
            return StepResult(
                step_id=step.id,
                status=StepStatus.FAILED.value,
                success=False,
                duration_seconds=elapsed,
                errors=[f"Template file not found: {step.template}"],
            )

        try:
            template_content = template_path.read_text()
        except Exception as exc:
            elapsed = time.monotonic() - t0
            return StepResult(
                step_id=step.id,
                status=StepStatus.FAILED.value,
                success=False,
                duration_seconds=elapsed,
                errors=[f"Failed to read template: {exc}"],
            )

        # Merge extra vars into context
        render_context = dict(context)
        if step.vars:
            from flows.template_env import render_template as _render
            for k, v in step.vars.items():
                if isinstance(v, str):
                    render_context[k] = _render(v, context)
                else:
                    render_context[k] = v

        # Render
        try:
            env = create_flow_template_env()
            tpl = env.from_string(template_content)
            rendered = tpl.render(**render_context)
        except Exception as exc:
            elapsed = time.monotonic() - t0
            return StepResult(
                step_id=step.id,
                status=StepStatus.FAILED.value,
                success=False,
                duration_seconds=elapsed,
                errors=[f"Template render failed: {exc}"],
            )

        elapsed = time.monotonic() - t0
        return StepResult(
            step_id=step.id,
            status=StepStatus.COMPLETED.value,
            success=True,
            output={"output": rendered, "format": step.output_format},
            duration_seconds=elapsed,
        )

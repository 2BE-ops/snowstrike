"""Handler for tool_exec flow steps."""

from __future__ import annotations

import logging
import time

from flows.schema import StepDefinition, StepResult, StepStatus

logger = logging.getLogger(__name__)


class ToolStepHandler:
    """Execute tool_exec steps directly via ToolExecutor."""

    def execute(
        self,
        step: StepDefinition,
        context: dict,
        workspace: str,
        engagement_id: int = 0,
    ) -> StepResult:
        from flows.template_env import render_template
        from tools.definitions import build_command
        from tools.executor import ToolExecutor

        # Render arg values through templates
        rendered_args = {}
        for key, val in step.args.items():
            if isinstance(val, str):
                rendered_args[key] = render_template(val, context)
            else:
                rendered_args[key] = val

        # Build command
        try:
            cmd_args = build_command(step.tool, rendered_args)
        except Exception as exc:
            return StepResult(
                step_id=step.id,
                status=StepStatus.FAILED.value,
                success=False,
                errors=[f"Command build failed: {exc}"],
            )

        if not cmd_args:
            return StepResult(
                step_id=step.id,
                status=StepStatus.FAILED.value,
                success=False,
                errors=[f"build_command returned empty for tool '{step.tool}'"],
            )

        # Execute
        timeout = step.timeout or 300
        executor = ToolExecutor()
        t0 = time.monotonic()

        try:
            tool_result = executor.run(
                tool_name=step.tool,
                args=cmd_args,
                timeout=timeout,
                cwd=workspace,
            )
        except Exception as exc:
            elapsed = time.monotonic() - t0
            logger.error("Tool execution failed for step '%s': %s", step.id, exc)
            return StepResult(
                step_id=step.id,
                status=StepStatus.FAILED.value,
                success=False,
                duration_seconds=elapsed,
                errors=[str(exc)],
            )

        elapsed = time.monotonic() - t0

        output = {
            "stdout": tool_result.stdout if step.capture_output else "",
            "stderr": tool_result.stderr,
            "return_code": tool_result.return_code,
            "outcome_kind": getattr(tool_result, "outcome_kind", "unknown"),
            "signal_detected": getattr(tool_result, "signal_detected", False),
            "duration": tool_result.duration_seconds,
        }

        # Alias stdout as 'output' for simpler template access
        output["output"] = output["stdout"]

        return StepResult(
            step_id=step.id,
            status=StepStatus.COMPLETED.value if tool_result.success else StepStatus.FAILED.value,
            success=tool_result.success,
            output=output,
            duration_seconds=elapsed,
            errors=[tool_result.stderr] if tool_result.stderr and not tool_result.success else [],
        )

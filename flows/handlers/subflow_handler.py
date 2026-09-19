"""Handler for sub_flow steps — invoke another flow as a nested step."""

from __future__ import annotations

import logging
import time

from flows.schema import StepDefinition, StepResult, StepStatus

logger = logging.getLogger(__name__)

_MAX_FLOW_DEPTH = 3


class SubFlowStepHandler:
    """Execute a sub-flow by recursively calling FlowRunner."""

    def execute(
        self,
        step: StepDefinition,
        context: dict,
        workspace: str,
        engagement_id: int = 0,
    ) -> StepResult:
        from flows.template_env import render_template
        from flows.registry import FlowRegistry
        from flows.runner import FlowRunner
        from pathlib import Path

        t0 = time.monotonic()

        # Depth check
        depth = context.get("_flow_depth", 0)
        if depth >= _MAX_FLOW_DEPTH:
            return StepResult(
                step_id=step.id,
                status=StepStatus.FAILED.value,
                success=False,
                errors=[f"Sub-flow depth limit exceeded ({_MAX_FLOW_DEPTH})"],
            )

        # Cycle check
        flow_chain = context.get("_flow_chain", [])
        if step.flow in flow_chain:
            return StepResult(
                step_id=step.id,
                status=StepStatus.FAILED.value,
                success=False,
                errors=[f"Sub-flow cycle detected: {' -> '.join(flow_chain)} -> {step.flow}"],
            )

        # Load sub-flow definition
        try:
            defs_dir = Path(__file__).parent.parent / "definitions"
            registry = FlowRegistry(defs_dir)
            registry.load_all()
            flow_def = registry.get_flow(step.flow)
        except KeyError:
            elapsed = time.monotonic() - t0
            return StepResult(
                step_id=step.id,
                status=StepStatus.FAILED.value,
                success=False,
                duration_seconds=elapsed,
                errors=[f"Sub-flow '{step.flow}' not found"],
            )

        # Resolve inputs
        sub_inputs = {}
        for key, val in step.inputs_map.items():
            if isinstance(val, str):
                sub_inputs[key] = render_template(val, context)
            else:
                sub_inputs[key] = val

        # If inherit_context, merge parent context inputs
        if step.inherit_context:
            parent_inputs = context.get("inputs", {})
            for k, v in parent_inputs.items():
                if k not in sub_inputs:
                    sub_inputs[k] = v

        # Execute sub-flow with incremented depth
        runner = FlowRunner()
        # Inject depth and chain into the sub-flow's execution
        # We do this by temporarily modifying the runner to pass extra context
        original_build = runner._build_context.__func__

        def patched_build(self_runner, flow_def_inner, inputs, ws, step_outputs):
            ctx = original_build(self_runner, flow_def_inner, inputs, ws, step_outputs)
            ctx["_flow_depth"] = depth + 1
            ctx["_flow_chain"] = flow_chain + [step.flow]
            return ctx

        import types
        runner._build_context = types.MethodType(patched_build, runner)

        try:
            result = runner.execute(
                flow_def,
                sub_inputs,
                workspace=workspace,
                engagement_id=engagement_id,
            )
        except Exception as exc:
            elapsed = time.monotonic() - t0
            return StepResult(
                step_id=step.id,
                status=StepStatus.FAILED.value,
                success=False,
                duration_seconds=elapsed,
                errors=[f"Sub-flow execution failed: {exc}"],
            )

        elapsed = time.monotonic() - t0
        success = result.status == "completed"

        output = {
            "result": result.to_dict(),
            "status": result.status,
            "duration": result.duration_seconds,
            "cost": result.total_cost_usd,
            "outputs": result.outputs,
        }

        return StepResult(
            step_id=step.id,
            status=StepStatus.COMPLETED.value if success else StepStatus.FAILED.value,
            success=success,
            output=output,
            duration_seconds=elapsed,
            cost_usd=result.total_cost_usd,
            errors=[result.error] if result.error else [],
        )

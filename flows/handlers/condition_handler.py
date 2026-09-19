"""Handler for condition flow steps."""

from __future__ import annotations

import logging
import time

from flows.schema import StepDefinition, StepResult, StepStatus

logger = logging.getLogger(__name__)


class ConditionStepHandler:
    """Evaluate condition expressions and store the boolean result."""

    def execute(
        self,
        step: StepDefinition,
        context: dict,
        workspace: str,
        engagement_id: int = 0,
    ) -> StepResult:
        from flows.condition_eval import ConditionEvaluator, ConditionError

        evaluator = ConditionEvaluator()
        t0 = time.monotonic()

        try:
            result = evaluator.evaluate(step.expression, context)
        except ConditionError as exc:
            elapsed = time.monotonic() - t0
            return StepResult(
                step_id=step.id,
                status=StepStatus.FAILED.value,
                success=False,
                duration_seconds=elapsed,
                errors=[f"Condition evaluation failed: {exc}"],
            )

        elapsed = time.monotonic() - t0
        logger.debug("Condition '%s': %s -> %s", step.id, step.expression, result)

        return StepResult(
            step_id=step.id,
            status=StepStatus.COMPLETED.value,
            success=True,
            output={"result": result},
            duration_seconds=elapsed,
        )

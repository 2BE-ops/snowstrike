"""Polymorphic step executor — routes steps to the correct handler."""

from __future__ import annotations

import logging
import time
from typing import Optional

from flows.schema import StepDefinition, StepResult, StepStatus

logger = logging.getLogger(__name__)


class StepExecutor:
    """Routes step execution to the appropriate handler."""

    def __init__(self):
        from flows.condition_eval import ConditionEvaluator
        self._condition_eval = ConditionEvaluator()

    def execute_step(
        self,
        step: StepDefinition,
        context: dict,
        workspace: str,
        engagement_id: int = 0,
    ) -> StepResult:
        """Execute a single step, handling when-clauses and retries."""

        # Evaluate `when` clause
        if step.when:
            try:
                if not self._condition_eval.evaluate(step.when, context):
                    logger.info("Step '%s' skipped: when clause is false", step.id)
                    return StepResult(
                        step_id=step.id,
                        status=StepStatus.SKIPPED.value,
                        success=True,
                    )
            except Exception as exc:
                logger.warning("Step '%s' when-clause error: %s", step.id, exc)
                return StepResult(
                    step_id=step.id,
                    status=StepStatus.FAILED.value,
                    success=False,
                    errors=[f"When clause evaluation failed: {exc}"],
                )

        # Look up handler
        from flows.handlers import STEP_HANDLERS

        handler_cls = STEP_HANDLERS.get(step.type)
        if handler_cls is None:
            return StepResult(
                step_id=step.id,
                status=StepStatus.FAILED.value,
                success=False,
                errors=[f"No handler for step type: {step.type}"],
            )

        handler = handler_cls()

        # Execute with retry logic
        max_attempts = 1
        delay = 0
        backoff = 1.0
        if step.retry:
            max_attempts = max(step.retry.max_attempts, 1)
            delay = step.retry.delay_seconds
            backoff = step.retry.backoff_multiplier

        last_result: Optional[StepResult] = None
        for attempt in range(1, max_attempts + 1):
            if attempt > 1:
                wait_time = delay * (backoff ** (attempt - 2))
                logger.info(
                    "Step '%s' retry %d/%d (waiting %.1fs)",
                    step.id, attempt, max_attempts, wait_time,
                )
                time.sleep(wait_time)

            try:
                result = handler.execute(step, context, workspace, engagement_id)
                result.attempt = attempt
            except Exception as exc:
                logger.error("Step '%s' handler exception: %s", step.id, exc)
                result = StepResult(
                    step_id=step.id,
                    status=StepStatus.FAILED.value,
                    success=False,
                    errors=[str(exc)],
                    attempt=attempt,
                )

            last_result = result
            if result.success:
                break

        return last_result

"""Handler for wait_for_event flow steps — pause until an event matches."""

from __future__ import annotations

import logging
import threading
import time

from flows.schema import StepDefinition, StepResult, StepStatus

logger = logging.getLogger(__name__)

_DEFAULT_TIMEOUT = 300  # 5 minutes


class WaitForEventStepHandler:
    """Wait for a specific event on the EventBus."""

    def execute(
        self,
        step: StepDefinition,
        context: dict,
        workspace: str,
        engagement_id: int = 0,
    ) -> StepResult:
        t0 = time.monotonic()
        timeout = step.timeout or _DEFAULT_TIMEOUT

        if not step.event_type_wait:
            return StepResult(
                step_id=step.id,
                status=StepStatus.FAILED.value,
                success=False,
                errors=["wait_for_event requires event_type"],
            )

        try:
            from memory.event_bus import get_event_bus, EventType
            event_type = getattr(EventType, step.event_type_wait, None)
            if event_type is None:
                return StepResult(
                    step_id=step.id,
                    status=StepStatus.FAILED.value,
                    success=False,
                    errors=[f"Unknown event type: {step.event_type_wait}"],
                )
        except ImportError:
            return StepResult(
                step_id=step.id,
                status=StepStatus.FAILED.value,
                success=False,
                errors=["EventBus not available"],
            )

        # Set up event listener
        matched_event = {}
        event_received = threading.Event()

        def on_event(event):
            # Check filter conditions
            if step.event_filter:
                for key, expected in step.event_filter.items():
                    actual = event.data.get(key)
                    if actual != expected:
                        return
            # Event matches
            matched_event["data"] = event.data
            matched_event["type"] = event.type.value if hasattr(event.type, "value") else str(event.type)
            matched_event["source"] = event.source
            event_received.set()

        bus = get_event_bus()
        unsub = bus.subscribe_filtered(on_event, event_type=event_type)

        try:
            # Wait for event or timeout
            received = event_received.wait(timeout=timeout)
        finally:
            unsub()

        elapsed = time.monotonic() - t0

        if not received:
            return StepResult(
                step_id=step.id,
                status=StepStatus.TIMED_OUT.value,
                success=False,
                duration_seconds=elapsed,
                errors=[f"Timed out waiting for event {step.event_type_wait} after {timeout}s"],
            )

        # Capture specified fields
        output = {"event_matched": True}
        event_data = matched_event.get("data", {})
        if step.event_capture:
            for field in step.event_capture:
                output[field] = event_data.get(field)
        else:
            output["data"] = event_data

        output["event_type"] = matched_event.get("type", "")
        output["event_source"] = matched_event.get("source", "")

        logger.debug("wait_for_event '%s': received %s after %.1fs", step.id, step.event_type_wait, elapsed)

        return StepResult(
            step_id=step.id,
            status=StepStatus.COMPLETED.value,
            success=True,
            output=output,
            duration_seconds=elapsed,
        )

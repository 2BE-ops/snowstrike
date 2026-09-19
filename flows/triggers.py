"""TriggerDispatcher — manages event, schedule, and agent-request triggers."""

from __future__ import annotations

import hashlib
import json
import logging
import threading
import time
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Callable, Optional

from flows.schema import FlowDefinition, TriggerConfig

if TYPE_CHECKING:
    from flows.engine import FlowEngine
    from flows.registry import FlowRegistry

logger = logging.getLogger(__name__)


class TriggerDispatcher:
    """Manages all trigger subscriptions for loaded flows."""

    def __init__(
        self,
        engine: FlowEngine,
        registry: FlowRegistry,
        engagement_dir: str = "",
        engagement_id: int = 0,
    ):
        self._engine = engine
        self._registry = registry
        self._engagement_dir = engagement_dir
        self._engagement_id = engagement_id

        self._running = False
        self._unsubscribers: list[Callable] = []
        self._schedule_timers: list[threading.Timer] = []
        self._agent_monitor_thread: Optional[threading.Thread] = None
        self._dedup_cache: dict[str, float] = {}  # fingerprint -> last_trigger_time
        self._active_runs: dict[str, int] = {}  # flow_name -> active_count
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Register all triggers from loaded flow definitions."""
        self._running = True
        flows = self._registry.list_flows()
        has_agent_triggers = False

        for flow_info in flows:
            try:
                flow_def = self._registry.get_flow(flow_info["name"])
                trigger = flow_def.spec.trigger

                if trigger.type == "event":
                    self._register_event_trigger(flow_def)
                elif trigger.type == "schedule":
                    self._register_schedule_trigger(flow_def)
                elif trigger.type == "agent_request":
                    has_agent_triggers = True
            except Exception as exc:
                logger.warning("Failed to register trigger for flow '%s': %s", flow_info["name"], exc)

        if has_agent_triggers:
            self._start_agent_monitor()

        logger.info("TriggerDispatcher started (%d flows registered)", len(flows))

    def stop(self) -> None:
        """Unsubscribe all triggers and stop timers."""
        self._running = False

        for unsub in self._unsubscribers:
            try:
                unsub()
            except Exception:
                pass
        self._unsubscribers.clear()

        for timer in self._schedule_timers:
            timer.cancel()
        self._schedule_timers.clear()

        if self._agent_monitor_thread and self._agent_monitor_thread.is_alive():
            self._agent_monitor_thread.join(timeout=5)

        logger.info("TriggerDispatcher stopped")

    # ------------------------------------------------------------------
    # Event triggers
    # ------------------------------------------------------------------

    def _register_event_trigger(self, flow_def: FlowDefinition) -> None:
        """Subscribe to EventBus for a specific event type with filters."""
        trigger = flow_def.spec.trigger
        flow_name = flow_def.metadata.name

        try:
            from memory.event_bus import get_event_bus, EventType
            event_type = getattr(EventType, trigger.event_type, None)
            if event_type is None:
                logger.warning("Flow '%s': unknown event type '%s'", flow_name, trigger.event_type)
                return
        except ImportError:
            logger.warning("EventBus not available for trigger registration")
            return

        def on_event(event):
            if not self._running:
                return
            # Evaluate filter conditions
            if trigger.filter and not self._evaluate_filter(trigger.filter, event.data):
                return
            # Debounce
            if not self._check_debounce(flow_name, "event", trigger.debounce_seconds):
                return
            # Concurrent run limit
            if not self._check_concurrent(flow_name, trigger.max_concurrent_runs):
                return

            # Resolve inputs from event data
            inputs = self._resolve_event_inputs(flow_def, event.data)

            logger.info("Event trigger fired for flow '%s' (event=%s)", flow_name, trigger.event_type)
            self._dispatch_flow(flow_def, inputs, "event", trigger.event_type)

        bus = get_event_bus()
        unsub = bus.subscribe_filtered(on_event, event_type=event_type)
        self._unsubscribers.append(unsub)
        logger.debug("Registered event trigger: flow '%s' on %s", flow_name, trigger.event_type)

    def _evaluate_filter(self, filter_spec: dict, event_data: dict) -> bool:
        """Evaluate filter conditions against event data."""
        for key, expected in filter_spec.items():
            if key == "data_match":
                try:
                    from flows.condition_eval import ConditionEvaluator
                    evaluator = ConditionEvaluator()
                    return evaluator.evaluate(str(expected), {"data": event_data, **event_data})
                except Exception:
                    return False
            else:
                actual = event_data.get(key)
                if actual != expected:
                    return False
        return True

    def _resolve_event_inputs(self, flow_def: FlowDefinition, event_data: dict) -> dict:
        """Resolve flow inputs from event data using source mappings."""
        inputs = {}
        for name, inp_def in flow_def.spec.inputs.items():
            # Check if input has a source: "trigger.data.field"
            # For now, try direct key match from event_data
            if name in event_data:
                inputs[name] = event_data[name]
            elif inp_def.default is not None:
                inputs[name] = inp_def.default
        return inputs

    # ------------------------------------------------------------------
    # Schedule triggers
    # ------------------------------------------------------------------

    def _register_schedule_trigger(self, flow_def: FlowDefinition) -> None:
        """Set up cron-based scheduling for a flow."""
        trigger = flow_def.spec.trigger
        flow_name = flow_def.metadata.name

        if trigger.one_shot:
            self._register_one_shot(flow_def)
            return

        if not trigger.cron:
            logger.warning("Flow '%s': schedule trigger has no cron expression", flow_name)
            return

        try:
            from croniter import croniter
        except ImportError:
            logger.warning("croniter not installed; schedule triggers disabled")
            return

        def schedule_next():
            if not self._running:
                return
            try:
                now = datetime.now(timezone.utc)
                cron = croniter(trigger.cron, now)
                next_time = cron.get_next(datetime)
                delay = (next_time - now).total_seconds()
                if delay < 0:
                    delay = 0

                timer = threading.Timer(delay, fire_and_reschedule)
                timer.daemon = True
                timer.start()
                self._schedule_timers.append(timer)
                logger.debug("Flow '%s' scheduled in %.0fs", flow_name, delay)
            except Exception as exc:
                logger.warning("Failed to schedule flow '%s': %s", flow_name, exc)

        def fire_and_reschedule():
            if not self._running:
                return
            logger.info("Schedule trigger fired for flow '%s'", flow_name)
            inputs = {
                name: inp_def.default
                for name, inp_def in flow_def.spec.inputs.items()
                if inp_def.default is not None
            }
            self._dispatch_flow(flow_def, inputs, "schedule", trigger.cron)
            schedule_next()

        schedule_next()
        logger.debug("Registered schedule trigger: flow '%s' cron='%s'", flow_name, trigger.cron)

    def _register_one_shot(self, flow_def: FlowDefinition) -> None:
        """Register a one-shot timer for a specific datetime."""
        trigger = flow_def.spec.trigger
        flow_name = flow_def.metadata.name

        try:
            fire_at = datetime.fromisoformat(trigger.one_shot)
            now = datetime.now(timezone.utc)
            if fire_at.tzinfo is None:
                fire_at = fire_at.replace(tzinfo=timezone.utc)
            delay = (fire_at - now).total_seconds()
            if delay <= 0:
                logger.info("Flow '%s' one-shot time already passed, skipping", flow_name)
                return

            def fire():
                if not self._running:
                    return
                logger.info("One-shot trigger fired for flow '%s'", flow_name)
                inputs = {
                    name: inp_def.default
                    for name, inp_def in flow_def.spec.inputs.items()
                    if inp_def.default is not None
                }
                self._dispatch_flow(flow_def, inputs, "schedule", f"one_shot:{trigger.one_shot}")

            timer = threading.Timer(delay, fire)
            timer.daemon = True
            timer.start()
            self._schedule_timers.append(timer)
            logger.debug("Registered one-shot trigger: flow '%s' at %s (%.0fs)", flow_name, trigger.one_shot, delay)
        except Exception as exc:
            logger.warning("Failed to register one-shot for flow '%s': %s", flow_name, exc)

    # ------------------------------------------------------------------
    # Agent request monitor
    # ------------------------------------------------------------------

    def _start_agent_monitor(self) -> None:
        """Start a background thread that polls HandoffQueue for flow_request handoffs."""
        self._agent_monitor_thread = threading.Thread(
            target=self._agent_monitor_loop,
            daemon=True,
            name="flow-agent-monitor",
        )
        self._agent_monitor_thread.start()

    def _agent_monitor_loop(self) -> None:
        """Poll HandoffQueue every 5s for flow_request handoffs."""
        while self._running:
            try:
                self._check_agent_requests()
            except Exception as exc:
                logger.debug("Agent monitor error: %s", exc)
            time.sleep(5)

    def _check_agent_requests(self) -> None:
        """Check HandoffQueue for flow_request handoffs and dispatch matching flows."""
        try:
            from agents.protocol import HandoffQueue
            if not self._engagement_dir:
                return
            queue = HandoffQueue(self._engagement_dir)
            handoffs = queue.peek()
        except Exception:
            return

        for handoff in handoffs:
            if handoff.handoff_type != "flow_request":
                continue

            flow_name = handoff.data.get("flow_name", "")
            if not flow_name:
                # Try suggested_action format: "trigger_flow:flow-name"
                if handoff.suggested_action.startswith("trigger_flow:"):
                    flow_name = handoff.suggested_action.split(":", 1)[1]

            if not flow_name:
                continue

            # Check if we have this flow
            try:
                flow_def = self._registry.get_flow(flow_name)
            except KeyError:
                continue

            trigger = flow_def.spec.trigger
            if trigger.type != "agent_request":
                continue

            # Check source agent restriction
            if trigger.source_agents and handoff.source_agent not in trigger.source_agents:
                continue

            # Check confidence
            if handoff.confidence < trigger.min_confidence:
                continue

            # Resolve inputs
            inputs = handoff.data.get("inputs", {})
            logger.info(
                "Agent request trigger fired for flow '%s' (from %s, confidence=%.2f)",
                flow_name, handoff.source_agent, handoff.confidence,
            )

            # Remove the handoff from the queue
            try:
                queue.get_for_agent("orchestrator")  # drain to remove it
            except Exception:
                pass

            self._dispatch_flow(flow_def, inputs, "agent_request", handoff.source_agent)

    # ------------------------------------------------------------------
    # Dispatch
    # ------------------------------------------------------------------

    def _dispatch_flow(
        self,
        flow_def: FlowDefinition,
        inputs: dict,
        trigger_type: str,
        trigger_source: str,
    ) -> None:
        """Dispatch a flow for execution via the engine."""
        flow_name = flow_def.metadata.name
        try:
            with self._lock:
                self._active_runs[flow_name] = self._active_runs.get(flow_name, 0) + 1

            self._engine.execute_async(
                flow_name=flow_name,
                inputs=inputs,
                workspace=self._engagement_dir or "",
                engagement_id=self._engagement_id,
                trigger_type=trigger_type,
                trigger_source=trigger_source,
            )
        except Exception as exc:
            logger.error("Failed to dispatch flow '%s': %s", flow_name, exc)
        finally:
            with self._lock:
                count = self._active_runs.get(flow_name, 1)
                if count <= 1:
                    self._active_runs.pop(flow_name, None)
                else:
                    self._active_runs[flow_name] = count - 1

    # ------------------------------------------------------------------
    # Dedup and concurrency
    # ------------------------------------------------------------------

    def _check_debounce(self, flow_name: str, trigger_type: str, debounce_seconds: int) -> bool:
        """Return True if trigger is allowed (not debounced)."""
        key = f"{flow_name}:{trigger_type}"
        now = time.monotonic()
        with self._lock:
            last = self._dedup_cache.get(key, 0)
            if now - last < debounce_seconds:
                logger.debug("Flow '%s' debounced (%.1fs remaining)", flow_name, debounce_seconds - (now - last))
                return False
            self._dedup_cache[key] = now
        return True

    def _check_concurrent(self, flow_name: str, max_concurrent: int) -> bool:
        """Return True if under concurrent run limit."""
        with self._lock:
            current = self._active_runs.get(flow_name, 0)
            if current >= max_concurrent:
                logger.debug("Flow '%s' at max concurrent runs (%d/%d)", flow_name, current, max_concurrent)
                return False
        return True

    @staticmethod
    def _fingerprint(flow_name: str, trigger_type: str, inputs: dict) -> str:
        """Generate dedup fingerprint."""
        canonical = json.dumps({"flow": flow_name, "type": trigger_type, "inputs": inputs}, sort_keys=True)
        return hashlib.sha256(canonical.encode()).hexdigest()[:16]

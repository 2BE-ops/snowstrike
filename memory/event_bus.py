"""
SnowStrike AI v7.0 - Event Bus

Central event system for real-time streaming of agent activity.
Replaces polling with push-based event delivery. All components
(agents, tools, orchestrator) emit events here; consumers (TUI,
CLI, logging) subscribe and receive them instantly.
"""

import asyncio
import json
import logging
import threading
import time
from collections import deque
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)


class EventType(str, Enum):
    # Agent lifecycle
    AGENT_START = "agent_start"
    AGENT_PROGRESS = "agent_progress"
    AGENT_COMPLETE = "agent_complete"
    AGENT_ERROR = "agent_error"

    # Tool lifecycle
    TOOL_START = "tool_start"
    TOOL_OUTPUT = "tool_output"          # streaming line from tool stdout
    TOOL_PROGRESS = "tool_progress"      # periodic progress update
    TOOL_COMPLETE = "tool_complete"

    # LLM lifecycle
    LLM_START = "llm_start"
    LLM_TOKEN = "llm_token"             # streaming token from Claude
    LLM_COMPLETE = "llm_complete"

    # Orchestrator lifecycle
    ORCHESTRATOR_DECISION = "orchestrator_decision"
    ORCHESTRATOR_ITERATION = "orchestrator_iteration"
    ORCHESTRATOR_WAVE = "orchestrator_wave"   # parallel agent wave dispatched

    # Findings
    FINDING_DISCOVERED = "finding_discovered"
    HANDOFF = "handoff"
    AGENT_HANDOFF = "agent_handoff"

    # Dashboard-specific live events
    AGENT_TURN = "agent_turn"
    NEW_EXECUTION = "new_execution"
    PLAN_UPDATE = "plan_update"

    # Model behavior
    MODEL_REFUSAL = "model_refusal"

    # Experiment lifecycle
    EXPERIMENT_VARIANT_UPDATE = "experiment_variant_update"
    EXPERIMENT_COMPLETE = "experiment_complete"

    # Hook system
    HOOK_BLOCK = "hook_block"
    HOOK_MODIFY = "hook_modify"
    HOOK_DEFER = "hook_defer"
    HOOK_INJECT = "hook_inject"

    # Scope monitor
    SCOPE_BLOCK = "scope_block"
    SCOPE_NEEDS_REVIEW = "scope_needs_review"

    # Flow lifecycle
    FLOW_START = "flow_start"
    FLOW_STEP_START = "flow_step_start"
    FLOW_STEP_COMPLETE = "flow_step_complete"
    FLOW_COMPLETE = "flow_complete"

    # General
    STATUS = "status"
    ERROR = "error"


@dataclass
class Event:
    """A single event emitted by any component."""
    type: EventType
    source: str                          # e.g. "recon_agent", "orchestrator", "nmap"
    data: dict = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    engagement_id: int = 0

    def to_dict(self) -> dict:
        return {
            "type": self.type.value if isinstance(self.type, EventType) else self.type,
            "source": self.source,
            "data": self.data,
            "timestamp": self.timestamp,
            "engagement_id": self.engagement_id,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    def to_sse(self) -> str:
        """Format as Server-Sent Event."""
        return f"event: {self.type.value if isinstance(self.type, EventType) else self.type}\ndata: {self.to_json()}\n\n"


class EventBus:
    """Thread-safe event bus with sync and async support.

    Supports:
    - Synchronous callbacks (for agents, tools)
    - Async generators (for SSE/websocket consumers)
    - Event history replay (for late-joining clients)
    - Topic-based filtering
    """

    _instance: Optional["EventBus"] = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._initialized = True

        self._subscribers: list[Callable[[Event], None]] = []
        self._async_queues: list[asyncio.Queue] = []
        self._history: deque[Event] = deque(maxlen=500)
        self._lock_internal = threading.Lock()

    def emit(self, event: Event) -> None:
        """Emit an event to all subscribers (sync + async)."""
        with self._lock_internal:
            self._history.append(event)

            # Sync subscribers
            for callback in self._subscribers:
                try:
                    callback(event)
                except Exception as e:
                    logger.debug(f"Event subscriber error: {e}")

            # Async queues (for SSE consumers)
            dead_queues = []
            for q in self._async_queues:
                try:
                    q.put_nowait(event)
                except asyncio.QueueFull:
                    dead_queues.append(q)
                except Exception:
                    dead_queues.append(q)

            for q in dead_queues:
                self._async_queues.remove(q)

    def subscribe(self, callback: Callable[[Event], None]) -> Callable:
        """Register a synchronous callback. Returns an unsubscribe function."""
        with self._lock_internal:
            self._subscribers.append(callback)

        def unsubscribe():
            with self._lock_internal:
                if callback in self._subscribers:
                    self._subscribers.remove(callback)

        return unsubscribe

    def subscribe_filtered(
        self,
        callback: Callable[[Event], None],
        event_type: Optional[EventType] = None,
        filter_fn: Optional[Callable[[Event], bool]] = None,
    ) -> Callable:
        """Register a callback that only fires for matching events.

        Args:
            callback: Function to call when a matching event is emitted.
            event_type: Only trigger on this event type (None = all types).
            filter_fn: Additional predicate on the event (None = no extra filter).

        Returns:
            An unsubscribe function.
        """
        def wrapper(event: Event):
            if event_type is not None and event.type != event_type:
                return
            if filter_fn is not None and not filter_fn(event):
                return
            try:
                callback(event)
            except Exception as exc:
                logger.debug("Filtered subscriber error: %s", exc)

        return self.subscribe(wrapper)

    def create_async_queue(self, maxsize: int = 200) -> asyncio.Queue:
        """Create an async queue for SSE/websocket consumers."""
        q = asyncio.Queue(maxsize=maxsize)
        with self._lock_internal:
            self._async_queues.append(q)
        return q

    def remove_async_queue(self, q: asyncio.Queue) -> None:
        """Remove an async queue when a consumer disconnects."""
        with self._lock_internal:
            if q in self._async_queues:
                self._async_queues.remove(q)

    def get_history(
        self,
        limit: int = 50,
        event_type: Optional[EventType] = None,
        engagement_id: Optional[int] = None,
    ) -> list[Event]:
        """Get recent event history, optionally filtered by type and engagement."""
        with self._lock_internal:
            events = list(self._history)
        if event_type:
            events = [e for e in events if e.type == event_type]
        if engagement_id is not None:
            events = [e for e in events if e.engagement_id == engagement_id]
        return events[-limit:]

    def clear(self) -> None:
        """Clear all state (for testing)."""
        with self._lock_internal:
            self._subscribers.clear()
            self._async_queues.clear()
            self._history.clear()

    # -- Convenience emitters --

    def agent_start(self, agent_name: str, task: str, engagement_id: int = 0):
        self.emit(Event(
            type=EventType.AGENT_START,
            source=agent_name,
            data={"task": task[:200]},
            engagement_id=engagement_id,
        ))

    def agent_complete(self, agent_name: str, success: bool, summary: str,
                       duration: float, engagement_id: int = 0):
        self.emit(Event(
            type=EventType.AGENT_COMPLETE,
            source=agent_name,
            data={"success": success, "summary": summary[:300], "duration": round(duration, 1)},
            engagement_id=engagement_id,
        ))

    def tool_start(
        self,
        tool_name: str,
        agent: str,
        command: str = "",
        engagement_id: int = 0,
        run_id: str = "",
    ):
        self.emit(Event(
            type=EventType.TOOL_START,
            source=agent,
            data={"tool": tool_name, "command": command[:200], "run_id": run_id},
            engagement_id=engagement_id,
        ))

    def tool_output(
        self,
        tool_name: str,
        agent: str,
        line: str,
        engagement_id: int = 0,
        run_id: str = "",
    ):
        self.emit(Event(
            type=EventType.TOOL_OUTPUT,
            source=agent,
            data={"tool": tool_name, "line": line[:500], "run_id": run_id},
            engagement_id=engagement_id,
        ))

    def tool_complete(
        self,
        tool_name: str,
        agent: str,
        success: bool,
        duration: float,
        engagement_id: int = 0,
        run_id: str = "",
    ):
        self.emit(Event(
            type=EventType.TOOL_COMPLETE,
            source=agent,
            data={
                "tool": tool_name,
                "success": success,
                "duration": round(duration, 1),
                "run_id": run_id,
            },
            engagement_id=engagement_id,
        ))

    def llm_start(self, agent: str, model: str, turn: int = 0, engagement_id: int = 0):
        self.emit(Event(
            type=EventType.LLM_START,
            source=agent,
            data={"model": model, "turn": turn},
            engagement_id=engagement_id,
        ))

    def llm_token(self, agent: str, token: str, engagement_id: int = 0, turn: int = 0):
        self.emit(Event(
            type=EventType.LLM_TOKEN,
            source=agent,
            data={"token": token, "turn": turn},
            engagement_id=engagement_id,
        ))

    def llm_complete(self, agent: str, model: str, input_tokens: int = 0,
                     output_tokens: int = 0, engagement_id: int = 0, turn: int = 0):
        self.emit(Event(
            type=EventType.LLM_COMPLETE,
            source=agent,
            data={
                "model": model,
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
                "turn": turn,
            },
            engagement_id=engagement_id,
        ))

    def _make_event(self, event_type: EventType, source: str, data: dict, engagement_id: int = 0) -> Event:
        """Create an Event object (convenience for callers that need custom events)."""
        return Event(type=event_type, source=source, data=data, engagement_id=engagement_id)

    def handoff(
        self,
        source: str,
        target: str,
        direction: str,
        engagement_id: int = 0,
        **data: Any,
    ):
        payload = {"source": source, "target": target, "direction": direction, **data}
        self.emit(Event(
            type=EventType.AGENT_HANDOFF,
            source=source,
            data=payload,
            engagement_id=engagement_id,
        ))

    def finding(self, agent: str, title: str, severity: str, engagement_id: int = 0):
        self.emit(Event(
            type=EventType.FINDING_DISCOVERED,
            source=agent,
            data={"title": title, "severity": severity},
            engagement_id=engagement_id,
        ))


# Module-level singleton accessor
def get_event_bus() -> EventBus:
    return EventBus()


def create_event_bus():
    """Create the EventBus backend. Currently the in-memory singleton."""
    return get_event_bus()

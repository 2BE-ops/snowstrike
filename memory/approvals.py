"""Approval queue for operator intervention during autonomous runs.

Agents can escalate decisions to a human operator (hook DEFER rules,
high-impact tool calls). Requesting threads block until the operator
responds or the request times out (auto-deny).

Consumed by the TUI approvals screen.
"""

import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from memory.event_bus import EventType, Event, get_event_bus


class ApprovalType(str, Enum):
    TOOL_EXECUTION = "tool_execution"
    FOCUS_REDIRECT = "focus_redirect"
    MANUAL_FINDING = "manual_finding"


@dataclass
class ApprovalRequest:
    id: str
    approval_type: ApprovalType
    description: str
    agent_name: str
    tool_name: str = ""
    tool_args: dict = field(default_factory=dict)
    urgency: str = "normal"
    created_at: float = field(default_factory=time.time)
    approved: Optional[bool] = None
    operator_note: str = ""
    responded_at: Optional[float] = None


class ApprovalQueue:
    """Thread-safe approval queue. Requesting threads block until operator responds."""

    _instance: Optional["ApprovalQueue"] = None
    _lock = threading.Lock()

    def __init__(self):
        self._requests: dict[str, ApprovalRequest] = {}
        self._events: dict[str, threading.Event] = {}
        self._lock_internal = threading.Lock()

    def request_approval(self, request: ApprovalRequest, timeout: float = 300) -> ApprovalRequest:
        """Submit an approval request and block until responded or timeout."""
        evt = threading.Event()
        with self._lock_internal:
            self._requests[request.id] = request
            self._events[request.id] = evt

        # Notify consumers via event bus
        get_event_bus().emit(Event(
            type=EventType.STATUS,
            source="approval_queue",
            data={
                "action": "approval_needed",
                "request_id": request.id,
                "approval_type": request.approval_type.value,
                "description": request.description,
                "agent_name": request.agent_name,
                "tool_name": request.tool_name,
                "urgency": request.urgency,
            },
        ))

        # Block calling thread
        responded = evt.wait(timeout=timeout)

        with self._lock_internal:
            self._events.pop(request.id, None)
            if not responded:
                # Auto-deny on timeout
                request.approved = False
                request.operator_note = "auto-denied: timeout"
                request.responded_at = time.time()
            # Remove from pending
            self._requests.pop(request.id, None)

        return request

    def respond(self, request_id: str, approved: bool, note: str = "") -> bool:
        """Operator responds to a pending request. Returns False if not found."""
        with self._lock_internal:
            req = self._requests.get(request_id)
            evt = self._events.get(request_id)
            if req is None or evt is None:
                return False
            req.approved = approved
            req.operator_note = note
            req.responded_at = time.time()
            evt.set()
        return True

    def get_pending(self) -> list[ApprovalRequest]:
        with self._lock_internal:
            return [r for r in self._requests.values() if r.approved is None]


def get_approval_queue() -> ApprovalQueue:
    """Singleton factory."""
    with ApprovalQueue._lock:
        if ApprovalQueue._instance is None:
            ApprovalQueue._instance = ApprovalQueue()
        return ApprovalQueue._instance

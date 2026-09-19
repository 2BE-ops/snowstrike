"""Per-execution flow state persistence with file-lock safety."""

from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from filelock import FileLock

from flows.schema import FlowResult, FlowStatus, StepResult, StepStatus

logger = logging.getLogger(__name__)


class FlowStateStore:
    """Per-execution state persistence backed by JSON + file-lock."""

    def __init__(self, workspace_dir: str | Path):
        self._dir = Path(workspace_dir)
        self._state_path = self._dir / "flow_state.json"
        self._lock_path = self._dir / "flow_state.json.lock"
        self._lock = FileLock(str(self._lock_path), timeout=30)

    def initialize(
        self,
        flow_id: str,
        flow_name: str,
        inputs: dict,
        execution_mode: str,
        step_ids: list[str],
        trigger_info: dict | None = None,
    ) -> dict:
        """Create initial flow state with all steps PENDING."""
        now = datetime.now(timezone.utc).isoformat()
        state = {
            "flow_id": flow_id,
            "flow_name": flow_name,
            "status": FlowStatus.RUNNING.value,
            "started_at": now,
            "updated_at": now,
            "completed_at": None,
            "trigger": trigger_info or {"type": "manual"},
            "inputs": inputs,
            "execution_mode": execution_mode,
            "workspace": str(self._dir),
            "steps": {
                sid: {
                    "status": StepStatus.PENDING.value,
                    "started_at": None,
                    "completed_at": None,
                    "duration_seconds": None,
                    "output": None,
                    "errors": [],
                    "cost_usd": 0.0,
                    "attempt": 0,
                }
                for sid in step_ids
            },
            "total_cost_usd": 0.0,
            "error": None,
        }
        self._write(state)
        return state

    def read(self) -> dict:
        """Read full state dict (file-locked)."""
        return self._load()

    def update_flow_status(self, status: str, error: str = "") -> None:
        with self._lock:
            state = self._load_unlocked()
            state["status"] = status
            state["updated_at"] = datetime.now(timezone.utc).isoformat()
            if error:
                state["error"] = error
            if status in (
                FlowStatus.COMPLETED.value,
                FlowStatus.FAILED.value,
                FlowStatus.TIMED_OUT.value,
                FlowStatus.CANCELLED.value,
            ):
                state["completed_at"] = datetime.now(timezone.utc).isoformat()
            self._write_unlocked(state)

    def update_step_status(
        self,
        step_id: str,
        status: str,
        output: dict | None = None,
        errors: list[str] | None = None,
        duration: float = 0,
        cost: float = 0,
        attempt: int = 1,
    ) -> None:
        with self._lock:
            state = self._load_unlocked()
            step = state["steps"].get(step_id, {})
            step["status"] = status
            step["attempt"] = attempt
            now = datetime.now(timezone.utc).isoformat()

            if status == StepStatus.RUNNING.value:
                step["started_at"] = now
            elif status in (
                StepStatus.COMPLETED.value,
                StepStatus.FAILED.value,
                StepStatus.TIMED_OUT.value,
                StepStatus.SKIPPED.value,
            ):
                step["completed_at"] = now
                step["duration_seconds"] = duration

            if output is not None:
                step["output"] = output
            if errors is not None:
                step["errors"] = errors
            if cost > 0:
                step["cost_usd"] = cost
                state["total_cost_usd"] = state.get("total_cost_usd", 0) + cost

            state["steps"][step_id] = step
            state["updated_at"] = now
            self._write_unlocked(state)

    def get_step_output(self, step_id: str) -> dict | None:
        state = self._load()
        step = state.get("steps", {}).get(step_id, {})
        return step.get("output")

    def get_completed_steps(self) -> set[str]:
        state = self._load()
        return {
            sid
            for sid, sdata in state.get("steps", {}).items()
            if sdata.get("status") == StepStatus.COMPLETED.value
        }

    def get_all_step_outputs(self) -> dict[str, dict]:
        state = self._load()
        return {
            sid: sdata.get("output", {})
            for sid, sdata in state.get("steps", {}).items()
            if sdata.get("output") is not None
        }

    def mark_flow_completed(self, status: str = "completed") -> FlowResult:
        """Finalize flow state and return a FlowResult."""
        with self._lock:
            state = self._load_unlocked()
            now = datetime.now(timezone.utc).isoformat()
            state["status"] = status
            state["completed_at"] = now
            state["updated_at"] = now

            # Compute total duration
            started = state.get("started_at", "")
            duration = 0.0
            if started:
                try:
                    t0 = datetime.fromisoformat(started)
                    t1 = datetime.fromisoformat(now)
                    duration = (t1 - t0).total_seconds()
                except ValueError:
                    pass

            # Build step results
            step_results = {}
            for sid, sdata in state.get("steps", {}).items():
                step_results[sid] = StepResult(
                    step_id=sid,
                    status=sdata.get("status", "pending"),
                    success=sdata.get("status") == StepStatus.COMPLETED.value,
                    output=sdata.get("output") or {},
                    duration_seconds=sdata.get("duration_seconds") or 0,
                    errors=sdata.get("errors", []),
                    attempt=sdata.get("attempt", 0),
                    started_at=sdata.get("started_at", ""),
                    completed_at=sdata.get("completed_at", ""),
                    cost_usd=sdata.get("cost_usd", 0),
                )

            self._write_unlocked(state)

        return FlowResult(
            flow_id=state["flow_id"],
            flow_name=state["flow_name"],
            status=status,
            started_at=state.get("started_at", ""),
            completed_at=now,
            duration_seconds=duration,
            inputs=state.get("inputs", {}),
            step_results=step_results,
            outputs={},
            total_cost_usd=state.get("total_cost_usd", 0),
            error=state.get("error", ""),
            workspace=str(self._dir),
        )

    # ------------------------------------------------------------------
    # Internal I/O
    # ------------------------------------------------------------------

    def _load(self) -> dict:
        with self._lock:
            return self._load_unlocked()

    def _load_unlocked(self) -> dict:
        if not self._state_path.exists():
            return {}
        with open(self._state_path) as f:
            return json.load(f)

    def _write(self, state: dict) -> None:
        with self._lock:
            self._write_unlocked(state)

    def _write_unlocked(self, state: dict) -> None:
        self._dir.mkdir(parents=True, exist_ok=True)
        tmp = self._state_path.with_suffix(".tmp")
        with open(tmp, "w") as f:
            json.dump(state, f, indent=2, default=str)
        tmp.rename(self._state_path)

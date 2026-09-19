"""FlowEngine — high-level facade for the flow system.

Used by the orchestrator, dashboard API, and CLI to interact with flows
without importing runner/registry/triggers directly.
"""

from __future__ import annotations

import logging
import threading
from concurrent.futures import Future, ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from flows.registry import FlowRegistry
from flows.runner import FlowRunner
from flows.schema import FlowDefinition, FlowResult, FlowStatus
from flows.state import FlowStateStore

logger = logging.getLogger(__name__)

_PROJECT_ROOT = Path(__file__).parent.parent


class FlowEngine:
    """Facade for the entire flow subsystem."""

    def __init__(
        self,
        definitions_dir: Path | str | None = None,
        workspace_base_dir: Path | str | None = None,
        max_parallel_steps: int = 3,
        max_parallel_flows: int = 2,
    ):
        self._definitions_dir = Path(definitions_dir) if definitions_dir else _PROJECT_ROOT / "flows" / "definitions"
        self._workspace_base = Path(workspace_base_dir) if workspace_base_dir else _PROJECT_ROOT / "flow-workspaces"
        self._max_parallel_steps = max_parallel_steps

        self._registry: Optional[FlowRegistry] = None
        self._trigger_dispatcher = None  # lazy import to avoid circular
        self._runner = FlowRunner(max_parallel_steps=max_parallel_steps)

        self._active_flows: dict[str, dict] = {}  # flow_id -> {future, flow_name, started_at, ...}
        self._completed_flows: list[dict] = []  # last N completed
        self._lock = threading.Lock()
        self._pool = ThreadPoolExecutor(max_workers=max_parallel_flows, thread_name_prefix="flow")

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def initialize(self) -> None:
        """Load registry and start trigger dispatcher."""
        self._registry = FlowRegistry(self._definitions_dir)
        self._registry.load_all()
        logger.info("FlowEngine initialized with %d flow definitions", len(self._registry.list_flows()))

    def start_triggers(self, engagement_dir: str = "", engagement_id: int = 0) -> None:
        """Start the trigger dispatcher for event/schedule/agent triggers."""
        if self._registry is None:
            self.initialize()
        try:
            from flows.triggers import TriggerDispatcher
            self._trigger_dispatcher = TriggerDispatcher(
                engine=self,
                registry=self._registry,
                engagement_dir=engagement_dir,
                engagement_id=engagement_id,
            )
            self._trigger_dispatcher.start()
        except Exception as exc:
            logger.warning("Failed to start trigger dispatcher: %s", exc)

    def shutdown(self) -> None:
        """Stop triggers and thread pool."""
        if self._trigger_dispatcher:
            self._trigger_dispatcher.stop()
        self._pool.shutdown(wait=False)

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------

    def trigger(
        self,
        flow_name: str,
        inputs: dict,
        workspace: str = "",
        engagement_id: int = 0,
        trigger_type: str = "manual",
        trigger_source: str = "",
    ) -> FlowResult:
        """Execute a flow synchronously. Returns FlowResult when done."""
        flow_def = self._get_flow(flow_name)
        return self._execute(flow_def, inputs, workspace, engagement_id, trigger_type, trigger_source)

    def execute_sync(
        self,
        flow_name: str,
        inputs: dict,
        workspace: str = "",
        engagement_id: int = 0,
    ) -> FlowResult:
        """Blocking execution for interrupt mode."""
        return self.trigger(flow_name, inputs, workspace, engagement_id, "orchestrator", "interrupt")

    def execute_async(
        self,
        flow_name: str,
        inputs: dict,
        workspace: str = "",
        engagement_id: int = 0,
        trigger_type: str = "manual",
        trigger_source: str = "",
    ) -> str:
        """Non-blocking execution. Returns flow_id immediately."""
        flow_def = self._get_flow(flow_name)
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        flow_id = f"{flow_name}_{ts}"

        future = self._pool.submit(
            self._execute, flow_def, inputs, workspace, engagement_id, trigger_type, trigger_source,
        )

        with self._lock:
            self._active_flows[flow_id] = {
                "future": future,
                "flow_name": flow_name,
                "flow_id": flow_id,
                "started_at": datetime.now(timezone.utc).isoformat(),
                "inputs": inputs,
                "trigger_type": trigger_type,
            }

        future.add_done_callback(lambda f: self._on_flow_complete(flow_id, f))
        return flow_id

    def _execute(
        self,
        flow_def: FlowDefinition,
        inputs: dict,
        workspace: str,
        engagement_id: int,
        trigger_type: str,
        trigger_source: str,
    ) -> FlowResult:
        """Internal execution wrapper with DB logging."""
        result = self._runner.execute(flow_def, inputs, workspace, engagement_id)

        # Log to database if engagement context exists
        if engagement_id:
            self._log_to_db(result, engagement_id, trigger_type, trigger_source)

        return result

    def _on_flow_complete(self, flow_id: str, future: Future) -> None:
        """Callback when an async flow completes."""
        with self._lock:
            info = self._active_flows.pop(flow_id, {})
            try:
                result = future.result()
                info["status"] = result.status
                info["duration"] = result.duration_seconds
                info["cost"] = result.total_cost_usd
            except Exception as exc:
                info["status"] = "failed"
                info["error"] = str(exc)
            self._completed_flows.append(info)
            if len(self._completed_flows) > 50:
                self._completed_flows = self._completed_flows[-50:]

    # ------------------------------------------------------------------
    # Query
    # ------------------------------------------------------------------

    def list_flows(self) -> list[dict]:
        """List available flow definitions."""
        if self._registry is None:
            self.initialize()
        return self._registry.list_flows()

    def get_flow(self, name: str) -> FlowDefinition:
        """Get a flow definition by name."""
        return self._get_flow(name)

    def get_active_flows(self) -> list[dict]:
        """List currently running flows."""
        with self._lock:
            return [
                {k: v for k, v in info.items() if k != "future"}
                for info in self._active_flows.values()
            ]

    def get_completed_flows(self, limit: int = 10) -> list[dict]:
        """List recently completed flows."""
        with self._lock:
            return list(self._completed_flows[-limit:])

    def get_flow_status(self, workspace: str) -> dict:
        """Get execution state from a workspace."""
        store = FlowStateStore(workspace)
        return store.read()

    def cancel_flow(self, flow_id: str) -> bool:
        """Cancel a running flow. Returns True if found and cancelled."""
        with self._lock:
            info = self._active_flows.get(flow_id)
            if info and "future" in info:
                info["future"].cancel()
                return True
        return False

    def get_available_flows_brief(self, state: dict | None = None) -> str:
        """Generate a text section for the orchestrator intelligence brief."""
        if self._registry is None:
            self.initialize()

        lines = []
        flows = self._registry.list_flows()
        if flows:
            lines.append(f"AVAILABLE FLOWS ({len(flows)}):")
            for f in flows[:8]:
                trigger = f.get("trigger_type", "manual")
                mode = f.get("execution_mode", "standalone")
                lines.append(f"  {f['name']}: {f['description'][:60]} [trigger={trigger}, mode={mode}]")
        else:
            lines.append("AVAILABLE FLOWS: None")

        active = self.get_active_flows()
        if active:
            lines.append(f"\nACTIVE FLOWS ({len(active)}):")
            for af in active:
                lines.append(f"  {af['flow_name']}: running since {af.get('started_at', '?')}")

        completed = self.get_completed_flows(3)
        if completed:
            lines.append(f"\nRECENT COMPLETED FLOWS:")
            for cf in completed[-3:]:
                status = cf.get("status", "?")
                dur = cf.get("duration", 0)
                lines.append(f"  {cf.get('flow_name', '?')}: {status} ({dur:.0f}s)")

        lines.append("")
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _get_flow(self, name: str) -> FlowDefinition:
        if self._registry is None:
            self.initialize()
        return self._registry.get_flow(name)

    def _log_to_db(
        self, result: FlowResult, engagement_id: int, trigger_type: str, trigger_source: str,
    ) -> None:
        """Log flow execution to the engagement database."""
        try:
            from memory.database import DatabaseManager
            db = DatabaseManager(Path(result.workspace).parent if result.workspace else ".")
            db.log_flow_execution(
                engagement_id=engagement_id,
                flow_id=result.flow_id,
                flow_name=result.flow_name,
                trigger_type=trigger_type,
                trigger_source=trigger_source,
                inputs=result.inputs,
                status=result.status,
                started_at=result.started_at,
                completed_at=result.completed_at,
                duration_seconds=result.duration_seconds,
                total_cost_usd=result.total_cost_usd,
                error=result.error,
                workspace=result.workspace,
            )
        except Exception as exc:
            logger.debug("Failed to log flow execution to DB: %s", exc)


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_engine: FlowEngine | None = None


def get_flow_engine() -> FlowEngine:
    """Get or create the global FlowEngine singleton."""
    global _engine
    if _engine is None:
        _engine = FlowEngine()
        _engine.initialize()
    return _engine

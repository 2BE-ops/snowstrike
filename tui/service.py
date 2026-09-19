"""Data facade for the TUI.

Wraps the read-only engagement readers (data/), the YAML registries,
the flows engine, and the approval queue behind small, defensive
helpers so screens never import infrastructure directly. All methods
are thread-safe enough for polling from the UI loop and fail soft:
a missing db / broken yaml yields empty data, never an exception.
"""

from __future__ import annotations

import json
import os
import threading
import time
import traceback
from pathlib import Path

from config.settings import ENGAGEMENTS_DIR

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

SEVERITY_STYLES = {
    "critical": "bold red",
    "high": "bold orange3",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
    "ok": "green",
    "fail": "red",
}


def _as_float(value, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


class EngagementHandle:
    """Live handle on one engagement directory: readers + cached stats."""

    def __init__(self, name: str):
        self.name = name
        self.path = str(ENGAGEMENTS_DIR / name)
        from data.db_reader import DBReader
        from data.file_reader import FileReader

        self.db = DBReader(os.path.join(self.path, "snowstrike.db"))
        self.files = FileReader(self.path)
        self._engagement_row: dict | None = None

    @property
    def exists_db(self) -> bool:
        return os.path.isfile(os.path.join(self.path, "snowstrike.db"))

    def engagement_row(self) -> dict:
        if self._engagement_row is None:
            self._engagement_row = self.db.get_engagement() or {}
        return self._engagement_row

    @property
    def engagement_id(self) -> int:
        return int(self.engagement_row().get("id", 0) or 0)

    def stats(self) -> dict:
        if not self.exists_db or not self.engagement_id:
            return {}
        try:
            return self.db.get_stats(self.engagement_id)
        except Exception:
            return {}

    def counts(self) -> dict:
        if not self.exists_db or not self.engagement_id:
            return {}
        try:
            return self.db.get_counts(self.engagement_id)
        except Exception:
            return {}

    def hosts(self) -> list[dict]:
        if not self.engagement_id:
            return []
        try:
            return self.db.get_hosts(self.engagement_id)
        except Exception:
            return []

    def vulnerabilities(self) -> list[dict]:
        if not self.engagement_id:
            return []
        try:
            return self.db.get_vulnerabilities(self.engagement_id)
        except Exception:
            return []

    def credentials(self) -> list[dict]:
        if not self.engagement_id:
            return []
        try:
            return self.db.get_credentials(self.engagement_id)
        except Exception:
            return []

    def timeline(self) -> list[dict]:
        if not self.engagement_id:
            return []
        try:
            return self.db.get_timeline(self.engagement_id)
        except Exception:
            return []

    def agent_activity(self, limit: int = 200) -> list[dict]:
        if not self.engagement_id:
            return []
        try:
            return self.db.get_agent_activity(self.engagement_id, limit=limit)
        except Exception:
            return []

    def story(self) -> str:
        return self.files.read_story()

    def state(self) -> dict:
        return self.files.read_state()

    def alerts(self) -> list:
        return self.files.read_alerts()

    def cost(self) -> float:
        """Total recorded LLM cost (metrics.json), 0.0 when absent."""
        try:
            with open(os.path.join(self.path, "metrics.json")) as f:
                data = json.load(f)
            return _as_float(data.get("total_cost_usd"))
        except (OSError, json.JSONDecodeError):
            return 0.0

    def status_label(self) -> str:
        """Coarse run status from STATE.json."""
        state = self.state()
        phase = str(state.get("phase", "") or state.get("status", "")).lower()
        if phase in {"running", "active", "in_progress"}:
            return "running"
        if phase in {"complete", "completed", "done", "finished"}:
            return "complete"
        if phase:
            return phase
        return "idle"

    def summary(self) -> dict:
        stats = self.stats()
        return {
            "name": self.name,
            "target": self.engagement_row().get("target", ""),
            "created": self.engagement_row().get("created_at", ""),
            "status": self.status_label(),
            "hosts": stats.get("hosts", 0),
            "services": stats.get("services", 0),
            "vulns": stats.get("vulnerabilities", {}).get("total", 0),
            "critical": stats.get("vulnerabilities", {}).get("critical", 0),
            "high": stats.get("vulnerabilities", {}).get("high", 0),
            "creds": stats.get("credentials", 0),
            "tool_runs": stats.get("tool_executions", 0),
            "cost": self.cost(),
        }


class TUIService:
    """Singleton facade the screens poll."""

    def __init__(self):
        self._engagements: dict[str, EngagementHandle] = {}
        self.current: EngagementHandle | None = None
        self._lock = threading.Lock()
        # Active local run (launched from this TUI process)
        self.run_state: dict = {"status": "idle", "message": ""}

    # ------------------------------------------------------------------
    # Engagements
    # ------------------------------------------------------------------

    def list_engagements(self) -> list[EngagementHandle]:
        handles: list[EngagementHandle] = []
        if not os.path.isdir(ENGAGEMENTS_DIR):
            return handles
        for entry in sorted(os.listdir(ENGAGEMENTS_DIR)):
            full = os.path.join(ENGAGEMENTS_DIR, entry)
            if not os.path.isdir(full) or entry == "presets":
                continue
            handles.append(self._handle(entry))
        handles.sort(key=lambda h: os.path.getmtime(h.path), reverse=True)
        return handles

    def _handle(self, name: str) -> EngagementHandle:
        with self._lock:
            if name not in self._engagements:
                self._engagements[name] = EngagementHandle(name)
            return self._engagements[name]

    def select(self, name: str) -> EngagementHandle | None:
        handle = self._handle(name)
        self.current = handle
        return handle

    # ------------------------------------------------------------------
    # Autonomous run (worker thread)
    # ------------------------------------------------------------------

    def launch_run(self, target: str, scope: str = "", methodology: str = "standard") -> None:
        """Launch an autonomous run in the calling thread (run inside a
        Textual worker with thread=True). Updates run_state as it goes."""
        self.run_state.update({"status": "starting", "message": f"creating engagement for {target}", "error": ""})
        try:
            from agents.orchestrator import OrchestratorAgent

            orch = OrchestratorAgent.create_engagement(
                target=target, scope=scope, methodology=methodology
            )
            eng_name = os.path.basename(orch.engagement_dir.rstrip("/\\"))
            self._handle(eng_name)
            self.run_state.update({
                "status": "running",
                "message": f"autonomous run on {eng_name}",
                "engagement": eng_name,
            })
            result = orch.run_autonomous()
            self.run_state.update({
                "status": "complete",
                "message": f"run finished: {str(result.get('status', 'done'))}",
            })
        except Exception as exc:  # noqa: BLE001 — surface any failure to the UI
            self.run_state.update({
                "status": "error",
                "message": f"run failed: {exc}",
                "error": traceback.format_exc(limit=4),
            })

    # ------------------------------------------------------------------
    # Tool catalog
    # ------------------------------------------------------------------

    def tool_catalog(self) -> list[dict]:
        try:
            from tools.registry_loader import get_registry

            registry = get_registry()
            if not registry.loaded:
                registry.load_all()
            return registry.get_catalog()
        except Exception:
            return []

    def binary_availability(self) -> dict[str, bool]:
        try:
            from tools.registry_loader import get_registry

            registry = get_registry()
            if not registry.loaded:
                registry.load_all()
            return registry.check_all_binaries()
        except Exception:
            return {}

    # ------------------------------------------------------------------
    # Agents & models
    # ------------------------------------------------------------------

    def agent_roster(self) -> list[dict]:
        try:
            from agents.registry import AgentRegistry

            registry = AgentRegistry()
            return registry.list_agents()
        except Exception:
            return []

    def model_configs(self) -> list[dict]:
        try:
            from profiles.model_config_manager import ModelConfigManager

            return ModelConfigManager().list_configs()
        except Exception:
            return []

    # ------------------------------------------------------------------
    # Flows
    # ------------------------------------------------------------------

    def flow_list(self) -> list[dict]:
        try:
            from flows.registry import FlowRegistry

            registry = FlowRegistry(Path(__file__).resolve().parent.parent / "flows" / "definitions")
            registry.load_all()
            return registry.list_flows()
        except Exception:
            return []

    def flow_validate(self, path: str) -> list[str]:
        try:
            from flows.registry import FlowRegistry

            registry = FlowRegistry(Path(path).parent)
            return registry.validate_flow_file(Path(path)) or []
        except Exception as exc:
            return [f"validation crashed: {exc}"]

    def flow_run(self, name: str, inputs: dict, on_event=None) -> dict:
        """Run a flow synchronously (call from a worker thread)."""
        from flows.registry import FlowRegistry
        from flows.runner import FlowRunner

        registry = FlowRegistry(Path(__file__).resolve().parent.parent / "flows" / "definitions")
        registry.load_all()
        flow_def = registry.get_flow(name)
        runner = FlowRunner()
        result = runner.execute(flow_def, inputs, workspace="")
        return {
            "flow": result.flow_name,
            "status": result.status,
            "duration": result.duration_seconds,
            "cost": result.total_cost_usd,
            "workspace": result.workspace,
            "steps": {
                sid: {"status": sr.status, "duration": sr.duration_seconds, "errors": sr.errors}
                for sid, sr in result.step_results.items()
            },
            "outputs": {k: str(v)[:200] for k, v in (result.outputs or {}).items()},
        }

    def flow_definitions_dir(self) -> Path:
        return Path(__file__).resolve().parent.parent / "flows" / "definitions"

    def recent_flow_workspaces(self) -> list[dict]:
        """Recent workspaces under flow-workspaces/ with their status."""
        root = Path(__file__).resolve().parent.parent / "flow-workspaces"
        out: list[dict] = []
        if not root.is_dir():
            return out
        for ws in sorted(root.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True):
            state_file = ws / "flow_state.json"
            entry = {"name": ws.name, "path": str(ws), "mtime": ws.stat().st_mtime, "status": "?"}
            if state_file.is_file():
                try:
                    entry.update(json.loads(state_file.read_text()))
                except (OSError, json.JSONDecodeError):
                    pass
            out.append(entry)
        return out[:25]

    # ------------------------------------------------------------------
    # Approvals
    # ------------------------------------------------------------------

    def pending_approvals(self) -> list[dict]:
        try:
            from memory.approvals import get_approval_queue

            pending = get_approval_queue().get_pending()
            return [
                {
                    "id": r.id,
                    "type": r.approval_type.value,
                    "agent": r.agent_name,
                    "tool": r.tool_name,
                    "urgency": r.urgency,
                    "description": r.description,
                    "age": max(0.0, time.time() - r.created_at),
                }
                for r in pending
            ]
        except Exception:
            return []

    def respond_approval(self, request_id: str, approved: bool, note: str = "") -> bool:
        from memory.approvals import get_approval_queue

        return get_approval_queue().respond(request_id, approved, note)


_service: TUIService | None = None


def get_service() -> TUIService:
    global _service
    if _service is None:
        _service = TUIService()
    return _service

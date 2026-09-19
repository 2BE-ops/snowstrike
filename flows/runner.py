"""FlowRunner — core DAG execution engine for SnowStrike flows."""

from __future__ import annotations

import json
import logging
import os
import time
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from flows.schema import (
    FlowDefinition,
    FlowResult,
    FlowStatus,
    StepDefinition,
    StepResult,
    StepStatus,
)
from flows.state import FlowStateStore
from flows.step_executor import StepExecutor
from flows.template_env import render_template

logger = logging.getLogger(__name__)

# Default project root (parent of flows/)
_PROJECT_ROOT = Path(__file__).parent.parent


class FlowRunner:
    """DAG-based flow execution engine."""

    def __init__(self, max_parallel_steps: int = 3):
        self._max_parallel = max_parallel_steps
        self._step_executor = StepExecutor()

    def execute(
        self,
        flow_def: FlowDefinition,
        inputs: dict,
        workspace: str = "",
        engagement_id: int = 0,
        resume: bool = False,
    ) -> FlowResult:
        """Execute a flow definition end-to-end."""
        flow_name = flow_def.metadata.name
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        flow_id = f"{flow_name}_{ts}"

        # Validate required inputs
        missing = []
        for name, inp_def in flow_def.spec.inputs.items():
            if inp_def.required and name not in inputs:
                if inp_def.default is None:
                    missing.append(name)
        if missing:
            return FlowResult(
                flow_id=flow_id,
                flow_name=flow_name,
                status=FlowStatus.FAILED.value,
                error=f"Missing required inputs: {', '.join(missing)}",
            )

        # Apply defaults
        for name, inp_def in flow_def.spec.inputs.items():
            if name not in inputs and inp_def.default is not None:
                inputs[name] = inp_def.default

        # Set up workspace
        if flow_def.spec.execution_mode == "standalone" and not workspace:
            workspace = self._setup_standalone_workspace(flow_def, flow_id, inputs)
        elif not workspace:
            workspace = str(_PROJECT_ROOT / "flow-workspaces" / flow_id)
            os.makedirs(workspace, exist_ok=True)

        logger.info("Flow '%s' starting (id=%s, workspace=%s)", flow_name, flow_id, workspace)

        # Emit start event
        self._emit_event("FLOW_START", {
            "flow_name": flow_name,
            "flow_id": flow_id,
            "inputs": inputs,
            "execution_mode": flow_def.spec.execution_mode,
        }, engagement_id)

        # Initialize state store
        state_store = FlowStateStore(workspace)
        step_ids = [s.id for s in flow_def.spec.steps]
        state_store.initialize(
            flow_id=flow_id,
            flow_name=flow_name,
            inputs=inputs,
            execution_mode=flow_def.spec.execution_mode,
            step_ids=step_ids,
        )

        # Topological sort -> execution levels
        steps_by_id = {s.id: s for s in flow_def.spec.steps}
        try:
            levels = self._topological_sort(flow_def.spec.steps)
        except Exception as exc:
            state_store.update_flow_status(FlowStatus.FAILED.value, str(exc))
            return state_store.mark_flow_completed(FlowStatus.FAILED.value)

        # Build initial context
        context = self._build_context(flow_def, inputs, workspace, {})

        # Execute levels
        flow_failed = False
        flow_start = time.monotonic()
        flow_timeout = flow_def.spec.timeout

        for level_idx, level_step_ids in enumerate(levels):
            # Check timeout
            if time.monotonic() - flow_start > flow_timeout:
                state_store.update_flow_status(FlowStatus.TIMED_OUT.value, "Flow timeout exceeded")
                self._emit_event("FLOW_COMPLETE", {
                    "flow_name": flow_name, "flow_id": flow_id,
                    "success": False, "reason": "timeout",
                }, engagement_id)
                return state_store.mark_flow_completed(FlowStatus.TIMED_OUT.value)

            level_steps = [steps_by_id[sid] for sid in level_step_ids if sid in steps_by_id]
            if not level_steps:
                continue

            logger.debug(
                "Flow '%s' level %d: executing %s",
                flow_name, level_idx, [s.id for s in level_steps],
            )

            # Execute level (parallel if multiple steps)
            level_results = self._execute_step_group(
                level_steps, context, workspace, engagement_id, state_store,
            )

            # Process results
            for step_id, step_result in level_results.items():
                # Update context with step outputs
                if step_result.output:
                    context["steps"][step_id] = step_result.output
                else:
                    context["steps"][step_id] = {"status": step_result.status}

                # Check failure handling
                if not step_result.success and step_result.status != StepStatus.SKIPPED.value:
                    step_def = steps_by_id.get(step_id)
                    on_fail = (step_def.on_failure if step_def and step_def.on_failure
                               else flow_def.spec.on_failure.strategy)

                    if on_fail == "stop":
                        logger.warning(
                            "Flow '%s' aborting: step '%s' failed with strategy=stop",
                            flow_name, step_id,
                        )
                        flow_failed = True
                        break

            if flow_failed:
                break

            # Cost budget check
            cost_budget = flow_def.spec.cost_budget
            if cost_budget > 0:
                state_data = state_store.read()
                current_cost = state_data.get("total_cost_usd", 0)
                if current_cost >= cost_budget:
                    logger.warning(
                        "Flow '%s' aborting: cost budget exceeded ($%.4f >= $%.4f)",
                        flow_name, current_cost, cost_budget,
                    )
                    state_store.update_flow_status(
                        FlowStatus.FAILED.value,
                        f"Cost budget exceeded: ${current_cost:.4f} >= ${cost_budget:.4f}",
                    )
                    self._emit_event("FLOW_COMPLETE", {
                        "flow_name": flow_name, "flow_id": flow_id,
                        "success": False, "reason": "budget_exceeded",
                        "cost": current_cost, "budget": cost_budget,
                    }, engagement_id)
                    return state_store.mark_flow_completed(FlowStatus.FAILED.value)

        # Finalize
        final_status = FlowStatus.FAILED.value if flow_failed else FlowStatus.COMPLETED.value

        # Resolve declared outputs
        flow_result = state_store.mark_flow_completed(final_status)
        flow_result.outputs = self._resolve_flow_outputs(flow_def, context["steps"])
        flow_result.workspace = workspace

        self._emit_event("FLOW_COMPLETE", {
            "flow_name": flow_name,
            "flow_id": flow_id,
            "success": not flow_failed,
            "duration": flow_result.duration_seconds,
            "cost": flow_result.total_cost_usd,
        }, engagement_id)

        logger.info(
            "Flow '%s' %s (%.1fs, $%.4f)",
            flow_name, final_status,
            flow_result.duration_seconds, flow_result.total_cost_usd,
        )

        # Log to engagement database if available
        if engagement_id:
            self._log_to_database(flow_result, engagement_id, workspace)

        return flow_result

    # ------------------------------------------------------------------
    # Topological sort
    # ------------------------------------------------------------------

    @staticmethod
    def _topological_sort(steps: list[StepDefinition]) -> list[list[str]]:
        """Kahn's algorithm returning grouped execution levels.

        Each level contains steps whose dependencies are all in prior levels.
        Steps within a level can execute in parallel.
        """
        if not steps:
            return []

        id_set = {s.id for s in steps}
        in_degree: dict[str, int] = {s.id: 0 for s in steps}
        adj: dict[str, list[str]] = defaultdict(list)
        deps: dict[str, set[str]] = {s.id: set() for s in steps}

        for s in steps:
            for dep in s.depends_on:
                if dep in id_set:
                    adj[dep].append(s.id)
                    in_degree[s.id] += 1
                    deps[s.id].add(dep)

        # Build levels
        levels: list[list[str]] = []
        ready: deque[str] = deque(sid for sid, d in in_degree.items() if d == 0)
        visited: set[str] = set()

        while ready:
            current_level = list(ready)
            levels.append(current_level)
            ready.clear()
            for node in current_level:
                visited.add(node)
                for neighbor in adj[node]:
                    in_degree[neighbor] -= 1
                    if in_degree[neighbor] == 0:
                        ready.append(neighbor)

        if len(visited) != len(id_set):
            unvisited = id_set - visited
            raise ValueError(f"DAG cycle detected involving: {', '.join(unvisited)}")

        return levels

    # ------------------------------------------------------------------
    # Step group execution
    # ------------------------------------------------------------------

    def _execute_step_group(
        self,
        steps: list[StepDefinition],
        context: dict,
        workspace: str,
        engagement_id: int,
        state_store: FlowStateStore,
    ) -> dict[str, StepResult]:
        """Execute a group of independent steps, possibly in parallel."""
        results: dict[str, StepResult] = {}

        if len(steps) == 1:
            # Single step — run directly
            step = steps[0]
            result = self._run_single_step(step, context, workspace, engagement_id, state_store)
            results[step.id] = result
            return results

        # Multiple steps — run in parallel
        with ThreadPoolExecutor(max_workers=min(len(steps), self._max_parallel)) as pool:
            futures = {}
            for step in steps:
                fut = pool.submit(
                    self._run_single_step, step, context, workspace, engagement_id, state_store,
                )
                futures[fut] = step.id

            for fut in as_completed(futures):
                step_id = futures[fut]
                try:
                    results[step_id] = fut.result()
                except Exception as exc:
                    logger.error("Step '%s' raised exception: %s", step_id, exc)
                    results[step_id] = StepResult(
                        step_id=step_id,
                        status=StepStatus.FAILED.value,
                        success=False,
                        errors=[str(exc)],
                    )

        return results

    def _run_single_step(
        self,
        step: StepDefinition,
        context: dict,
        workspace: str,
        engagement_id: int,
        state_store: FlowStateStore,
    ) -> StepResult:
        """Run one step with state tracking and event emission."""
        self._emit_event("FLOW_STEP_START", {
            "step_id": step.id, "step_type": step.type,
        }, engagement_id)

        state_store.update_step_status(step.id, StepStatus.RUNNING.value)

        result = self._step_executor.execute_step(step, context, workspace, engagement_id)

        state_store.update_step_status(
            step.id,
            result.status,
            output=result.output,
            errors=result.errors,
            duration=result.duration_seconds,
            cost=result.cost_usd,
            attempt=result.attempt,
        )

        self._emit_event("FLOW_STEP_COMPLETE", {
            "step_id": step.id,
            "step_type": step.type,
            "success": result.success,
            "status": result.status,
            "duration": result.duration_seconds,
        }, engagement_id)

        return result

    # ------------------------------------------------------------------
    # Standalone workspace
    # ------------------------------------------------------------------

    def _setup_standalone_workspace(
        self, flow_def: FlowDefinition, flow_id: str, inputs: dict
    ) -> str:
        """Create standalone workspace with minimal SharedState for agents."""
        ws = _PROJECT_ROOT / "flow-workspaces" / flow_id
        for subdir in ("artifacts", "logs/raw", "logs/conversations", "loot"):
            (ws / subdir).mkdir(parents=True, exist_ok=True)

        # Initialize minimal SharedState so agents have a valid engagement context
        try:
            from memory.shared_state import SharedState
            shared = SharedState(str(ws))
            target = inputs.get("target", inputs.get("target_range", "flow-execution"))
            shared.initialize(
                target=str(target),
                scope=[str(target)],
                out_of_scope=[],
                methodology="flow",
            )
        except Exception as exc:
            logger.warning("Could not initialize SharedState for standalone flow: %s", exc)

        return str(ws)

    # ------------------------------------------------------------------
    # Context building
    # ------------------------------------------------------------------

    @staticmethod
    def _build_context(
        flow_def: FlowDefinition, inputs: dict, workspace: str, step_outputs: dict,
    ) -> dict:
        """Build the template context dict available to all steps."""
        return {
            "inputs": inputs,
            "steps": dict(step_outputs),
            "workspace": workspace,
            "engagement_dir": workspace,
            "now": datetime.now(timezone.utc),
            "flow": {
                "name": flow_def.metadata.name,
                "version": flow_def.metadata.version,
                "display_name": flow_def.metadata.display_name,
            },
            "trigger": {"type": flow_def.spec.trigger.type},
            "context": {},
            "env": {
                k: v for k, v in os.environ.items()
                if k.startswith("SNOWSTRIKE_")
            },
            # Sub-flow recursion tracking
            "_flow_depth": 0,
            "_flow_chain": [flow_def.metadata.name],
        }

    # ------------------------------------------------------------------
    # Output resolution
    # ------------------------------------------------------------------

    @staticmethod
    def _resolve_flow_outputs(flow_def: FlowDefinition, step_outputs: dict) -> dict:
        """Extract declared outputs from step results."""
        outputs = {}
        for name, out_def in flow_def.spec.outputs.items():
            if not out_def.source:
                continue
            # Source format: "step_id.field.path"
            parts = out_def.source.split(".", 1)
            step_id = parts[0]
            field_path = parts[1] if len(parts) > 1 else ""

            step_data = step_outputs.get(step_id)
            if step_data is None:
                continue

            if not field_path:
                outputs[name] = step_data
                continue

            # Walk the field path
            current = step_data
            for part in field_path.split("."):
                if isinstance(current, dict):
                    current = current.get(part)
                else:
                    current = None
                    break
            outputs[name] = current
        return outputs

    # ------------------------------------------------------------------
    # Event emission
    # ------------------------------------------------------------------

    @staticmethod
    def _log_to_database(result: FlowResult, engagement_id: int, workspace: str) -> None:
        """Log flow execution and step results to engagement database."""
        try:
            from memory.database import DatabaseManager
            db = DatabaseManager(workspace)
            flow_db_id = db.log_flow_execution(
                engagement_id=engagement_id,
                flow_id=result.flow_id,
                flow_name=result.flow_name,
                status=result.status,
                started_at=result.started_at,
                completed_at=result.completed_at,
                duration_seconds=result.duration_seconds,
                total_cost_usd=result.total_cost_usd,
                error=result.error,
                workspace=result.workspace,
            )
            for step_id, sr in result.step_results.items():
                summary = ""
                if sr.output:
                    s = sr.output.get("summary", "")
                    if not s:
                        s = str(sr.output)[:200]
                    summary = str(s)[:2000]
                db.log_flow_step(
                    flow_execution_id=flow_db_id,
                    step_id=step_id,
                    step_type=sr.output.get("step_type", "") if sr.output else "",
                    status=sr.status,
                    started_at=sr.started_at,
                    completed_at=sr.completed_at,
                    duration_seconds=sr.duration_seconds,
                    cost_usd=sr.cost_usd,
                    output_summary=summary,
                    error="; ".join(sr.errors) if sr.errors else "",
                )
        except Exception as exc:
            logger.debug("Failed to log flow to database: %s", exc)

    @staticmethod
    def _emit_event(event_type_name: str, data: dict, engagement_id: int = 0) -> None:
        """Emit a flow event to the event bus (best-effort)."""
        try:
            from memory.event_bus import get_event_bus, EventType, Event
            etype = getattr(EventType, event_type_name, EventType.STATUS)
            bus = get_event_bus()
            bus.emit(Event(
                type=etype,
                source="flow_engine",
                data=data,
                engagement_id=engagement_id,
            ))
        except Exception:
            pass

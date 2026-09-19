"""Flow definition validation — cycles, deps, agents, tools, required fields."""

from __future__ import annotations

import logging
from collections import defaultdict, deque
from typing import TYPE_CHECKING

from flows.schema import FlowDefinition, StepDefinition, StepType

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)

_MAX_STEPS = 30

_VALID_STEP_TYPES = {t.value for t in StepType}

_VALID_INPUT_TYPES = {"string", "integer", "boolean", "list", "dict"}


class FlowValidationError(Exception):
    def __init__(self, errors: list[str]):
        self.errors = errors
        super().__init__(f"{len(errors)} validation error(s): {'; '.join(errors)}")


def validate_flow(flow_def: FlowDefinition) -> list[str]:
    """Run all validation checks.  Returns list of error strings (empty = valid)."""
    errors: list[str] = []
    steps = flow_def.spec.steps

    errors.extend(_validate_metadata(flow_def))
    errors.extend(_validate_step_ids_unique(steps))
    errors.extend(_validate_step_types(steps))
    errors.extend(_validate_dependencies_exist(steps))
    errors.extend(_validate_dag_no_cycles(steps))
    errors.extend(_validate_required_fields(steps))
    errors.extend(_validate_agent_steps(steps))
    errors.extend(_validate_tool_steps(steps))
    errors.extend(_validate_inputs(flow_def))
    errors.extend(_validate_step_count(steps))
    return errors


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------

def _validate_metadata(flow_def: FlowDefinition) -> list[str]:
    errors = []
    if not flow_def.metadata.name or flow_def.metadata.name == "unnamed":
        errors.append("metadata.name is required")
    if flow_def.kind != "Flow":
        errors.append(f"kind must be 'Flow', got '{flow_def.kind}'")
    return errors


def _validate_step_ids_unique(steps: list[StepDefinition]) -> list[str]:
    seen: set[str] = set()
    dupes: list[str] = []
    for s in steps:
        if s.id in seen:
            dupes.append(f"Duplicate step ID: '{s.id}'")
        seen.add(s.id)
    return dupes


def _validate_step_types(steps: list[StepDefinition]) -> list[str]:
    errors = []
    for s in steps:
        if s.type not in _VALID_STEP_TYPES:
            errors.append(f"Step '{s.id}': unknown type '{s.type}'")
    return errors


def _validate_dependencies_exist(steps: list[StepDefinition]) -> list[str]:
    ids = {s.id for s in steps}
    errors = []
    for s in steps:
        for dep in s.depends_on:
            if dep not in ids:
                errors.append(f"Step '{s.id}': depends_on '{dep}' does not exist")
    return errors


def _validate_dag_no_cycles(steps: list[StepDefinition]) -> list[str]:
    """Kahn's algorithm for cycle detection."""
    if not steps:
        return []

    id_set = {s.id for s in steps}
    in_degree: dict[str, int] = {sid: 0 for sid in id_set}
    adj: dict[str, list[str]] = defaultdict(list)

    for s in steps:
        for dep in s.depends_on:
            if dep in id_set:
                adj[dep].append(s.id)
                in_degree[s.id] += 1

    queue: deque[str] = deque(sid for sid, d in in_degree.items() if d == 0)
    visited = 0

    while queue:
        node = queue.popleft()
        visited += 1
        for neighbor in adj[node]:
            in_degree[neighbor] -= 1
            if in_degree[neighbor] == 0:
                queue.append(neighbor)

    if visited != len(id_set):
        cycle_nodes = [sid for sid, d in in_degree.items() if d > 0]
        return [f"DAG cycle detected involving steps: {', '.join(cycle_nodes)}"]
    return []


def _validate_required_fields(steps: list[StepDefinition]) -> list[str]:
    errors = []
    for s in steps:
        if s.type == StepType.AGENT_DISPATCH.value:
            if not s.agent:
                errors.append(f"Step '{s.id}': agent_dispatch requires 'agent'")
            if not s.task:
                errors.append(f"Step '{s.id}': agent_dispatch requires 'task'")
        elif s.type == StepType.TOOL_EXEC.value:
            if not s.tool:
                errors.append(f"Step '{s.id}': tool_exec requires 'tool'")
        elif s.type == StepType.CONDITION.value:
            if not s.expression:
                errors.append(f"Step '{s.id}': condition requires 'expression'")
        elif s.type == StepType.TRANSFORM.value:
            if not s.operation:
                errors.append(f"Step '{s.id}': transform requires 'operation'")
        elif s.type == StepType.SAVE_ARTIFACT.value:
            if not s.path:
                errors.append(f"Step '{s.id}': save_artifact requires 'path'")
            if not s.content:
                errors.append(f"Step '{s.id}': save_artifact requires 'content'")
        elif s.type == StepType.SUB_FLOW.value:
            if not s.flow:
                errors.append(f"Step '{s.id}': sub_flow requires 'flow'")
        elif s.type == StepType.HTTP_REQUEST.value:
            if not s.url:
                errors.append(f"Step '{s.id}': http_request requires 'url'")
        elif s.type == StepType.TEMPLATE_RENDER.value:
            if not s.template:
                errors.append(f"Step '{s.id}': template_render requires 'template'")
        elif s.type == StepType.PARALLEL_FORK.value:
            if not s.branches:
                errors.append(f"Step '{s.id}': parallel_fork requires 'branches'")
        elif s.type == StepType.WAIT_FOR_EVENT.value:
            if not s.event_type_wait:
                errors.append(f"Step '{s.id}': wait_for_event requires 'event_type'")
    return errors


def _validate_agent_steps(steps: list[StepDefinition]) -> list[str]:
    """Check that agent types referenced in agent_dispatch steps exist."""
    agent_steps = [s for s in steps if s.type == StepType.AGENT_DISPATCH.value]
    if not agent_steps:
        return []

    errors = []
    try:
        from agents.registry import AgentRegistry
        from pathlib import Path

        config_dir = Path(__file__).parent.parent / "agent-configs"
        registry = AgentRegistry(config_dir)
        registry.load_all()
        available = set(registry.get_agent_classes().keys())
    except Exception:
        logger.debug("Could not load AgentRegistry for validation, skipping agent checks")
        return []

    for s in agent_steps:
        if s.agent not in available:
            errors.append(
                f"Step '{s.id}': agent '{s.agent}' not found in registry "
                f"(available: {', '.join(sorted(available))})"
            )
    return errors


def _validate_tool_steps(steps: list[StepDefinition]) -> list[str]:
    """Check that tool names referenced in tool_exec steps exist."""
    tool_steps = [s for s in steps if s.type == StepType.TOOL_EXEC.value]
    if not tool_steps:
        return []

    errors = []
    try:
        from tools.definitions import COMMAND_BUILDERS
        available = set(COMMAND_BUILDERS.keys())
    except Exception:
        logger.debug("Could not load COMMAND_BUILDERS for validation, skipping tool checks")
        return []

    # Also try the YAML-based registry
    try:
        from tools.registry_loader import get_registry
        yaml_registry = get_registry()
        yaml_defs = yaml_registry.get_all_definitions()
        available.update(d["name"] for d in yaml_defs)
    except Exception:
        pass

    for s in tool_steps:
        if s.tool not in available:
            errors.append(
                f"Step '{s.id}': tool '{s.tool}' not found"
            )
    return errors


def _validate_inputs(flow_def: FlowDefinition) -> list[str]:
    errors = []
    for name, inp in flow_def.spec.inputs.items():
        if inp.type not in _VALID_INPUT_TYPES:
            errors.append(
                f"Input '{name}': invalid type '{inp.type}' "
                f"(valid: {', '.join(_VALID_INPUT_TYPES)})"
            )
    return errors


def _validate_step_count(steps: list[StepDefinition]) -> list[str]:
    if len(steps) > _MAX_STEPS:
        return [f"Flow has {len(steps)} steps (max {_MAX_STEPS})"]
    return []

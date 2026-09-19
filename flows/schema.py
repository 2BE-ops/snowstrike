"""Flow data models — definitions, results, and YAML parsing."""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class FlowStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    CANCELLED = "cancelled"


class StepStatus(str, Enum):
    PENDING = "pending"
    READY = "ready"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    SKIPPED = "skipped"


class StepType(str, Enum):
    AGENT_DISPATCH = "agent_dispatch"
    TOOL_EXEC = "tool_exec"
    CONDITION = "condition"
    TRANSFORM = "transform"
    SAVE_ARTIFACT = "save_artifact"
    SUB_FLOW = "sub_flow"
    HTTP_REQUEST = "http_request"
    TEMPLATE_RENDER = "template_render"
    PARALLEL_FORK = "parallel_fork"
    WAIT_FOR_EVENT = "wait_for_event"


class FailureStrategy(str, Enum):
    STOP = "stop"
    SKIP_FAILED = "skip_failed"
    RETRY_FAILED = "retry_failed"


# ---------------------------------------------------------------------------
# Config dataclasses
# ---------------------------------------------------------------------------

@dataclass
class InputDefinition:
    name: str
    type: str = "string"
    required: bool = False
    default: Any = None
    description: str = ""


@dataclass
class OutputDefinition:
    name: str
    type: str = "string"
    source: str = ""
    description: str = ""


@dataclass
class RetryConfig:
    max_attempts: int = 1
    delay_seconds: int = 5
    backoff_multiplier: float = 2.0


@dataclass
class FailureConfig:
    strategy: str = "stop"
    notify: bool = True
    max_retries: int = 1
    fallback_flow: str = ""


@dataclass
class TriggerConfig:
    type: str = "manual"

    # Event trigger fields
    event_type: str = ""
    filter: dict = field(default_factory=dict)
    debounce_seconds: int = 30
    max_concurrent_runs: int = 1

    # Schedule trigger fields
    cron: str = ""
    one_shot: str = ""
    timezone: str = ""
    catch_up: bool = False

    # Agent request trigger fields
    handoff_type: str = "flow_request"
    source_agents: list[str] = field(default_factory=list)
    min_confidence: float = 0.6


# ---------------------------------------------------------------------------
# Step definition — union of all step-type fields
# ---------------------------------------------------------------------------

@dataclass
class StepDefinition:
    id: str
    type: str
    depends_on: list[str] = field(default_factory=list)
    when: str = ""
    timeout: int = 0
    retry: Optional[RetryConfig] = None
    on_failure: str = ""

    # agent_dispatch
    agent: str = ""
    task: str = ""
    model_override: str = ""
    max_turns: int = 0
    inject_context: dict = field(default_factory=dict)
    capture: dict = field(default_factory=dict)

    # tool_exec
    tool: str = ""
    args: dict = field(default_factory=dict)
    capture_output: bool = True
    compact_output: bool = True

    # condition
    expression: str = ""

    # transform
    operation: str = ""
    sources: list[str] = field(default_factory=list)
    params: dict = field(default_factory=dict)

    # save_artifact
    path: str = ""
    content: str = ""
    mode: str = "write"
    format: str = "raw"

    # sub_flow
    flow: str = ""
    inputs_map: dict = field(default_factory=dict)
    inherit_context: bool = False

    # http_request
    method: str = "GET"
    url: str = ""
    headers: dict = field(default_factory=dict)
    body: str = ""
    expected_status: list[int] = field(default_factory=lambda: [200, 201, 204])
    capture_response: bool = True

    # template_render
    template: str = ""
    vars: dict = field(default_factory=dict)
    output_format: str = "text"

    # parallel_fork
    branches: list[str] = field(default_factory=list)
    join: str = "all"

    # wait_for_event
    event_type_wait: str = ""
    event_filter: dict = field(default_factory=dict)
    event_capture: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Flow definition
# ---------------------------------------------------------------------------

@dataclass
class FlowMetadata:
    name: str
    version: int = 1
    display_name: str = ""
    description: str = ""
    author: str = ""
    tags: list[str] = field(default_factory=list)
    category: str = "custom"


@dataclass
class FlowSpec:
    trigger: TriggerConfig = field(default_factory=TriggerConfig)
    execution_mode: str = "standalone"
    inputs: dict[str, InputDefinition] = field(default_factory=dict)
    outputs: dict[str, OutputDefinition] = field(default_factory=dict)
    timeout: int = 3600
    cost_budget: float = 0.0
    on_failure: FailureConfig = field(default_factory=FailureConfig)
    steps: list[StepDefinition] = field(default_factory=list)


@dataclass
class FlowDefinition:
    api_version: str = "snowstrike/v1"
    kind: str = "Flow"
    metadata: FlowMetadata = field(default_factory=lambda: FlowMetadata(name="unnamed"))
    spec: FlowSpec = field(default_factory=FlowSpec)

    def to_dict(self) -> dict:
        from dataclasses import asdict
        return asdict(self)


# ---------------------------------------------------------------------------
# Result dataclasses
# ---------------------------------------------------------------------------

@dataclass
class StepResult:
    step_id: str
    status: str
    success: bool
    output: dict = field(default_factory=dict)
    duration_seconds: float = 0.0
    errors: list[str] = field(default_factory=list)
    attempt: int = 1
    started_at: str = ""
    completed_at: str = ""
    cost_usd: float = 0.0

    def to_dict(self) -> dict:
        from dataclasses import asdict
        return asdict(self)


@dataclass
class FlowResult:
    flow_id: str
    flow_name: str
    status: str
    started_at: str = ""
    completed_at: str = ""
    duration_seconds: float = 0.0
    inputs: dict = field(default_factory=dict)
    step_results: dict[str, StepResult] = field(default_factory=dict)
    outputs: dict = field(default_factory=dict)
    total_cost_usd: float = 0.0
    error: str = ""
    workspace: str = ""

    def to_dict(self) -> dict:
        d = {
            "flow_id": self.flow_id,
            "flow_name": self.flow_name,
            "status": self.status,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "duration_seconds": self.duration_seconds,
            "inputs": self.inputs,
            "step_results": {k: v.to_dict() for k, v in self.step_results.items()},
            "outputs": self.outputs,
            "total_cost_usd": self.total_cost_usd,
            "error": self.error,
            "workspace": self.workspace,
        }
        return d


# ---------------------------------------------------------------------------
# YAML parser
# ---------------------------------------------------------------------------

def _parse_retry(raw: dict | None) -> Optional[RetryConfig]:
    if not raw:
        return None
    return RetryConfig(
        max_attempts=raw.get("max_attempts", 1),
        delay_seconds=raw.get("delay_seconds", 5),
        backoff_multiplier=raw.get("backoff_multiplier", 2.0),
    )


def _parse_step(raw: dict) -> StepDefinition:
    return StepDefinition(
        id=raw["id"],
        type=raw["type"],
        depends_on=raw.get("depends_on", []),
        when=raw.get("when", ""),
        timeout=raw.get("timeout", 0),
        retry=_parse_retry(raw.get("retry")),
        on_failure=raw.get("on_failure", ""),
        # agent_dispatch
        agent=raw.get("agent", ""),
        task=raw.get("task", ""),
        model_override=raw.get("model_override", ""),
        max_turns=raw.get("max_turns", 0),
        inject_context=raw.get("inject_context", {}),
        capture=raw.get("capture", {}),
        # tool_exec
        tool=raw.get("tool", ""),
        args=raw.get("args", {}),
        capture_output=raw.get("capture_output", True),
        compact_output=raw.get("compact_output", True),
        # condition
        expression=raw.get("expression", ""),
        # transform
        operation=raw.get("operation", ""),
        sources=raw.get("sources", []),
        params=raw.get("params", {}),
        # save_artifact
        path=raw.get("path", ""),
        content=raw.get("content", ""),
        mode=raw.get("mode", "write"),
        format=raw.get("format", "raw"),
        # sub_flow
        flow=raw.get("flow", ""),
        inputs_map=raw.get("inputs", {}) if raw.get("type") == "sub_flow" else {},
        inherit_context=raw.get("inherit_context", False),
        # http_request
        method=raw.get("method", "GET"),
        url=raw.get("url", ""),
        headers=raw.get("headers", {}),
        body=raw.get("body", ""),
        expected_status=raw.get("expected_status", [200, 201, 204]),
        capture_response=raw.get("capture_response", True),
        # template_render
        template=raw.get("template", ""),
        vars=raw.get("vars", {}),
        output_format=raw.get("output_format", "text"),
        # parallel_fork
        branches=raw.get("branches", []),
        join=raw.get("join", "all"),
        # wait_for_event
        event_type_wait=raw.get("event_type", "") if raw.get("type") == "wait_for_event" else "",
        event_filter=raw.get("filter", {}) if raw.get("type") == "wait_for_event" else {},
        event_capture=raw.get("capture", []) if raw.get("type") == "wait_for_event" else [],
    )


def _parse_inputs(raw: dict | None) -> dict[str, InputDefinition]:
    if not raw:
        return {}
    result = {}
    for name, spec in raw.items():
        if isinstance(spec, dict):
            result[name] = InputDefinition(
                name=name,
                type=spec.get("type", "string"),
                required=spec.get("required", False),
                default=spec.get("default"),
                description=spec.get("description", ""),
            )
        else:
            result[name] = InputDefinition(name=name, default=spec)
    return result


def _parse_outputs(raw: dict | None) -> dict[str, OutputDefinition]:
    if not raw:
        return {}
    result = {}
    for name, spec in raw.items():
        if isinstance(spec, dict):
            result[name] = OutputDefinition(
                name=name,
                type=spec.get("type", "string"),
                source=spec.get("source", ""),
                description=spec.get("description", ""),
            )
        else:
            result[name] = OutputDefinition(name=name, source=str(spec))
    return result


def parse_flow_yaml(data: dict) -> FlowDefinition:
    """Convert a raw YAML dict into a FlowDefinition."""
    meta_raw = data.get("metadata", {})
    spec_raw = data.get("spec", {})

    metadata = FlowMetadata(
        name=meta_raw.get("name", "unnamed"),
        version=meta_raw.get("version", 1),
        display_name=meta_raw.get("display_name", meta_raw.get("name", "")),
        description=meta_raw.get("description", ""),
        author=meta_raw.get("author", ""),
        tags=meta_raw.get("tags", []),
        category=meta_raw.get("category", "custom"),
    )

    trigger_raw = spec_raw.get("trigger", {})
    trigger = TriggerConfig(
        type=trigger_raw.get("type", "manual"),
        event_type=trigger_raw.get("event_type", ""),
        filter=trigger_raw.get("filter", {}),
        debounce_seconds=trigger_raw.get("debounce_seconds", 30),
        max_concurrent_runs=trigger_raw.get("max_concurrent_runs", 1),
        cron=trigger_raw.get("cron", ""),
        one_shot=trigger_raw.get("one_shot", ""),
        timezone=trigger_raw.get("timezone", ""),
        catch_up=trigger_raw.get("catch_up", False),
        handoff_type=trigger_raw.get("handoff_type", "flow_request"),
        source_agents=trigger_raw.get("source_agents", []),
        min_confidence=trigger_raw.get("min_confidence", 0.6),
    )

    failure_raw = spec_raw.get("on_failure", {})
    on_failure = FailureConfig(
        strategy=failure_raw.get("strategy", "stop"),
        notify=failure_raw.get("notify", True),
        max_retries=failure_raw.get("max_retries", 1),
        fallback_flow=failure_raw.get("fallback_flow", ""),
    )

    steps = [_parse_step(s) for s in spec_raw.get("steps", [])]

    spec = FlowSpec(
        trigger=trigger,
        execution_mode=spec_raw.get("execution_mode", "standalone"),
        inputs=_parse_inputs(spec_raw.get("inputs")),
        outputs=_parse_outputs(spec_raw.get("outputs")),
        timeout=spec_raw.get("timeout", 3600),
        cost_budget=spec_raw.get("cost_budget", 0.0),
        on_failure=on_failure,
        steps=steps,
    )

    return FlowDefinition(
        api_version=data.get("apiVersion", "snowstrike/v1"),
        kind=data.get("kind", "Flow"),
        metadata=metadata,
        spec=spec,
    )

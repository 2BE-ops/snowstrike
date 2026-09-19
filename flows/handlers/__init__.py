"""Step handler registry."""

from flows.handlers.agent_handler import AgentStepHandler
from flows.handlers.tool_handler import ToolStepHandler
from flows.handlers.condition_handler import ConditionStepHandler
from flows.handlers.transform_handler import TransformStepHandler
from flows.handlers.artifact_handler import ArtifactStepHandler
from flows.handlers.subflow_handler import SubFlowStepHandler
from flows.handlers.http_handler import HttpRequestStepHandler
from flows.handlers.template_handler import TemplateRenderStepHandler
from flows.handlers.parallel_fork_handler import ParallelForkStepHandler
from flows.handlers.wait_event_handler import WaitForEventStepHandler

STEP_HANDLERS: dict[str, type] = {
    "agent_dispatch": AgentStepHandler,
    "tool_exec": ToolStepHandler,
    "condition": ConditionStepHandler,
    "transform": TransformStepHandler,
    "save_artifact": ArtifactStepHandler,
    "sub_flow": SubFlowStepHandler,
    "http_request": HttpRequestStepHandler,
    "template_render": TemplateRenderStepHandler,
    "parallel_fork": ParallelForkStepHandler,
    "wait_for_event": WaitForEventStepHandler,
}

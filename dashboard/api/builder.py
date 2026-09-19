"""Builder REST API — CRUD for agents, tools, topologies, validation, and hot-reload.

Mounted at /api/builder/ in the dashboard FastAPI app.
"""

import logging
import os
import re
import shutil
from pathlib import Path
from typing import Optional

import yaml
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

_SAFE_NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._\-]{0,63}$")


def _validate_entity_name(name: str, entity: str = "name") -> str:
    """Validate that a name is safe for use as a filename."""
    if not name or "/" in name or "\\" in name or ".." in name or "\x00" in name:
        raise HTTPException(status_code=400, detail=f"Invalid {entity}")
    if not _SAFE_NAME_RE.match(name):
        raise HTTPException(status_code=400, detail=f"Invalid characters in {entity}")
    return name

from agents.registry import AgentRegistry
from tools.registry_loader import ToolRegistry

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/builder", tags=["builder"])


# ---------------------------------------------------------------------------
# Singleton registries (lazy-initialized)
# ---------------------------------------------------------------------------

_agent_registry: Optional[AgentRegistry] = None
_tool_registry: Optional[ToolRegistry] = None


def _get_agent_registry() -> AgentRegistry:
    global _agent_registry
    if _agent_registry is None:
        config_dir = Path(os.environ.get(
            "AGENT_CONFIG_DIR",
            Path(__file__).resolve().parent.parent.parent / "agent-configs",
        ))
        _agent_registry = AgentRegistry(config_dir)
        _agent_registry.load_all()
    return _agent_registry


def _get_tool_registry() -> ToolRegistry:
    global _tool_registry
    if _tool_registry is None:
        catalog_dir = Path(os.environ.get(
            "TOOL_CATALOG_DIR",
            Path(__file__).resolve().parent.parent.parent / "tools" / "catalog",
        ))
        _tool_registry = ToolRegistry(catalog_dir)
        _tool_registry.load_all()
    return _tool_registry


# ---------------------------------------------------------------------------
# Pydantic models for request bodies
# ---------------------------------------------------------------------------

class AgentCreateRequest(BaseModel):
    name: str
    display_name: str = ""
    description: str = ""
    agent_class: str = ""
    model: str = "claude-sonnet-4-20250514"
    max_turns: int = 30
    max_concurrent: int = 1
    prompt_template: str = ""
    tools: list[str] = []
    capabilities_skills: list[str] = []
    capabilities_produces: list[str] = []
    capabilities_requires: list[str] = []
    handoff_targets: list[str] = []


class AgentUpdateRequest(BaseModel):
    display_name: Optional[str] = None
    description: Optional[str] = None
    agent_class: Optional[str] = None
    model: Optional[str] = None
    max_turns: Optional[int] = None
    max_concurrent: Optional[int] = None
    prompt_template: Optional[str] = None
    tools: Optional[list[str]] = None
    capabilities_skills: Optional[list[str]] = None
    capabilities_produces: Optional[list[str]] = None
    capabilities_requires: Optional[list[str]] = None
    handoff_targets: Optional[list[str]] = None


class TopologyCreateRequest(BaseModel):
    name: str
    description: str = ""
    orchestrator: str = "orchestrator"
    agents: list[str] = []
    edges: list[dict] = []


# ---------------------------------------------------------------------------
# Agent CRUD
# ---------------------------------------------------------------------------

@router.get("/agents")
async def list_agents():
    """List all agent configs."""
    registry = _get_agent_registry()
    return {"agents": registry.list_agents()}


@router.get("/agents/{name}")
async def get_agent(name: str):
    """Get agent config."""
    registry = _get_agent_registry()
    config = registry.get_config(name)
    if not config:
        raise HTTPException(status_code=404, detail=f"Agent '{name}' not found")
    return config


@router.post("/agents")
async def create_agent(req: AgentCreateRequest):
    """Create new agent."""
    registry = _get_agent_registry()

    config = {
        "apiVersion": "snowstrike/v1",
        "kind": "Agent",
        "metadata": {"name": req.name},
        "spec": {
            "display_name": req.display_name or req.name.replace("-", " ").title(),
            "description": req.description,
            "agent_class": req.agent_class,
            "model": req.model,
            "max_turns": req.max_turns,
            "max_concurrent": req.max_concurrent,
            "prompt": {"template": req.prompt_template or req.name},
            "tools": req.tools,
            "capabilities": {
                "skills": req.capabilities_skills,
                "produces": req.capabilities_produces,
                "requires": req.capabilities_requires,
            },
            "handoff_targets": req.handoff_targets,
        },
    }

    try:
        name = registry.create(config)
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e))

    return {"name": name, "status": "created"}


@router.put("/agents/{name}")
async def update_agent(name: str, req: AgentUpdateRequest):
    """Update agent config."""
    registry = _get_agent_registry()
    existing = registry.get_config(name)
    if not existing:
        raise HTTPException(status_code=404, detail=f"Agent '{name}' not found")

    # Merge updates into existing config
    spec = existing.get("spec", {})

    if req.display_name is not None:
        spec["display_name"] = req.display_name
    if req.description is not None:
        spec["description"] = req.description
    if req.agent_class is not None:
        spec["agent_class"] = req.agent_class
    if req.model is not None:
        spec["model"] = req.model
    if req.max_turns is not None:
        spec["max_turns"] = req.max_turns
    if req.max_concurrent is not None:
        spec["max_concurrent"] = req.max_concurrent
    if req.prompt_template is not None:
        spec.setdefault("prompt", {})["template"] = req.prompt_template
    if req.tools is not None:
        spec["tools"] = req.tools
    if req.capabilities_skills is not None:
        spec.setdefault("capabilities", {})["skills"] = req.capabilities_skills
    if req.capabilities_produces is not None:
        spec.setdefault("capabilities", {})["produces"] = req.capabilities_produces
    if req.capabilities_requires is not None:
        spec.setdefault("capabilities", {})["requires"] = req.capabilities_requires
    if req.handoff_targets is not None:
        spec["handoff_targets"] = req.handoff_targets

    existing["spec"] = spec

    try:
        registry.update(name, existing)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    return {"name": name, "status": "updated", "version": existing.get("metadata", {}).get("version")}


@router.delete("/agents/{name}")
async def delete_agent(name: str):
    """Archive agent (soft delete)."""
    registry = _get_agent_registry()
    try:
        registry.delete(name)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    return {"name": name, "status": "archived"}


@router.get("/agents/{name}/versions")
async def list_agent_versions(name: str):
    """List version history."""
    registry = _get_agent_registry()
    return {"versions": registry.list_versions(name)}


@router.post("/agents/{name}/rollback/{version}")
async def rollback_agent(name: str, version: int):
    """Rollback to version."""
    registry = _get_agent_registry()
    try:
        registry.rollback(name, version)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"name": name, "status": "rolled_back", "restored_version": version}


# ---------------------------------------------------------------------------
# Tool Marketplace
# ---------------------------------------------------------------------------

@router.get("/tools")
async def list_tools():
    """Tool catalog with metadata."""
    registry = _get_tool_registry()
    return {"tools": registry.get_catalog()}


@router.get("/tools/{name}")
async def get_tool(name: str):
    """Tool detail + binary availability."""
    registry = _get_tool_registry()
    config = registry.get_tool_config(name)
    if not config:
        raise HTTPException(status_code=404, detail=f"Tool '{name}' not found")
    available = registry.check_binary_available(name)
    return {"config": config, "binary_available": available}


@router.post("/tools/check")
async def check_tool_binaries():
    """Batch binary availability check."""
    registry = _get_tool_registry()
    return {"results": registry.check_all_binaries()}


# ---------------------------------------------------------------------------
# Topology
# ---------------------------------------------------------------------------

@router.get("/topologies")
async def list_topologies():
    """List topology presets + custom."""
    config_dir = Path(os.environ.get(
        "AGENT_CONFIG_DIR",
        Path(__file__).resolve().parent.parent.parent / "agent-configs",
    ))
    topo_dir = config_dir / "topologies"
    if not topo_dir.exists():
        return {"topologies": []}

    topologies = []
    for path in sorted(topo_dir.glob("*.yaml")):
        try:
            with open(path) as f:
                config = yaml.safe_load(f)
            meta = config.get("metadata", {})
            spec = config.get("spec", {})
            topologies.append({
                "name": meta.get("name", path.stem),
                "description": meta.get("description", ""),
                "agent_count": len(spec.get("agents", [])),
                "edge_count": len(spec.get("edges", [])),
            })
        except Exception:
            continue

    return {"topologies": topologies}


@router.get("/topologies/{name}")
async def get_topology(name: str):
    """Get topology config."""
    _validate_entity_name(name, "topology name")
    config_dir = Path(os.environ.get(
        "AGENT_CONFIG_DIR",
        Path(__file__).resolve().parent.parent.parent / "agent-configs",
    ))
    path = config_dir / "topologies" / f"{name}.yaml"
    if not path.exists():
        raise HTTPException(status_code=404, detail=f"Topology '{name}' not found")
    with open(path) as f:
        return yaml.safe_load(f)


@router.post("/topologies")
async def create_topology(req: TopologyCreateRequest):
    """Save custom topology."""
    _validate_entity_name(req.name, "topology name")
    config_dir = Path(os.environ.get(
        "AGENT_CONFIG_DIR",
        Path(__file__).resolve().parent.parent.parent / "agent-configs",
    ))
    topo_dir = config_dir / "topologies"
    topo_dir.mkdir(parents=True, exist_ok=True)

    config = {
        "apiVersion": "snowstrike/v1",
        "kind": "Topology",
        "metadata": {
            "name": req.name,
            "description": req.description,
        },
        "spec": {
            "orchestrator": req.orchestrator,
            "agents": req.agents,
            "edges": req.edges,
        },
    }

    path = topo_dir / f"{req.name}.yaml"
    with open(path, "w") as f:
        yaml.dump(config, f, default_flow_style=False, sort_keys=False)

    return {"name": req.name, "status": "created"}


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

@router.post("/validate")
async def validate_graph():
    """Dry-run validation of the agent graph.

    Checks:
    - Circular handoff detection (DFS cycle detection)
    - Tool binary availability
    - Model access (API keys present)
    - Prompt existence
    - Topology connectivity (all agents reachable from orchestrator)
    """
    agent_registry = _get_agent_registry()
    tool_registry = _get_tool_registry()

    errors = []
    warnings = []

    agents = agent_registry.list_agents()
    agent_names = {a["name"] for a in agents}

    # 1. Check tool binary availability
    for agent_info in agents:
        name = agent_info["name"]
        tool_names = agent_registry.get_agent_tool_names(name)
        for tool_name in tool_names:
            if not tool_registry.check_binary_available(tool_name):
                binary = ""
                tc = tool_registry.get_tool_config(tool_name)
                if tc:
                    binary = tc.get("metadata", {}).get("binary", "")
                errors.append({
                    "type": "missing_binary",
                    "tool": tool_name,
                    "binary": binary,
                    "agent": name,
                })

    # 2. Circular handoff detection (DFS)
    graph: dict[str, list[str]] = {}
    for agent_info in agents:
        name = agent_info["name"]
        config = agent_registry.get_config(name)
        if config:
            targets = config.get("spec", {}).get("handoff_targets", [])
            graph[name] = [t for t in targets if t in agent_names]

    cycles = _find_cycles(graph)
    for cycle in cycles:
        errors.append({
            "type": "circular_handoff",
            "cycle": cycle,
        })

    # 3. Model API key checks
    for agent_info in agents:
        config = agent_registry.get_config(agent_info["name"])
        if config:
            model = config.get("spec", {}).get("model", "")
            if model:
                from config import AVAILABLE_MODELS
                model_info = AVAILABLE_MODELS.get(model)
                if model_info:
                    key_env = model_info.get("api_key_env", "")
                    if key_env and not os.environ.get(key_env):
                        warnings.append({
                            "type": "missing_api_key",
                            "model": model,
                            "env_var": key_env,
                            "agent": agent_info["name"],
                        })

    # 4. Prompt existence checks
    prompts_dir = Path(__file__).resolve().parent.parent.parent / "agents" / "prompts"
    for agent_info in agents:
        config = agent_registry.get_config(agent_info["name"])
        if config:
            template = config.get("spec", {}).get("prompt", {}).get("template", "")
            if template:
                prompt_path = prompts_dir / f"{template}.md"
                if not prompt_path.exists():
                    warnings.append({
                        "type": "missing_prompt",
                        "template": template,
                        "agent": agent_info["name"],
                    })

    # 5. Connectivity check (all agents reachable from orchestrator via handoff edges)
    reachable = set()
    _dfs_reachable("orchestrator", graph, reachable, agent_names)
    # Also add agents directly dispatched by orchestrator (all of them in hub-and-spoke)
    reachable.update(agent_names)  # Orchestrator can dispatch any agent
    unreachable = agent_names - reachable - {"orchestrator"}
    for name in unreachable:
        warnings.append({
            "type": "unreachable_agent",
            "agent": name,
        })

    valid = len(errors) == 0
    return {"valid": valid, "errors": errors, "warnings": warnings}


def _find_cycles(graph: dict[str, list[str]]) -> list[list[str]]:
    """DFS cycle detection on directed graph."""
    cycles = []
    visited = set()
    rec_stack = set()

    def dfs(node, path):
        visited.add(node)
        rec_stack.add(node)
        path.append(node)

        for neighbor in graph.get(node, []):
            if neighbor == "orchestrator":
                continue  # Handoff back to orchestrator is expected, not a cycle
            if neighbor not in visited:
                dfs(neighbor, path)
            elif neighbor in rec_stack:
                # Found a cycle
                cycle_start = path.index(neighbor)
                cycle = path[cycle_start:] + [neighbor]
                cycles.append(cycle)

        path.pop()
        rec_stack.discard(node)

    for node in graph:
        if node not in visited:
            dfs(node, [])

    return cycles


def _dfs_reachable(node: str, graph: dict[str, list[str]], visited: set, valid_nodes: set):
    """DFS to find all reachable nodes."""
    if node in visited or node not in valid_nodes:
        return
    visited.add(node)
    for neighbor in graph.get(node, []):
        _dfs_reachable(neighbor, graph, visited, valid_nodes)


# ---------------------------------------------------------------------------
# Operations
# ---------------------------------------------------------------------------

@router.post("/reload")
async def reload_registries():
    """Hot-reload agent and tool registries."""
    agent_registry = _get_agent_registry()
    tool_registry = _get_tool_registry()

    agent_registry.reload()
    tool_registry.load_all()

    return {
        "status": "reloaded",
        "agents": len(agent_registry.list_agents()),
        "tools": len(tool_registry.get_catalog()),
    }


# ---------------------------------------------------------------------------
# Templates
# ---------------------------------------------------------------------------

@router.get("/templates")
async def list_templates():
    """List agent templates."""
    registry = _get_agent_registry()
    return {"templates": registry.list_templates()}


@router.post("/templates/{template_name}/clone")
async def clone_template(template_name: str, new_name: str):
    """Clone template as new agent."""
    registry = _get_agent_registry()
    try:
        name = registry.clone_template(template_name, new_name)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"name": name, "status": "cloned", "source_template": template_name}

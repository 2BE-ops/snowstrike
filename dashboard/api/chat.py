import json
import logging
import os
import threading
from dataclasses import asdict, is_dataclass
from typing import Any

import anthropic
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from config import ANTHROPIC_API_KEY, MODELS
from agents.orchestrator import OrchestratorAgent
from agents.model_client import create_model_client, resolve_model_for_role
from memory.database import DatabaseManager
from memory.chat_compactor import (
    run_compaction,
    build_compacted_messages,
    get_compaction_info,
    get_compaction_state,
    set_compaction_enabled,
)

# Track background autonomous runs per engagement
_autonomous_runs: dict[str, dict] = {}
_AUTONOMOUS_STATE_FILE = "autonomous_state.json"

logger = logging.getLogger(__name__)


def _classify_and_sanitize_chat(text: str) -> tuple[str, bool]:
    """Check if dashboard chat response is a model refusal.

    Returns (sanitized_text, was_refusal).
    """
    from agents.base_agent import classify_refusal
    refusal_class = classify_refusal(text, tools_were_used=False)
    if refusal_class:
        return (
            "The AI model declined this request. Try rephrasing or adjusting scope.",
            True,
        )
    return text, False


def _log_chat_refusal(eng_dir: str, model: str, raw_text: str):
    """Append a refusal audit record for dashboard chat."""
    import fcntl
    from datetime import datetime

    log_dir = os.path.join(eng_dir, "logs")
    os.makedirs(log_dir, exist_ok=True)

    record = {
        "timestamp": datetime.now().isoformat(),
        "agent_type": "dashboard_chat",
        "agent_name": "dashboard_chat",
        "model": model,
        "provider": "unknown",
        "refusal_excerpt": raw_text[:300],
        "refusal_class": "chat",
    }

    refusal_path = os.path.join(log_dir, "model_refusals.jsonl")
    try:
        with open(refusal_path, "a") as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            try:
                f.write(json.dumps(record, default=str) + "\n")
            finally:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)
    except Exception as e:
        logger.error(f"Failed to write chat refusal audit: {e}")


def _save_autonomous_state(eng_dir: str, eng_key: str, status: str, result: Any = None):
    """Persist autonomous run state to disk so it survives dashboard restarts."""
    state_path = os.path.join(eng_dir, _AUTONOMOUS_STATE_FILE)
    state = {
        "status": status,
        "eng_key": eng_key,
        "started_at": _autonomous_runs.get(eng_key, {}).get("started_at"),
        "result": result if isinstance(result, (dict, type(None))) else str(result),
    }
    try:
        with open(state_path, "w") as f:
            json.dump(state, f, indent=2, default=str)
    except Exception as e:
        logger.warning(f"Failed to save autonomous state: {e}")


def _load_autonomous_state(eng_dir: str) -> dict | None:
    """Load persisted autonomous state from disk."""
    state_path = os.path.join(eng_dir, _AUTONOMOUS_STATE_FILE)
    if os.path.exists(state_path):
        try:
            with open(state_path) as f:
                return json.load(f)
        except Exception:
            pass
    return None


def _load_chat_history(history_file: str) -> list[dict]:
    """Read chat history with a shared file lock."""
    if not os.path.exists(history_file):
        return []
    try:
        import fcntl
        with open(history_file, "r") as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_SH)
            try:
                return json.load(f)
            finally:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)
    except Exception as e:
        logger.error(f"Failed to load chat history: {e}")
        return []


def _save_chat_history(history_file: str, messages: list[dict]) -> None:
    """Persist chat history atomically so refreshes never lose committed turns."""
    import fcntl

    os.makedirs(os.path.dirname(history_file), exist_ok=True)
    tmp_path = history_file + ".tmp"
    lock_path = history_file + ".lock"

    with open(lock_path, "w") as lock_file:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        try:
            with open(tmp_path, "w") as f:
                json.dump(messages, f, indent=2, default=str)
                f.write("\n")
            os.replace(tmp_path, history_file)
        finally:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


def _cleanup_incomplete_assistant_turn(messages: list[dict]) -> list[dict]:
    """Remove unfinished tool calls while preserving any assistant text already produced."""
    if not messages:
        return messages
    last = messages[-1]
    if last.get("role") != "assistant":
        return messages
    content = last.get("content")
    if not isinstance(content, list):
        return messages
    has_tool_use = any(
        isinstance(block, dict) and (
            block.get("type") == "tool_use" or
            _provider_message_has_tool_calls(block)
        )
        for block in content
    )
    if not has_tool_use:
        return messages

    preserved = [
        block for block in content
        if isinstance(block, dict)
        and block.get("type") != "tool_use"
        and not _provider_message_has_tool_calls(block)
    ]
    if preserved:
        messages[-1] = {**last, "content": preserved}
    else:
        messages.pop()
    return messages


def _provider_message_has_tool_calls(block: dict) -> bool:
    """Check whether a preserved provider message still contains tool calls."""
    if block.get("type") != "provider_assistant_message":
        return False
    message = block.get("message")
    return isinstance(message, dict) and bool(message.get("tool_calls"))


def _assistant_has_preserved_provider_message(msg: dict) -> bool:
    """Return True if an assistant turn includes the lossless provider payload."""
    if msg.get("role") != "assistant":
        return False
    content = msg.get("content")
    if not isinstance(content, list):
        return False
    return any(
        isinstance(block, dict) and block.get("type") == "provider_assistant_message"
        for block in content
    )


def _repair_legacy_openai_history(messages: list[dict]) -> tuple[list[dict], bool]:
    """Drop lossy pre-fix tool-call turns that cannot be replayed safely."""
    repaired: list[dict] = []
    modified = False
    idx = 0

    while idx < len(messages):
        msg = messages[idx]
        content = msg.get("content")
        if (
            msg.get("role") == "assistant"
            and isinstance(content, list)
            and any(
                isinstance(block, dict) and block.get("type") == "tool_use"
                for block in content
            )
            and not _assistant_has_preserved_provider_message(msg)
        ):
            modified = True
            tool_ids = {
                block.get("id", "")
                for block in content
                if isinstance(block, dict) and block.get("type") == "tool_use"
            }
            text_blocks = [
                block for block in content
                if isinstance(block, dict) and block.get("type") == "text"
            ]
            if text_blocks:
                repaired.append({**msg, "content": text_blocks})

            next_idx = idx + 1
            if next_idx < len(messages):
                next_msg = messages[next_idx]
                next_content = next_msg.get("content")
                if (
                    next_msg.get("role") == "user"
                    and isinstance(next_content, list)
                    and next_content
                    and all(
                        isinstance(block, dict)
                        and block.get("type") == "tool_result"
                        and block.get("tool_use_id", "") in tool_ids
                        for block in next_content
                    )
                ):
                    idx += 2
                    continue

            idx += 1
            continue

        repaired.append(msg)
        idx += 1

    return repaired, modified


def _serialize_chat_content(content: Any) -> Any:
    """Serialize SDK objects to JSON-safe content for persisted chat history."""
    if content is None or isinstance(content, (str, int, float, bool)):
        return content
    if isinstance(content, list):
        return [_serialize_chat_content(item) for item in content]
    if isinstance(content, dict):
        return {
            key: _serialize_chat_content(value)
            for key, value in content.items()
        }
    if is_dataclass(content):
        return _serialize_chat_content(asdict(content))
    if hasattr(content, "model_dump"):
        try:
            dumped = content.model_dump(exclude_none=True)
        except TypeError:
            dumped = content.model_dump()
        return _serialize_chat_content(dumped)
    if hasattr(content, "__dict__"):
        return {
            key: _serialize_chat_content(value)
            for key, value in vars(content).items()
            if not key.startswith("_")
        }
    return str(content)

def _build_chat_system_prompt() -> str:
    """Build the system prompt used by both sync and streaming chat endpoints."""
    return """You are the SnowStrike Orchestrator Agent, the interactive interface for managing penetration testing engagements.

## Capabilities
You can query engagement state, dispatch agents, run phases, manage the attack plan, and launch full autonomous pentests using your available tools.

## Available Agents
When using `run_agent`, these are the valid agent types:
- **recon**: Network scanning, service detection, DNS, SMB/LDAP enumeration
- **webapp**: Web application vulnerability testing (SQLi, XSS, directory brute-force)
- **browser**: Headless browser analysis, screenshots, DOM/network behavior inspection
- **attack**: ALL offensive operations — exploitation, privilege escalation, credential attacks, post-exploitation
- **cloud**: Cloud infrastructure assessment (AWS, Azure, GCP, Kubernetes)
- **binary**: Binary analysis, reverse engineering, exploit development
- **forensics**: Memory/file forensics, steganography, and cryptanalysis workflows
- **osint**: Passive intelligence gathering (Shodan, username search, credential leaks)
- **reporting**: Generate the final penetration test report

## Safety Rules
- NEVER dispatch agents against targets outside the engagement scope.
- Before running `run_phase`, `replan`, or `run_autonomous`, confirm with the user what they expect.
- Before running `run_agent`, ensure the task is specific — include IPs, ports, service versions, and endpoint paths. Never dispatch with vague tasks like "hack the target".
- Summarize what you're about to do before executing any heavy operation.

## Interaction Style
- Be concise and professional. Use formatted markdown.
- When showing findings, group by severity.
- When the user asks about status, use `get_shared_state` and `get_attack_story` to give a current picture.
- Proactively surface important findings or blockers the user may not have seen."""


router = APIRouter(prefix="/api")

ORCHESTRATOR_TOOLS = [
    {
        "name": "run_phase",
        "description": "Execute a penetration testing phase by dispatching specialized sub-agents. The orchestrator dispatches sub-agents in parallel waves.",
        "input_schema": {
            "type": "object",
            "properties": {
                "phase": {
                    "type": "string",
                    "description": "Phase to execute - recon, enumeration, vuln_analysis, exploitation, post_exploit, or reporting"
                }
            },
            "required": ["phase"]
        }
    },
    {
        "name": "run_agent",
        "description": "Directly dispatch a specific sub-agent with a custom task. Use this for targeted operations outside the normal phase flow.",
        "input_schema": {
            "type": "object",
            "properties": {
                "agent_type": {"type": "string", "description": "Agent to dispatch - recon, webapp, browser, attack, cloud, binary, forensics, osint, or reporting"},
                "task": {"type": "string", "description": "Detailed task description for the agent"}
            },
            "required": ["agent_type", "task"]
        }
    },
    {
        "name": "query_findings",
        "description": "Query discovered vulnerabilities, credentials, and artifacts.",
        "input_schema": {
            "type": "object",
            "properties": {
                "severity": {"type": "string", "description": "Filter by severity (critical, high, medium, low, info)"},
                "host": {"type": "string", "description": "Filter by host IP"},
                "finding_type": {"type": "string", "description": "Filter type (vulnerability, credential, all)"}
            }
        }
    },
    {
        "name": "query_credentials",
        "description": "Query all discovered credentials from the engagement.",
        "input_schema": {"type": "object", "properties": {}}
    },
    {
        "name": "get_shared_state",
        "description": "Get the current shared state across all agents.",
        "input_schema": {"type": "object", "properties": {}}
    },
    {
        "name": "get_attack_story",
        "description": "Get the running attack narrative markdown.",
        "input_schema": {"type": "object", "properties": {}}
    },
    {
        "name": "get_current_plan",
        "description": "Get the current attack plan.",
        "input_schema": {"type": "object", "properties": {}}
    },
    {
        "name": "replan",
        "description": "Re-evaluate and adjust the attack plan based on current findings.",
        "input_schema": {"type": "object", "properties": {}}
    },
    {
        "name": "run_autonomous",
        "description": "Run the full penetration test end-to-end autonomously. Automatically transitions between all phases (recon → enumeration → vuln analysis → exploitation → post-exploit → reporting), running quality gates and replanning between each phase. Use this when the user wants a full automated pentest.",
        "input_schema": {
            "type": "object",
            "properties": {},
        }
    }
]

class ChatMessage(BaseModel):
    message: str

def get_orchestrator(request: Request, eng_name: str) -> OrchestratorAgent:
    engagements_dir = request.app.state.engagements_dir
    edir = os.path.join(engagements_dir, eng_name)
    if not os.path.exists(edir):
        raise HTTPException(status_code=404, detail="Engagement not found")
    return OrchestratorAgent.resume_engagement(edir)

def handle_tool_call(orch: OrchestratorAgent, tool_name: str, tool_input: dict) -> Any:
    try:
        if tool_name == "run_phase":
            return orch.execute_phase(tool_input.get("phase"))
        elif tool_name == "run_agent":
            r = orch.dispatch_agent(tool_input.get("agent_type", ""), tool_input.get("task", ""))
            safe_summary = str(r.summary) if not isinstance(r.summary, str) else (r.summary or "")
            return {
                "success": r.success,
                "agent": r.agent_name,
                "summary": safe_summary[:2000],
                "tools_used": r.tools_used,
                "duration_seconds": r.duration_seconds,
                "errors": r.errors,
                "suggested_next_steps": r.suggested_next_steps,
            }
        elif tool_name == "query_findings":
            return orch.get_findings(
                tool_input.get("severity", ""),
                tool_input.get("host", ""),
                tool_input.get("finding_type", "")
            )
        elif tool_name == "query_credentials":
            return orch.get_credentials()
        elif tool_name == "get_shared_state":
            return orch.get_shared_state()
        elif tool_name == "get_attack_story":
            return orch.get_attack_story()
        elif tool_name == "get_current_plan":
            return orch.get_current_plan()
        elif tool_name == "replan":
            return orch.replan()
        elif tool_name == "run_autonomous":
            eng_dir = orch.engagement_dir
            eng_key = os.path.basename(eng_dir)

            # Check if already running (in-memory check)
            if eng_key in _autonomous_runs and _autonomous_runs[eng_key].get("status") == "running":
                return {"status": "already_running", "message": "Autonomous run is already in progress. Check the dashboard for live updates."}

            # Check persisted state (dashboard may have restarted)
            persisted = _load_autonomous_state(eng_dir)
            if persisted and persisted.get("status") == "running":
                # Previous run was killed by restart — mark it and start fresh
                logger.warning(f"[Chat] Found orphaned autonomous run for {eng_key}, restarting")
                _save_autonomous_state(eng_dir, eng_key, "restarted_after_crash")

            # Launch in background thread
            _autonomous_runs[eng_key] = {"status": "running", "started_at": None, "result": None}
            _save_autonomous_state(eng_dir, eng_key, "running")

            def _run_bg():
                import time
                _autonomous_runs[eng_key]["started_at"] = time.time()
                try:
                    result = orch.run_autonomous()
                    _autonomous_runs[eng_key]["status"] = "completed"
                    _autonomous_runs[eng_key]["result"] = result
                    _save_autonomous_state(eng_dir, eng_key, "completed", result)
                except Exception as e:
                    _autonomous_runs[eng_key]["status"] = "failed"
                    _autonomous_runs[eng_key]["result"] = {"error": str(e)}
                    _save_autonomous_state(eng_dir, eng_key, "failed", {"error": str(e)})
                    logger.error(f"Autonomous run failed: {e}")

            t = threading.Thread(target=_run_bg, daemon=True)
            t.start()
            return {"status": "started", "message": "Autonomous pentest launched in background. Agents will work through recon → exploitation → reporting with automatic phase forcing when recon saturates."}
        else:
            return {"error": f"Unknown tool: {tool_name}"}
    except Exception as e:
        return {"error": str(e)}

@router.post("/engagement/{eng_name}/chat")
def chat(request: Request, eng_name: str, payload: ChatMessage):
    orch = get_orchestrator(request, eng_name)

    # Resolve per-engagement orchestrator model
    engagements_dir = request.app.state.engagements_dir
    edir = os.path.join(engagements_dir, eng_name)
    db = DatabaseManager(edir)
    model_config = db.get_model_config(orch.engagement_id)
    chat_model = resolve_model_for_role("orchestrator", model_config)

    try:
        client = create_model_client(chat_model)
    except ValueError as e:
        return {"response": f"Error: {e}"}
    db.close()
    
    # Load history
    edir = os.path.join(request.app.state.engagements_dir, eng_name)
    history_file = os.path.join(edir, "chat_history.json")
    
    messages = _load_chat_history(history_file)
            
    messages = _cleanup_incomplete_assistant_turn(messages)
    if getattr(client, "is_openai_compatible", False):
        messages, repaired = _repair_legacy_openai_history(messages)
        if repaired:
            _save_chat_history(history_file, messages)
    
    messages.append({"role": "user", "content": payload.message})
    _save_chat_history(history_file, messages)

    system_prompt = _build_chat_system_prompt()

    # --- Context compaction ---
    compaction_state = run_compaction(edir, messages, chat_model, system_prompt, model_config)
    compaction_occurred = False
    if compaction_state and compaction_state.get("compacted_memory"):
        llm_messages = build_compacted_messages(messages, compaction_state)
        compaction_occurred = True
    else:
        llm_messages = messages

    max_turns = 10
    final_text = ""

    try:
        for _ in range(max_turns):
            response = client.messages.create(
                model=chat_model,
                system=system_prompt,
                messages=llm_messages,
                tools=ORCHESTRATOR_TOOLS,
                max_tokens=4096,
            )
            
            assistant_content = _serialize_chat_content(response.content)
            for block in response.content:
                if block.type == "text":
                    final_text += block.text
            
            # Append to both full history and LLM view
            messages.append({"role": "assistant", "content": assistant_content})
            llm_messages.append({"role": "assistant", "content": assistant_content})
            _save_chat_history(history_file, messages)

            if response.stop_reason != "tool_use":
                break

            tool_results = []
            for block in response.content:
                if block.type == "tool_use":
                    logger.info(f"Chat agent calling tool: {block.name}")
                    result = handle_tool_call(orch, block.name, block.input)
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": json.dumps(result, default=str)
                    })

            messages.append({"role": "user", "content": tool_results})
            llm_messages.append({"role": "user", "content": tool_results})
            _save_chat_history(history_file, messages)

    except Exception as e:
        logger.error(f"Chat API error: {e}", exc_info=True)
        final_text = "An error occurred while communicating with the AI model. Check server logs for details."

    _save_chat_history(history_file, messages)

    # Post-loop refusal detection and sanitization
    final_text, was_refusal = _classify_and_sanitize_chat(final_text)
    if was_refusal:
        _log_chat_refusal(edir, chat_model, final_text)

    resp = {"response": final_text}
    if compaction_occurred:
        resp["compaction"] = get_compaction_info(edir)
    return resp

@router.post("/engagement/{eng_name}/chat/stream")
def chat_stream(request: Request, eng_name: str, payload: ChatMessage):
    """SSE streaming chat endpoint. Yields events as the orchestrator thinks/acts."""
    orch = get_orchestrator(request, eng_name)

    engagements_dir = request.app.state.engagements_dir
    edir = os.path.join(engagements_dir, eng_name)
    db = DatabaseManager(edir)
    model_config = db.get_model_config(orch.engagement_id)
    chat_model = resolve_model_for_role("orchestrator", model_config)

    try:
        client = create_model_client(chat_model)
    except ValueError as e:
        def _err():
            yield f"data: {json.dumps({'type': 'error', 'text': str(e)})}\n\n"
            yield "data: [DONE]\n\n"
        return StreamingResponse(_err(), media_type="text/event-stream")
    db.close()

    # Load history
    history_file = os.path.join(edir, "chat_history.json")
    messages = _load_chat_history(history_file)

    messages = _cleanup_incomplete_assistant_turn(messages)
    if getattr(client, "is_openai_compatible", False):
        messages, repaired = _repair_legacy_openai_history(messages)
        if repaired:
            _save_chat_history(history_file, messages)

    messages.append({"role": "user", "content": payload.message})
    _save_chat_history(history_file, messages)

    system_prompt = _build_chat_system_prompt()

    # --- Context compaction ---
    compaction_state = run_compaction(edir, messages, chat_model, system_prompt, model_config)
    compaction_occurred = False
    if compaction_state and compaction_state.get("compacted_memory"):
        llm_messages = build_compacted_messages(messages, compaction_state)
        compaction_occurred = True
    else:
        llm_messages = messages

    def _generate():
        nonlocal compaction_occurred
        max_turns = 10
        final_text = ""

        # Notify frontend if compaction just happened
        if compaction_occurred:
            info = get_compaction_info(edir)
            yield f"data: {json.dumps({'type': 'compaction', 'info': info})}\n\n"

        try:
            for turn in range(max_turns):
                response = client.messages.create(
                    model=chat_model,
                    system=system_prompt,
                    messages=llm_messages,
                    tools=ORCHESTRATOR_TOOLS,
                    max_tokens=4096,
                )

                assistant_content = _serialize_chat_content(response.content)
                for block in response.content:
                    if block.type == "text":
                        final_text_chunk = block.text
                        yield f"data: {json.dumps({'type': 'text', 'text': final_text_chunk})}\n\n"
                    elif block.type == "tool_use":
                        yield f"data: {json.dumps({'type': 'tool_call', 'tool': block.name})}\n\n"

                # Append to both full history and LLM view
                messages.append({"role": "assistant", "content": assistant_content})
                llm_messages.append({"role": "assistant", "content": assistant_content})
                _save_chat_history(history_file, messages)

                if response.stop_reason != "tool_use":
                    break

                # Execute tool calls
                tool_results = []
                for block in response.content:
                    if block.type == "tool_use":
                        logger.info(f"Stream chat agent calling tool: {block.name}")
                        yield f"data: {json.dumps({'type': 'tool_executing', 'tool': block.name})}\n\n"
                        result = handle_tool_call(orch, block.name, block.input)
                        tool_results.append({
                            "type": "tool_result",
                            "tool_use_id": block.id,
                            "content": json.dumps(result, default=str)
                        })
                        yield f"data: {json.dumps({'type': 'tool_done', 'tool': block.name})}\n\n"

                messages.append({"role": "user", "content": tool_results})
                llm_messages.append({"role": "user", "content": tool_results})
                _save_chat_history(history_file, messages)

        except Exception as e:
            logger.error(f"Stream chat error: {e}", exc_info=True)
            yield f"data: {json.dumps({'type': 'error', 'text': 'An error occurred. Check server logs for details.'})}\n\n"

        # Save history
        try:
            _save_chat_history(history_file, messages)
        except Exception as e:
            logger.error(f"Failed to save chat history: {e}")

        # Post-loop refusal detection (text already streamed, but log + notify)
        _, was_refusal = _classify_and_sanitize_chat(final_text)
        if was_refusal:
            _log_chat_refusal(edir, chat_model, final_text)
            yield f"data: {json.dumps({'type': 'refusal', 'text': 'Model declined this request.'})}\n\n"

        yield "data: [DONE]\n\n"

    return StreamingResponse(_generate(), media_type="text/event-stream")

@router.get("/engagement/{eng_name}/chat/history")
def get_chat_history(request: Request, eng_name: str):
    edir = os.path.join(request.app.state.engagements_dir, eng_name)
    history_file = os.path.join(edir, "chat_history.json")
    
    messages = []
    raw_messages = _load_chat_history(history_file)
    for msg in raw_messages:
        if msg["role"] == "user":
            if isinstance(msg["content"], str):
                messages.append({"role": "user", "content": msg["content"]})
        elif msg["role"] == "assistant":
            if isinstance(msg["content"], str):
                messages.append({"role": "assistant", "content": msg["content"]})
            elif isinstance(msg["content"], list):
                text = "".join(b["text"] for b in msg["content"] if b["type"] == "text")
                if text:
                    messages.append({"role": "assistant", "content": text})
            
    return {"history": messages}


# ======================================================================
# Context Compaction endpoints
# ======================================================================

class CompactionToggle(BaseModel):
    enabled: bool


@router.get("/engagement/{eng_name}/compaction")
def get_compaction(request: Request, eng_name: str):
    """Get compaction state for an engagement."""
    edir = os.path.join(request.app.state.engagements_dir, eng_name)
    if not os.path.exists(edir):
        raise HTTPException(status_code=404, detail="Engagement not found")
    return get_compaction_info(edir)


@router.put("/engagement/{eng_name}/compaction")
def toggle_compaction(request: Request, eng_name: str, payload: CompactionToggle):
    """Enable or disable context compaction for an engagement."""
    edir = os.path.join(request.app.state.engagements_dir, eng_name)
    if not os.path.exists(edir):
        raise HTTPException(status_code=404, detail="Engagement not found")
    set_compaction_enabled(edir, payload.enabled)
    return get_compaction_info(edir)


# ======================================================================
# Direct vulnerability exploitation / exploration endpoints
# ======================================================================

class ExploitVulnRequest(BaseModel):
    title: str
    severity: str = ""
    host_ip: str = ""
    cve_id: str = ""
    description: str = ""
    service: str = ""

@router.post("/engagement/{eng_name}/exploit-vuln")
def exploit_vuln(request: Request, eng_name: str, payload: ExploitVulnRequest):
    """
    Dispatch the Attack Agent to exploit a specific vulnerability.
    Also informs the orchestrator's shared state so it stays aware.
    """
    orch = get_orchestrator(request, eng_name)

    # Build a precise task for the Attack Agent
    parts = [f"Exploit the following vulnerability on {payload.host_ip or 'the target'}:"]
    parts.append(f"  Title: {payload.title}")
    if payload.severity:
        parts.append(f"  Severity: {payload.severity}")
    if payload.cve_id and payload.cve_id != "--":
        parts.append(f"  CVE: {payload.cve_id}")
    if payload.description:
        parts.append(f"  Description: {payload.description[:500]}")
    if payload.service:
        parts.append(f"  Affected service: {payload.service}")
    parts.append("")
    parts.append("Attempt to exploit this vulnerability to gain access or demonstrate impact.")
    parts.append("Try multiple approaches if the first attempt fails.")
    task = "\n".join(parts)

    # Update shared state so orchestrator knows about user-directed exploitation
    try:
        from memory.shared_state import SharedState
        ss = SharedState(orch.engagement_dir)
        state = ss.read()
        user_actions = state.get("user_directed_actions", [])
        user_actions.append({
            "action": "exploit_vuln",
            "vuln_title": payload.title,
            "host_ip": payload.host_ip,
            "cve_id": payload.cve_id,
        })
        ss.update_section("user_directed_actions", user_actions)
    except Exception as e:
        logger.warning(f"Failed to update shared state for exploit-vuln: {e}")

    # Dispatch in background thread so we don't block the UI
    result_holder = {"status": "running"}

    def _run():
        try:
            r = orch.dispatch_agent("attack", task)
            result_holder["status"] = "completed"
            result_holder["success"] = r.success
            result_holder["summary"] = (r.summary or "")[:2000]
            result_holder["tools_used"] = r.tools_used
            result_holder["duration_seconds"] = r.duration_seconds
            result_holder["errors"] = r.errors
        except Exception as e:
            result_holder["status"] = "failed"
            result_holder["error"] = str(e)

    t = threading.Thread(target=_run, daemon=True)
    t.start()

    return {
        "status": "dispatched",
        "message": f"Attack Agent dispatched to exploit: {payload.title}",
        "task": task,
    }


@router.post("/engagement/{eng_name}/explore-vuln")
def explore_vuln(request: Request, eng_name: str, payload: ExploitVulnRequest):
    """
    Use the LLM to generate contextual exploitation options for a vulnerability.
    Returns tailored advice based on the engagement's current state.
    """
    orch = get_orchestrator(request, eng_name)

    # Gather context
    context_parts = []
    try:
        from memory.shared_state import SharedState
        ss = SharedState(orch.engagement_dir)
        state = ss.read()
        target = state.get("target", "unknown")
        context_parts.append(f"Target: {target}")
        if state.get("hosts"):
            context_parts.append(f"Known hosts: {', '.join(str(h) for h in state['hosts'][:10])}")
        if state.get("credentials"):
            context_parts.append(f"Available credentials: {len(state['credentials'])} found")
        if state.get("active_shells"):
            context_parts.append(f"Active shells: {len(state['active_shells'])}")
    except Exception:
        pass

    context = "\n".join(context_parts)

    system_msg = "You are a senior penetration tester advising on exploitation options. Provide specific, actionable advice referencing actual tools (metasploit modules, scripts, manual techniques). Tailor advice to the specific CVE/vulnerability when known."

    prompt = f"""Given this vulnerability found during an engagement:

<vulnerability>
  Title: {payload.title}
  Severity: {payload.severity or 'unknown'}
  Host: {payload.host_ip or 'unknown'}
  CVE: {payload.cve_id or 'none'}
  Description: {payload.description or 'none provided'}
  Service: {payload.service or 'unknown'}
</vulnerability>

<engagement_context>
{context}
</engagement_context>

Provide 3-5 concrete exploitation options, ordered by likelihood of success. For each option:
1. A short name/title
2. The approach (1-2 sentences)
3. Tools that would be used
4. Risk level (safe/moderate/aggressive)
5. Expected outcome if successful"""

    # Resolve model
    engagements_dir = request.app.state.engagements_dir
    edir = os.path.join(engagements_dir, eng_name)
    db = DatabaseManager(edir)
    model_config = db.get_model_config(orch.engagement_id)
    model = resolve_model_for_role("orchestrator", model_config)
    db.close()

    try:
        client = create_model_client(model)
        response = client.messages.create(
            model=model,
            max_tokens=2000,
            system=system_msg,
            messages=[{"role": "user", "content": prompt}],
        )
        text = ""
        for block in response.content:
            if block.type == "text":
                text += block.text
        return {"options": text}
    except Exception as e:
        logger.error(f"Explore vuln LLM call failed: {e}")
        raise HTTPException(500, "Failed to generate options. Check server logs for details.")

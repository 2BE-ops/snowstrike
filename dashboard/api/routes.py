"""FastAPI routes for the dashboard."""

import asyncio
import json
import logging
import os
import shlex
import time
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

from fastapi import APIRouter, HTTPException, Query, Request, UploadFile, File
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from dashboard.data.db_reader import DBReader
from dashboard.data.file_reader import FileReader

router = APIRouter(prefix="/api")

# ---------------------------------------------------------------------------
# Input validation helpers
# ---------------------------------------------------------------------------
import re as _re

_SAFE_NAME_RE = _re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._\- ]{0,127}$")


def _validate_engagement_name(name: str) -> str:
    """Validate and sanitize an engagement/entity name to prevent path traversal."""
    if not name:
        raise HTTPException(status_code=400, detail="Name is required")
    # Reject path traversal characters
    if "/" in name or "\\" in name or ".." in name or "\x00" in name:
        raise HTTPException(status_code=400, detail="Invalid characters in name")
    if not _SAFE_NAME_RE.match(name):
        raise HTTPException(status_code=400, detail="Name contains disallowed characters")
    return name


def _get_readers(request: Request) -> tuple[DBReader, FileReader, int]:
    """Get the DB reader and file reader for the active engagement.

    Self-heals older/partial engagement directories by creating a database and
    engagement row when they are missing but the directory exists.
    """
    eng_name = request.cookies.get("active_engagement")
    if not eng_name:
        raise HTTPException(status_code=400, detail="No active engagement selected.")
    _validate_engagement_name(eng_name)

    engagements_dir = request.app.state.engagements_dir
    edir = os.path.join(engagements_dir, eng_name)

    if not os.path.isdir(edir):
        raise HTTPException(status_code=404, detail="Engagement directory not found.")

    db_path = os.path.join(edir, "snowstrike.db")

    # Self-heal: if the directory exists but the DB does not, bootstrap it
    if not os.path.exists(db_path):
        _ensure_engagement_row(edir, eng_name)

    db = DBReader(db_path)
    fr = FileReader(edir)
    eng = db.get_engagement()
    eid = eng["id"] if eng else 1
    return db, fr, eid


def _infer_target_from_engagement_name(eng_name: str) -> str:
    """Infer a reasonable target string from an engagement directory name."""
    parts = eng_name.split("_", 1)
    target = parts[1] if len(parts) > 1 else eng_name
    return target.replace("_", ".")


def _ensure_engagement_row(engagement_dir: str, eng_name: str) -> tuple["DatabaseManager", dict]:
    """Return a writable DB manager plus an engagement row, creating one if absent.

    Older engagement directories can contain a SQLite database without a row in the
    `engagement` table. The dashboard settings endpoints need that row in order to
    persist model overrides and metadata, so we bootstrap it on demand.
    """
    from memory.database import DatabaseManager

    db_manager = DatabaseManager(engagement_dir)
    eng = db_manager.get_engagement(1)
    if eng:
        return db_manager, eng

    target = _infer_target_from_engagement_name(eng_name)
    engagement_id = db_manager.create_engagement(
        name=eng_name,
        target=target,
        methodology="standard",
    )
    eng = db_manager.get_engagement(engagement_id)
    return db_manager, eng


class _SnapshotSharedState:
    """Tiny shared-state adapter for dashboard-side context estimation."""

    def __init__(self, state: dict):
        self._state = state or {}

    def read(self) -> dict:
        return self._state


def _get_orchestrator_context_snapshot(
    engagement_dir: str,
    engagement: Optional[dict],
    state: dict,
) -> Optional[dict]:
    """Estimate current orchestrator context usage for the dashboard."""
    from agents.model_client import resolve_model_for_role
    from agents.orchestrator import OrchestratorAgent
    from config import (
        AGENTS_PROMPTS_DIR,
        AVAILABLE_MODELS,
        MAX_ORCHESTRATOR_ITERATIONS,
        get_model_context_window,
    )

    model_config = {}
    if engagement:
        try:
            model_config = json.loads(engagement.get("model_config") or "{}")
        except (json.JSONDecodeError, TypeError, AttributeError):
            model_config = {}

    prompt_dir = AGENTS_PROMPTS_DIR
    active_master_profile = _load_engagement_master_profile(engagement_dir)
    if active_master_profile:
        try:
            from profiles.master_profile_manager import MasterProfileManager

            resolved = MasterProfileManager().resolve(active_master_profile)
            if resolved.get("effective_models"):
                model_config = resolved["effective_models"]
            if resolved.get("prompt_dir"):
                prompt_dir = resolved["prompt_dir"]
        except Exception:
            active_master_profile = None

    orchestrator_model = resolve_model_for_role("orchestrator", model_config)
    prompt_path = Path(prompt_dir) / "orchestrator.md"
    raw_prompt = prompt_path.read_text() if prompt_path.exists() else ""
    system_prompt = raw_prompt.replace(
        "{AGENT_CAPABILITIES_BLOCK}",
        OrchestratorAgent._render_agent_capabilities(),
    )

    estimator = OrchestratorAgent.__new__(OrchestratorAgent)
    estimator.shared_state = _SnapshotSharedState(state or {})
    estimator._agent_dispatch_counts = {}
    estimator._recon_saturation_threshold = 3
    estimator._consecutive_no_progress = 0
    estimator.failed_approaches = []
    estimator.iteration_history = []

    brief = estimator._build_intelligence_brief(1, MAX_ORCHESTRATOR_ITERATIONS)
    base_prompt_tokens = (
        estimator._estimate_text_tokens(system_prompt)
        + estimator._estimate_text_tokens(brief)
        + 512
    )

    # Include chat history tokens in the estimate
    chat_history_tokens = 0
    try:
        history_path = os.path.join(engagement_dir, "chat_history.json")
        if os.path.exists(history_path):
            with open(history_path, "r") as f:
                raw_history = json.load(f)
            from memory.chat_compactor import (
                _estimate_messages_tokens,
                get_compaction_info,
                get_compaction_state,
                build_compacted_messages,
            )
            compaction_st = get_compaction_state(engagement_dir)
            if compaction_st.get("enabled") and compaction_st.get("compacted_memory"):
                # Estimate what the LLM would actually see after compaction
                compacted_msgs = build_compacted_messages(raw_history, compaction_st)
                chat_history_tokens = _estimate_messages_tokens(compacted_msgs)
            else:
                chat_history_tokens = _estimate_messages_tokens(raw_history)
    except Exception:
        pass

    prompt_tokens = base_prompt_tokens + chat_history_tokens
    context_window = max(get_model_context_window(orchestrator_model, 150_000), 1)
    reserve = max(12_000, min(context_window // 5, 120_000))
    usable_window = max(12_000, context_window - reserve)
    raw_pressure = prompt_tokens / context_window
    usable_pressure = prompt_tokens / usable_window

    # Get compaction info
    compaction_info = None
    try:
        from memory.chat_compactor import get_compaction_info
        compaction_info = get_compaction_info(engagement_dir)
    except Exception:
        pass

    model_info = AVAILABLE_MODELS.get(orchestrator_model, {})
    return {
        "model": orchestrator_model,
        "model_label": model_info.get("label", orchestrator_model),
        "provider": model_info.get("provider", "unknown"),
        "context_window": context_window,
        "usable_window": usable_window,
        "prompt_tokens": prompt_tokens,
        "chat_history_tokens": chat_history_tokens,
        "percent_used": round(raw_pressure * 100, 1),
        "usable_percent_used": round(usable_pressure * 100, 1),
        "active_master_profile": active_master_profile or "",
        "compaction": compaction_info,
    }


# ======================================================================
# Engagement
# ======================================================================


@router.get("/engagement")
def get_engagement(request: Request):
    db, fr, eid = _get_readers(request)
    eng = db.get_engagement()
    if not eng:
        return {"engagement": None}
    return {"engagement": eng}


@router.get("/engagements")
def list_engagements(request: Request):
    engagements_dir = request.app.state.engagements_dir
    result = []
    if os.path.isdir(engagements_dir):
        for name in sorted(os.listdir(engagements_dir)):
            edir = os.path.join(engagements_dir, name)
            db_path = os.path.join(edir, "snowstrike.db")
            if os.path.isdir(edir):
                # Self-heal: create DB for engagement dirs that are missing one
                if not os.path.exists(db_path):
                    try:
                        _ensure_engagement_row(edir, name)
                    except Exception:
                        continue
                try:
                    db = DBReader(db_path)
                    eng = db.get_engagement()
                except Exception:
                    eng = None  # Skip DBs we can't read (e.g. wrong permissions)

                group_name = eng.get("group_name", "Default") if eng else "Default"
                tags_str = eng.get("tags", "[]") if eng else "[]"
                try:
                    tags = json.loads(tags_str) if tags_str else []
                except:
                    tags = []
                
                result.append({
                    "name": name, 
                    "path": edir,
                    "target": eng.get("target", "unknown") if eng else "unknown",
                    "status": eng.get("status", "unknown") if eng else "unknown",
                    "group_name": group_name,
                    "tags": tags,
                    "created_at": eng.get("created_at") if eng else None
                })
    return {"engagements": result}

class EngagementCreate(BaseModel):
    target: str
    name: str = ""
    group_name: str = "Default"
    tags: list[str] = []
    scope: str = ""
    out_of_scope: str = ""
    methodology: str = "standard"

@router.post("/engagements")
def create_engagement(request: Request, payload: EngagementCreate):
    try:
        import os
        from datetime import datetime
        from config import ENGAGEMENTS_DIR
        from memory.database import DatabaseManager
        from memory.shared_state import SharedState
        from memory.attack_story import AttackStory
        from memory.network_map import NetworkMap

        scope_list = [s.strip() for s in payload.scope.split(",") if s.strip()] if payload.scope else [payload.target]
        oos_list = [s.strip() for s in payload.out_of_scope.split(",") if s.strip()] if payload.out_of_scope else []
        
        timestamp = datetime.now().strftime("%Y-%m-%d")
        safe_target = payload.target.replace("/", "_").replace(":", "_").replace(" ", "_")[:50]
        eng_name = payload.name or f"{timestamp}_{safe_target}"
        eng_dir = str(ENGAGEMENTS_DIR / eng_name)

        os.makedirs(eng_dir, exist_ok=True)
        os.makedirs(os.path.join(eng_dir, "logs", "raw"), exist_ok=True)
        os.makedirs(os.path.join(eng_dir, "loot"), exist_ok=True)

        db_manager = DatabaseManager(eng_dir)
        engagement_id = db_manager.create_engagement(
            name=eng_name,
            target=payload.target,
            scope=scope_list,
            out_of_scope=oos_list,
            methodology=payload.methodology,
        )
        
        # Add the UI metadata
        eng_row = db_manager.get_engagement(engagement_id)
        if eng_row:
            db_manager.update_engagement_metadata(eng_row["id"], payload.group_name, payload.tags)
        db_manager.close()
        
        # Initialize necessary states
        shared_state = SharedState(eng_dir)
        shared_state.initialize(target=payload.target, scope=scope_list, out_of_scope=oos_list, methodology=payload.methodology)
        
        story = AttackStory(eng_dir)
        story.initialize(target=payload.target, methodology=payload.methodology)
        
        network_map = NetworkMap(eng_dir)
        network_map.save()

        eng_dir_name = os.path.basename(eng_dir)
        return {"status": "success", "engagement_name": eng_dir_name}
    except Exception as e:
        import traceback
        logger.error("Engagement creation failed: %s\n%s", e, traceback.format_exc())
        raise HTTPException(status_code=500, detail="Engagement creation failed")

@router.delete("/engagements/{eng_name}")
def delete_engagement(request: Request, eng_name: str):
    """Delete an engagement and all its data."""
    import shutil
    engagements_dir = request.app.state.engagements_dir
    # Sanitize to prevent path traversal
    if "/" in eng_name or "\\" in eng_name or ".." in eng_name:
        raise HTTPException(status_code=400, detail="Invalid engagement name")
    edir = os.path.join(engagements_dir, eng_name)
    if not os.path.isdir(edir):
        raise HTTPException(status_code=404, detail="Engagement not found")
    shutil.rmtree(edir)
    return {"status": "success", "deleted": eng_name}


@router.post("/clear-all-data")
def clear_all_data(request: Request):
    """Delete ALL engagements and their data."""
    import shutil
    engagements_dir = request.app.state.engagements_dir
    deleted = []
    if os.path.isdir(engagements_dir):
        for name in os.listdir(engagements_dir):
            edir = os.path.join(engagements_dir, name)
            if os.path.isdir(edir):
                shutil.rmtree(edir)
                deleted.append(name)
    return {"status": "success", "deleted": deleted, "count": len(deleted)}


class EngagementMetaUpdate(BaseModel):
    group_name: str
    tags: list[str]


class ModelConfigUpdate(BaseModel):
    models: dict[str, str]  # role -> model_id

@router.post("/engagement/{eng_name}/meta")
def update_engagement_meta(request: Request, eng_name: str, meta: EngagementMetaUpdate):
    engagements_dir = request.app.state.engagements_dir
    edir = os.path.join(engagements_dir, eng_name)
    db_manager, row = _ensure_engagement_row(edir, eng_name)
    db_manager.update_engagement_metadata(row["id"], meta.group_name, meta.tags)
    db_manager.close()
    return {"status": "success"}


# ======================================================================
# Model Configuration (per-engagement)
# ======================================================================


@router.get("/available-models")
def get_available_models():
    """Return the list of models and configurable roles for the settings UI."""
    from config import AVAILABLE_MODELS, CONFIGURABLE_ROLES, MODELS
    models = []
    for model_id, info in AVAILABLE_MODELS.items():
        models.append({
            "id": model_id,
            "label": info["label"],
            "provider": info["provider"],
        })
    return {
        "models": models,
        "roles": CONFIGURABLE_ROLES,
        "defaults": MODELS,
    }


@router.get("/engagement/{eng_name}/model-config")
def get_model_config(request: Request, eng_name: str):
    engagements_dir = request.app.state.engagements_dir
    edir = os.path.join(engagements_dir, eng_name)
    db_manager, eng = _ensure_engagement_row(edir, eng_name)
    config = db_manager.get_model_config(eng["id"])
    db_manager.close()
    return {"model_config": config}


@router.post("/engagement/{eng_name}/model-config")
def update_model_config(request: Request, eng_name: str, payload: ModelConfigUpdate):
    engagements_dir = request.app.state.engagements_dir
    edir = os.path.join(engagements_dir, eng_name)
    from config import AVAILABLE_MODELS
    # Validate model IDs
    for role, model_id in payload.models.items():
        if model_id and model_id not in AVAILABLE_MODELS:
            raise HTTPException(400, f"Unknown model: {model_id}")
    db_manager, eng = _ensure_engagement_row(edir, eng_name)
    # Only store non-empty overrides
    clean = {k: v for k, v in payload.models.items() if v}
    db_manager.update_model_config(eng["id"], clean)
    db_manager.close()
    return {"status": "success", "model_config": clean}


@router.get("/engagement/{eng_name}/cost")
def get_engagement_cost(request: Request, eng_name: str):
    """Return LLM cost summary for an engagement."""
    engagements_dir = request.app.state.engagements_dir
    edir = os.path.join(engagements_dir, eng_name)
    db_path = os.path.join(edir, "snowstrike.db")
    if not os.path.exists(db_path):
        raise HTTPException(404, "Engagement database not found")
    _, eng = _ensure_engagement_row(edir, eng_name)
    db = DBReader(db_path)
    # Read cost data using read-only DB access (no CostTracker which writes)
    try:
        rows = db._query(
            """SELECT provider, model,
                      SUM(input_tokens) AS input_tokens,
                      SUM(output_tokens) AS output_tokens,
                      SUM(cost_usd) AS cost_usd,
                      COUNT(*) AS calls
               FROM llm_costs WHERE engagement_id = ?
               GROUP BY provider, model ORDER BY cost_usd DESC""",
            (eng["id"],),
        )
    except Exception:
        rows = []  # Table may not exist yet in fresh engagements
    total_usd = 0.0
    total_tokens = 0
    by_provider = {}
    for row in rows:
        provider = row["provider"]
        tokens = row["input_tokens"] + row["output_tokens"]
        total_usd += row["cost_usd"]
        total_tokens += tokens
        if provider not in by_provider:
            by_provider[provider] = {"cost_usd": 0.0, "input_tokens": 0, "output_tokens": 0, "calls": 0, "models": {}}
        p = by_provider[provider]
        p["cost_usd"] += row["cost_usd"]
        p["input_tokens"] += row["input_tokens"]
        p["output_tokens"] += row["output_tokens"]
        p["calls"] += row["calls"]
        p["models"][row["model"]] = {
            "cost_usd": round(row["cost_usd"], 6),
            "input_tokens": row["input_tokens"],
            "output_tokens": row["output_tokens"],
            "calls": row["calls"],
        }
    for p in by_provider.values():
        p["cost_usd"] = round(p["cost_usd"], 6)
    return {
        "engagement_id": eng["id"],
        "total_usd": round(total_usd, 6),
        "total_tokens": total_tokens,
        "by_provider": by_provider,
    }



# ======================================================================
# State & Story
# ======================================================================


@router.get("/state")
def get_state(request: Request):
    _, fr, _ = _get_readers(request)
    return {"state": fr.read_state()}


@router.get("/story")
def get_story(request: Request):
    _, fr, _ = _get_readers(request)
    return {"story": fr.read_story()}


@router.get("/plan")
def get_plan(request: Request):
    _, fr, _ = _get_readers(request)
    return {"plan": fr.read_plan()}


# ======================================================================
# Network Map
# ======================================================================


@router.get("/network-map")
def get_network_map(request: Request):
    _, fr, _ = _get_readers(request)
    return {"network_map": fr.read_network_map()}


# ======================================================================
# Hosts & Services
# ======================================================================


@router.get("/hosts")
def get_hosts(request: Request):
    db, fr, eid = _get_readers(request)
    hosts = db.get_hosts(eid)
    if not hosts:
        # Fall back to STATE.json
        state = fr.read_state()
        state_hosts = state.get("hosts", {})
        for ip, info in state_hosts.items():
            host_entry = {"ip": ip, "hostname": info.get("hostname"), "os": info.get("os"), "services": info.get("services", [])}
            hosts.append(host_entry)
    return {"hosts": hosts, "count": len(hosts)}


# ======================================================================
# Vulnerabilities
# ======================================================================


@router.get("/vulnerabilities")
def get_vulnerabilities(request: Request, severity: str = ""):
    db, fr, eid = _get_readers(request)
    vulns = db.get_vulnerabilities(eid, severity)
    if not vulns:
        # Fall back to STATE.json
        state = fr.read_state()
        state_vulns = state.get("vulns_summary", [])
        for v in state_vulns:
            if severity and v.get("severity", "").lower() != severity.lower():
                continue
            vulns.append(v)
    return {"vulnerabilities": vulns, "count": len(vulns)}


# ======================================================================
# Credentials
# ======================================================================


@router.get("/credentials")
def get_credentials(request: Request):
    db, fr, eid = _get_readers(request)
    creds = db.get_credentials(eid)
    if not creds:
        state = fr.read_state()
        creds = state.get("credentials_summary") or []
    return {"credentials": creds, "count": len(creds)}


# ======================================================================
# Loot
# ======================================================================


@router.get("/loot")
def get_loot(request: Request):
    db, fr, eid = _get_readers(request)
    loot_db = db.get_loot(eid)
    loot_files = fr.list_loot_files()
    return {"loot": loot_db, "files": loot_files, "count": len(loot_db)}


@router.post("/engagement/{eng_name}/upload")
async def upload_files(request: Request, eng_name: str, files: list[UploadFile] = File(...)):
    """Upload files to the engagement's loot/uploads directory for analysis.

    Files are saved to loot/uploads/ and registered in the loot DB table
    so agents and the dashboard can reference them.
    """
    engagements_dir = request.app.state.engagements_dir
    eng_dir = os.path.join(engagements_dir, eng_name)

    if not os.path.isdir(eng_dir):
        raise HTTPException(status_code=404, detail=f"Engagement '{eng_name}' not found")

    upload_dir = os.path.join(eng_dir, "loot", "uploads")
    os.makedirs(upload_dir, exist_ok=True)

    # Safety limits
    MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 MB
    MAX_FILES = 10
    # Only block extensions that could be accidentally executed on the server.
    # Binaries (.exe, .dll, .so, .elf) are fine — this is a pentest tool and
    # users upload them for reverse engineering / analysis.
    BLOCKED_EXTENSIONS = {".scr", ".vbs", ".vbe", ".wsf", ".wsh"}

    if len(files) > MAX_FILES:
        raise HTTPException(status_code=400, detail=f"Maximum {MAX_FILES} files per upload")

    uploaded = []
    db = None
    engagement_id = None

    for upload_file in files:
        filename = os.path.basename(upload_file.filename or "unnamed")
        # Sanitize filename — strip path components and null bytes
        filename = filename.replace("\x00", "").replace("/", "_").replace("\\", "_")
        if not filename:
            continue

        ext = os.path.splitext(filename)[1].lower()
        if ext in BLOCKED_EXTENSIONS:
            raise HTTPException(
                status_code=400,
                detail=f"File type '{ext}' is not allowed: {filename}"
            )

        # Read and check size
        content = await upload_file.read()
        if len(content) > MAX_FILE_SIZE:
            raise HTTPException(
                status_code=400,
                detail=f"File '{filename}' exceeds {MAX_FILE_SIZE // (1024*1024)} MB limit"
            )

        # Deduplicate filename if it already exists
        dest_path = os.path.join(upload_dir, filename)
        if os.path.exists(dest_path):
            name, ext = os.path.splitext(filename)
            counter = 1
            while os.path.exists(dest_path):
                filename = f"{name}_{counter}{ext}"
                dest_path = os.path.join(upload_dir, filename)
                counter += 1

        with open(dest_path, "wb") as f:
            f.write(content)

        # Register in loot DB
        rel_path = os.path.relpath(dest_path, eng_dir)
        try:
            if db is None:
                db_mgr, eng_row = _ensure_engagement_row(eng_dir, eng_name)
                db = db_mgr
                engagement_id = eng_row["id"] if eng_row else 1
            if engagement_id:
                db.add_loot(
                    engagement_id=engagement_id,
                    loot_type="upload",
                    file_path=rel_path,
                    description=f"Uploaded via dashboard: {upload_file.filename}",
                )
        except Exception:
            pass  # Non-fatal — file is saved even if DB insert fails

        uploaded.append({
            "name": filename,
            "path": rel_path,
            "size": len(content),
        })

    return {"uploaded": uploaded, "count": len(uploaded)}


# ======================================================================
# Alerts
# ======================================================================


@router.get("/alerts")
def get_alerts(request: Request):
    """Get all alerts for the active engagement."""
    eng_name = request.cookies.get("active_engagement")
    if not eng_name:
        return {"alerts": []}
    engagements_dir = request.app.state.engagements_dir
    edir = os.path.join(engagements_dir, eng_name)
    alerts_path = os.path.join(edir, "alerts.json")
    if not os.path.exists(alerts_path):
        return {"alerts": []}
    try:
        with open(alerts_path) as f:
            data = json.load(f)
        return {"alerts": data.get("alerts", [])}
    except (json.JSONDecodeError, IOError):
        return {"alerts": []}


@router.delete("/alerts")
def clear_alerts(request: Request):
    """Clear all alerts for the active engagement."""
    eng_name = request.cookies.get("active_engagement")
    if not eng_name:
        return {"status": "ok"}
    engagements_dir = request.app.state.engagements_dir
    edir = os.path.join(engagements_dir, eng_name)
    alerts_path = os.path.join(edir, "alerts.json")
    if os.path.exists(alerts_path):
        with open(alerts_path, "w") as f:
            json.dump({"alerts": []}, f)
    return {"status": "success"}


# ======================================================================
# Tool Executions
# ======================================================================


@router.get("/tool-executions")
def get_tool_executions(
    request: Request, agent: str = "", since_id: int = 0
):
    db, fr, eid = _get_readers(request)
    execs = db.get_tool_executions(eid, agent, since_id)
    # Inject raw output previews for real terminal display
    for ex in execs:
        raw_path = ex.get("raw_output_path", "")
        if raw_path:
            try:
                full_path = os.path.join(fr.engagement_dir, raw_path)
                with open(full_path, "r", errors="replace") as _f:
                    ex["raw_preview"] = _f.read(8192)
                file_size = os.path.getsize(full_path)
                ex["raw_total_bytes"] = file_size
                ex["raw_truncated"] = file_size > 8192
            except OSError:
                pass
    if not execs:
        # Fall back to raw log files
        logs = fr.list_raw_logs()
        for i, log in enumerate(logs):
            fname = log["filename"]
            # Parse tool name from filename pattern: toolname_date_time.txt
            parts = fname.rsplit("_", 2)
            tool_name = parts[0] if parts else fname
            agent_type = "recon"  # default
            if any(t in tool_name for t in ["nikto", "gobuster", "ffuf", "feroxbuster", "dirb"]):
                agent_type = "webapp"
            elif any(t in tool_name for t in ["hydra", "exploit", "metasploit"]):
                agent_type = "attack"
            execs.append({
                "id": i + 1,
                "tool_name": tool_name,
                "agent": agent_type,
                "agent_type": agent_type,
                "status": "completed",
                "duration_seconds": None,
                "raw_log_path": log["path"],
                "size_bytes": log["size_bytes"],
                "summary": f"Tool output saved ({log['size_bytes']} bytes)",
            })
    return {"executions": execs, "count": len(execs)}


@router.get("/tool-executions/{exec_id}/raw")
def get_raw_log(request: Request, exec_id: int):
    db, fr, eid = _get_readers(request)
    execs = db.get_tool_executions(eid)
    target = None
    for e in execs:
        if e["id"] == exec_id:
            target = e
            break
    if not target:
        raise HTTPException(404, "Execution not found")
    raw_path = target.get("raw_output_path", "")
    if not raw_path:
        return {"raw": target.get("compacted_summary", "[no output]")}
    content = fr.read_raw_log(raw_path)
    return {"raw": content, "path": raw_path}


# ======================================================================
# Agents
# ======================================================================


@router.get("/agents")
def get_agents(request: Request):
    db, _, eid = _get_readers(request)
    agents = db.get_agents(eid)
    return {"agents": agents}


# ======================================================================
# Agent Activity & Stats
# ======================================================================


@router.get("/agent-activity")
def get_agent_activity(request: Request, limit: int = 200):
    db, fr, eid = _get_readers(request)
    activity = db.get_agent_activity(eid, limit)
    conversations = fr.read_agent_conversations()
    return {"activity": activity, "conversations": conversations}


@router.get("/live-turns")
def get_live_turns(request: Request, limit: int = 200):
    _, fr, _ = _get_readers(request)
    turns = fr.read_live_turns()
    if limit > 0:
        turns = turns[-limit:]
    return {"turns": turns, "count": len(turns)}


@router.get("/stats")
def get_stats(request: Request):
    db, fr, eid = _get_readers(request)
    stats = db.get_stats(eid)
    eng = db.get_engagement()
    state = fr.read_state()
    if state:
        stats["current_phase"] = state.get("current_phase", state.get("engagement", {}).get("phase", "unknown"))
        stats["completed_phases"] = state.get("completed_phases", [])
        stats["methodology"] = state.get("engagement", {}).get("methodology", "standard")
        stats["agent_notes"] = state.get("agent_notes", {})
        stats["agent_todos"] = state.get("agent_todos", {}) or {}
        # Augment with STATE.json data when DB is empty
        hosts = state.get("hosts", {})
        if hosts and stats.get("hosts", 0) == 0:
            stats["hosts"] = len(hosts)
            svc_count = sum(len(h.get("services", [])) for h in hosts.values())
            stats["services"] = svc_count
        vulns = state.get("vulns_summary", [])
        if vulns and stats.get("vulnerabilities", {}).get("total", 0) == 0:
            sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": len(vulns)}
            for v in vulns:
                s = v.get("severity", "info").lower()
                if s in sev_counts:
                    sev_counts[s] += 1
            stats["vulnerabilities"] = sev_counts
        creds = state.get("credentials_summary") or []
        if creds and stats.get("credentials", 0) == 0:
            stats["credentials"] = len(creds)

    engagement_dir = fr.engagement_dir
    try:
        stats["orchestrator_context"] = _get_orchestrator_context_snapshot(
            engagement_dir,
            eng,
            state if isinstance(state, dict) else {},
        )
    except Exception:
        stats["orchestrator_context"] = None

    # Include autonomous run status if available
    from dashboard.api.chat import _autonomous_runs
    eng_name = request.cookies.get("active_engagement", "")
    run_info = _autonomous_runs.get(eng_name, {})
    if run_info:
        stats["autonomous_run"] = {
            "status": run_info.get("status", "unknown"),
            "started_at": run_info.get("started_at"),
        }
    return stats


# ======================================================================
# Phase 5: Failure observability endpoints
# ======================================================================

@router.get("/failure-summary")
def get_failure_summary(request: Request):
    """Failure breakdown by category, tool, agent, and outcome kind."""
    db, fr, eid = _get_readers(request)
    return db.get_failure_summary(eid)


@router.get("/outcome-stats")
def get_outcome_stats(request: Request):
    """Quick outcome distribution for dashboard cards."""
    db, fr, eid = _get_readers(request)
    return db.get_outcome_stats(eid)


@router.get("/tool-executions/filtered")
def get_tool_executions_filtered(
    request: Request,
    agent: str = "",
    tool_name: str = "",
    outcome_kind: str = "",
    failure_category: str = "",
    since_id: int = 0,
    run_id: str = "",
    agent_turn: int | None = None,
):
    """Get tool executions with rich filtering by outcome/failure category."""
    db, fr, eid = _get_readers(request)
    return db.get_tool_executions_filtered(
        eid,
        agent=agent,
        tool_name=tool_name,
        outcome_kind=outcome_kind,
        failure_category=failure_category,
        since_id=since_id,
        run_id=run_id,
        agent_turn=agent_turn,
    )


@router.get("/autonomous-status")
def get_autonomous_status(request: Request):
    """Get the status of the autonomous pentest run for this engagement."""
    from dashboard.api.chat import _autonomous_runs
    eng_name = request.cookies.get("active_engagement", "")
    run_info = _autonomous_runs.get(eng_name, {})
    if not run_info:
        return {"status": "not_started"}
    result = {
        "status": run_info.get("status", "unknown"),
        "started_at": run_info.get("started_at"),
    }
    if run_info.get("status") in ("completed", "failed"):
        run_result = run_info.get("result", {})
        if isinstance(run_result, dict):
            result["summary"] = {
                k: v for k, v in run_result.items()
                if k in ("total_duration", "phases_completed", "success")
            }
            if "error" in run_result:
                result["error"] = str(run_result["error"])[:500]
    return result


@router.get("/engagement-health")
def get_engagement_health(request: Request):
    """Consolidated engagement health dashboard data."""
    db, fr, eid = _get_readers(request)
    stats = db.get_stats(eid)
    state = fr.read_state()
    conversations = fr.read_agent_conversations()

    # Build agent status cards
    agent_cards = []
    for agent_info in (stats.get("agents") or []):
        card = {
            "name": agent_info.get("agent", "Unknown"),
            "tool_runs": agent_info.get("tool_runs", 0),
            "successes": agent_info.get("successes", 0),
            "duration": agent_info.get("total_duration", 0),
        }
        # Find conversation log entry for this agent
        for conv in (conversations or []):
            if conv.get("agent") == card["name"]:
                card["turns"] = conv.get("turns", 0)
                card["errors"] = conv.get("errors", [])
                card["duration_seconds"] = conv.get("duration_seconds", 0)
        agent_cards.append(card)

    # Phase progress
    completed = []
    current = "unknown"
    if state:
        completed = state.get("completed_phases", [])
        current = state.get("current_phase", "unknown")

    # Autonomous run status
    from dashboard.api.chat import _autonomous_runs
    eng_name = request.cookies.get("active_engagement", "")
    run_info = _autonomous_runs.get(eng_name, {})

    return {
        "phase": {
            "current": current,
            "completed": completed,
        },
        "stats": {
            "hosts": stats.get("hosts", 0),
            "services": stats.get("services", 0),
            "vulnerabilities": stats.get("vulnerabilities", {}),
            "credentials": stats.get("credentials", 0),
            "tool_executions": stats.get("tool_executions", 0),
        },
        "agents": agent_cards,
        "autonomous": {
            "status": run_info.get("status", "not_started") if run_info else "not_started",
            "started_at": run_info.get("started_at"),
        },
    }


# ======================================================================
# Timeline (for replay)
# ======================================================================


@router.get("/timeline")
def get_timeline(request: Request):
    db, _, eid = _get_readers(request)
    events = db.get_timeline(eid)
    return {"events": events, "count": len(events)}


# ======================================================================
# SSE - Server-Sent Events for live updates
# ======================================================================


@router.get("/events")
async def sse_events(request: Request):
    """SSE stream that pushes diffs every 2 seconds."""
    db, fr, eid = _get_readers(request)

    async def event_generator():
        last_mtimes = {}
        last_max_exec_id = 0
        last_counts = {}
        last_live_turn_count = fr.count_live_turns()

        while True:
            # Check if client disconnected
            if await request.is_disconnected():
                break

            changed = []

            # Check file mtimes
            mtimes = fr.get_mtimes()
            for key in mtimes:
                if mtimes[key] != last_mtimes.get(key, 0):
                    changed.append(key)
            last_mtimes = mtimes

            # Check DB counts
            try:
                counts = db.get_counts(eid)
                for table, count in counts.items():
                    if count != last_counts.get(table, 0):
                        changed.append(f"db_{table}")
                last_counts = counts
            except Exception:
                pass

            # Emit events for changes
            if "state" in changed:
                data = json.dumps(fr.read_state())
                yield f"event: state_update\ndata: {data}\n\n"

            if "story" in changed:
                data = json.dumps({"story": fr.read_story()})
                yield f"event: story_update\ndata: {data}\n\n"

            if "network_map" in changed:
                data = json.dumps(fr.read_network_map())
                yield f"event: network_update\ndata: {data}\n\n"

            # New tool executions — include raw output preview
            if "db_tool_executions" in changed:
                try:
                    new_execs = db.get_tool_executions(eid, since_id=last_max_exec_id)
                    for ex in new_execs:
                        # Inject first 8KB of raw output so terminal shows real data
                        raw_path = ex.get("raw_output_path", "")
                        if raw_path:
                            try:
                                full_path = os.path.join(fr.engagement_dir, raw_path)
                                with open(full_path, "r", errors="replace") as _f:
                                    raw_preview = _f.read(8192)
                                file_size = os.path.getsize(full_path)
                                ex["raw_preview"] = raw_preview
                                ex["raw_total_bytes"] = file_size
                                ex["raw_truncated"] = file_size > 8192
                            except OSError:
                                pass
                        data = json.dumps(ex)
                        yield f"event: new_execution\ndata: {data}\n\n"
                    new_max = db.get_max_tool_execution_id(eid)
                    if new_max > last_max_exec_id:
                        last_max_exec_id = new_max
                except Exception:
                    pass

            # New hosts / vulns / creds
            if "db_hosts" in changed:
                hosts = db.get_hosts(eid)
                data = json.dumps({"hosts": hosts})
                yield f"event: hosts_update\ndata: {data}\n\n"

            if "db_vulnerabilities" in changed:
                vulns = db.get_vulnerabilities(eid)
                data = json.dumps({"vulnerabilities": vulns})
                yield f"event: vulns_update\ndata: {data}\n\n"

            if "db_credentials" in changed:
                creds = db.get_credentials(eid)
                data = json.dumps({"credentials": creds})
                yield f"event: creds_update\ndata: {data}\n\n"

            # Alerts
            if "alerts" in changed:
                alerts = fr.read_alerts()
                data = json.dumps({"alerts": alerts})
                yield f"event: alerts_update\ndata: {data}\n\n"

            # Live agent conversation turns
            if "live_turns" in changed:
                try:
                    new_turns = fr.read_live_turns(since_line=last_live_turn_count)
                    for turn in new_turns:
                        data = json.dumps(turn, default=str)
                        yield f"event: agent_turn\ndata: {data}\n\n"
                    last_live_turn_count = fr.count_live_turns()
                except Exception:
                    pass

            # Heartbeat
            yield f"event: heartbeat\ndata: {json.dumps({'time': time.time()})}\n\n"

            await asyncio.sleep(2)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.get("/events/live")
async def sse_events_live(request: Request):
    """Hybrid live SSE stream.

    Uses the event bus for instant tool/prompt activity and lightweight polling
    for persisted state files such as story, plan, and network map.
    """
    db, fr, eid = _get_readers(request)
    try:
        from memory.event_bus import get_event_bus
    except ImportError:
        # Fallback to polling-based endpoint
        return await sse_events(request)

    event_bus = get_event_bus()
    queue = event_bus.create_async_queue(maxsize=500)

    async def event_generator():
        last_mtimes = fr.get_mtimes()
        try:
            last_counts = db.get_counts(eid)
        except Exception:
            last_counts = {}
        last_poll_at = time.monotonic()
        last_heartbeat_at = 0.0

        try:
            # Replay recent history for late-joining clients
            history = event_bus.get_history(limit=200, engagement_id=eid)
            for event in history:
                yield event.to_sse()

            while True:
                if await request.is_disconnected():
                    break

                now = time.monotonic()
                if now - last_poll_at >= 2.0:
                    changed = []
                    mtimes = fr.get_mtimes()
                    for key, mtime in mtimes.items():
                        if mtime != last_mtimes.get(key, 0):
                            changed.append(key)
                    last_mtimes = mtimes

                    try:
                        counts = db.get_counts(eid)
                        for table, count in counts.items():
                            if count != last_counts.get(table, 0):
                                changed.append(f"db_{table}")
                        last_counts = counts
                    except Exception:
                        pass

                    if "state" in changed:
                        data = json.dumps(fr.read_state())
                        yield f"event: state_update\ndata: {data}\n\n"

                    if "story" in changed:
                        data = json.dumps({"story": fr.read_story()})
                        yield f"event: story_update\ndata: {data}\n\n"

                    if "network_map" in changed:
                        data = json.dumps(fr.read_network_map())
                        yield f"event: network_update\ndata: {data}\n\n"

                    if "plan" in changed:
                        data = json.dumps({"plan": fr.read_plan()})
                        yield f"event: plan_update\ndata: {data}\n\n"

                    if "db_hosts" in changed:
                        hosts = db.get_hosts(eid)
                        data = json.dumps({"hosts": hosts})
                        yield f"event: hosts_update\ndata: {data}\n\n"

                    if "db_vulnerabilities" in changed:
                        vulns = db.get_vulnerabilities(eid)
                        data = json.dumps({"vulnerabilities": vulns})
                        yield f"event: vulns_update\ndata: {data}\n\n"

                    if "db_credentials" in changed:
                        creds = db.get_credentials(eid)
                        data = json.dumps({"credentials": creds})
                        yield f"event: creds_update\ndata: {data}\n\n"

                    if "alerts" in changed:
                        alerts = fr.read_alerts()
                        data = json.dumps({"alerts": alerts})
                        yield f"event: alerts_update\ndata: {data}\n\n"

                    last_poll_at = now

                try:
                    event = await asyncio.wait_for(queue.get(), timeout=0.75)
                    if event.engagement_id != eid:
                        continue
                    yield event.to_sse()
                except asyncio.TimeoutError:
                    if now - last_heartbeat_at >= 5.0:
                        yield f"event: heartbeat\ndata: {{\"time\": {time.time()}}}\n\n"
                        last_heartbeat_at = now

        finally:
            event_bus.remove_async_queue(queue)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


# ======================================================================
# Agent Conversations (full prompt/response logs)
# ======================================================================

@router.get("/conversations")
async def list_conversations(request: Request):
    """List all saved agent conversations for the active engagement."""
    _, fr, _ = _get_readers(request)
    conv_dir = os.path.join(fr.engagement_dir, "logs", "conversations")
    if not os.path.isdir(conv_dir):
        return {"conversations": []}

    conversations = []
    for fname in sorted(os.listdir(conv_dir), reverse=True):
        if not fname.endswith(".json"):
            continue
        fpath = os.path.join(conv_dir, fname)
        try:
            with open(fpath) as f:
                data = json.load(f)
            conversations.append({
                "filename": fname,
                "agent": data.get("agent", "unknown"),
                "agent_type": data.get("agent_type", "unknown"),
                "model": data.get("model", "unknown"),
                "timestamp": data.get("timestamp", ""),
                "duration_seconds": data.get("duration_seconds", 0),
                "turns": len(data.get("conversation", [])),
                "tools_used": data.get("tools_used", []),
                "errors": data.get("errors", []),
            })
        except Exception:
            continue

    return {"conversations": conversations}


@router.get("/conversations/{filename}")
async def get_conversation(request: Request, filename: str):
    """Get the full conversation for a specific agent run."""
    _, fr, _ = _get_readers(request)

    # Sanitize filename to prevent path traversal
    if "/" in filename or "\\" in filename or ".." in filename:
        raise HTTPException(status_code=400, detail="Invalid filename")

    conv_path = os.path.join(fr.engagement_dir, "logs", "conversations", filename)
    if not os.path.exists(conv_path):
        raise HTTPException(status_code=404, detail="Conversation not found")

    with open(conv_path) as f:
        data = json.load(f)
    return data


# ======================================================================
# Testing Framework — Model Configs and Comparison
# ======================================================================


@router.get("/testing/model-configs")
async def list_model_configs(request: Request):
    """List all model configurations."""
    from profiles.model_config_manager import ModelConfigManager
    mcm = ModelConfigManager()
    return {"configs": mcm.list_configs()}


@router.get("/testing/model-configs/{name}")
async def get_model_config(name: str, request: Request):
    """Get a specific model configuration."""
    from profiles.model_config_manager import ModelConfigManager
    mcm = ModelConfigManager()
    config = mcm.get_config(name)
    if not config:
        raise HTTPException(status_code=404, detail=f"Model config '{name}' not found")
    return config


class SaveModelConfigRequest(BaseModel):
    name: str
    roles: dict[str, str]
    description: str = ""
    tags: list[str] = []


@router.post("/testing/model-configs")
async def save_model_config(body: SaveModelConfigRequest, request: Request):
    """Create/save a model configuration."""
    from profiles.model_config_manager import ModelConfigManager
    mcm = ModelConfigManager()
    path = mcm.save_config(
        name=body.name,
        roles=body.roles,
        description=body.description,
        tags=body.tags,
    )
    return {"success": True, "path": str(path)}


@router.get("/testing/estimate-cost/{config_name}")
async def estimate_cost(
    config_name: str,
    tokens_per_agent: int = Query(default=100000),
    request: Request = None,
):
    """Estimate cost for a model configuration."""
    from profiles.model_config_manager import ModelConfigManager
    mcm = ModelConfigManager()
    return mcm.estimate_config_cost(config_name, tokens_per_agent)


@router.get("/testing/results")
async def get_test_results(
    target_ip: str = Query(default=""),
    ctf_tag: str = Query(default=""),
    profile_name: str = Query(default=""),
    request: Request = None,
):
    """Get test results filtered by target, tag, or profile."""
    from profiles.metrics_recorder import MetricsRecorder
    engagements_dir = request.app.state.engagements_dir
    return {
        "results": MetricsRecorder.find_metrics(
            engagements_dir,
            target_ip=target_ip,
            ctf_tag=ctf_tag,
            profile_name=profile_name,
        )
    }


@router.get("/testing/comparison")
async def get_comparison(
    target_ip: str = Query(default=""),
    ctf_tag: str = Query(default=""),
    request: Request = None,
):
    """Get comparison analysis across engagement runs."""
    from profiles.comparison import EngagementComparison
    engagements_dir = request.app.state.engagements_dir
    comp = EngagementComparison(engagements_dir)
    metrics = comp.get_comparison_data(target_ip=target_ip, ctf_tag=ctf_tag)
    return comp.analyze(metrics)


@router.get("/testing/comparison/report")
async def get_comparison_report(
    target_ip: str = Query(default=""),
    ctf_tag: str = Query(default=""),
    format: str = Query(default="markdown"),
    request: Request = None,
):
    """Generate comparison report in markdown, CSV, or JSON format."""
    from profiles.comparison import EngagementComparison
    engagements_dir = request.app.state.engagements_dir
    comp = EngagementComparison(engagements_dir)

    if format == "csv":
        csv_data = comp.export_csv(target_ip=target_ip, ctf_tag=ctf_tag)
        return StreamingResponse(
            iter([csv_data]),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=comparison.csv"},
        )
    elif format == "json":
        return comp.export_json(target_ip=target_ip, ctf_tag=ctf_tag)
    else:
        report = comp.generate_report(target_ip=target_ip, ctf_tag=ctf_tag)
        return {"report": report}


@router.get("/testing/model-costs")
async def get_model_costs(request: Request):
    """Get the full model costs registry."""
    from profiles.model_config_manager import ModelConfigManager
    mcm = ModelConfigManager()
    return {"models": mcm.get_model_costs()}


# ======================================================================
# Settings — Model Configuration Management
# ======================================================================


@router.delete("/settings/model-configs/{config_name}")
async def delete_model_config(config_name: str, request: Request):
    """Delete a model configuration."""
    from profiles.model_config_manager import ModelConfigManager
    mcm = ModelConfigManager()
    if mcm.delete_config(config_name):
        return {"success": True}
    raise HTTPException(status_code=404, detail=f"Config '{config_name}' not found")


# ======================================================================
# Prompt Profiles
# ======================================================================


@router.get("/settings/prompt-profiles")
async def list_prompt_profiles(request: Request):
    """List all prompt profiles."""
    from profiles.master_profile_manager import MasterProfileManager
    mpm = MasterProfileManager()
    return {"profiles": mpm.list_prompt_profiles()}


@router.get("/settings/prompt-profiles/{name}")
async def get_prompt_profile(name: str, request: Request):
    """Get a prompt profile with all agent prompts."""
    from profiles.master_profile_manager import MasterProfileManager
    mpm = MasterProfileManager()
    profile = mpm.get_prompt_profile(name)
    if not profile:
        raise HTTPException(404, f"Prompt profile '{name}' not found")
    return profile


@router.get("/settings/prompt-profiles/{name}/agent/{agent_type}")
async def get_agent_prompt(name: str, agent_type: str, request: Request):
    """Get a single agent's prompt from a profile."""
    from profiles.master_profile_manager import MasterProfileManager
    mpm = MasterProfileManager()
    content = mpm.get_agent_prompt(name, agent_type)
    if content is None:
        raise HTTPException(404, f"Prompt for '{agent_type}' not found in profile '{name}'")
    return {"agent_type": agent_type, "profile": name, "content": content}


class SaveAgentPromptRequest(BaseModel):
    content: str


@router.put("/settings/prompt-profiles/{name}/agent/{agent_type}")
async def save_agent_prompt(name: str, agent_type: str, body: SaveAgentPromptRequest, request: Request):
    """Save a single agent's prompt in a profile."""
    from profiles.master_profile_manager import MasterProfileManager
    mpm = MasterProfileManager()
    path = mpm.save_agent_prompt(name, agent_type, body.content)
    return {"success": True, "path": str(path)}


class CreatePromptProfileRequest(BaseModel):
    name: str
    description: str = ""
    source: str = "default"
    tags: list[str] = []


@router.post("/settings/prompt-profiles")
async def create_prompt_profile(body: CreatePromptProfileRequest, request: Request):
    """Create a new prompt profile (copied from source or default)."""
    from profiles.master_profile_manager import MasterProfileManager
    mpm = MasterProfileManager()
    try:
        result = mpm.create_prompt_profile(
            name=body.name, description=body.description,
            source=body.source, tags=body.tags,
        )
        return {"success": True, **result}
    except ValueError as e:
        raise HTTPException(400, str(e))


class RenamePromptProfileRequest(BaseModel):
    new_name: str


@router.post("/settings/prompt-profiles/{name}/rename")
async def rename_prompt_profile(name: str, body: RenamePromptProfileRequest, request: Request):
    """Rename a prompt profile."""
    from profiles.master_profile_manager import MasterProfileManager
    mpm = MasterProfileManager()
    if mpm.rename_prompt_profile(name, body.new_name):
        return {"success": True}
    raise HTTPException(400, "Rename failed (source missing or target exists)")


@router.post("/settings/prompt-profiles/{name}/duplicate")
async def duplicate_prompt_profile(name: str, body: RenamePromptProfileRequest, request: Request):
    """Duplicate a prompt profile under a new name."""
    from profiles.master_profile_manager import MasterProfileManager
    mpm = MasterProfileManager()
    try:
        result = mpm.duplicate_prompt_profile(name, body.new_name)
        return {"success": True, **result}
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.delete("/settings/prompt-profiles/{name}")
async def delete_prompt_profile(name: str, request: Request):
    """Delete a prompt profile."""
    from profiles.master_profile_manager import MasterProfileManager
    mpm = MasterProfileManager()
    try:
        if mpm.delete_prompt_profile(name):
            return {"success": True}
        raise HTTPException(404, f"Prompt profile '{name}' not found")
    except ValueError as e:
        raise HTTPException(400, str(e))


# ======================================================================
# Master Profiles
# ======================================================================


@router.get("/settings/master-profiles")
async def list_master_profiles(request: Request):
    """List all master profiles with aggregated stats."""
    from profiles.master_profile_manager import MasterProfileManager
    mpm = MasterProfileManager()
    return {"profiles": mpm.list_master_profiles()}


@router.get("/settings/master-profiles/{name}")
async def get_master_profile(name: str, request: Request):
    """Get a master profile with full details and history."""
    from profiles.master_profile_manager import MasterProfileManager
    mpm = MasterProfileManager()
    profile = mpm.get_master_profile(name)
    if not profile:
        raise HTTPException(404, f"Master profile '{name}' not found")
    return profile


@router.get("/settings/master-profiles/{name}/resolve")
async def resolve_master_profile(name: str, request: Request):
    """Resolve a master profile to effective models and prompts."""
    from profiles.master_profile_manager import MasterProfileManager
    mpm = MasterProfileManager()
    try:
        resolved = mpm.resolve(name)
        # Convert Path to string for JSON serialization
        resolved["prompt_dir"] = str(resolved["prompt_dir"])
        return resolved
    except ValueError as e:
        raise HTTPException(404, str(e))


class SaveMasterProfileRequest(BaseModel):
    name: str
    models_config: str  # name of a saved model config preset
    prompt_profile: str
    description: str = ""
    tags: list[str] = []
    agent_overrides: dict[str, dict[str, str]] = {}


@router.post("/settings/master-profiles")
async def save_master_profile(body: SaveMasterProfileRequest, request: Request):
    """Create or update a master profile."""
    from profiles.master_profile_manager import MasterProfileManager
    mpm = MasterProfileManager()
    path = mpm.save_master_profile(
        name=body.name,
        model_config=body.models_config,
        prompt_profile=body.prompt_profile,
        description=body.description,
        tags=body.tags,
        agent_overrides=body.agent_overrides,
    )
    return {"success": True, "path": str(path)}


@router.delete("/settings/master-profiles/{name}")
async def delete_master_profile(name: str, request: Request):
    """Delete a master profile."""
    from profiles.master_profile_manager import MasterProfileManager
    mpm = MasterProfileManager()
    if mpm.delete_master_profile(name):
        return {"success": True}
    raise HTTPException(404, f"Master profile '{name}' not found")


# ======================================================================
# Master Profile — Engagement Activation
# ======================================================================


class ActivateMasterProfileRequest(BaseModel):
    master_profile: str


@router.post("/engagement/{eng_name}/master-profile")
async def activate_master_profile(eng_name: str, body: ActivateMasterProfileRequest, request: Request):
    """Set the active master profile for an engagement.

    Stores the master profile name in the engagement metadata and applies the
    resolved model config as per-engagement overrides.
    """
    from profiles.master_profile_manager import MasterProfileManager

    engagements_dir = request.app.state.engagements_dir
    edir = os.path.join(engagements_dir, eng_name)
    mpm = MasterProfileManager()

    try:
        resolved = mpm.resolve(body.master_profile)
    except ValueError as e:
        raise HTTPException(400, str(e))

    # Persist to engagement DB: store model config overrides + master profile name
    db_manager, eng = _ensure_engagement_row(edir, eng_name)
    db_manager.update_model_config(eng["id"], resolved["effective_models"])

    # Store master profile name in engagement metadata via a JSON field
    _save_engagement_master_profile(edir, body.master_profile)

    db_manager.close()
    return {
        "success": True,
        "master_profile": body.master_profile,
        "effective_models": resolved["effective_models"],
        "effective_prompts": resolved["effective_prompts"],
    }


@router.get("/engagement/{eng_name}/master-profile")
async def get_engagement_master_profile(eng_name: str, request: Request):
    """Get the active master profile for an engagement."""
    engagements_dir = request.app.state.engagements_dir
    edir = os.path.join(engagements_dir, eng_name)
    mp_name = _load_engagement_master_profile(edir)
    if not mp_name:
        return {"master_profile": None}

    from profiles.master_profile_manager import MasterProfileManager
    mpm = MasterProfileManager()
    profile = mpm.get_master_profile(mp_name)
    return {"master_profile": mp_name, "profile_data": profile}


class SaveCurrentAsProfileRequest(BaseModel):
    type: str  # "model_config" | "prompt_profile" | "master_profile"
    name: str
    description: str = ""
    tags: list[str] = []


@router.post("/engagement/{eng_name}/save-as-profile")
async def save_current_as_profile(eng_name: str, body: SaveCurrentAsProfileRequest, request: Request):
    """Save the current engagement's effective config as a named profile."""
    engagements_dir = request.app.state.engagements_dir
    edir = os.path.join(engagements_dir, eng_name)

    if body.type == "model_config":
        from profiles.model_config_manager import ModelConfigManager
        db_manager, eng = _ensure_engagement_row(edir, eng_name)
        current_models = db_manager.get_model_config(eng["id"])
        db_manager.close()
        mcm = ModelConfigManager()
        path = mcm.save_config(body.name, current_models, body.description, body.tags)
        return {"success": True, "path": str(path)}

    elif body.type == "prompt_profile":
        from profiles.master_profile_manager import MasterProfileManager
        mpm = MasterProfileManager()
        # The active prompt profile: copy from whatever is active
        mp_name = _load_engagement_master_profile(edir)
        source = "default"
        if mp_name:
            profile = mpm.get_master_profile(mp_name)
            if profile:
                source = profile.get("prompt_profile", "default")
        result = mpm.create_prompt_profile(body.name, body.description, source=source, tags=body.tags)
        return {"success": True, **result}

    elif body.type == "master_profile":
        from profiles.master_profile_manager import MasterProfileManager
        from profiles.model_config_manager import ModelConfigManager
        db_manager, eng = _ensure_engagement_row(edir, eng_name)
        current_models = db_manager.get_model_config(eng["id"])
        db_manager.close()

        # Save a model config first
        mcm = ModelConfigManager()
        mc_name = f"{body.name}_models"
        mcm.save_config(mc_name, current_models, f"Auto-saved from {eng_name}")

        # Get active prompt profile
        mp_name = _load_engagement_master_profile(edir)
        prompt_profile = "default"
        if mp_name:
            mpm = MasterProfileManager()
            existing = mpm.get_master_profile(mp_name)
            if existing:
                prompt_profile = existing.get("prompt_profile", "default")

        mpm = MasterProfileManager()
        path = mpm.save_master_profile(
            body.name, mc_name, prompt_profile, body.description, body.tags,
        )
        return {"success": True, "path": str(path)}

    raise HTTPException(400, f"Unknown profile type: {body.type}")


# ======================================================================
# Master Profile History & Cost Tracking
# ======================================================================


@router.get("/settings/master-profiles/{name}/history")
async def get_master_profile_history(name: str, request: Request):
    """Get run history for a master profile."""
    from profiles.master_profile_manager import MasterProfileManager
    mpm = MasterProfileManager()
    return mpm.get_aggregated_stats(name)


@router.get("/settings/profile-history")
async def get_all_profile_history(request: Request):
    """Get aggregated history across all master profiles."""
    from profiles.master_profile_manager import MasterProfileManager
    mpm = MasterProfileManager()
    profiles = mpm.list_master_profiles()
    result = []
    for p in profiles:
        stats = mpm.get_aggregated_stats(p["name"])
        stats["profile_name"] = p["name"]
        stats["description"] = p.get("description", "")
        result.append(stats)
    return {"profiles": result}


# ======================================================================
# Helpers — engagement master profile persistence
# ======================================================================


def _save_engagement_master_profile(engagement_dir: str, master_profile_name: str):
    """Persist the active master profile name for an engagement."""
    meta_path = os.path.join(engagement_dir, "profile_config.json")
    data = {}
    if os.path.exists(meta_path):
        try:
            with open(meta_path) as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError):
            data = {}
    data["active_master_profile"] = master_profile_name
    with open(meta_path, "w") as f:
        json.dump(data, f, indent=2)


def _load_engagement_master_profile(engagement_dir: str) -> Optional[str]:
    """Load the active master profile name for an engagement."""
    meta_path = os.path.join(engagement_dir, "profile_config.json")
    if not os.path.exists(meta_path):
        return None
    try:
        with open(meta_path) as f:
            data = json.load(f)
        return data.get("active_master_profile")
    except (json.JSONDecodeError, OSError):
        return None


# ---------------------------------------------------------------------------
# Credentialed execution
# ---------------------------------------------------------------------------

class CredentialedExecRequest(BaseModel):
    tool_name: str
    command_template: str
    context: str


def _scrub_credentials(text: str, credentials: list[str]) -> str:
    """Remove credential values from output text."""
    for cred in credentials:
        if cred:
            text = text.replace(cred, "[REDACTED]")
    return text


@router.post("/credentialed-exec")
async def credentialed_exec(body: CredentialedExecRequest, request: Request):
    """Execute a tool with operator-held credentials injected server-side."""
    store: dict = getattr(request.app.state, "credential_store", {})
    cred_value = store.get(body.tool_name)
    if not cred_value:
        raise HTTPException(
            status_code=400,
            detail=f"No credentials configured for tool '{body.tool_name}'",
        )

    if "{CREDENTIAL}" not in body.command_template:
        raise HTTPException(
            status_code=400,
            detail="command_template must contain {CREDENTIAL} placeholder",
        )

    command = body.command_template.replace("{CREDENTIAL}", cred_value)
    try:
        parts = shlex.split(command)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid command syntax: {e}")
    if not parts:
        raise HTTPException(status_code=400, detail="Empty command after substitution")

    from tools.executor import ToolExecutor

    executor = ToolExecutor()
    result = executor.run(tool_name=parts[0], args=parts[1:], timeout=120)

    creds_to_scrub = [cred_value]
    return {
        "tool_name": body.tool_name,
        "return_code": result.return_code,
        "stdout": _scrub_credentials(result.stdout, creds_to_scrub),
        "stderr": _scrub_credentials(result.stderr, creds_to_scrub),
        "duration": result.duration_seconds,
    }


@router.get("/credentials/configured")
async def list_configured_credentials(request: Request):
    """Return tool names that have credentials configured (no values)."""
    store: dict = getattr(request.app.state, "credential_store", {})
    return {"configured": list(store.keys())}

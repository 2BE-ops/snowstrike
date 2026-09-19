"""
SnowStrike AI v7.0 - Orchestrator Agent (Goal-Driven Architecture)

Replaces the rigid phase pipeline with an iterative decision loop.
Opus evaluates a compact intelligence brief each iteration and decides
the single highest-value next action. Sub-agents execute on Sonnet.
"""

import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Dict, Optional

import anthropic

from config import (
    ANTHROPIC_API_KEY,
    ENGAGEMENTS_DIR,
    INTELLIGENCE_BRIEF_TOKEN_BUDGET,
    MAX_PARALLEL_AGENTS,
    MAX_ORCHESTRATOR_ITERATIONS,
    OBJECTIVE_TEMPLATES,
    AGENT_TYPES,
    DB_FILENAME,
    get_model_context_window,
    require_root,
)
from agents.model_client import create_model_client, resolve_model_for_role
from memory.cost_tracker import CostTracker
from memory.event_bus import get_event_bus, EventType
from profiles.metrics_recorder import MetricsRecorder
from agents.protocol import (
    AGENT_CAPABILITIES,
    AgentHandoff,
    HandoffQueue,
    format_handoff_for_context,
)
from memory.database import DatabaseManager
from memory.shared_state import SharedState
from memory.attack_story import AttackStory
from memory.engagement_memory import EngagementMemory
from memory.network_map import NetworkMap
from tools.scope_hook import register_scope_enforcement
from agents.base_agent import AgentResult
from agents.verification_gate import VerificationGate, VerificationStatus

# Agent imports — current specialist runtime agents
from agents.recon_agent import ReconAgent
from agents.webapp_agent import WebAppAgent
from agents.browser_agent import BrowserAgent
from agents.attack_agent import AttackAgent
from agents.cloud_agent import CloudAgent
from agents.binary_agent import BinaryREAgent
from agents.ghidra_agent import GhidraAgent
from agents.forensics_agent import ForensicsAgent
from agents.osint_agent import OSINTAgent
from agents.reporting_agent import ReportingAgent
from agents.alerts_agent import AlertsAgent
from agents.scope_monitor import ScopeMonitor

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Orchestrator state machine (for STATUS events)
# ---------------------------------------------------------------------------

class OrchestratorState(str, Enum):
    """Lifecycle states emitted as STATUS events during run_autonomous."""
    THINKING = "THINKING"
    DISPATCHING = "DISPATCHING"
    AGENT_RUNNING = "AGENT_RUNNING"
    COLLECTING = "COLLECTING"
    IDLE = "IDLE"
    PAUSED = "PAUSED"
    FINISHED = "FINISHED"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ensure_list(val, default=None):
    """Safely coerce a value to a list."""
    if val is None:
        return default or []
    if isinstance(val, list):
        return val
    if isinstance(val, dict):
        return list(val.values())
    if isinstance(val, str):
        return [val]
    return list(val) if hasattr(val, "__iter__") else [val]


def _ensure_dict(val, default=None):
    """Safely coerce a value to a dict."""
    if isinstance(val, dict):
        return val
    return default or {}


# ---------------------------------------------------------------------------
# Agent class registry — dynamic from YAML, with hardcoded fallback
# ---------------------------------------------------------------------------

_HARDCODED_AGENT_CLASSES = {
    "recon": ReconAgent,
    "webapp": WebAppAgent,
    "browser": BrowserAgent,
    "attack": AttackAgent,
    "cloud": CloudAgent,
    "binary": BinaryREAgent,
    "ghidra": GhidraAgent,
    "forensics": ForensicsAgent,
    "osint": OSINTAgent,
    "reporting": ReportingAgent,
}


def _init_agent_registry():
    """Initialize AgentRegistry from YAML configs; fall back to hardcoded dicts."""
    config_dir = Path(os.environ.get("AGENT_CONFIG_DIR", Path(__file__).parent.parent / "agent-configs"))
    try:
        from agents.registry import AgentRegistry
        registry = AgentRegistry(Path(config_dir))
        registry.load_all()
        if registry.get_agent_classes():
            return registry
    except Exception as e:
        logger.debug("AgentRegistry init failed, using hardcoded fallback: %s", e)
    return None


_agent_registry = _init_agent_registry()

if _agent_registry is not None:
    AGENT_CLASSES = _agent_registry.get_agent_classes()
else:
    AGENT_CLASSES = dict(_HARDCODED_AGENT_CLASSES)


def get_agent_registry():
    """Return the active AgentRegistry instance, or None if using hardcoded fallback."""
    return _agent_registry


class OrchestratorAgent:
    """
    Goal-driven orchestrator. Replaces the rigid phase pipeline with an
    iterative loop where Opus evaluates an intelligence brief and picks
    the single highest-value next action each iteration.

    Flow:
        1. Initialize objectives from engagement type
        2. Loop:
            a. Build compact intelligence brief (what we know, what failed,
               what access we have, what objectives remain)
            b. Send brief to Opus → receive a JSON decision
            c. Dispatch the chosen agent on Sonnet
            d. Collect result, update state
            e. Repeat until objectives met or budget exhausted
        3. Generate report
    """

    def __init__(self, engagement_dir: str, engagement_id: int = 1):
        self.engagement_dir = engagement_dir
        self.engagement_id = engagement_id

        # Memory systems
        self.db = DatabaseManager(engagement_dir)
        self.shared_state = SharedState(engagement_dir)
        self.handoff_queue = HandoffQueue(engagement_dir)
        self.story = AttackStory(engagement_dir)
        self.network_map = NetworkMap(engagement_dir)
        # Perform tool preflight as early as possible on startup.
        self._initialize_tool_compatibility_map()

        # Register scope enforcement hook (priority 1 — blocks out-of-scope targets)
        register_scope_enforcement(engagement_dir)

        # Load YAML-configured hook rules (operator-defined, priority 50)
        self._load_yaml_hooks()

        # Per-engagement model overrides
        self.model_config = self.db.get_model_config(engagement_id)

        # Orchestrator uses the orchestrator tier (Opus)
        orchestrator_model = resolve_model_for_role("orchestrator", self.model_config)
        self.client = create_model_client(orchestrator_model)
        self.orchestrator_model = orchestrator_model

        # Initialize agent roster before rendering capabilities (needed by _render_agent_capabilities)
        self._agent_roster: list[str] = []  # empty = all agents allowed

        # Load orchestrator prompt and inject agent capabilities at runtime
        prompt_path = Path(__file__).parent / "prompts" / "orchestrator.md"
        raw_prompt = prompt_path.read_text() if prompt_path.exists() else ""
        self.system_prompt = raw_prompt.replace(
            "{AGENT_CAPABILITIES_BLOCK}",
            self._render_agent_capabilities(),
        )

        # Alerts agent (compaction tier — Kimi/Haiku, read-only monitor)
        self.alerts_agent = AlertsAgent(engagement_dir, self.model_config, engagement_id=engagement_id)

        # Verification gate (compaction tier — challenges high-value claims)
        self.verification_gate = VerificationGate(model_config=self.model_config)

        # Parallel scope monitor (event bus subscriber — validates tool targets)
        self.scope_monitor = ScopeMonitor(self.engagement_dir)
        self.scope_monitor.start()

        # Cost tracking
        self.cost_tracker = CostTracker(self.db.db_path)

        # Metrics recorder for A/B testing (optional — initialized when using profiles)
        self._metrics_recorder: Optional[MetricsRecorder] = None

        # Profile metadata (set when running with a test profile)
        self._profile_name: str = ""
        self._prompt_preset: str = ""
        self._model_config_name: str = ""
        self._prompt_dir: Optional[Path] = None
        self._effective_prompts: dict[str, str] = {}

        # Auto-load master profile if one is active for this engagement
        self._auto_load_master_profile()

        # Cross-engagement memory (global SQLite at ~/.snowstrike/memory.db)
        self.engagement_memory = EngagementMemory()

        # Execution history (for the intelligence brief)
        self.iteration_history: list[dict] = []
        self.failed_approaches: list[str] = []

        # Phase-forcing counters (architectural fix: prevent recon loops)
        self._dispatch_lock = threading.Lock()  # Guards mutable dispatch tracking state
        self._agent_dispatch_counts: dict[str, int] = {}
        self._consecutive_no_progress: int = 0
        self._last_known_state_hash: str = ""
        self._recon_saturation_threshold: int = 3  # after N recon dispatches, force exploitation
        self._consecutive_error_limit: int = 3  # circuit breaker
        self._task_fingerprints: dict[str, int] = {}  # fingerprint -> dispatch count
        self._max_similar_dispatches: int = 2  # max times a similar task can be dispatched
        self._task_last_dispatch_ts: dict[str, float] = {}  # fingerprint -> unix timestamp
        self._dispatch_cooldown_seconds: int = 180  # dedupe cooldown window
        self._banned_task_fingerprints: set[str] = set()
        self._recent_failed_fingerprints: list[str] = []
        self._objective_state_hash: str = ""
        self._objective_stall_iterations: int = 0
        self._objective_stall_limit: int = 3
        self._consecutive_ban_blocks: int = 0
        self._max_consecutive_ban_blocks: int = 3  # after N, escape to different modality or terminate
        self._target_instability_count: int = 0  # tracks service instability signals
        self._target_instability_threshold: int = 3  # after N, throttle exploit retries

        # Incremental brief tracking (Phase 4)
        self._last_brief_snapshot: dict = {}  # snapshot of state at last brief
        self._brief_cache: str = ""  # last full brief text

        # Run finalization flag — prevents any dispatch after the run is declared complete
        self._run_finalized: bool = False

        # What-if fork cooldown: track last iteration a what-if was used
        self._what_if_last_iteration: int = -10  # allow immediate first use
        self._what_if_cooldown_iterations: int = 5


    # =========================================================================
    # Context value tiering for iteration history
    # =========================================================================

    def _assess_context_value(self, result) -> str:
        """Classify result into 'full', 'summary', or 'discard'.

        full: Contains credentials, shells, confirmed vulns — keep everything
        summary: Useful recon data but no critical findings — keep abbreviated
        discard: Failed with no new information — keep only the fact it was tried
        """
        findings = getattr(result, "findings", None) or {}
        summary_text = str(getattr(result, "summary", "") or "").lower()

        cred_refs = findings.get("credential_references", 0) or 0
        vuln_refs = findings.get("vuln_references", 0) or 0
        findings_saved = findings.get("findings_saved", 0) or 0

        critical_keywords = [
            "credential", "password", "shell", "access gained", "root",
            "admin", "flag", "exploit", "reverse shell", "rce",
        ]
        has_critical = any(kw in summary_text for kw in critical_keywords)

        if has_critical or cred_refs > 0 or vuln_refs > 0 or findings_saved > 0:
            return "full"

        success = getattr(result, "success", False)
        host_refs = findings.get("host_references", 0) or 0
        tools_used_count = findings.get("tools_used_count", 0) or 0

        recon_keywords = ["host", "port", "service", "open", "discovered", "found", "running"]
        has_recon = any(kw in summary_text for kw in recon_keywords)

        if success and (host_refs > 0 or has_recon or tools_used_count > 2):
            return "summary"

        return "discard"

    def _build_history_entry(self, result, iteration: int, agent_type: str, task: str) -> dict:
        """Build a tiered iteration_history entry based on context value."""
        tier = self._assess_context_value(result)
        outcome_class = getattr(result, "outcome_class", "normal")

        if tier == "full":
            return {
                "iteration": iteration,
                "agent": agent_type,
                "task": task[:300],
                "success": result.success,
                "summary": (str(result.summary)[:500] if result.summary else ""),
                "findings": getattr(result, "findings", None) or {},
                "outcome_class": outcome_class,
                "context_value": "full",
            }
        elif tier == "summary":
            return {
                "iteration": iteration,
                "agent": agent_type,
                "task": task[:150],
                "success": result.success,
                "summary": (str(result.summary)[:200] if result.summary else ""),
                "outcome_class": outcome_class,
                "context_value": "summary",
            }
        else:  # discard
            return {
                "iteration": iteration,
                "agent": agent_type,
                "task": task[:80],
                "success": result.success,
                "summary": "No new findings.",
                "outcome_class": outcome_class,
                "context_value": "discard",
            }

    # =========================================================================
    # Auto-load master profile from engagement config
    # =========================================================================

    def _auto_load_master_profile(self):
        """Check if the engagement has an active master profile and apply it.

        Also reads experiment-level overrides from profile_config.json:
        - agent_roster: restrict which agents the orchestrator can dispatch
        - prompt_dir_override: use compiled prompt directory
        """
        try:
            config_path = os.path.join(self.engagement_dir, "profile_config.json")
            if not os.path.exists(config_path):
                return
            import json as _json
            with open(config_path) as f:
                data = _json.load(f)
            mp_name = data.get("active_master_profile")
            if mp_name:
                self.apply_master_profile(mp_name)
                logger.info(f"[Orchestrator] Auto-loaded master profile: {mp_name}")

            # Agent roster restriction
            roster = data.get("agent_roster", [])
            if roster:
                self._agent_roster = roster
                # Re-render system prompt with filtered capabilities
                prompt_path = Path(__file__).parent / "prompts" / "orchestrator.md"
                src = self._prompt_dir or prompt_path.parent
                raw = (src / "orchestrator.md").read_text() if (src / "orchestrator.md").exists() else ""
                if not raw and prompt_path.exists():
                    raw = prompt_path.read_text()
                self.system_prompt = raw.replace(
                    "{AGENT_CAPABILITIES_BLOCK}",
                    self._render_agent_capabilities(),
                )
                logger.info(f"[Orchestrator] Agent roster restricted to: {roster}")

            # Prompt directory override (from prompt compilation)
            prompt_dir = data.get("prompt_dir_override")
            if prompt_dir and Path(prompt_dir).is_dir():
                self._prompt_dir = Path(prompt_dir)
                logger.info(f"[Orchestrator] Using compiled prompt dir: {prompt_dir}")
        except Exception as e:
            logger.warning(f"[Orchestrator] Failed to auto-load master profile: {e}")

    # =========================================================================
    # Prompt helpers
    # =========================================================================

    def _render_agent_capabilities(self) -> str:
        """Generate a concise agent capability summary from AGENT_CAPABILITIES.

        This replaces the static list that was previously hardcoded in
        orchestrator.md, keeping the prompt in sync with protocol.py
        automatically. If an agent_roster is set, only listed agents are shown.

        Uses the AgentRegistry when available, falls back to protocol.py's
        hardcoded AGENT_CAPABILITIES dict.
        """
        # Use registry capabilities if available, else hardcoded
        caps_dict = (
            _agent_registry.get_capabilities()
            if _agent_registry is not None
            else AGENT_CAPABILITIES
        )
        lines: list[str] = []
        for name, cap in caps_dict.items():
            # Filter by roster if set
            if self._agent_roster and name not in self._agent_roster:
                continue
            caps = ", ".join(c.replace("_", " ") for c in cap.capabilities[:8])
            extra = f" (+{len(cap.capabilities) - 8} more)" if len(cap.capabilities) > 8 else ""
            requires = ", ".join(cap.requires) if cap.requires else "none"
            lines.append(f"- **{name}**: {caps}{extra}. Requires: {requires}.")
        return "\n".join(lines)

    # =========================================================================
    # Engagement Lifecycle (unchanged interface, new internals)
    # =========================================================================

    @classmethod
    def create_engagement(
        cls,
        target: str,
        scope: str = "",
        methodology: str = "standard",
        out_of_scope: str = "",
        name: str = "",
    ) -> "OrchestratorAgent":
        """Create a new engagement directory and initialize all systems."""
        scope_list = [s.strip() for s in scope.split(",") if s.strip()] if scope else [target]
        oos_list = [s.strip() for s in out_of_scope.split(",") if s.strip()] if out_of_scope else []

        timestamp = datetime.now().strftime("%Y-%m-%d")
        safe_target = target.replace("/", "_").replace(":", "_").replace(" ", "_")[:50]
        eng_name = name or f"{timestamp}_{safe_target}"
        eng_dir = str(ENGAGEMENTS_DIR / eng_name)

        os.makedirs(eng_dir, exist_ok=True)
        os.makedirs(os.path.join(eng_dir, "logs", "raw"), exist_ok=True)
        os.makedirs(os.path.join(eng_dir, "loot"), exist_ok=True)

        db = DatabaseManager(eng_dir)
        engagement_id = db.create_engagement(
            name=eng_name,
            target=target,
            scope=scope_list,
            out_of_scope=oos_list,
            methodology=methodology,
        )

        shared_state = SharedState(eng_dir)
        shared_state.initialize(
            target=target,
            scope=scope_list,
            out_of_scope=oos_list,
            methodology=methodology,
        )

        # Store initial objectives in shared state
        objectives = OBJECTIVE_TEMPLATES.get(methodology, OBJECTIVE_TEMPLATES["standard"])
        shared_state.update_section("objectives", [
            {"description": obj, "status": "pending"} for obj in objectives
        ])

        story = AttackStory(eng_dir)
        story.initialize(target=target, methodology=methodology)

        network_map = NetworkMap(eng_dir)
        network_map.save()

        logger.info(f"Created engagement: {eng_name} (id={engagement_id})")
        return cls(eng_dir, engagement_id)

    @classmethod
    def resume_engagement(cls, engagement_dir: str) -> "OrchestratorAgent":
        """Resume an existing engagement from its directory."""
        db = DatabaseManager(engagement_dir)
        eng = db.get_engagement(1)
        if eng is None:
            eng_name = os.path.basename(engagement_dir)
            parts = eng_name.split("_", 1)
            target = parts[1] if len(parts) > 1 else eng_name
            target = target.replace("_", ".")
            engagement_id = db.create_engagement(
                name=eng_name, target=target, methodology="standard"
            )
            logger.info(f"Auto-created engagement row: {eng_name} (id={engagement_id})")
        else:
            engagement_id = eng["id"]
        return cls(engagement_dir, engagement_id=engagement_id)

    @classmethod
    def list_engagements(cls) -> list[dict]:
        """List all engagement directories with basic info."""
        engagements = []
        eng_base = ENGAGEMENTS_DIR
        if not eng_base.exists():
            return engagements
        for entry in sorted(eng_base.iterdir()):
            if entry.is_dir() and (entry / DB_FILENAME).exists():
                try:
                    db = DatabaseManager(str(entry))
                    eng = db.get_engagement(1)
                    engagements.append({
                        "directory": str(entry),
                        "name": entry.name,
                        "target": eng.get("target", "unknown") if eng else "unknown",
                        "status": eng.get("status", "unknown") if eng else "unknown",
                        "methodology": eng.get("methodology", "unknown") if eng else "unknown",
                        "created_at": eng.get("created_at", "") if eng else "",
                    })
                except Exception:
                    engagements.append({
                        "directory": str(entry),
                        "name": entry.name,
                        "target": "error reading",
                        "status": "error",
                    })
        return engagements

    # =========================================================================
    # Profile Application (for A/B testing)
    # =========================================================================

    def apply_profile(self, profile_name: str) -> None:
        """Apply a test profile to this engagement.

        Loads the profile's prompt preset and model configuration,
        overriding the defaults. Also initializes the metrics recorder.
        """
        from profiles.profile_manager import ProfileManager

        pm = ProfileManager()
        resolved = pm.resolve_profile(profile_name)

        self._profile_name = profile_name
        self._prompt_preset = resolved["metadata"].get("prompt_preset", "")
        self._model_config_name = resolved["metadata"].get("model_config", "")
        self._prompt_dir = resolved["prompt_dir"]
        self._effective_prompts = {}  # all agents use the same prompt preset

        # Apply model config overrides
        model_config = resolved["model_config"]
        if model_config:
            self.model_config = model_config
            # Re-create orchestrator client with new model
            orchestrator_model = resolve_model_for_role("orchestrator", self.model_config)
            self.client = create_model_client(orchestrator_model)
            self.orchestrator_model = orchestrator_model

        # Apply prompt preset (override orchestrator prompt)
        if self._prompt_dir:
            orch_prompt = self._prompt_dir / "orchestrator.md"
            if orch_prompt.exists():
                raw = orch_prompt.read_text()
                self.system_prompt = raw.replace(
                    "{AGENT_CAPABILITIES_BLOCK}",
                    self._render_agent_capabilities(),
                )

        # Initialize metrics recorder
        self._metrics_recorder = MetricsRecorder(self.engagement_dir, self.engagement_id)

        logger.info(
            f"[Orchestrator] Applied profile '{profile_name}' "
            f"(prompts={self._prompt_preset}, models={self._model_config_name})"
        )

    def apply_master_profile(self, master_profile_name: str) -> Dict:
        """Apply a master profile to this engagement.

        Resolves the master profile into effective models, prompts (including
        per-agent overrides), and re-configures the orchestrator and all
        future agent dispatches accordingly.

        Returns the resolved profile dict for snapshotting.
        """
        from profiles.master_profile_manager import MasterProfileManager

        mpm = MasterProfileManager()
        resolved = mpm.resolve(master_profile_name)

        self._profile_name = master_profile_name
        self._prompt_preset = resolved["prompt_profile"]
        self._model_config_name = resolved.get("metadata", {}).get("model_config", "")
        self._prompt_dir = resolved["prompt_dir"]
        self._effective_prompts = resolved["effective_prompts"]

        # Apply effective model config
        effective_models = resolved["effective_models"]
        if effective_models:
            self.model_config = effective_models
            orchestrator_model = resolve_model_for_role("orchestrator", self.model_config)
            self.client = create_model_client(orchestrator_model)
            self.orchestrator_model = orchestrator_model

        # Apply orchestrator prompt from profile
        if self._prompt_dir:
            orch_prompt = self._prompt_dir / "orchestrator.md"
            if orch_prompt.exists():
                raw = orch_prompt.read_text()
                self.system_prompt = raw.replace(
                    "{AGENT_CAPABILITIES_BLOCK}",
                    self._render_agent_capabilities(),
                )

        # Initialize metrics recorder
        self._metrics_recorder = MetricsRecorder(self.engagement_dir, self.engagement_id)

        logger.info(
            f"[Orchestrator] Applied master profile '{master_profile_name}' "
            f"(prompts={self._prompt_preset}, models={self._model_config_name}, "
            f"overrides={list(resolved['agent_overrides'].keys())})"
        )
        return resolved

    # =========================================================================
    # Phase Forcing & Progress Detection
    # =========================================================================

    @staticmethod
    def _task_fingerprint(agent_type: str, task: str) -> str:
        """Create a normalized fingerprint for an agent+task to detect duplicates.

        Strips variable parts (iteration numbers, timestamps, IP formatting
        differences) so that semantically identical tasks produce the same hash.
        """
        # Normalize: lowercase, collapse whitespace, strip numbers that look
        # like iteration/attempt counters, and remove common filler phrases
        normalized = task.lower()
        normalized = re.sub(r'\b(iteration|attempt|retry|try)\s*#?\d+\b', '', normalized)
        normalized = re.sub(r'\b\d{4}-\d{2}-\d{2}[\sT]\d{2}:\d{2}[:\d]*\b', '', normalized)
        normalized = re.sub(r'\s+', ' ', normalized).strip()
        key = f"{agent_type}:{normalized}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    def _compute_state_hash(self) -> str:
        """Hash key state metrics to detect whether progress was made."""
        state = self.shared_state.read()
        creds = _ensure_list(state.get("credentials_summary", []))
        vulns = _ensure_list(state.get("vulns_summary", []))
        access = (state.get("access") or {})
        shells = _ensure_list(access.get("shells", []))
        loot = _ensure_list(state.get("loot", []))
        return f"c{len(creds)}v{len(vulns)}s{len(shells)}l{len(loot)}"

    def _dispatch_cooldown_remaining(self, fingerprint: str) -> int:
        """Return cooldown seconds remaining for a task fingerprint (0 if ready)."""
        last_ts = self._task_last_dispatch_ts.get(fingerprint)
        if not last_ts:
            return 0
        elapsed = time.time() - last_ts
        remaining = int(self._dispatch_cooldown_seconds - elapsed)
        return remaining if remaining > 0 else 0

    def _mark_dispatched(self, fingerprint: str) -> None:
        """Record dispatch timestamp for cooldown dedupe."""
        self._task_last_dispatch_ts[fingerprint] = time.time()

    def _check_foothold_transition(self) -> Optional[dict]:
        """Hard state transition: once command execution exists, default to post-exploitation.

        When shells/sessions are present but objectives are incomplete,
        the controller should pivot to privesc/credential-harvesting/flag-hunting
        rather than continuing generic exploit loops.

        Returns a forced dispatch decision or None.
        """
        state = self.shared_state.read()
        access = _ensure_dict(state.get("access"))
        shells = _ensure_list(access.get("shells", []))
        sessions = _ensure_list(access.get("sessions", []))
        auth_access = _ensure_list(state.get("authenticated_access", []))

        if not shells and not sessions:
            return None

        # Check if objectives are already complete
        objectives = _ensure_list(state.get("objectives", []))
        pending = [o for o in objectives if isinstance(o, dict) and o.get("status") == "pending"]
        if not pending:
            return None

        # Check if we already dispatched a post-exploitation task this cycle
        attack_dispatches = self._agent_dispatch_counts.get("attack", 0)
        # Only force if the most recent attack dispatch was NOT a privesc task
        if self.iteration_history:
            last_few = self.iteration_history[-3:]
            privesc_keywords = ["privesc", "privilege", "escalat", "post-exploit",
                                "flag", "credential", "dump", "loot", "sensitive",
                                "shadow", "passwd", "suid", "sudo", "cron"]
            recent_privesc = any(
                any(kw in (h.get("task", "") or "").lower() for kw in privesc_keywords)
                for h in last_few if h.get("agent") == "attack"
            )
            if recent_privesc:
                return None

        # Build a targeted post-exploitation task
        shell_info = []
        for sh in shells[:3]:
            if isinstance(sh, dict):
                shell_info.append(f"{sh.get('user', '?')}@{sh.get('host', '?')} ({sh.get('type', '?')})")
            else:
                shell_info.append(str(sh))

        target = (state.get("engagement") or {}).get("target", "unknown")
        creds = _ensure_list(state.get("credentials_summary", []))
        cred_list = ", ".join(
            f"{c.get('username', '?')}" for c in creds[:5]
        ) if creds else "none yet"

        # Check which objectives remain to guide the task
        pending_descs = [o.get("description", "") for o in pending[:5]]

        task = (
            f"FOOTHOLD OBTAINED — pivot to post-exploitation and objective completion.\n"
            f"Target: {target}\n"
            f"Active shells: {'; '.join(shell_info)}\n"
            f"Known credentials: {cred_list}\n"
            f"REMAINING OBJECTIVES:\n" +
            "\n".join(f"  - {d}" for d in pending_descs) + "\n\n"
            f"Your priorities (IN ORDER):\n"
            f"1. Read flag files, sensitive data, and proof files referenced by objectives\n"
            f"2. Dump credentials: /etc/shadow, config files, application databases, browser creds\n"
            f"3. Check SUID binaries, sudo -l, cron jobs, writable scripts for privilege escalation\n"
            f"4. Enumerate home directories, /opt, /var, /tmp for loot and lateral movement paths\n"
            f"5. If current user is unprivileged, escalate before hunting flags\n"
            f"Do NOT run more port scans, web brute-force, or broad exploit attempts.\n"
            f"Use the existing foothold to achieve the remaining objectives."
        )

        logger.warning(
            "[Orchestrator] FOOTHOLD TRANSITION: %d shell(s), %d pending objectives. "
            "Forcing post-exploitation.",
            len(shells), len(pending),
        )
        self.story.add_event(
            f"FOOTHOLD TRANSITION: {len(shells)} shell(s) active, "
            f"pivoting to post-exploitation for {len(pending)} remaining objectives."
        )

        return {
            "action": "dispatch",
            "agent": "attack",
            "task": task,
            "reasoning": f"Foothold obtained ({len(shells)} shells). Pivoting to post-exploitation/privesc.",
            "_forced": True,
        }

    def _collect_agent_recommendations(self) -> list[str]:
        """Collect unaddressed next-step recommendations from recent agent results.

        These are agent-suggested follow-up actions that the orchestrator
        should weigh before forcing a phase transition.
        """
        recommendations = []
        for entry in self.iteration_history[-5:]:
            summary = entry.get("summary", "")
            if not summary:
                continue
            # Look for explicit recommendation patterns in agent summaries
            for marker in ["recommend", "suggest", "next step", "should ", "consider ",
                           "follow up", "follow-up", "deeper scan", "enumerate"]:
                if marker in summary.lower():
                    recommendations.append(f"[{entry.get('agent', '?')}] {summary[:200]}")
                    break
        return recommendations

    def _check_recon_saturation(self) -> Optional[dict]:
        """
        Detect when recon/webapp agents have been dispatched too many times
        without progress. Returns a forced dispatch decision if saturation
        is detected, or None to let the LLM decide normally.

        Evidence-based: incorporates agent recommendations into the forced
        task rather than discarding them. Reversible: only forces when
        there's no evidence of productive recon progress.
        """
        recon_dispatches = self._agent_dispatch_counts.get("recon", 0)
        webapp_dispatches = self._agent_dispatch_counts.get("webapp", 0)
        total_recon = recon_dispatches + webapp_dispatches

        state = self.shared_state.read()
        creds = _ensure_list(state.get("credentials_summary", []))
        vulns = _ensure_list(state.get("vulns_summary", []))
        access = (state.get("access") or {})
        shells = _ensure_list(access.get("shells", []))

        # If we already have access, don't force anything
        if shells:
            return None

        # Collect agent recommendations — if agents have specific follow-up
        # suggestions that haven't been tried yet, give the orchestrator
        # one more iteration to act on them before forcing
        agent_recs = self._collect_agent_recommendations()
        # If the last dispatched agent had recommendations AND we haven't
        # hit the hard cap (threshold + 2), let the orchestrator decide
        hard_cap = self._recon_saturation_threshold + 2
        if agent_recs and total_recon < hard_cap and total_recon >= self._recon_saturation_threshold:
            # Include recommendations in the next brief instead of forcing
            logger.info(
                "[Orchestrator] Recon at soft saturation (%d dispatches) but agents "
                "have %d unaddressed recommendations — deferring force.",
                total_recon, len(agent_recs),
            )
            return None

        # If recon has run enough times AND we have vulns but no access
        if total_recon >= self._recon_saturation_threshold and vulns and not creds and not shells:
            # Build a targeted exploitation task from known vulns
            high_vulns = [v for v in vulns if v.get("severity", "").lower() in ("critical", "high")]
            if not high_vulns:
                high_vulns = [v for v in vulns if v.get("severity", "").lower() == "medium"]
            if not high_vulns:
                high_vulns = vulns[:3]

            target = (state.get("engagement") or {}).get("target", "unknown")
            hosts = (state.get("hosts") or {})

            # Build specific exploitation tasks from findings
            vuln_details = []
            for v in high_vulns[:5]:
                title = v.get("title") or v.get("description", "unknown vuln")
                host = v.get("host", target)
                vuln_details.append(f"- {title} on {host}")

            # Build service list for credential attacks
            service_details = []
            for ip, info in hosts.items():
                if isinstance(info, dict):
                    for svc in info.get("services", []):
                        name = svc.get("name") or svc.get("service_name") or svc.get("service", "")
                        port = svc.get("port", "")
                        version = svc.get("version", "")
                        service_details.append(f"{ip}:{port} ({name} {version})")

            # Incorporate agent recommendations into the forced task
            rec_block = ""
            if agent_recs:
                rec_block = (
                    "\nAGENT RECOMMENDATIONS (unaddressed follow-ups):\n" +
                    "\n".join(f"  {r}" for r in agent_recs[:5]) +
                    "\nConsider these alongside the exploitation priorities below.\n"
                )

            task = (
                f"RECON SATURATION REACHED — switching to exploitation.\n"
                f"Target: {target}\n"
                f"Known services: {'; '.join(service_details[:10])}\n"
                f"Known vulnerabilities:\n" + "\n".join(vuln_details) + "\n"
                f"{rec_block}\n"
                f"Your priorities:\n"
                f"1. Try default/common credentials on ALL services (SSH, web admin panels, MinIO, databases)\n"
                f"2. Exploit any known CVEs for the discovered service versions\n"
                f"3. Check for anonymous/unauthenticated access on object storage, APIs, admin panels\n"
                f"4. Try CMS-specific attacks (default creds, known exploits, file upload, etc.)\n"
                f"5. Check for exposed secrets in web application source, config files, backup files\n"
                f"Do NOT run more port scans or directory brute-force. Focus on EXPLOITATION."
            )

            logger.warning(
                "[Orchestrator] RECON SATURATION: %d recon/webapp dispatches, "
                "%d vulns, 0 creds, 0 shells. Forcing attack agent.",
                total_recon, len(vulns),
            )
            self.story.add_event(
                f"PHASE FORCING: Recon saturation after {total_recon} recon dispatches. "
                f"Forcing exploitation with {len(vulns)} known vulns."
            )

            return {
                "action": "dispatch",
                "agent": "attack",
                "task": task,
                "reasoning": f"Recon saturation reached ({total_recon} dispatches). Forcing exploitation phase.",
                "_forced": True,
            }

        # If we have credentials but no shells, force credential testing
        if total_recon >= 2 and creds and not shells:
            service_details = []
            hosts = _ensure_dict(state.get("hosts"))
            for ip, info in hosts.items():
                if isinstance(info, dict):
                    for svc in info.get("services", []):
                        name = svc.get("name") or svc.get("service_name") or svc.get("service", "")
                        port = svc.get("port", "")
                        version = svc.get("version", "")
                        service_details.append(f"{ip}:{port} ({name} {version})")
            cred_list = ", ".join(
                f"{c.get('username', '?')}:{c.get('password', c.get('hash', '?'))}"
                for c in creds[:5]
            )
            task = (
                f"Test discovered credentials against all services.\n"
                f"Credentials: {cred_list}\n"
                f"Services: {'; '.join(service_details[:10]) if service_details else 'check shared state'}\n"
                f"Try SSH, web admin panels, databases, MinIO/S3 — every service that accepts auth."
            )
            logger.warning("[Orchestrator] Forcing credential testing — have creds but no shells.")
            self.story.add_event("PHASE FORCING: Credentials found, forcing credential testing across services.")
            return {
                "action": "dispatch",
                "agent": "attack",
                "task": task,
                "reasoning": "Credentials discovered but not tested against all services.",
                "_forced": True,
            }

        return None

    # =========================================================================
    # Fragile-Target Handling
    # =========================================================================

    _INSTABILITY_PATTERNS = [
        "502 bad gateway", "502 proxy error", "503 service unavailable",
        "504 gateway timeout", "connection reset", "connection refused",
        "too many users", "too many connections", "too many requests",
        "rate limit", "service unavailable", "server overloaded",
        "connection timed out", "broken pipe", "read timeout",
    ]

    def _detect_target_instability(self, result: AgentResult) -> None:
        """Detect signs of target service instability from agent results.

        Increments instability counter when error patterns suggest the target
        is becoming unreliable. Resets on clean successful results.
        """
        summary = (str(result.summary) if result.summary else "").lower()
        errors = " ".join(str(e) for e in (result.errors or [])).lower()
        combined = summary + " " + errors

        hit = any(pattern in combined for pattern in self._INSTABILITY_PATTERNS)

        if hit:
            self._target_instability_count += 1
            if self._target_instability_count == self._target_instability_threshold:
                logger.warning(
                    "[Orchestrator] TARGET INSTABILITY: %d signals detected. "
                    "Switching to low-noise mode.",
                    self._target_instability_count,
                )
                self.story.add_event(
                    f"TARGET INSTABILITY: {self._target_instability_count} instability signals "
                    f"detected. Throttling exploit retries and preferring low-noise commands."
                )
        elif result.success:
            # Successful clean result — decay instability counter
            if self._target_instability_count > 0:
                self._target_instability_count = max(0, self._target_instability_count - 1)

    # =========================================================================
    # Intelligence Brief Builder (v7.1: Incremental)
    # =========================================================================

    def _build_intelligence_brief_incremental(self, iteration: int, max_iterations: int) -> str:
        """Build an incremental intelligence brief that only sends deltas after iteration 1.

        On iteration 1: sends the full brief and caches the state snapshot.
        On subsequent iterations: sends only what changed since the last snapshot,
        plus the always-needed context (budget, objectives, last result).
        """
        state = self.shared_state.read()

        # Compute current counts for delta detection
        hosts = _ensure_dict(state.get("hosts"))
        access = _ensure_dict(state.get("access"))
        current_snapshot = {
            "host_count": len(hosts),
            "cred_count": len(_ensure_list(state.get("credentials_summary", []))),
            "vuln_count": len(_ensure_list(state.get("vulns_summary", []))),
            "shell_count": len(_ensure_list(access.get("shells", []))),
            "dispatch_counts": dict(self._agent_dispatch_counts),
            "failed_count": len(self.failed_approaches),
        }

        # First iteration or significant changes: send full brief
        if iteration <= 1 or not self._last_brief_snapshot:
            full_brief = self._build_intelligence_brief(iteration, max_iterations)
            self._last_brief_snapshot = current_snapshot
            self._brief_cache = full_brief
            return full_brief

        # Check what changed
        changes = []
        prev = self._last_brief_snapshot

        if current_snapshot["host_count"] != prev.get("host_count", 0):
            changes.append(f"hosts: {prev.get('host_count', 0)} → {current_snapshot['host_count']}")
        if current_snapshot["cred_count"] != prev.get("cred_count", 0):
            changes.append(f"credentials: {prev.get('cred_count', 0)} → {current_snapshot['cred_count']}")
        if current_snapshot["vuln_count"] != prev.get("vuln_count", 0):
            changes.append(f"vulnerabilities: {prev.get('vuln_count', 0)} → {current_snapshot['vuln_count']}")
        if current_snapshot["shell_count"] != prev.get("shell_count", 0):
            changes.append(f"shells: {prev.get('shell_count', 0)} → {current_snapshot['shell_count']}")

        # If significant changes or every 5 iterations, send full brief
        if len(changes) >= 3 or iteration % 5 == 0 or current_snapshot["shell_count"] != prev.get("shell_count", 0):
            full_brief = self._build_intelligence_brief(iteration, max_iterations)
            self._last_brief_snapshot = current_snapshot
            self._brief_cache = full_brief
            return full_brief

        # Build delta brief (much smaller)
        budget_remaining = max_iterations - iteration
        lines = [
            f"ITERATION {iteration} | BUDGET: {budget_remaining}/{max_iterations} remaining",
            "",
        ]

        if changes:
            lines.append("CHANGES SINCE LAST DECISION:")
            for c in changes:
                lines.append(f"  + {c}")
            lines.append("")

        # Always include last agent result
        if self.iteration_history:
            last = self.iteration_history[-1]
            lines.append(f"LAST AGENT: {last.get('agent', '?')} ({'success' if last.get('success') else 'FAILED'})")
            summary = last.get("summary", "")
            if summary:
                lines.append(f"  {str(summary)[:300]}")
            lines.append("")

        # Include recent failures
        new_failures = self.failed_approaches[prev.get("failed_count", 0):]
        if new_failures:
            lines.append("NEW FAILURES:")
            for f_desc in new_failures[-5:]:
                lines.append(f"  - {f_desc}")
            lines.append("")

        # No-progress warning
        if self._consecutive_no_progress >= 2:
            lines.append(f"⚠️ NO PROGRESS: {self._consecutive_no_progress} consecutive dispatches with no new findings.")
            lines.append("")

        # Dispatch counts
        if self._agent_dispatch_counts:
            counts_str = ", ".join(f"{k}={v}" for k, v in sorted(self._agent_dispatch_counts.items()))
            lines.append(f"DISPATCH COUNTS: {counts_str}")

        lines.append("")
        lines.append("Refer to your previous context for full state. Decide the next action.")

        self._last_brief_snapshot = current_snapshot
        return "\n".join(lines)

    def _build_intelligence_brief(self, iteration: int, max_iterations: int) -> str:
        """
        Build a compact intelligence brief for the orchestrator.
        This is the core information Opus sees each decision iteration.

        Uses priority-based token budget allocation:
          P1 (CRITICAL) — always included, never trimmed
          P2 (HIGH)     — included if budget allows
          P3 (MEDIUM)   — compressed to one-line summaries if needed
          P4 (LOW)      — omitted if over budget
        """
        token_budget = INTELLIGENCE_BRIEF_TOKEN_BUDGET
        state = self.shared_state.read()
        engagement = (state.get("engagement") or {})
        target = engagement.get("target", "unknown")
        hosts = _ensure_dict(state.get("hosts"))
        creds = _ensure_list(state.get("credentials_summary", []))
        vulns = _ensure_list(state.get("vulns_summary", []))
        techs = _ensure_dict(state.get("technologies"))
        objectives = _ensure_list(state.get("objectives", []))
        domains = _ensure_list(state.get("domains", []))
        attack_surfaces = _ensure_list(state.get("attack_surfaces", []))
        agent_blockers = _ensure_list(state.get("agent_blockers", []))
        auth_access = _ensure_list(state.get("authenticated_access", []))
        agent_notes = _ensure_dict(state.get("agent_notes"))

        budget_remaining = max_iterations - iteration
        omitted_sections = []

        def _tokens(text: str) -> int:
            return max(1, len(text or "") // 4)

        def _render(lines: list) -> str:
            return "\n".join(lines)

        # ==================================================================
        # Priority 1 — CRITICAL: always included, never trimmed
        # ==================================================================

        p1_lines = []

        # Header: engagement scope, current phase
        p1_lines.append(f"ITERATION {iteration} | BUDGET: {budget_remaining}/{max_iterations} remaining")
        p1_lines.append(f"TARGET: {target}")
        scope = engagement.get("scope", [])
        phase = state.get("current_phase", "init")
        methodology = engagement.get("methodology", "")
        if scope:
            p1_lines.append(f"SCOPE: {', '.join(str(s) for s in scope[:10])}")
        p1_lines.append(f"PHASE: {phase}" + (f" ({methodology})" if methodology else ""))
        p1_lines.append("")

        # Cross-engagement lessons (only on the first iteration)
        if iteration == 1:
            try:
                mem = self.engagement_memory
                lessons_lines = []
                target_mem = mem.query_for_target(methodology or "standard")
                for t in target_mem.get("techniques", [])[:5]:
                    lessons_lines.append(
                        f"  - {t['technique']} (success {t['success_rate']:.0%}): {t.get('notes', '')}"
                    )
                for p in target_mem.get("patterns", [])[:5]:
                    lessons_lines.append(
                        f"  - Pattern '{p['pattern_name']}': {p.get('recommended_approach', '')}"
                    )
                tool_issues = mem.query_all_tool_issues()
                for ti in tool_issues[:3]:
                    lessons_lines.append(
                        f"  - Tool '{ti['tool_name']}' (fail {ti['failure_rate']:.0%}): "
                        f"{ti.get('workarounds') or ti.get('common_errors', '')}"
                    )
                if lessons_lines:
                    p1_lines.append("LESSONS FROM PREVIOUS ENGAGEMENTS:")
                    p1_lines.extend(lessons_lines)
                    p1_lines.append("")
            except Exception as e:
                logger.debug("Failed to load cross-engagement memories: %s", e)

        # Objectives
        if objectives:
            p1_lines.append("OBJECTIVES:")
            for obj in objectives:
                if isinstance(obj, dict):
                    status = obj.get("status", "pending")
                    desc = obj.get("description", "?")
                    marker = "[x]" if status == "completed" else "[ ]"
                    p1_lines.append(f"  {marker} {desc}")
                elif isinstance(obj, str):
                    p1_lines.append(f"  [ ] {obj}")
            p1_lines.append("")

        # Active shells / authenticated access
        access = (state.get("access") or {})
        shells = _ensure_list(access.get("shells", []))
        sessions = _ensure_list(access.get("sessions", []))
        if shells or sessions or auth_access:
            p1_lines.append(f"ACCESS: {len(shells)} shell(s), {len(sessions)} session(s), {len(auth_access)} authenticated")
            for sh in shells[:3]:
                if isinstance(sh, dict):
                    p1_lines.append(f"  Shell: {sh.get('user', '?')}@{sh.get('host', '?')} ({sh.get('type', '?')})")
                else:
                    p1_lines.append(f"  Shell: {sh}")
            for aa in auth_access[:3]:
                if isinstance(aa, dict):
                    p1_lines.append(f"  Auth: {aa.get('username', '?')}@{aa.get('host', aa.get('url', '?'))} ({aa.get('access_level', '?')})")
        else:
            p1_lines.append("ACCESS: No shells or sessions")
        p1_lines.append("")

        # Agent blockers
        if agent_blockers:
            p1_lines.append(f"BLOCKERS ({len(agent_blockers)}):")
            for b in agent_blockers[-5:]:
                if isinstance(b, dict):
                    p1_lines.append(f"  [{b.get('agent', '?')}] {b.get('reason', '?')}")
                else:
                    p1_lines.append(f"  {b}")
            p1_lines.append("")

        # Dispatch counts & operational warnings
        if self._agent_dispatch_counts:
            counts_str = ", ".join(f"{k}={v}" for k, v in sorted(self._agent_dispatch_counts.items()))
            p1_lines.append(f"DISPATCH COUNTS: {counts_str}")
            total_recon = self._agent_dispatch_counts.get("recon", 0) + self._agent_dispatch_counts.get("webapp", 0)
            if total_recon >= self._recon_saturation_threshold - 1:
                p1_lines.append("⚠️ RECON SATURATION WARNING: You have dispatched recon/webapp agents many times.")
                p1_lines.append("   Strongly prefer offensive agents (attack, webapp) for your next dispatch.")
                p1_lines.append("   Use the intel you have. If you dispatch recon/webapp again without strong justification, the system may override.")
        p1_lines.append("")

        if self._consecutive_no_progress >= 2:
            p1_lines.append(f"⚠️ NO PROGRESS: {self._consecutive_no_progress} consecutive dispatches produced no new findings.")
            p1_lines.append("   Try a DIFFERENT approach or agent type.")
            p1_lines.append("")

        if self._target_instability_count >= self._target_instability_threshold:
            p1_lines.append(f"⚠️ TARGET INSTABILITY: {self._target_instability_count} instability signals detected.")
            p1_lines.append("   The target service is unreliable. Use low-noise, single-command approaches.")
            p1_lines.append("   Do NOT brute-force, spray, or run heavy scanners.")
            p1_lines.append("")

        p1_text = _render(p1_lines)
        used_tokens = _tokens(p1_text)

        # ==================================================================
        # Priority 2 — HIGH: included if budget allows
        # ==================================================================

        p2_sections = []  # (name, rendered_text)

        # Recent iteration history (last 3)
        if self.iteration_history:
            hist_lines = []
            recent = self.iteration_history[-3:]
            for i, entry in enumerate(recent):
                agent_name = entry.get("agent", "?")
                success = entry.get("success", False)
                summary = entry.get("summary", "")
                if isinstance(summary, str) and len(summary) > 300:
                    summary = summary[:297] + "..."
                label = "LAST AGENT" if i == len(recent) - 1 else f"RECENT [{len(recent) - i} ago]"
                hist_lines.append(f"{label}: {agent_name} ({'success' if success else 'FAILED'})")
                if summary:
                    hist_lines.append(f"  {summary}")
            hist_lines.append("")
            p2_sections.append(("recent iteration history", _render(hist_lines)))

        # Available Flows
        try:
            from flows.engine import get_flow_engine
            flow_engine = get_flow_engine()
            flows_brief = flow_engine.get_available_flows_brief(state)
            if flows_brief.strip():
                p2_sections.append(("available flows", flows_brief))
        except Exception:
            pass

        # Credentials summary
        creds_lines = []
        if creds:
            creds_lines.append(f"CREDENTIALS ({len(creds)}):")
            for c in creds[:8]:
                user = c.get("username", "?")
                ctype = c.get("type", "?")
                host = c.get("host", "")
                creds_lines.append(f"  {user} ({ctype}){f' on {host}' if host else ''}")
        else:
            creds_lines.append("CREDENTIALS: None")
        creds_lines.append("")
        p2_sections.append(("credentials summary", _render(creds_lines)))

        # Vulnerability summary
        vulns_lines = []
        if vulns:
            sev_order = ["critical", "high", "medium", "low", "info"]
            sev_groups = {}
            for v in vulns:
                sev = v.get("severity", "info").lower()
                sev_groups.setdefault(sev, []).append(v)
            sev_summary = ", ".join(f"{len(vs)} {sev}" for sev, vs in
                                    sorted(sev_groups.items(),
                                           key=lambda x: sev_order.index(x[0])
                                           if x[0] in sev_order else 5))
            vulns_lines.append(f"VULNS ({len(vulns)}): {sev_summary}")
            important = sorted(vulns, key=lambda v: sev_order.index(
                v.get("severity", "info").lower()) if v.get("severity", "info").lower() in
                sev_order else 5)
            for v in important[:5]:
                title = v.get("title") or v.get("name") or v.get("description", "?")
                if isinstance(title, str) and len(title) > 80:
                    title = title[:77] + "..."
                sev = v.get("severity", "?")
                host = v.get("host", "")
                vulns_lines.append(f"  [{sev}] {title}{f' on {host}' if host else ''}")
        else:
            vulns_lines.append("VULNS: None confirmed")
        vulns_lines.append("")
        p2_sections.append(("vulnerability summary", _render(vulns_lines)))

        # Recent failed approaches (last 5)
        if self.failed_approaches:
            recent_fails = self.failed_approaches[-5:]
            fail_lines = [f"FAILED ({len(self.failed_approaches)} total, showing last {len(recent_fails)}):"]
            for f_desc in recent_fails:
                fail_lines.append(f"  - {f_desc}")
            fail_lines.append("")
            p2_sections.append(("recent failed approaches", _render(fail_lines)))

        p2_included = []
        for sec_name, sec_text in p2_sections:
            sec_tokens = _tokens(sec_text)
            if used_tokens + sec_tokens <= token_budget:
                p2_included.append(sec_text)
                used_tokens += sec_tokens
            else:
                omitted_sections.append(sec_name)

        # ==================================================================
        # Priority 3 — MEDIUM: compressed to one-line if over budget
        # ==================================================================

        p3_sections = []  # (name, full_text, compressed_text)

        # Full host inventory
        if hosts:
            full_lines = ["HOSTS:"]
            total_services = 0
            for ip, info in hosts.items():
                if not isinstance(info, dict):
                    continue
                os_info = info.get("os", "")
                services = info.get("services", [])
                total_services += len(services)
                svc_strs = []
                for svc in services:
                    name = svc.get("name") or svc.get("service_name") or svc.get("service", "?")
                    port = svc.get("port", "?")
                    version = svc.get("version", "")
                    s = f"{name}/{port}"
                    if version:
                        s += f" ({version})"
                    svc_strs.append(s)
                host_line = f"  {ip}"
                if os_info:
                    host_line += f" [{os_info}]"
                if svc_strs:
                    host_line += f": {', '.join(svc_strs)}"
                full_lines.append(host_line)
            full_lines.append("")
            compressed = f"HOSTS: {len(hosts)} hosts discovered, {total_services} services\n"
            p3_sections.append(("host inventory", _render(full_lines), compressed))
        else:
            static = "HOSTS: None discovered yet\n"
            p3_sections.append(("host inventory", static, static))

        # Technology inventory
        if techs:
            full_lines = ["TECHNOLOGIES:"]
            for target_key, tech_list in techs.items():
                if isinstance(tech_list, list):
                    full_lines.append(f"  {target_key}: {', '.join(str(t) for t in tech_list[:10])}")
            full_lines.append("")
            total_techs = sum(len(v) if isinstance(v, list) else 1 for v in techs.values())
            compressed = f"TECHNOLOGIES: {total_techs} technologies across {len(techs)} targets\n"
            p3_sections.append(("technology inventory", _render(full_lines), compressed))

        # Domains list
        if domains:
            full_lines = [f"DOMAINS ({len(domains)}):"]
            for d in domains[:20]:
                full_lines.append(f"  {d}")
            if len(domains) > 20:
                full_lines.append(f"  ... and {len(domains) - 20} more")
            full_lines.append("")
            compressed = f"DOMAINS: {len(domains)} domains discovered\n"
            p3_sections.append(("domains list", _render(full_lines), compressed))

        p3_included = []
        for sec_name, full_text, compressed_text in p3_sections:
            full_tokens = _tokens(full_text)
            if used_tokens + full_tokens <= token_budget:
                p3_included.append(full_text)
                used_tokens += full_tokens
            else:
                comp_tokens = _tokens(compressed_text)
                if used_tokens + comp_tokens <= token_budget:
                    p3_included.append(compressed_text)
                    used_tokens += comp_tokens
                else:
                    omitted_sections.append(sec_name)

        # ==================================================================
        # Priority 4 — LOW: omitted if over budget
        # ==================================================================

        p4_sections = []  # (name, text)

        # Older iteration history (>3 iterations ago)
        if len(self.iteration_history) > 3:
            older = self.iteration_history[:-3]
            older_lines = [f"OLDER HISTORY ({len(older)} entries):"]
            for entry in older[-5:]:
                agent_name = entry.get("agent", "?")
                success = "ok" if entry.get("success") else "FAIL"
                older_lines.append(f"  {agent_name}={success}")
            older_lines.append("")
            p4_sections.append(("older iteration history", _render(older_lines)))

        # Agent notes
        if agent_notes:
            notes_lines = ["AGENT NOTES:"]
            for aname, note in agent_notes.items():
                notes_lines.append(f"  [{aname}] {str(note)[:200]}")
            notes_lines.append("")
            p4_sections.append(("agent notes", _render(notes_lines)))

        # Agent recommendations
        agent_recs = self._collect_agent_recommendations()
        if agent_recs:
            rec_lines = ["AGENT RECOMMENDATIONS (unaddressed follow-ups):"]
            for rec in agent_recs[-5:]:
                rec_lines.append(f"  {rec}")
            rec_lines.append("   Consider acting on these before switching strategy.")
            rec_lines.append("")
            p4_sections.append(("agent recommendations", _render(rec_lines)))

        # Attack surfaces (count summary)
        if attack_surfaces:
            p4_sections.append(("attack surfaces",
                                f"ATTACK SURFACES ({len(attack_surfaces)}): {', '.join(str(s) for s in attack_surfaces[:15])}\n"))

        # Older failed approaches (>5 ago)
        if len(self.failed_approaches) > 5:
            older_fails = self.failed_approaches[:-5]
            older_lines = [f"OLDER FAILURES ({len(older_fails)}):"]
            for f_desc in older_fails[-5:]:
                older_lines.append(f"  - {f_desc}")
            older_lines.append("")
            p4_sections.append(("older failed approaches", _render(older_lines)))

        p4_included = []
        for sec_name, sec_text in p4_sections:
            sec_tokens = _tokens(sec_text)
            if used_tokens + sec_tokens <= token_budget:
                p4_included.append(sec_text)
                used_tokens += sec_tokens
            else:
                omitted_sections.append(sec_name)

        # ==================================================================
        # Assemble final brief
        # ==================================================================

        parts = [p1_text]
        parts.extend(p2_included)
        parts.extend(p3_included)
        parts.extend(p4_included)

        footer = f"BRIEF BUDGET: used {used_tokens}/{token_budget} tokens"
        if omitted_sections:
            footer += f", omitted: [{', '.join(omitted_sections)}]"
        parts.append(footer)

        return "\n".join(parts)

    @staticmethod
    def _estimate_text_tokens(text: str) -> int:
        """Cheap token estimate used for dynamic budget sizing."""
        return max(1, len(text or "") // 4)

    def _resolve_dynamic_iteration_budget(self) -> int:
        """Scale the autonomous iteration budget to model window and brief size."""
        base_budget = MAX_ORCHESTRATOR_ITERATIONS
        hard_cap = int(os.environ.get("SNOWSTRIKE_MAX_ITERATIONS_HARD_CAP", "60"))
        context_window = max(get_model_context_window(self.orchestrator_model, 150_000), 1)
        reserve = max(12_000, min(context_window // 5, 120_000))
        usable_window = max(12_000, context_window - reserve)

        preview_brief = self._build_intelligence_brief(1, base_budget)
        prompt_tokens = (
            self._estimate_text_tokens(self.system_prompt)
            + self._estimate_text_tokens(preview_brief)
            + 512
        )
        pressure = prompt_tokens / usable_window

        state = self.shared_state.read()
        complexity_score = (
            len(_ensure_dict(state.get("hosts"))) * 2
            + len(_ensure_list(state.get("vulns_summary", [])))
            + len(_ensure_list(state.get("credentials_summary", []))) * 2
            + len(_ensure_dict(state.get("web_apps", {})))
            + len(_ensure_list(state.get("authenticated_access", []))) * 2
        )
        complexity_bonus = min(10, complexity_score // 3)

        scaled_budget = base_budget
        if pressure >= 0.40:
            scaled_budget = round(base_budget * 0.60)
        elif pressure >= 0.28:
            scaled_budget = round(base_budget * 0.80)
        elif pressure <= 0.08 and usable_window >= 800_000:
            scaled_budget = round(base_budget * 1.60)
        elif pressure <= 0.15 and usable_window >= 320_000:
            scaled_budget = round(base_budget * 1.20)

        if pressure <= 0.22:
            scaled_budget += complexity_bonus

        final_budget = max(12, min(hard_cap, scaled_budget))
        logger.info(
            "[Orchestrator] Dynamic iteration budget: %s (base=%s, model=%s, prompt_tokens~%s, usable_window=%s, raw_window=%s, pressure=%.3f, complexity_bonus=%s)",
            final_budget,
            base_budget,
            self.orchestrator_model,
            prompt_tokens,
            usable_window,
            context_window,
            pressure,
            complexity_bonus if pressure <= 0.22 else 0,
        )
        return final_budget

    # =========================================================================
    # Orchestrator Decision Loop
    # =========================================================================

    def _ask_orchestrator(self, brief: str, allow_parallel: bool = True) -> dict:
        """
        Send the intelligence brief to Opus and get a JSON decision back.

        When allow_parallel=True, the orchestrator can return multiple independent
        agent dispatches in a single decision for concurrent execution.
        Returns parsed decision dict or error dict.
        """
        parallel_instruction = ""
        if allow_parallel:
            parallel_instruction = (
                "\nYou may return a \"parallel\" action with up to 3 independent dispatches. "
                "Follow the parallel dispatch rules from your prompt: separate targets/modalities, "
                "no cross-dispatch dependencies, no overlapping attack surface.\n"
                '{"action": "parallel", "dispatches": [{"agent": "recon", "task": "..."}, {"agent": "osint", "task": "..."}], '
                '"reasoning": "..."}\n'
            )

        what_if_instruction = (
            "\nWhen facing a risky tool execution that might crash a service or be very loud, "
            "consider dispatching with action='what_if'. Provide an 'agent' type, an "
            "'aggressive_task' (the high-risk/high-reward approach), and a 'conservative_task' "
            "(the safe fallback). The system will fork engagement state, try the aggressive "
            "approach first, and fall back to the conservative task if it fails.\n"
            '{"action": "what_if", "agent": "attack", "aggressive_task": "...", '
            '"conservative_task": "...", "reasoning": "..."}\n'
            "Note: what_if has a cooldown of 5 iterations between uses.\n"
        )

        trigger_flow_instruction = (
            "\nWhen the situation calls for a coordinated multi-step process rather than "
            "a single agent dispatch, use action='trigger_flow' to trigger a predefined flow "
            "pipeline. Flows handle sequencing and data piping between agents automatically. "
            "Check the Available Flows section in the brief for what's available.\n"
            '{"action": "trigger_flow", "flow": "flow-name", "inputs": {"key": "value"}, '
            '"reasoning": "..."}\n'
        )

        prompt = (
            "Based on this intelligence brief, decide the most valuable next action(s).\n"
            "Return ONLY a JSON object (no markdown fences, no explanation).\n"
            f"{parallel_instruction}"
            f"{what_if_instruction}"
            f"{trigger_flow_instruction}\n"
            f"{brief}"
        )

        try:
            response = self.client.messages.create(
                model=self.orchestrator_model,
                max_tokens=1024,
                system=self.system_prompt,
                messages=[{"role": "user", "content": prompt}],
            )

            # Record orchestrator decision cost
            try:
                usage = getattr(response, "usage", None)
                if usage is not None:
                    inp = getattr(usage, "input_tokens", 0)
                    out = getattr(usage, "output_tokens", 0)
                    if inp or out:
                        self.cost_tracker.record(
                            engagement_id=self.engagement_id,
                            model=self.orchestrator_model,
                            input_tokens=inp,
                            output_tokens=out,
                            agent="orchestrator",
                        )
            except Exception as e:
                logger.debug(f"[Orchestrator] Cost tracking failed: {e}")

            response_text = ""
            for block in response.content:
                if block.type == "text":
                    response_text += block.text

            # Log orchestrator turn for audit trail
            self._log_orchestrator_turn(prompt, response_text)

            # Check for model refusal on the orchestrator itself
            from agents.base_agent import classify_refusal
            refusal_class = classify_refusal(response_text, tools_were_used=False)
            if refusal_class:
                logger.warning(
                    f"[Orchestrator] Model refusal on decision ({refusal_class}): "
                    f"{response_text[:80]}"
                )
                self._log_orchestrator_refusal(prompt, response_text, refusal_class)
                return {
                    "action": "error",
                    "reasoning": "Model refusal on orchestrator decision; no action taken.",
                    "outcome_class": "model_refusal",
                }

            decision = self._extract_json(response_text)
            if decision:
                return decision

            # If JSON extraction fails, try to salvage
            logger.warning(f"[Orchestrator] Could not parse decision JSON: {response_text[:200]}")
            return {
                "action": "error",
                "reasoning": f"Failed to parse decision: {response_text[:200]}",
            }

        except Exception as e:
            logger.error(f"[Orchestrator] Decision error: {e}")
            return {"action": "error", "reasoning": str(e)}

    def _log_orchestrator_turn(self, prompt: str, response_text: str):
        """Persist orchestrator prompt+response for audit trail."""
        try:
            log_dir = Path(self.engagement_dir) / "logs" / "conversations"
            log_dir.mkdir(parents=True, exist_ok=True)

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            entry = {
                "timestamp": datetime.now().isoformat(),
                "agent": "orchestrator",
                "model": self.orchestrator_model,
                "engagement_id": self.engagement_id,
                "prompt": prompt[:5000],
                "system_prompt": (self.system_prompt or "")[:5000],
                "response": response_text[:5000],
            }
            path = log_dir / f"orchestrator_{timestamp}.json"
            with open(path, "w") as f:
                json.dump(entry, f, indent=2, default=str)
        except Exception as e:
            logger.debug(f"[Orchestrator] Turn logging failed: {e}")

    def _log_orchestrator_refusal(self, prompt: str, response_text: str,
                                   refusal_class: str):
        """Write orchestrator refusal to the shared refusal audit log."""
        import fcntl

        try:
            log_dir = Path(self.engagement_dir) / "logs"
            log_dir.mkdir(parents=True, exist_ok=True)

            record = {
                "timestamp": datetime.now().isoformat(),
                "engagement_id": self.engagement_id,
                "agent_type": "orchestrator",
                "agent_name": "orchestrator",
                "model": self.orchestrator_model,
                "provider": "anthropic",
                "task": prompt[:500],
                "refusal_class": refusal_class,
                "refusal_excerpt": response_text[:300],
                "turn": 0,
                "stop_reason": "end_turn",
                "context_hash": hashlib.sha256(
                    ((self.system_prompt or "") + prompt).encode(errors="replace")
                ).hexdigest()[:16],
            }

            refusal_path = log_dir / "model_refusals.jsonl"
            with open(refusal_path, "a") as f:
                fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                try:
                    f.write(json.dumps(record, default=str) + "\n")
                finally:
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        except Exception as e:
            logger.error(f"[Orchestrator] Failed to write refusal audit: {e}")

    def _dispatch_parallel(self, dispatches: list[dict]) -> list[tuple[str, AgentResult]]:
        """Dispatch multiple agents concurrently using ThreadPoolExecutor.

        Returns list of (agent_type, AgentResult) tuples.
        """
        event_bus = get_event_bus()
        event_bus.emit(event_bus._make_event(
            EventType.ORCHESTRATOR_WAVE, "orchestrator",
            {"agents": [d.get("agent", "?") for d in dispatches], "count": len(dispatches)},
            self.engagement_id,
        ))

        results = []

        def _run_agent(dispatch: dict) -> tuple[str, AgentResult]:
            agent_type = dispatch["agent"]
            task = dispatch["task"]

            # Track dispatch (thread-safe via lock)
            with self._dispatch_lock:
                self._agent_dispatch_counts[agent_type] = self._agent_dispatch_counts.get(agent_type, 0) + 1
                fp = self._task_fingerprint(agent_type, task)
                self._task_fingerprints[fp] = self._task_fingerprints.get(fp, 0) + 1
                self._mark_dispatched(fp)

            result = self.dispatch_agent(agent_type, task)
            return agent_type, result

        with ThreadPoolExecutor(max_workers=min(len(dispatches), MAX_PARALLEL_AGENTS)) as executor:
            futures = {
                executor.submit(_run_agent, d): d
                for d in dispatches
            }
            for future in as_completed(futures):
                dispatch = futures[future]
                try:
                    agent_type, result = future.result()
                    results.append((agent_type, result))
                except Exception as e:
                    agent_type = dispatch.get("agent", "unknown")
                    logger.error(f"[Orchestrator] Parallel agent {agent_type} failed: {e}")
                    results.append((agent_type, AgentResult(
                        agent_name=agent_type,
                        task=dispatch.get("task", ""),
                        success=False,
                        summary=f"Parallel execution error: {e}",
                        errors=[str(e)],
                    )))

        return results

    def _emit_state(self, event_bus, state: "OrchestratorState", iteration: int,
                    message: str, **extra) -> None:
        """Emit a STATUS event for an orchestrator state transition."""
        data = {"state": state.value, "iteration": iteration, "message": message}
        data.update(extra)
        event_bus.emit(event_bus._make_event(
            EventType.STATUS, "orchestrator", data, self.engagement_id,
        ))

    def run_autonomous(self) -> dict:
        """
        Goal-driven autonomous engagement loop.

        v7.1: Supports parallel agent dispatch, event bus integration,
        and incremental intelligence briefs.
        """
        logger.info("[Orchestrator] Starting goal-driven autonomous run")
        start_time = time.time()
        max_iter = self._resolve_dynamic_iteration_budget()
        event_bus = get_event_bus()

        self.story.add_event("AUTONOMOUS MODE: Starting goal-driven engagement")
        self.story.add_event(
            f"AUTONOMOUS MODE: Iteration budget set to {max_iter} "
            f"(model={self.orchestrator_model})"
        )

        # Initialize metrics recording if recorder is attached
        if self._metrics_recorder:
            state = self.shared_state.read()
            target = (state.get("engagement") or {}).get("target", "unknown")
            methodology = (state.get("engagement") or {}).get("methodology", "standard")
            self._metrics_recorder.start_engagement(
                target_ip=target,
                methodology=methodology,
                profile_name=self._profile_name,
                prompt_preset=self._prompt_preset,
                model_config=self._model_config_name,
            )

        # Ensure objectives exist
        state = self.shared_state.read()
        objectives = state.get("objectives", [])
        if not objectives:
            methodology = (state.get("engagement") or {}).get("methodology", "standard")
            obj_templates = OBJECTIVE_TEMPLATES.get(methodology, OBJECTIVE_TEMPLATES["standard"])
            objectives = [{"description": obj, "status": "pending"} for obj in obj_templates]
            self.shared_state.update_section("objectives", objectives)

        iteration_results = []
        consecutive_errors = 0
        iteration = 1
        finished = False

        while iteration <= max_iter:
            logger.info(f"[Orchestrator] === Iteration {iteration}/{max_iter} ===")

            # 0. Check for phase forcing BEFORE asking the LLM
            # Foothold transition takes priority: if we have shells, pivot to post-exploitation
            forced_decision = self._check_foothold_transition()
            if not forced_decision:
                forced_decision = self._check_recon_saturation()
            if forced_decision:
                decision = forced_decision
                action = decision["action"]
                reasoning = decision["reasoning"]
                logger.warning(f"[Orchestrator] FORCED DECISION: {reasoning}")
            else:
                # 1. Build the intelligence brief (incremental after first iteration)
                brief = self._build_intelligence_brief_incremental(iteration, max_iter)

                # 2. Ask Opus for a decision (allow parallel dispatches)
                self._emit_state(event_bus, OrchestratorState.THINKING, iteration,
                                 f"Evaluating iteration {iteration}/{max_iter}")
                decision = self._ask_orchestrator(brief, allow_parallel=True)
                action = decision.get("action", "error")
                reasoning = decision.get("reasoning", "")

            self.story.add_event(
                f"Iteration {iteration}: {action} — {reasoning[:150]}"
            )
            logger.info(f"[Orchestrator] Decision: {action} | {reasoning[:100]}")

            # Emit orchestrator decision event
            event_bus.emit(event_bus._make_event(
                EventType.ORCHESTRATOR_DECISION, "orchestrator",
                {"iteration": iteration, "action": action, "reasoning": reasoning[:200]},
                self.engagement_id,
            ))

            # Evaluate ORCHESTRATOR_DECISION hooks
            try:
                from tools.hooks import (
                    HookAction as _HookAction,
                    HookEvent as _HookEvent,
                    HookEventType as _HookEventType,
                    get_hook_registry as _get_hook_registry,
                )
                _orch_hook_event = _HookEvent(
                    event_type=_HookEventType.ORCHESTRATOR_DECISION,
                    tool_name="orchestrator",
                    tool_args=decision,
                    agent_name="orchestrator",
                    engagement_id=self.engagement_id,
                )
                _hook_action, _hook_rule, _ = _get_hook_registry().evaluate(_orch_hook_event)
                if _hook_action == _HookAction.BLOCK:
                    logger.warning(
                        "[Orchestrator] Decision BLOCKED by hook '%s', skipping iteration %d",
                        _hook_rule.name if _hook_rule else "?", iteration,
                    )
                    continue
            except Exception as _hook_err:
                logger.debug("[Orchestrator] ORCHESTRATOR_DECISION hook error: %s", _hook_err)

            # 3. Handle the decision
            if action == "finish":
                self._run_finalized = True
                self.story.add_event(
                    f"ENGAGEMENT COMPLETE: {decision.get('final_summary', reasoning)}"
                )
                iteration_results.append({
                    "iteration": iteration,
                    "action": "finish",
                    "reasoning": reasoning,
                })
                finished = True
                break

            elif action == "dispatch":
                agent_type = decision.get("agent", "")
                task = decision.get("task", "")

                if not agent_type or not task:
                    logger.warning("[Orchestrator] Empty agent or task in dispatch decision")
                    self.failed_approaches.append(f"Iteration {iteration}: empty dispatch")
                    consecutive_errors += 1
                    if consecutive_errors >= self._consecutive_error_limit:
                        logger.error("[Orchestrator] CIRCUIT BREAKER: Too many consecutive errors/empty dispatches")
                        self.story.add_event("CIRCUIT BREAKER: Forcing exploitation after repeated errors")
                        # Reset and force attack on next iteration
                        consecutive_errors = 0
                        self._agent_dispatch_counts["recon"] = self._recon_saturation_threshold
                    self._apply_objective_progression_gate(iteration)
                    iteration += 1
                    continue

                # Pre-dispatch validation (skip for forced decisions)
                if not decision.get("_forced"):
                    skip_reason = self._pre_dispatch_check(agent_type, task)
                    if skip_reason:
                        logger.warning(f"[Orchestrator] Pre-dispatch check failed: {skip_reason}")
                        self.story.add_event(f"SKIPPED {agent_type}: {skip_reason}")
                        self.failed_approaches.append(f"{agent_type}: {skip_reason}")
                        iteration_results.append({
                            "iteration": iteration,
                            "action": "skipped",
                            "agent": agent_type,
                            "reason": skip_reason,
                        })
                        consecutive_errors += 1
                        self._apply_objective_progression_gate(iteration)
                        iteration += 1
                        continue

                # Task deduplication: reject near-identical tasks that already failed
                fp = self._task_fingerprint(agent_type, task)
                if fp in self._banned_task_fingerprints:
                    self._consecutive_ban_blocks += 1
                    skip_msg = (
                        f"Task fingerprint is banned due to repeated objective stall/failure "
                        f"(ban block {self._consecutive_ban_blocks}/{self._max_consecutive_ban_blocks})."
                    )
                    logger.warning(f"[Orchestrator] BANNED FINGERPRINT: {agent_type} — {skip_msg}")
                    self.story.add_event(f"BANNED TASK BLOCKED {agent_type}: {skip_msg}")
                    self.failed_approaches.append(f"{agent_type}: {skip_msg} (task: {task[:80]})")
                    iteration_results.append({
                        "iteration": iteration,
                        "action": "banned_blocked",
                        "agent": agent_type,
                        "reason": skip_msg,
                    })
                    consecutive_errors += 1

                    # Hard-stop ban loops after a few consecutive blocked iterations.
                    # At this point the orchestrator is no longer making progress.
                    if self._consecutive_ban_blocks >= self._max_consecutive_ban_blocks:
                        logger.warning(
                            "[Orchestrator] BAN-LOOP STOP: %s consecutive banned blocks. "
                            "Terminating to reporting.",
                            self._consecutive_ban_blocks,
                        )
                        self.story.add_event(
                            f"BAN-LOOP STOP: {self._consecutive_ban_blocks} consecutive "
                            f"banned blocks. Terminating to reporting."
                        )
                        self._consecutive_ban_blocks = 0
                        self._run_finalized = True
                        self.story.add_event(
                            "BUDGET SAVED: Terminating early due to ban-loop stall. "
                            "Dispatching reporting agent."
                        )
                        self.dispatch_agent(
                            "reporting",
                            "Generate penetration test report with all findings discovered so far. "
                            "The engagement stalled due to repeated task bans."
                        )
                        finished = True
                        break

                    self._apply_objective_progression_gate(iteration)
                    iteration += 1
                    continue
                else:
                    # Reset ban block counter on any non-banned dispatch
                    self._consecutive_ban_blocks = 0
                prior_count = self._task_fingerprints.get(fp, 0)
                if prior_count >= self._max_similar_dispatches:
                    skip_msg = f"Similar task already dispatched {prior_count}x without progress — blocked to prevent loop"
                    logger.warning(f"[Orchestrator] DEDUP BLOCK: {agent_type} — {skip_msg}")
                    self.story.add_event(f"DEDUP BLOCKED {agent_type}: {skip_msg}")
                    self.failed_approaches.append(f"{agent_type}: {skip_msg} (task: {task[:80]})")
                    iteration_results.append({
                        "iteration": iteration,
                        "action": "dedup_blocked",
                        "agent": agent_type,
                        "reason": skip_msg,
                    })
                    consecutive_errors += 1
                    if consecutive_errors >= self._consecutive_error_limit:
                        logger.warning("[Orchestrator] CIRCUIT BREAKER after dedup blocks")
                        self.story.add_event("CIRCUIT BREAKER: Repeated dedup blocks, forcing phase change")
                        consecutive_errors = 0
                        self._agent_dispatch_counts["recon"] = self._recon_saturation_threshold
                    self._apply_objective_progression_gate(iteration)
                    iteration += 1
                    continue

                cooldown_remaining = self._dispatch_cooldown_remaining(fp)
                if cooldown_remaining > 0:
                    skip_msg = (
                        f"Task recently dispatched ({self._dispatch_cooldown_seconds}s cooldown), "
                        f"retry in ~{cooldown_remaining}s"
                    )
                    logger.warning(f"[Orchestrator] COOLDOWN BLOCK: {agent_type} — {skip_msg}")
                    self.story.add_event(f"COOLDOWN BLOCKED {agent_type}: {skip_msg}")
                    iteration_results.append({
                        "iteration": iteration,
                        "action": "cooldown_blocked",
                        "agent": agent_type,
                        "reason": skip_msg,
                    })
                    time.sleep(min(max(cooldown_remaining, 1), 2))
                    continue
                self._task_fingerprints[fp] = prior_count + 1
                self._mark_dispatched(fp)

                # Track agent dispatch counts for saturation detection
                self._agent_dispatch_counts[agent_type] = self._agent_dispatch_counts.get(agent_type, 0) + 1

                # Snapshot state before dispatch to detect progress
                state_before = self._compute_state_hash()

                # Fragile-target handling: if instability detected, add throttle prefix
                if self._target_instability_count >= self._target_instability_threshold:
                    task = (
                        "⚠️ TARGET INSTABILITY DETECTED — use low-noise approach.\n"
                        "- Prefer single commands over automated scanners\n"
                        "- Wait between requests; do NOT brute-force or spray\n"
                        "- Checkpoint every discovery immediately (save_finding)\n"
                        "- If the service returns errors, STOP and report what you have\n\n"
                        + task
                    )

                # Dispatch the agent
                self._emit_state(event_bus, OrchestratorState.DISPATCHING, iteration,
                                 f"Dispatching {agent_type}",
                                 agent=agent_type, task=task[:80])
                dispatch_t0 = time.time()
                result = self.dispatch_agent(agent_type, task)
                dispatch_dur = round(time.time() - dispatch_t0, 1)

                # Collect result
                self._emit_state(event_bus, OrchestratorState.COLLECTING, iteration,
                                 f"Collecting {agent_type} result",
                                 agent=agent_type, duration=dispatch_dur)

                # --- Verification gate: challenge high-value claims ---
                _skip_objectives = False
                if self.verification_gate.should_verify(result):
                    vr = self.verification_gate.verify(result)
                    if vr.status == VerificationStatus.FABRICATED:
                        logger.warning(
                            "[Orchestrator] FABRICATED result from %s: %s",
                            agent_type, vr.reason,
                        )
                        self.story.add_event(
                            f"VERIFICATION FAILED: {agent_type} result flagged as "
                            f"FABRICATED — {vr.reason[:150]}"
                        )
                        result.success = False
                        result.summary = f"[FABRICATED] {result.summary}"
                        _skip_objectives = True
                    elif vr.status == VerificationStatus.UNVERIFIED:
                        logger.info(
                            "[Orchestrator] UNVERIFIED result from %s: %s",
                            agent_type, vr.reason,
                        )
                        result.summary = f"[UNVERIFIED] {result.summary}"

                # Detect target instability from result
                self._detect_target_instability(result)

                # Check if progress was made
                state_after = self._compute_state_hash()
                if state_before == state_after:
                    self._consecutive_no_progress += 1
                    logger.info(f"[Orchestrator] No progress detected ({self._consecutive_no_progress} consecutive)")
                    self._recent_failed_fingerprints.append(fp)
                else:
                    self._consecutive_no_progress = 0
                    # Real progress made — reset dedup counters so agents can retry
                    # previously-blocked approaches with new intel
                    self._task_fingerprints.clear()
                    logger.info(f"[Orchestrator] Progress detected: {state_before} → {state_after}")

                # Track result for next iteration's brief
                is_refusal = getattr(result, 'outcome_class', 'normal') == 'model_refusal'

                self.iteration_history.append(
                    self._build_history_entry(result, iteration, agent_type, task)
                )

                # Model refusals: don't poison failure tracking or dedup
                if is_refusal:
                    self._refusal_count = getattr(self, '_refusal_count', 0) + 1
                    if not hasattr(self, '_refused_fingerprints'):
                        self._refused_fingerprints = {}
                    self._refused_fingerprints[fp] = self._refused_fingerprints.get(fp, 0) + 1
                    logger.warning(
                        f"[Orchestrator] Model refusal #{self._refusal_count} "
                        f"on {agent_type}: {task[:80]}"
                    )
                    self.story.add_event(
                        f"MODEL REFUSAL: {agent_type} agent — provider declined "
                        f"offensive task (refusal #{self._refusal_count})"
                    )
                # Track failures and reset/increment error counter
                elif not result.success or result.errors:
                    failure_desc = f"{agent_type}: {task[:100]}"
                    if result.errors:
                        failure_desc += f" — {result.errors[0][:100]}"
                    self.failed_approaches.append(failure_desc)
                    consecutive_errors += 1
                    self._recent_failed_fingerprints.append(fp)
                else:
                    consecutive_errors = 0  # Reset on success

                # Circuit breaker: after N consecutive failures, force phase change
                if consecutive_errors >= self._consecutive_error_limit:
                    logger.warning(f"[Orchestrator] CIRCUIT BREAKER: {consecutive_errors} consecutive failures")
                    self.story.add_event(f"CIRCUIT BREAKER: {consecutive_errors} consecutive failures, forcing phase advancement")
                    consecutive_errors = 0
                    # Bump recon count to trigger saturation on next iteration
                    self._agent_dispatch_counts["recon"] = max(
                        self._agent_dispatch_counts.get("recon", 0),
                        self._recon_saturation_threshold
                    )

                # Update objectives if specified (skip for fabricated results)
                if not _skip_objectives:
                    obj_updates = decision.get("objectives_update", [])
                    if obj_updates:
                        self._update_objectives(obj_updates)

                iteration_results.append({
                    "iteration": iteration,
                    "action": "dispatch",
                    "agent": agent_type,
                    "success": result.success,
                    "summary": (str(result.summary)[:300] if result.summary else ""),
                    "tools_used": len(result.tools_used),
                })

                # Record iteration metrics
                if self._metrics_recorder:
                    self._metrics_recorder.record_iteration(
                        iteration=iteration,
                        budget_remaining=max_iter - iteration,
                        budget_total=max_iter,
                        agent_type=agent_type,
                        task=task[:200],
                        success=result.success,
                        duration_seconds=result.duration_seconds,
                    )

                # Run alerts check (cheap Kimi call, non-blocking for the loop)
                try:
                    last_res = {
                        "agent": agent_type,
                        "success": result.success,
                        "summary": str(result.summary)[:300] if result.summary else "",
                        "errors": result.errors[:3] if result.errors else [],
                    }
                    new_alerts = self.alerts_agent.check(
                        iteration=iteration,
                        last_result=last_res,
                    )
                    for alert in new_alerts:
                        self.story.add_event(
                            f"ALERT [{alert.severity.upper()}]: {alert.title}"
                        )
                except Exception as e:
                    logger.debug(f"[Orchestrator] Alerts check failed (non-fatal): {e}")

            elif action == "parallel":
                # v7.1: Parallel agent dispatch
                dispatches = decision.get("dispatches", [])
                if not dispatches or not isinstance(dispatches, list):
                    logger.warning("[Orchestrator] Empty parallel dispatches, treating as error")
                    consecutive_errors += 1
                    self._apply_objective_progression_gate(iteration)
                    iteration += 1
                    continue

                # Validate and cap dispatches
                valid_dispatches = []
                wave_fingerprints: set[str] = set()
                cooldown_filtered = False
                for d in dispatches[:MAX_PARALLEL_AGENTS]:
                    if isinstance(d, dict) and d.get("agent") and d.get("task"):
                        # Pre-dispatch validation
                        skip = self._pre_dispatch_check(d["agent"], d["task"])
                        if skip:
                            logger.warning(f"[Orchestrator] Skipping parallel {d['agent']}: {skip}")
                            continue
                        # Dedup check
                        fp = self._task_fingerprint(d["agent"], d["task"])
                        if fp in self._banned_task_fingerprints:
                            logger.warning(f"[Orchestrator] Banned fingerprint blocked parallel {d['agent']}")
                            continue
                        if fp in wave_fingerprints:
                            logger.warning(f"[Orchestrator] Wave dedup blocked parallel {d['agent']}")
                            continue
                        if self._task_fingerprints.get(fp, 0) >= self._max_similar_dispatches:
                            logger.warning(f"[Orchestrator] Dedup blocked parallel {d['agent']}")
                            continue
                        if self._dispatch_cooldown_remaining(fp) > 0:
                            logger.warning(f"[Orchestrator] Cooldown blocked parallel {d['agent']}")
                            cooldown_filtered = True
                            continue
                        # Enrich task
                        d["task"] = self._enrich_task(d["agent"], d["task"])
                        wave_fingerprints.add(fp)
                        valid_dispatches.append(d)

                if not valid_dispatches:
                    if cooldown_filtered:
                        logger.info("[Orchestrator] Parallel wave deferred by cooldown; retrying without spending iteration budget")
                        time.sleep(2)
                        continue
                    logger.warning("[Orchestrator] All parallel dispatches were filtered out")
                    consecutive_errors += 1
                    self._apply_objective_progression_gate(iteration)
                    iteration += 1
                    continue

                logger.info(f"[Orchestrator] PARALLEL DISPATCH: {[d['agent'] for d in valid_dispatches]}")
                self.story.add_event(
                    f"PARALLEL DISPATCH: {', '.join(d['agent'] for d in valid_dispatches)}"
                )

                state_before = self._compute_state_hash()
                agents_in_wave = [d["agent"] for d in valid_dispatches]
                self._emit_state(event_bus, OrchestratorState.DISPATCHING, iteration,
                                 f"Parallel dispatch: {', '.join(agents_in_wave)}",
                                 agents=agents_in_wave)
                wave_t0 = time.time()
                parallel_results = self._dispatch_parallel(valid_dispatches)
                wave_dur = round(time.time() - wave_t0, 1)
                self._emit_state(event_bus, OrchestratorState.COLLECTING, iteration,
                                 f"Collecting parallel results",
                                 agents=agents_in_wave, duration=wave_dur)
                state_after = self._compute_state_hash()

                # Track progress
                if state_before == state_after:
                    self._consecutive_no_progress += 1
                    self._recent_failed_fingerprints.extend(list(wave_fingerprints))
                else:
                    self._consecutive_no_progress = 0
                    self._task_fingerprints.clear()

                # Process results (with verification gate)
                any_success = False
                for agent_type, result in parallel_results:
                    if self.verification_gate.should_verify(result):
                        vr = self.verification_gate.verify(result)
                        if vr.status == VerificationStatus.FABRICATED:
                            logger.warning(
                                "[Orchestrator] FABRICATED parallel result from %s: %s",
                                agent_type, vr.reason,
                            )
                            self.story.add_event(
                                f"VERIFICATION FAILED: {agent_type} (parallel) flagged as "
                                f"FABRICATED — {vr.reason[:150]}"
                            )
                            result.success = False
                            result.summary = f"[FABRICATED] {result.summary}"
                        elif vr.status == VerificationStatus.UNVERIFIED:
                            logger.info(
                                "[Orchestrator] UNVERIFIED parallel result from %s: %s",
                                agent_type, vr.reason,
                            )
                            result.summary = f"[UNVERIFIED] {result.summary}"

                    self.iteration_history.append(
                        self._build_history_entry(result, iteration, agent_type, "(parallel)")
                    )
                    if result.success:
                        any_success = True
                        consecutive_errors = 0
                    else:
                        failure_desc = f"{agent_type}: parallel dispatch"
                        if result.errors:
                            failure_desc += f" — {result.errors[0][:100]}"
                        self.failed_approaches.append(failure_desc)
                        fp = self._task_fingerprint(agent_type, "(parallel)")
                        self._recent_failed_fingerprints.append(fp)

                if not any_success:
                    consecutive_errors += 1

                iteration_results.append({
                    "iteration": iteration,
                    "action": "parallel",
                    "agents": [r[0] for r in parallel_results],
                    "success": any_success,
                })

                # Record metrics
                if self._metrics_recorder:
                    self._metrics_recorder.record_iteration(
                        iteration=iteration,
                        budget_remaining=max_iter - iteration,
                        budget_total=max_iter,
                        agent_type=f"parallel({','.join(r[0] for r in parallel_results)})",
                        task="parallel dispatch",
                        success=any_success,
                        duration_seconds=sum(r[1].duration_seconds for r in parallel_results),
                    )

            elif action == "trigger_flow":
                # Dispatch a predefined multi-step flow pipeline
                flow_name = decision.get("flow", decision.get("flow_name", ""))
                flow_inputs = decision.get("inputs", {})
                if not flow_name:
                    logger.warning("[Orchestrator] trigger_flow decision missing flow name")
                    consecutive_errors += 1
                    self._apply_objective_progression_gate(iteration)
                    iteration += 1
                    continue

                try:
                    from flows.engine import get_flow_engine
                    flow_engine = get_flow_engine()
                    flow_def = flow_engine.get_flow(flow_name)
                    exec_mode = flow_def.spec.execution_mode

                    logger.info(f"[Orchestrator] Triggering flow '{flow_name}' (mode={exec_mode})")
                    self.story.add_event(f"FLOW TRIGGERED: {flow_name} ({reasoning})")
                    event_bus.emit(event_bus._make_event(
                        EventType.ORCHESTRATOR_DECISION, "orchestrator",
                        {"action": "trigger_flow", "flow": flow_name},
                        self.engagement_id,
                    ))

                    if exec_mode == "interrupt":
                        # Synchronous — block until flow completes
                        flow_result = flow_engine.execute_sync(
                            flow_name, flow_inputs,
                            workspace=self.engagement_dir,
                            engagement_id=self.engagement_id,
                        )
                        success = flow_result.status == "completed"
                        self.iteration_history.append({
                            "agent": f"flow:{flow_name}",
                            "task": f"Flow pipeline: {flow_name}",
                            "success": success,
                            "summary": f"Flow {flow_result.status} ({flow_result.duration_seconds:.0f}s, ${flow_result.total_cost_usd:.4f})",
                        })
                    else:
                        # Parallel/background — non-blocking
                        flow_engine.execute_async(
                            flow_name, flow_inputs,
                            workspace=self.engagement_dir,
                            engagement_id=self.engagement_id,
                            trigger_type="orchestrator",
                        )
                        self.iteration_history.append({
                            "agent": f"flow:{flow_name}",
                            "task": f"Flow pipeline: {flow_name}",
                            "success": True,
                            "summary": f"Flow '{flow_name}' dispatched in {exec_mode} mode",
                        })

                    consecutive_errors = 0
                    iteration_results.append({
                        "iteration": iteration,
                        "action": "trigger_flow",
                        "flow": flow_name,
                        "reasoning": reasoning,
                    })
                except KeyError:
                    logger.warning(f"[Orchestrator] Flow '{flow_name}' not found")
                    self.failed_approaches.append(f"Flow '{flow_name}' not found")
                    consecutive_errors += 1
                except Exception as exc:
                    logger.error(f"[Orchestrator] Flow trigger failed: {exc}")
                    self.failed_approaches.append(f"Flow '{flow_name}': {exc}")
                    consecutive_errors += 1

            elif action == "what_if":
                # Fork-try-discard pattern for risky decisions
                agent_type = decision.get("agent", "")
                aggressive_task = decision.get("aggressive_task", "")
                conservative_task = decision.get("conservative_task", "")

                if not agent_type or not aggressive_task or not conservative_task:
                    logger.warning("[Orchestrator] Incomplete what_if decision, treating as error")
                    self.failed_approaches.append(f"Iteration {iteration}: incomplete what_if")
                    consecutive_errors += 1
                    self._apply_objective_progression_gate(iteration)
                    iteration += 1
                    continue

                self._agent_dispatch_counts[agent_type] = self._agent_dispatch_counts.get(agent_type, 0) + 1

                state_before = self._compute_state_hash()
                self._emit_state(event_bus, OrchestratorState.DISPATCHING, iteration,
                                 f"What-if fork: {agent_type}",
                                 agent=agent_type, task=aggressive_task[:80])
                dispatch_t0 = time.time()
                result = self._try_what_if(
                    aggressive_task=aggressive_task,
                    conservative_task=conservative_task,
                    agent_type=agent_type,
                    iteration=iteration,
                )
                dispatch_dur = round(time.time() - dispatch_t0, 1)

                self._emit_state(event_bus, OrchestratorState.COLLECTING, iteration,
                                 f"Collecting what-if result",
                                 agent=agent_type, duration=dispatch_dur)

                # Progress tracking
                state_after = self._compute_state_hash()
                if state_before == state_after:
                    self._consecutive_no_progress += 1
                else:
                    self._consecutive_no_progress = 0
                    self._task_fingerprints.clear()

                self.iteration_history.append(
                    self._build_history_entry(result, iteration, agent_type, f"(what_if)")
                )

                if not result.success or result.errors:
                    failure_desc = f"{agent_type}: what_if — {aggressive_task[:80]}"
                    self.failed_approaches.append(failure_desc)
                    consecutive_errors += 1
                else:
                    consecutive_errors = 0

                iteration_results.append({
                    "iteration": iteration,
                    "action": "what_if",
                    "agent": agent_type,
                    "success": result.success,
                    "summary": (str(result.summary)[:300] if result.summary else ""),
                })

                if self._metrics_recorder:
                    self._metrics_recorder.record_iteration(
                        iteration=iteration,
                        budget_remaining=max_iter - iteration,
                        budget_total=max_iter,
                        agent_type=f"what_if({agent_type})",
                        task=aggressive_task[:200],
                        success=result.success,
                        duration_seconds=result.duration_seconds,
                    )

            elif action == "error":
                logger.error(f"[Orchestrator] Error decision: {reasoning}")
                self.failed_approaches.append(f"Orchestrator error: {reasoning[:100]}")
                iteration_results.append({
                    "iteration": iteration,
                    "action": "error",
                    "reasoning": reasoning,
                })
                consecutive_errors += 1
                # Circuit breaker for repeated LLM errors
                if consecutive_errors >= self._consecutive_error_limit:
                    logger.error("[Orchestrator] CIRCUIT BREAKER: Too many LLM errors, forcing exploitation")
                    self.story.add_event("CIRCUIT BREAKER: LLM errors, forcing exploitation")
                    consecutive_errors = 0
                    self._agent_dispatch_counts["recon"] = self._recon_saturation_threshold

            else:
                logger.warning(f"[Orchestrator] Unknown action: {action}")
                self.failed_approaches.append(f"Unknown action: {action}")
                consecutive_errors += 1

            # Objective progression gate: force strategy pivot if stalled.
            self._apply_objective_progression_gate(iteration)
            self._emit_state(event_bus, OrchestratorState.IDLE, iteration,
                             f"Iteration {iteration} complete")
            iteration += 1

        if not finished and iteration > max_iter:
            # Hit max iterations — finalize before dispatching reporting
            self._run_finalized = True
            self.story.add_event(
                f"BUDGET EXHAUSTED after {max_iter} iterations. Dispatching reporting agent."
            )
            # Auto-dispatch reporting as final action (allowed even when finalized)
            self.dispatch_agent(
                "reporting",
                "Generate penetration test report with all findings discovered so far. "
                "The engagement budget was exhausted before all objectives were met."
            )

        total_duration = time.time() - start_time
        self._emit_state(event_bus, OrchestratorState.FINISHED, iteration - 1,
                         f"Engagement complete ({total_duration:.0f}s)",
                         duration=round(total_duration, 1),
                         iterations=len(iteration_results))
        self.story.add_event(f"AUTONOMOUS MODE: Complete ({total_duration:.0f}s, {len(iteration_results)} iterations)")

        cost_summary = self.cost_tracker.get_summary(self.engagement_id)

        # Compute split result semantics:
        # - exploit_achieved: at least one meaningful exploit/access was obtained
        # - objectives_completed: all engagement objectives are marked complete
        state = self.shared_state.read()
        objectives = _ensure_list(state.get("objectives", []))
        access = _ensure_dict(state.get("access"))
        shells = _ensure_list(access.get("shells", []))
        creds = _ensure_list(state.get("credentials_summary", []))
        vulns = _ensure_list(state.get("vulns_summary", []))
        auth_access = _ensure_list(state.get("authenticated_access", []))
        high_vulns = [v for v in vulns if isinstance(v, dict) and
                      str(v.get("severity", "")).lower() in ("critical", "high")]

        exploit_achieved = bool(shells or auth_access or creds or high_vulns)
        pending_objectives = [
            o for o in objectives
            if isinstance(o, dict) and o.get("status") != "completed"
        ]
        objectives_completed = len(pending_objectives) == 0 and len(objectives) > 0

        # The legacy "success" field now reflects actual objective completion,
        # not just "the run executed without crashing"
        success = objectives_completed

        # Finalize metrics recording — populate findings, access, and success metrics
        if self._metrics_recorder:
            try:
                db_findings = self.db.query_findings(self.engagement_id)
                for f in db_findings:
                    self._metrics_recorder.record_finding(
                        f.get("severity", "info")
                    )
                for a in auth_access:
                    if isinstance(a, dict):
                        self._metrics_recorder.record_access(
                            a.get("access_level", "user")
                        )
                for obj in objectives:
                    if isinstance(obj, dict) and obj.get("status") == "completed":
                        self._metrics_recorder.record_objective_completed(
                            obj.get("description", "")
                        )
                if any(
                    isinstance(a, dict)
                    and str(a.get("access_level", "")).lower() in ("root", "admin", "system")
                    for a in auth_access
                ):
                    self._metrics_recorder.record_success_metric("root_obtained")
                    self._metrics_recorder.record_success_metric("privesc_achieved")
                if auth_access or shells:
                    self._metrics_recorder.record_success_metric("shell_obtained")
            except Exception as e:
                logger.warning(f"[Orchestrator] Failed to populate metrics: {e}")
            self._metrics_recorder.finish_engagement(cost_summary)

        # Record run to master profile history if one is active
        self._record_master_profile_run(total_duration, cost_summary)

        # Persist cross-engagement lessons
        try:
            eng_info = (state.get("engagement") or {})
            self.engagement_memory.record_engagement_summary(
                engagement_id=os.path.basename(self.engagement_dir),
                summary={
                    "target": eng_info.get("target", ""),
                    "methodology": eng_info.get("methodology", ""),
                    "duration_hours": total_duration / 3600.0,
                    "findings_count": len(vulns),
                    "key_lessons": "; ".join(
                        o.get("description", "")
                        for o in objectives
                        if isinstance(o, dict) and o.get("status") == "completed"
                    ),
                },
            )
            # Record technique feedback from high-value findings
            methodology_type = eng_info.get("methodology", "standard")
            for v in high_vulns:
                if isinstance(v, dict) and v.get("title"):
                    self.engagement_memory.record_technique(
                        technique=v["title"],
                        target_type=methodology_type,
                        success=True,
                        notes=v.get("host", ""),
                    )
        except Exception as e:
            logger.debug("Failed to record cross-engagement memory: %s", e)

        # Consolidate memory to prevent unbounded growth
        try:
            from memory.engagement_memory import MemoryConsolidator
            consolidator = MemoryConsolidator()
            stats = consolidator.consolidate(self.engagement_memory)
            logger.info("[MemoryConsolidator] %s", stats)
        except Exception as e:
            logger.debug("Memory consolidation failed (non-fatal): %s", e)

        return {
            "success": success,
            "exploit_achieved": exploit_achieved,
            "objectives_completed": objectives_completed,
            "pending_objectives": [o.get("description", "") for o in pending_objectives],
            "mode": "autonomous",
            "total_duration_seconds": total_duration,
            "iterations": len(iteration_results),
            "budget_total": max_iter,
            "results": iteration_results,
            "cost": cost_summary,
            "profile": self._profile_name or None,
        }

    def _record_master_profile_run(self, duration: float, cost_summary: dict):
        """Record this run in the master profile's history if one is active."""
        if not self._profile_name:
            return
        try:
            from profiles.master_profile_manager import MasterProfileManager
            mpm = MasterProfileManager()
            # Only record if it's a master profile (not a legacy test profile)
            mp = mpm.get_master_profile(self._profile_name)
            if not mp:
                return

            resolved = mpm.resolve(self._profile_name)
            snapshot = mpm.snapshot_effective_config(resolved)

            state = self.shared_state.read()
            target = (state.get("engagement") or {}).get("target", "unknown")
            methodology = (state.get("engagement") or {}).get("methodology", "standard")

            total_usd = cost_summary.get("total_usd", 0.0) if cost_summary else 0.0
            total_tokens = 0
            if cost_summary:
                for prov in cost_summary.get("by_provider", {}).values():
                    total_tokens += prov.get("input_tokens", 0) + prov.get("output_tokens", 0)

            # Build findings summary from metrics
            findings = {}
            if self._metrics_recorder:
                metrics = self._metrics_recorder.get_metrics()
                findings = metrics.get("findings_count", {})

            eng_name = os.path.basename(self.engagement_dir)
            mpm.record_run(
                master_profile_name=self._profile_name,
                engagement_name=eng_name,
                target=target,
                methodology=methodology,
                effective_snapshot=snapshot,
                duration_seconds=duration,
                cost_usd=total_usd,
                tokens=total_tokens,
                findings_summary=findings,
                outcome_summary=f"Completed in {duration:.0f}s, ${total_usd:.4f}",
            )
        except Exception as e:
            logger.warning(f"[Orchestrator] Failed to record master profile run: {e}")

    # =========================================================================
    # Pre-Dispatch Validation
    # =========================================================================

    def _pre_dispatch_check(self, agent_type: str, task: str) -> Optional[str]:
        """
        Validate that dispatching this agent makes sense given current state.
        Returns None if OK, or a reason string if the dispatch should be skipped.
        """
        state = self.shared_state.read()
        task_lower = task.lower()

        if agent_type in ("attack", "exploit", "privesc"):
            # For privilege escalation tasks, require existing access
            privesc_keywords = ["privilege", "escalat", "privesc", "post-exploit", "post_exploit",
                                "dump cred", "dump hash", "lateral", "linpeas", "winpeas"]
            is_privesc = any(kw in task_lower for kw in privesc_keywords)

            if is_privesc:
                access = (state.get("access") or {})
                shells = _ensure_list(access.get("shells", []))
                sessions = _ensure_list(access.get("sessions", []))
                creds = _ensure_list(state.get("credentials_summary", []))
                # Need at least a shell, session, or usable credentials
                if not shells and not sessions and not creds:
                    return (
                        "No shells, sessions, or credentials in shared state. "
                        "Cannot escalate privileges without existing access. "
                        "Dispatch recon or webapp first to find attack vectors."
                    )

        if agent_type == "osint":
            # OSINT needs identity/domain targets, not bare IPs
            engagement = (state.get("engagement") or {})
            target = engagement.get("target", "")
            import re
            # If target is just an IP and task doesn't mention domains/names
            if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target):
                domains = state.get("domains")
                if isinstance(domains, dict):
                    has_domain = bool(domains.get("primary_domain"))
                elif isinstance(domains, list):
                    has_domain = bool(domains)
                else:
                    has_domain = False
                if not has_domain and "domain" not in task_lower and "employee" not in task_lower:
                    return (
                        "OSINT against a bare IP with no domain context is low-value. "
                        "Sherlock searches social media usernames, not IPs. "
                        "Run recon first to discover domain names and hostnames."
                    )

        return None  # All checks passed

    def _objective_signature(self, objectives) -> str:
        """Create a stable signature of objective status progression."""
        normalized = []
        for obj in _ensure_list(objectives):
            if isinstance(obj, dict):
                normalized.append({
                    "description": str(obj.get("description", "")).strip().lower(),
                    "status": str(obj.get("status", "pending")).strip().lower(),
                })
            elif isinstance(obj, str):
                normalized.append({
                    "description": obj.strip().lower(),
                    "status": "pending",
                })
        normalized.sort(key=lambda x: x["description"])
        raw = json.dumps(normalized, sort_keys=True)
        return hashlib.sha1(raw.encode("utf-8")).hexdigest()

    def _apply_objective_progression_gate(self, iteration: int) -> None:
        """Detect stalled objective state and force a strategy pivot."""
        state = self.shared_state.read()
        objectives = _ensure_list(state.get("objectives", []))
        sig = self._objective_signature(objectives)
        if not self._objective_state_hash:
            self._objective_state_hash = sig
            self._objective_stall_iterations = 0
            return

        if sig == self._objective_state_hash:
            self._objective_stall_iterations += 1
        else:
            self._objective_state_hash = sig
            self._objective_stall_iterations = 0
            self._recent_failed_fingerprints.clear()
            return

        if self._objective_stall_iterations < self._objective_stall_limit:
            return

        to_ban = self._recent_failed_fingerprints[-5:]
        if to_ban:
            self._banned_task_fingerprints.update(to_ban)
        self._recent_failed_fingerprints.clear()
        self._objective_stall_iterations = 0

        logger.warning(
            "[Orchestrator] OBJECTIVE STALL: forcing strategy pivot at iteration %s; banned %s fingerprints.",
            iteration,
            len(to_ban),
        )
        self.story.add_event(
            f"OBJECTIVE STALL GATE: No objective progression for {self._objective_stall_limit} iterations. "
            f"Pivoting strategy and banning {len(to_ban)} failed task fingerprints."
        )
        # Trigger recon saturation forcing path to pivot into exploitation-oriented actions.
        self._agent_dispatch_counts["recon"] = max(
            self._agent_dispatch_counts.get("recon", 0),
            self._recon_saturation_threshold,
        )

    def _initialize_tool_compatibility_map(self) -> None:
        """Preflight check common external binaries and persist compatibility."""
        try:
            existing = self.shared_state.read().get("tool_compatibility")
            if isinstance(existing, dict) and existing.get("checked_at"):
                return
        except Exception:
            pass

        probes = {
            "httpx_probe": {"binary": "httpx", "version_args": [["-version"], ["--version"], ["-h"]]},
            "testssl_scan": {"binary": "testssl", "version_args": [["--version"], ["-v"], ["-h"]]},
            "arjun_scan": {"binary": "arjun", "version_args": [["--version"], ["-h"]]},
            "gobuster_scan": {"binary": "gobuster", "version_args": [["version"], ["-h"], ["--help"]]},
            "feroxbuster_scan": {"binary": "feroxbuster", "version_args": [["--version"], ["-h"], ["--help"]]},
            "nikto_scan": {"binary": "nikto", "version_args": [["-Version"], ["-h"], ["--help"]]},
        }

        tools = {}
        for tool_name, cfg in probes.items():
            binary = cfg["binary"]
            path = shutil.which(binary)
            if not path:
                tools[tool_name] = {
                    "binary": binary,
                    "available": False,
                    "compatible": False,
                    "version": "",
                    "reason": "binary_missing",
                }
                continue

            version_line = ""
            last_err = ""
            for args in cfg["version_args"]:
                try:
                    proc = subprocess.run(
                        [path, *args],
                        capture_output=True,
                        text=True,
                        timeout=8,
                    )
                    out = (proc.stdout or proc.stderr or "").strip()
                    if out:
                        version_line = out.splitlines()[0][:240]
                        break
                    if proc.returncode == 0:
                        version_line = "available"
                        break
                except Exception as exc:
                    last_err = str(exc)

            compatible = True
            reason = "ok"
            lowered = version_line.lower()
            if tool_name == "httpx_probe" and version_line and "projectdiscovery" not in lowered and "httpx" in lowered:
                # Likely python httpx CLI, not ProjectDiscovery binary expected by wrappers.
                compatible = False
                reason = "unsupported_httpx_variant"

            tools[tool_name] = {
                "binary": binary,
                "available": True,
                "compatible": compatible,
                "version": version_line or "unknown",
                "reason": reason if compatible else reason,
                "error": last_err,
            }

        compatibility_map = {
            "checked_at": datetime.utcnow().isoformat() + "Z",
            "tools": tools,
        }
        try:
            self.shared_state.update_section("tool_compatibility", compatibility_map)
        except Exception as e:
            logger.debug("[Orchestrator] Failed to persist tool compatibility map: %s", e)

    def _load_yaml_hooks(self) -> None:
        """Load operator-defined hook rules from config/hooks.yaml."""
        from config import PROJECT_ROOT
        hooks_path = PROJECT_ROOT / "config" / "hooks.yaml"
        if not hooks_path.exists():
            return
        try:
            from tools.hook_loader import load_hooks_from_yaml
            from tools.hooks import get_hook_registry
            registry = get_hook_registry()
            rules = load_hooks_from_yaml(str(hooks_path))
            for rule in rules:
                registry.add_rule(rule)
        except Exception as e:
            logger.warning("[Orchestrator] Failed to load YAML hooks: %s", e)

    # =========================================================================
    # What-If Fork-Try-Discard Pattern
    # =========================================================================

    def _try_what_if(self, aggressive_task: str, conservative_task: str,
                     agent_type: str, iteration: int) -> AgentResult:
        """Fork-try-discard pattern for high-risk decisions.

        1. Fork current engagement state
        2. Try aggressive approach on the fork
        3. If successful with meaningful findings: merge results back to main
        4. If failed: discard fork, try conservative approach on main

        Returns the AgentResult from whichever path succeeds.
        """
        from memory.engagement_fork import EngagementForker

        # Cooldown enforcement
        since_last = iteration - self._what_if_last_iteration
        if since_last < self._what_if_cooldown_iterations:
            logger.warning(
                "[Orchestrator] What-if cooldown active (%d/%d iterations since last). "
                "Falling through to conservative task.",
                since_last, self._what_if_cooldown_iterations,
            )
            self.story.add_event(
                f"WHAT-IF COOLDOWN: Only {since_last} iterations since last what-if "
                f"(need {self._what_if_cooldown_iterations}). Using conservative approach."
            )
            return self.dispatch_agent(agent_type, conservative_task)

        self._what_if_last_iteration = iteration

        # Attempt fork creation (fall through to conservative on failure)
        try:
            forker = EngagementForker(self.engagement_dir)
            fork_point = forker.create_fork(
                description=f"What-if: {aggressive_task[:100]}",
                iteration=iteration,
                metadata={"agent_type": agent_type, "mode": "what_if"},
            )
        except Exception as e:
            logger.error(
                "[Orchestrator] Fork creation failed (%s). Falling through to conservative.",
                e,
            )
            self.story.add_event(
                f"WHAT-IF FORK FAILED: {e}. Using conservative approach."
            )
            return self.dispatch_agent(agent_type, conservative_task)

        self.story.add_event(
            f"WHAT-IF: Forking state to try aggressive approach: "
            f"{aggressive_task[:100]}"
        )

        # Try aggressive approach using a fresh orchestrator on the fork
        try:
            fork_orch = OrchestratorAgent.resume_engagement(
                fork_point.fork_engagement_dir
            )
            aggressive_result = fork_orch.dispatch_agent(agent_type, aggressive_task)
        except Exception as e:
            logger.error("[Orchestrator] Aggressive dispatch on fork failed: %s", e)
            aggressive_result = AgentResult(
                agent_name=agent_type,
                task=aggressive_task,
                success=False,
                summary=f"Fork dispatch error: {e}",
                errors=[str(e)],
            )

        # Evaluate: did the aggressive approach produce meaningful findings?
        if aggressive_result.success and self._has_meaningful_findings(aggressive_result):
            self._merge_fork_results(fork_point, aggressive_result)
            self.story.add_event(
                f"WHAT-IF SUCCESS: Aggressive approach worked on fork. "
                f"Merged additive results back to main state."
            )
            return aggressive_result
        else:
            reason = "failed" if not aggressive_result.success else "no meaningful findings"
            self.story.add_event(
                f"WHAT-IF DISCARD: Aggressive approach {reason}. "
                f"Discarding fork, trying conservative approach on main state."
            )
            return self.dispatch_agent(agent_type, conservative_task)

    @staticmethod
    def _has_meaningful_findings(result: AgentResult) -> bool:
        """Check if an AgentResult contains meaningful new findings."""
        findings = getattr(result, "findings", None) or {}
        summary_text = str(getattr(result, "summary", "") or "").lower()

        cred_refs = findings.get("credential_references", 0) or 0
        vuln_refs = findings.get("vuln_references", 0) or 0
        findings_saved = findings.get("findings_saved", 0) or 0

        if cred_refs > 0 or vuln_refs > 0 or findings_saved > 0:
            return True

        meaningful_keywords = [
            "credential", "password", "shell", "access gained", "root",
            "admin", "flag", "exploit", "reverse shell", "rce", "vulnerability",
            "token", "key", "secret",
        ]
        return any(kw in summary_text for kw in meaningful_keywords)

    def _merge_fork_results(self, fork_point, result: AgentResult) -> None:
        """Merge successful fork results back to main engagement state.

        Only merges ADDITIVE changes: new credentials, new vulns, new access.
        Does NOT merge: removed entries, phase changes, objective status changes.
        """
        import json as _json
        from memory.engagement_fork import ForkPoint

        fork_state_path = os.path.join(
            fork_point.fork_engagement_dir, "STATE.json"
        )
        if not os.path.exists(fork_state_path):
            logger.warning("[Orchestrator] Fork STATE.json not found, skipping merge")
            return

        with open(fork_state_path, "r", encoding="utf-8") as f:
            fork_state = _json.load(f)

        main_state = self.shared_state.read()

        # Merge new credentials (additive only — skip those already in main)
        main_creds = main_state.get("credentials_summary", [])
        main_cred_keys = {
            (c.get("username", ""), c.get("type", ""), c.get("host", ""))
            for c in main_creds if isinstance(c, dict)
        }
        for cred in fork_state.get("credentials_summary", []):
            if isinstance(cred, dict):
                key = (cred.get("username", ""), cred.get("type", ""), cred.get("host", ""))
                if key not in main_cred_keys:
                    self.shared_state.append_to_list("credentials_summary", cred)
                    main_cred_keys.add(key)

        # Merge new vulns (additive only)
        main_vulns = main_state.get("vulns_summary", [])
        main_vuln_keys = {
            (v.get("title", v.get("name", "")), v.get("host", ""))
            for v in main_vulns if isinstance(v, dict)
        }
        for vuln in fork_state.get("vulns_summary", []):
            if isinstance(vuln, dict):
                key = (vuln.get("title", vuln.get("name", "")), vuln.get("host", ""))
                if key not in main_vuln_keys:
                    self.shared_state.append_to_list("vulns_summary", vuln)
                    main_vuln_keys.add(key)

        # Merge new shells (additive only)
        fork_access = fork_state.get("access", {})
        if isinstance(fork_access, dict):
            main_access = main_state.get("access", {}) or {}
            main_shells = main_access.get("shells", []) if isinstance(main_access, dict) else []
            main_shell_keys = {
                (s.get("user", ""), s.get("host", ""), s.get("type", ""))
                for s in main_shells if isinstance(s, dict)
            }
            for shell in fork_access.get("shells", []):
                if isinstance(shell, dict):
                    key = (shell.get("user", ""), shell.get("host", ""), shell.get("type", ""))
                    if key not in main_shell_keys:
                        self.shared_state.append_to_list("access.shells", shell)
                        main_shell_keys.add(key)

        logger.info("[Orchestrator] Merged additive fork results into main state")

    # =========================================================================
    # Agent Dispatch
    # =========================================================================

    def dispatch_agent(self, agent_type: str, task: str) -> AgentResult:
        """Instantiate and run a sub-agent with a focused task.

        Refuses to dispatch if the run has been finalized (except for
        the reporting agent, which is the final allowed action).
        """
        if self._run_finalized and agent_type != "reporting":
            logger.warning(
                "[Orchestrator] BLOCKED post-finalization dispatch: %s "
                "(run already finalized)", agent_type,
            )
            return AgentResult(
                agent_name=agent_type,
                task=task,
                success=False,
                summary="Dispatch blocked: run already finalized.",
                errors=["Run finalized — no further dispatches allowed."],
            )

        # Agent roster restriction: reject agents not in the roster
        if self._agent_roster and agent_type not in self._agent_roster:
            logger.warning(
                "[Orchestrator] BLOCKED dispatch: %s not in agent roster %s",
                agent_type, self._agent_roster,
            )
            return AgentResult(
                agent_name=agent_type,
                task=task,
                success=False,
                summary=f"Agent '{agent_type}' not in experiment roster.",
                errors=[f"Agent '{agent_type}' restricted by experiment configuration."],
            )

        event_bus = get_event_bus()
        agent_class = AGENT_CLASSES.get(agent_type)
        if not agent_class:
            return AgentResult(
                agent_name=agent_type,
                task=task,
                success=False,
                summary=f"Unknown agent type: {agent_type}",
                errors=[f"Unknown agent type: {agent_type}"],
            )

        # Retrieve YAML config for this agent (if registry is active)
        agent_yaml_config = None
        if _agent_registry is not None:
            agent_yaml_config = _agent_registry.get_config(agent_type)

        # Build and persist agent-specific TODO state before dispatch
        state_snapshot = self.shared_state.read()
        agent_name = getattr(agent_class, "agent_name", agent_type)
        todo_data = self._build_subagent_todo_data(agent_type, task, state_snapshot)
        self._set_agent_todo(agent_name, agent_type, todo_data)

        # Enrich task with key context + TODO list
        enriched_task = self._enrich_task(agent_type, task)

        # Resolve model for this agent type (tool_calling tier by default)
        agent_model = resolve_model_for_role(agent_type, self.model_config)
        logger.info(
            f"[Orchestrator] Dispatching {agent_type} (model={agent_model}): {enriched_task[:120]}..."
        )
        event_bus.handoff(
            "Orchestrator",
            getattr(agent_class, "agent_name", agent_type),
            "dispatch",
            engagement_id=self.engagement_id,
            agent_type=agent_type,
            task=enriched_task[:500],
        )

        # Resolve per-agent prompt directory from master profile
        agent_prompt_dir = ""
        if self._prompt_dir:
            agent_prompt_dir = str(self._prompt_dir)
        # Check for per-agent prompt override from master profile
        if hasattr(self, '_effective_prompts') and self._effective_prompts:
            agent_prompt_name = self._effective_prompts.get(agent_type)
            if agent_prompt_name and agent_prompt_name != self._prompt_preset:
                from config import PROJECT_ROOT
                override_dir = PROJECT_ROOT / "engagements" / "presets" / "prompts" / agent_prompt_name
                if override_dir.is_dir():
                    agent_prompt_dir = str(override_dir)

        agent = agent_class(
            engagement_dir=self.engagement_dir,
            engagement_id=self.engagement_id,
            model_override=agent_model,
            prompt_dir=agent_prompt_dir,
            agent_config=agent_yaml_config,
        )

        result = agent.execute(enriched_task)
        self._finalize_agent_todo(agent_name, result)

        # Log critical handoffs (filter out stale blocked entries)
        stale_blockers = ["Blocked:", "blocker:", "generic_command broken"]
        critical_handoffs = [
            h for h in self.handoff_queue.peek()
            if h.priority in ("critical", "high") and h.source_agent == agent.agent_name
            and not any(blocker in h.summary for blocker in stale_blockers)
        ]
        if critical_handoffs:
            self.story.add_event(
                f"Critical intel from {agent_type}: "
                + "; ".join(h.summary for h in critical_handoffs[:5])
            )

        return result

    @staticmethod
    def _enrich_task(agent_type: str, task: str) -> str:
        """Return the task string as-is.

        Context (target, credentials, hosts, services, etc.) is injected by
        the sub-agent's own ``_build_context()`` from shared state — doing it
        here as well caused duplicate and sometimes inconsistent context blocks.
        The TODO block is no longer appended either; agent system prompts
        already define methodology and summary expectations.
        """
        return task

    def _build_subagent_todo_data(self, agent_type: str, task: str, state: dict) -> dict:
        """Build structured TODO data for sub-agent dispatches.

        Keeps only the primary assignment and definition-of-done checklist.
        Role-specific execution goals are already covered by each agent's
        system prompt, and engagement objectives are already factored into
        the orchestrator's task selection — duplicating them here caused
        conflicting / redundant instructions.
        """
        items = [
            {
                "id": "primary_assignment",
                "group": "primary_assignment",
                "text": task,
                "status": "in_progress",
            },
            {
                "id": "dod_save_findings",
                "group": "definition_of_done",
                "text": "Save all confirmed findings immediately (`save_finding`).",
                "status": "in_progress",
            },
            {
                "id": "dod_update_state",
                "group": "definition_of_done",
                "text": "Update shared state/network map with new intel.",
                "status": "in_progress",
            },
            {
                "id": "dod_summary_next_steps",
                "group": "definition_of_done",
                "text": "Return a concise summary with concrete suggested next steps.",
                "status": "in_progress",
            },
        ]

        return {
            "task": task,
            "agent_type": agent_type,
            "status": "in_progress",
            "generated_at": datetime.now().isoformat(),
            "items": items,
            "progress": self._compute_todo_progress(items),
        }

    @staticmethod
    def _compute_todo_progress(items: list[dict]) -> dict:
        """Compute completion stats for dashboard display."""
        actionable_groups = {"primary_assignment", "definition_of_done"}
        actionable = [i for i in items if i.get("group") in actionable_groups]
        total = len(actionable)
        completed = sum(1 for i in actionable if i.get("status") == "completed")
        percent = int((completed / total) * 100) if total else 0
        return {"completed": completed, "total": total, "percent": percent}

    def _set_agent_todo(self, agent_name: str, agent_type: str, todo_data: dict) -> None:
        """Store/replace the latest TODO for a specific agent."""
        try:
            state = self.shared_state.read()
            agent_todos = state.get("agent_todos", {}) or {}
            entry = dict(todo_data)
            entry["agent_name"] = agent_name
            entry["agent_type"] = agent_type
            entry["updated_at"] = datetime.now().isoformat()
            entry["progress"] = self._compute_todo_progress(entry.get("items", []))
            agent_todos[agent_name] = entry
            self.shared_state.update_section("agent_todos", agent_todos)
        except Exception as e:
            logger.debug(f"[Orchestrator] Failed to store agent TODO for {agent_name}: {e}")

    def _finalize_agent_todo(self, agent_name: str, result: AgentResult) -> None:
        """Update TODO completion state after an agent run finishes.

        Each item is evaluated individually against concrete evidence
        (tool usage, result fields) rather than blanket success/failure.
        """
        try:
            state = self.shared_state.read()
            agent_todos = state.get("agent_todos", {}) or {}
            entry = agent_todos.get(agent_name)
            if not isinstance(entry, dict):
                return

            items = entry.get("items", [])
            tool_set = set(result.tools_used or [])
            summary_present = bool((result.summary or "").strip())
            next_steps_present = bool(result.suggested_next_steps)

            for item in items:
                group = item.get("group")
                item_id = item.get("id", "")
                if group == "primary_assignment":
                    item["status"] = "completed" if result.success else "failed"
                elif group == "definition_of_done":
                    if item_id == "dod_save_findings":
                        item["status"] = "completed" if "save_finding" in tool_set else "pending"
                    elif item_id == "dod_update_state":
                        item["status"] = (
                            "completed"
                            if ("update_shared_state" in tool_set or "add_to_network_map" in tool_set)
                            else "pending"
                        )
                    elif item_id == "dod_summary_next_steps":
                        item["status"] = (
                            "completed" if (summary_present and next_steps_present) else "pending"
                        )

            progress = self._compute_todo_progress(items)
            if result.success and progress.get("completed", 0) == progress.get("total", 0):
                todo_status = "completed"
            elif result.success:
                todo_status = "partial"
            else:
                todo_status = "failed"

            entry["items"] = items
            entry["status"] = todo_status
            entry["progress"] = progress
            entry["updated_at"] = datetime.now().isoformat()
            entry["last_result"] = {
                "success": result.success,
                "duration_seconds": round(result.duration_seconds, 1),
                "errors": (result.errors or [])[:3],
                "tools_used": len(result.tools_used or []),
            }
            agent_todos[agent_name] = entry
            self.shared_state.update_section("agent_todos", agent_todos)
        except Exception as e:
            logger.debug(f"[Orchestrator] Failed to finalize agent TODO for {agent_name}: {e}")

    # =========================================================================
    # Objective Management
    # =========================================================================

    # Words too common to count as meaningful overlap for objective matching
    _OBJECTIVE_STOPWORDS = frozenset({
        "the", "a", "an", "and", "or", "of", "to", "in", "on", "for", "by",
        "is", "it", "be", "as", "at", "this", "that", "with", "from", "not",
        "all", "any", "but", "if", "no", "do", "has", "have", "will", "can",
    })

    def _objective_has_required_evidence(self, objective_description: str) -> bool:
        """Prevent high-level compromise objectives from completing on weak evidence."""
        desc = (objective_description or "").lower()
        sensitive_markers = (
            "attack chain",
            "intended vulnerability",
            "initial access",
            "foothold",
            "gain access",
            "authenticated",
            "exploit",
        )
        if not any(marker in desc for marker in sensitive_markers):
            return True

        state = self.shared_state.read()
        auth_access = _ensure_list(state.get("authenticated_access", []))
        creds = _ensure_list(state.get("credentials_summary", []))
        state_vulns = _ensure_list(state.get("vulns_summary", []))

        has_auth = any(isinstance(item, dict) for item in auth_access)
        has_creds = any(isinstance(item, dict) for item in creds)
        has_high_state_vuln = any(
            isinstance(v, dict) and str(v.get("severity", "")).lower() in ("critical", "high")
            for v in state_vulns
        )

        has_db_evidence = False
        try:
            findings = self.db.query_findings(self.engagement_id)
        except Exception:
            findings = []
        for finding in findings:
            severity = str(finding.get("severity", "")).lower()
            if severity in ("critical", "high") or finding.get("confirmed") or finding.get("exploitable"):
                has_db_evidence = True
                break

        return has_auth or has_creds or has_high_state_vuln or has_db_evidence

    def _update_objectives(self, completed_descriptions: list[str]):
        """Mark objectives as completed based on meaningful keyword overlap.

        Requires that at least 50% of the non-stopword tokens in the completion
        description appear in the objective description, OR that the completion
        is a direct substring of the objective. This prevents false matches on
        single common words like 'attack' or 'map'.
        """
        objectives = self.shared_state.read_section("objectives") or []
        updated = False
        for obj in objectives:
            if isinstance(obj, dict) and obj.get("status") == "pending":
                desc = obj.get("description", "").lower()
                for comp in completed_descriptions:
                    comp_lower = comp.lower().strip()
                    matched = False
                    # Direct substring match (strongest signal)
                    if comp_lower in desc or desc in comp_lower:
                        matched = True
                    # Keyword overlap: require majority of meaningful words to match
                    if not matched:
                        comp_words = {
                            w for w in re.findall(r'[a-z]+', comp_lower)
                            if w not in self._OBJECTIVE_STOPWORDS and len(w) > 2
                        }
                        if not comp_words:
                            continue
                        matches = sum(1 for w in comp_words if w in desc)
                        matched = len(comp_words) >= 2 and matches / len(comp_words) >= 0.5
                    if matched:
                        if not self._objective_has_required_evidence(desc):
                            logger.info(
                                "[Orchestrator] Objective completion gated pending stronger evidence: %s",
                                obj.get("description", ""),
                            )
                            break
                        obj["status"] = "completed"
                        updated = True
                        self.story.add_event(f"Objective completed: {obj['description']}")
                        break
        if updated:
            self.shared_state.update_section("objectives", objectives)

    # =========================================================================
    # Legacy Phase Execution (backwards compatibility)
    # =========================================================================

    def execute_phase(self, phase: str) -> dict:
        """
        Execute a single phase by dispatching the appropriate agent.
        Kept for backwards compatibility with the MCP server and dashboard.
        Maps old phase names to agent dispatches.
        """
        state = self.shared_state.read()
        target = (state.get("engagement") or {}).get("target", "unknown")

        phase_to_agent = {
            "recon": ("recon", f"Full port scan, service detection, and enumeration on {target}"),
            "enumeration": ("recon", f"Deep service enumeration and technology fingerprinting on {target}"),
            "vuln_analysis": ("webapp", f"Vulnerability scanning and testing on all discovered web services for {target}"),
            "exploitation": ("attack", f"Exploit confirmed vulnerabilities on {target}. Check shared state for targets."),
            "post_exploit": ("attack", f"Privilege escalation and post-exploitation on {target}. Check shared state for existing access."),
            "reporting": ("reporting", f"Generate penetration test report for {target}"),
        }

        agent_type, task = phase_to_agent.get(phase, ("recon", f"Investigate {target}"))
        self.shared_state.update_section("current_phase", phase)
        self.story.add_event(f"Phase execution (legacy): {phase}")

        result = self.dispatch_agent(agent_type, task)

        completed = self.shared_state.read_section("completed_phases") or []
        if phase not in completed:
            self.shared_state.append_to_list("completed_phases", phase)

        return {
            "success": result.success,
            "phase": phase,
            "agent": agent_type,
            "summary": str(result.summary)[:500] if result.summary else "",
            "tools_used": len(result.tools_used),
            "errors": result.errors,
        }

    def execute_wave(self, tasks: list[dict]) -> list[AgentResult]:
        """Execute a wave of agent tasks in parallel (kept for compatibility)."""
        if len(tasks) == 1:
            return [self.dispatch_agent(tasks[0]["agent"], tasks[0]["task"])]

        results = []
        with ThreadPoolExecutor(max_workers=min(len(tasks), MAX_PARALLEL_AGENTS)) as pool:
            futures = {}
            for task in tasks:
                future = pool.submit(self.dispatch_agent, task["agent"], task["task"])
                futures[future] = task
            for future in as_completed(futures):
                task = futures[future]
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    results.append(AgentResult(
                        agent_name=task["agent"],
                        task=task["task"],
                        success=False,
                        summary=f"Agent failed: {e}",
                        errors=[str(e)],
                    ))
        return results

    # =========================================================================
    # Plan Creation (simplified — generates objectives, not rigid phases)
    # =========================================================================

    def create_plan(self) -> dict:
        """
        Generate an initial plan. For the goal-driven architecture, this
        primarily sets up objectives and an initial recon task. The detailed
        phase-by-phase plan is no longer needed — the orchestrator decides
        dynamically.
        """
        state = self.shared_state.read()
        engagement = (state.get("engagement") or {})
        methodology = engagement.get("methodology", "standard")
        target = engagement.get("target", "unknown")

        objectives = OBJECTIVE_TEMPLATES.get(methodology, OBJECTIVE_TEMPLATES["standard"])

        plan = {
            "methodology": methodology,
            "target": target,
            "objectives": objectives,
            "strategy": "goal-driven iterative (orchestrator decides next action each iteration)",
            "agents": AGENT_TYPES,
            "phases": [
                {
                    "name": "initial_recon",
                    "waves": [
                        {"tasks": [
                            {"agent": "recon", "task": f"Full TCP port scan with version detection on {target}. Identify all services, OS, and hostnames."},
                        ]},
                    ],
                    "quality_gate": "At least 1 host with services discovered",
                },
            ],
        }

        # Store objectives in shared state
        self.shared_state.update_section("objectives", [
            {"description": obj, "status": "pending"} for obj in objectives
        ])

        self._save_plan(plan)
        return plan

    def _save_plan(self, plan: dict):
        """Save the plan to disk."""
        plan_path = Path(self.engagement_dir) / "PLAN.md"
        lines = ["# Attack Plan (Goal-Driven)\n"]
        lines.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        lines.append(f"**Strategy:** {plan.get('strategy', 'iterative')}\n\n")

        lines.append("## Objectives\n")
        for obj in plan.get("objectives", []):
            if isinstance(obj, str):
                lines.append(f"- [ ] {obj}\n")
            elif isinstance(obj, dict):
                status = "[x]" if obj.get("status") == "completed" else "[ ]"
                lines.append(f"- {status} {obj.get('description', '')}\n")
        lines.append("\n")

        lines.append("## Available Agents\n")
        for agent in plan.get("agents", AGENT_TYPES):
            lines.append(f"- {agent}\n")
        lines.append("\n")

        # Write initial recon if present
        for phase in plan.get("phases", []):
            lines.append(f"## Initial Phase: {phase.get('name', '')}\n")
            for wave in phase.get("waves", []):
                for task in wave.get("tasks", []):
                    lines.append(f"- **{task['agent']}**: {task['task']}\n")
        lines.append("\n---\n*Subsequent actions decided dynamically by orchestrator*\n")

        plan_path.write_text("".join(lines))
        json_path = Path(self.engagement_dir) / "plan.json"
        json_path.write_text(json.dumps(plan, indent=2))

    # =========================================================================
    # Utilities
    # =========================================================================

    def _extract_json(self, text: str) -> Optional[dict]:
        """Extract JSON object from LLM response text."""
        import re
        # Try code blocks first
        for pattern in [r"```json\s*\n(.*?)\n```", r"```\s*\n(.*?)\n```"]:
            matches = re.findall(pattern, text, re.DOTALL)
            for match in matches:
                try:
                    return json.loads(match)
                except json.JSONDecodeError:
                    continue
        # Try raw JSON
        brace_start = text.find("{")
        brace_end = text.rfind("}")
        if brace_start >= 0 and brace_end > brace_start:
            try:
                return json.loads(text[brace_start:brace_end + 1])
            except json.JSONDecodeError:
                pass
        # Try whole text
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return None

    def replan(self) -> dict:
        """Compatibility shim — in the goal-driven model, replanning happens
        implicitly every iteration. This returns the current state summary."""
        state = self.shared_state.read()
        return {
            "success": True,
            "note": "Goal-driven model replans every iteration automatically",
            "hosts": len((state.get("hosts") or {})),
            "vulns": len(_ensure_list(state.get("vulns_summary", []))),
            "creds": len(_ensure_list(state.get("credentials_summary", []))),
        }

    def quality_gate(self, phase: str, criteria: str = "") -> dict:
        """Compatibility shim for quality gate checks."""
        state = self.shared_state.read()
        hosts = (state.get("hosts") or {})
        vulns = _ensure_list(state.get("vulns_summary", []))
        creds = _ensure_list(state.get("credentials_summary", []))
        return {
            "passed": True,
            "phase": phase,
            "detail": f"Hosts: {len(hosts)}, Vulns: {len(vulns)}, Creds: {len(creds)}",
        }

    # =========================================================================
    # Query Methods (unchanged interface)
    # =========================================================================

    def get_findings(self, severity: str = "", host: str = "", finding_type: str = "") -> list:
        return self.db.query_findings(
            self.engagement_id,
            severity=severity or None,
            host=host or None,
            finding_type=finding_type or None,
        )

    def get_credentials(self) -> list:
        return self.db.query_credentials(self.engagement_id)

    def get_shared_state(self) -> dict:
        return self.shared_state.read()

    def get_attack_story(self) -> str:
        return self.story.read()

    def get_network_map(self, format: str = "mermaid") -> str:
        if format == "json":
            return json.dumps(self.network_map.export_json(), indent=2)
        elif format == "dot":
            return self.network_map.export_dot()
        return self.network_map.export_mermaid()

    def get_current_plan(self) -> str:
        plan_path = Path(self.engagement_dir) / "PLAN.md"
        if plan_path.exists():
            return plan_path.read_text()
        return "No plan created yet."

    def server_health(self) -> dict:
        from tools.executor import ToolExecutor
        from tools.registry import get_all_binaries
        executor = ToolExecutor()
        binaries = get_all_binaries()
        status = executor.check_tools_status(list(binaries))
        available = sum(1 for v in status.values() if v)
        return {
            "status": "healthy",
            "tools_available": available,
            "tools_total": len(status),
            "tools_missing": [k for k, v in status.items() if not v],
            "engagement_dir": self.engagement_dir if hasattr(self, "engagement_dir") else None,
        }

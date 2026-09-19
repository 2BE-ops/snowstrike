"""
File-locked JSON state management for cross-agent shared state.

Provides thread-safe read/write access to a shared STATE.json file
using file-level locking via the `filelock` library. All agents in
an engagement coordinate through this single source of truth.
"""

import json
import logging
import os
from pathlib import Path
from datetime import datetime, timezone
import json
import os
import threading

from filelock import FileLock

logger = logging.getLogger(__name__)


def _evaluate_pre_state_write(section: str, value, engagement_id: int = 0) -> bool:
    """Evaluate PRE_STATE_WRITE hooks. Returns True if write is allowed."""
    try:
        from tools.hooks import (
            HookAction, HookEvent, HookEventType, get_hook_registry,
        )
        event = HookEvent(
            event_type=HookEventType.PRE_STATE_WRITE,
            tool_name="shared_state",
            tool_args={},
            agent_name="shared_state",
            engagement_id=engagement_id,
            state_section=section,
            state_value=value,
        )
        action, rule, _ = get_hook_registry().evaluate(event)
        if action == HookAction.BLOCK:
            logger.info("[Hook] PRE_STATE_WRITE blocked section '%s' by '%s'",
                        section, rule.name if rule else "?")
            return False
    except Exception as e:
        logger.debug("PRE_STATE_WRITE hook error: %s", e)
    return True


class SharedState:
    """Thread-safe JSON file for cross-agent shared state."""

    _DICT_SECTIONS = (
        "engagement",
        "hosts",
        "technologies",
        "agent_notes",
        "agent_todos",
        "web_apps",
        "tool_quarantines",
        "tool_compatibility",
    )
    _LIST_SECTIONS = (
        "domains",
        "credentials_summary",
        "vulns_summary",
        "attack_surfaces",
        "completed_phases",
        "objectives",
        "agent_blockers",
        "authenticated_access",
        "scope_violations",
    )
    _CORE_NONNULL_SECTIONS = (
        "hosts",
        "technologies",
        "attack_surfaces",
    )

    # Sections that require target-fidelity validation before writes.
    _SCOPE_VALIDATED_LIST_SECTIONS = (
        "domains",
        "attack_surfaces",
        "vulns_summary",
    )

    def __init__(self, engagement_dir: str):
        self._dir = Path(engagement_dir)
        self._state_path = self._dir / "STATE.json"
        self._lock_path = self._dir / "STATE.json.lock"
        self._lock = FileLock(str(self._lock_path), timeout=30)
        self._scope_validator = None  # Lazily initialized from engagement state

    # ------------------------------------------------------------------
    # Initialization
    # ------------------------------------------------------------------

    def initialize(self, target: str, scope: list, out_of_scope: list, methodology: str):
        """Create initial state for a new engagement.

        Overwrites any existing STATE.json with a clean default structure.
        """
        self._dir.mkdir(parents=True, exist_ok=True)

        state = {
            "engagement": {
                "target": target,
                "scope": list(scope),
                "out_of_scope": list(out_of_scope),
                "methodology": methodology,
                "phase": "init",
                "started_at": datetime.now(timezone.utc).isoformat(),
            },
            "hosts": {},                # ip -> {hostname, os, services: [port_info...]}
            "domains": [],
            "technologies": {},         # domain/ip -> [tech_list]
            "credentials_summary": [],  # [{username, type, source}] (no passwords!)
            "vulns_summary": [],        # [{id, title, severity, host}]
            "attack_surfaces": [],      # ["webapp:80", "ssh:22", ...]
            "web_apps": {},             # host/url -> {product, version, auth, endpoints, ...}
            "authenticated_access": [], # [{host, url, access_level, username, product, ...}]
            "current_phase": "init",
            "completed_phases": [],
            "agent_notes": {},          # agent_name -> last summary
            "agent_todos": {},          # agent_name -> latest TODO/progress snapshot
            "agent_blockers": [],       # [{agent, reason, category, timestamp, next_action}]
            "tool_quarantines": {},     # tool_name -> {reason, source_agent, timestamp}
            "tool_compatibility": {},   # tool_name -> {compatible: bool, reason: str, ...}
        }

        with self._lock:
            self._write(state)

        return state

    # ------------------------------------------------------------------
    # Read helpers
    # ------------------------------------------------------------------

    def read(self) -> dict:
        """Read the full state dictionary."""
        with self._lock:
            return self._load()

    def read_section(self, key: str):
        """Read a single top-level section.

        Raises KeyError if the section does not exist.
        """
        with self._lock:
            state = self._load()
        if key not in state:
            raise KeyError(f"Section '{key}' not found in shared state")
        return state[key]

    # ------------------------------------------------------------------
    # Write helpers
    # ------------------------------------------------------------------

    def update_section(self, key: str, value):
        """Overwrite a top-level section (file-locked)."""
        if not _evaluate_pre_state_write(key, value):
            return "[HOOK BLOCKED] Write to section '{}' blocked by hook".format(key)
        with self._lock:
            state = self._load()
            state[key] = value
            self._write(state)

    def append_to_list(self, key: str, item):
        """Append *item* to a list section (file-locked, deduplicates).

        Deduplication compares JSON-serialised representations so that
        dicts with the same content are treated as equal regardless of
        insertion order of keys.

        Items targeting scope-validated sections are checked for target
        fidelity before persistence.
        """
        if not _evaluate_pre_state_write(key, item):
            return  # Blocked by hook
        if key in self._SCOPE_VALIDATED_LIST_SECTIONS:
            if not self._validate_item_for_section(key, item):
                return  # Silently drop out-of-scope entries
        with self._lock:
            state = self._load()
            section = state.get(key) or []
            if not isinstance(section, list):
                section = []  # Auto-fix corrupted state: reset to empty list

            # Deduplicate using canonical JSON strings
            item_canonical = json.dumps(item, sort_keys=True)
            existing = {json.dumps(i, sort_keys=True) for i in section}
            if item_canonical not in existing:
                section.append(item)

            state[key] = section
            self._write(state)

    def _get_scope_validator(self):
        """Lazily initialize and return the ScopeValidator from engagement state."""
        if self._scope_validator is not None:
            return self._scope_validator
        try:
            from memory.scope_validator import ScopeValidator
            state = self._load() if self._state_path.exists() else {}
            engagement = state.get("engagement", {})
            if not isinstance(engagement, dict):
                engagement = {}
            target = engagement.get("target", "")
            scope = engagement.get("scope", [])
            oos = engagement.get("out_of_scope", [])
            if target:
                self._scope_validator = ScopeValidator(target, scope, oos)
            else:
                return None
        except Exception as e:
            logger.debug("Failed to initialize ScopeValidator: %s", e)
            return None
        return self._scope_validator

    def _validate_item_for_section(self, key: str, item) -> bool:
        """Check if an item passes target-fidelity validation for the given section.

        Returns True if the item should be persisted, False if it should be rejected.
        """
        validator = self._get_scope_validator()
        if validator is None:
            return True  # No validator = no filtering

        if key == "domains":
            if not validator.validate_domain_entry(item):
                logger.info("Scope filter rejected domain entry: %s", item)
                return False
        elif key == "attack_surfaces":
            if not validator.validate_attack_surface(item):
                logger.info("Scope filter rejected attack_surface: %s", item)
                return False
        elif key == "vulns_summary":
            if not validator.validate_vuln_entry(item):
                logger.info("Scope filter rejected vuln (OOB host): %s",
                            item.get("host", "") if isinstance(item, dict) else item)
                return False
        return True

    def update_host(self, ip: str, hostname: str = None, os: str = None, services: list = None):
        """Update or add a host in the hosts dict (file-locked).

        Merges provided fields with any existing record for *ip*.
        Services are merged by (port, proto) key, with newer entries
        overwriting older ones.
        """
        if not ip or not ip.strip():
            return  # Skip empty IPs
        # Target-fidelity check: reject hosts not in scope
        validator = self._get_scope_validator()
        if validator and not validator.validate_host_ip(ip.strip()):
            logger.info("Scope filter rejected host IP: %s", ip)
            return
        with self._lock:
            state = self._load()
            hosts = state.get("hosts", {})

            existing = hosts.get(ip, {
                "hostname": None,
                "os": None,
                "services": [],
            })

            if hostname is not None:
                existing["hostname"] = hostname
            if os is not None:
                existing["os"] = os
            if services is not None:
                # Merge services by (port, proto) key
                svc_map = {}
                for svc in existing.get("services", []):
                    key = (svc.get("port"), svc.get("proto", "tcp"))
                    svc_map[key] = svc
                for svc in services:
                    key = (svc.get("port"), svc.get("proto", "tcp"))
                    svc_map[key] = svc
                existing["services"] = list(svc_map.values())

            hosts[ip] = existing
            state["hosts"] = hosts
            self._write(state)

    # ------------------------------------------------------------------
    # Internal I/O
    # ------------------------------------------------------------------

    def _load(self) -> dict:
        """Load and normalize STATE.json. Returns normalized dict."""
        if not self._state_path.exists():
            return self._normalize_state({})
        with open(self._state_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return self._normalize_state(data)

    def _normalize_state(self, state: dict) -> dict:
        """Normalize state schema so prompt-builders always receive safe shapes."""
        if not isinstance(state, dict):
            state = {}

        # Ensure dict-backed sections are always dicts
        for key in self._DICT_SECTIONS:
            val = state.get(key)
            if not isinstance(val, dict):
                state[key] = {}

        # Ensure list-backed sections are always lists
        for key in self._LIST_SECTIONS:
            val = state.get(key)
            if not isinstance(val, list):
                state[key] = []

        # Keep current_phase aligned to known engagement/current phase fallback
        phase = state.get("current_phase")
        if not isinstance(phase, str) or not phase.strip():
            state["current_phase"] = (
                state.get("engagement", {}).get("phase")
                if isinstance(state.get("engagement"), dict)
                else "init"
            ) or "init"

        # Enforce non-null core collections regardless of external writes.
        if not isinstance(state.get("hosts"), dict):
            state["hosts"] = {}
        if not isinstance(state.get("technologies"), dict):
            state["technologies"] = {}
        if not isinstance(state.get("attack_surfaces"), list):
            state["attack_surfaces"] = []

        return state

    def _write(self, state: dict):
        """Write *state* to STATE.json atomically (write-then-rename)."""
        state = self._normalize_state(state)
        tmp_path = self._state_path.with_suffix(".tmp")
        with open(tmp_path, "w", encoding="utf-8") as fh:
            json.dump(state, fh, indent=2, default=str)
            fh.write("\n")
        os.replace(str(tmp_path), str(self._state_path))


def create_shared_state(engagement_dir: str, **kwargs) -> "SharedState":
    """Create the SharedState backend. Currently the file-based implementation."""
    return SharedState(engagement_dir, **kwargs)

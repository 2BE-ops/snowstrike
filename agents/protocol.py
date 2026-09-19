"""
SnowStrike AI v7.0 - Agent-to-Agent Communication Protocol

Structured handoff protocol for inter-agent communication within the
multi-agent pentesting framework. Agents produce findings, credentials,
access tokens, escalation paths, and intelligence that other agents
consume. The orchestrator routes handoffs between agents based on
capability declarations and priority.

Thread-safe, file-lock-backed persistence ensures handoffs survive
agent restarts and concurrent access from multiple agent processes.
"""

import json
import hashlib
import logging
import os
import threading
from dataclasses import dataclass, field, asdict, fields
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional, Union

from filelock import FileLock

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Handoff types and priority levels
# ---------------------------------------------------------------------------

HANDOFF_TYPES = frozenset({
    "finding",
    "credential",
    "access_obtained",
    "escalation_path",
    "attack_surface",
    "intelligence",
    "request",
    "flow_request",
})

PRIORITY_LEVELS = ("critical", "high", "medium", "low")

PRIORITY_ORDER = {level: idx for idx, level in enumerate(PRIORITY_LEVELS)}


# ---------------------------------------------------------------------------
# Core data structures
# ---------------------------------------------------------------------------

@dataclass
class AgentHandoff:
    """
    A structured handoff message passed between agents.

    Handoffs are the primary unit of inter-agent communication. When an
    agent discovers something actionable (a credential, an open port, an
    escalation path), it creates a handoff addressed to the agent best
    suited to act on it -- or to ``"orchestrator"`` if routing should be
    decided centrally.

    Attributes:
        source_agent:    Agent type that produced this handoff.
        target_agent:    Agent type that should receive it, or
                         ``"orchestrator"`` for central routing.
        handoff_type:    Semantic category -- one of :data:`HANDOFF_TYPES`.
        priority:        Urgency -- one of :data:`PRIORITY_LEVELS`.
        summary:         Human-readable one-liner describing the handoff.
        data:            Structured payload (credentials, hosts, paths, etc.).
        suggested_action: Free-text recommendation for the receiver.
        confidence:      Confidence score in the range ``[0.0, 1.0]``.
        timestamp:       ISO-8601 UTC timestamp (auto-populated on creation).
    """

    source_agent: str
    target_agent: str
    handoff_type: str
    priority: str
    summary: str
    data: dict = field(default_factory=dict)
    suggested_action: str = ""
    confidence: float = 1.0
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def __post_init__(self) -> None:
        if self.handoff_type not in HANDOFF_TYPES:
            raise ValueError(
                f"Invalid handoff_type {self.handoff_type!r}. "
                f"Must be one of {sorted(HANDOFF_TYPES)}"
            )
        if self.priority not in PRIORITY_ORDER:
            raise ValueError(
                f"Invalid priority {self.priority!r}. "
                f"Must be one of {list(PRIORITY_LEVELS)}"
            )
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(
                f"Confidence must be between 0.0 and 1.0, got {self.confidence}"
            )

    # -- Serialisation helpers ------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        """Return a plain dict suitable for JSON serialisation."""
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "AgentHandoff":
        """Reconstruct a handoff from a plain dict."""
        allowed = {f.name for f in fields(cls)}
        cleaned = {k: v for k, v in d.items() if k in allowed}
        return cls(**cleaned)

    # -- Sorting support ------------------------------------------------------

    @property
    def priority_rank(self) -> int:
        """Lower number == higher priority (critical=0, low=3)."""
        return PRIORITY_ORDER[self.priority]


@dataclass
class AgentCapability:
    """
    Declares what an agent can do, what it needs, and what it produces.

    The orchestrator uses capability declarations to decide which agent
    should handle a given handoff and whether the required pre-conditions
    (``requires``) have been satisfied by other agents' ``produces``.

    Attributes:
        agent_type:     Canonical name of the agent (e.g. ``"recon"``).
        capabilities:   Actions the agent can perform
                        (e.g. ``["port_scanning", "service_fingerprinting"]``).
        requires:       Intelligence the agent needs before it can be
                        effective (e.g. ``["target_hosts"]``).
        produces:       Intelligence the agent generates
                        (e.g. ``["open_ports", "service_versions"]``).
        max_concurrent: Maximum simultaneous instances of this agent.
    """

    agent_type: str
    capabilities: list[str] = field(default_factory=list)
    requires: list[str] = field(default_factory=list)
    produces: list[str] = field(default_factory=list)
    max_concurrent: int = 1


# ---------------------------------------------------------------------------
# Capability registry for SnowStrike sub-agents (11 specialists)
# ---------------------------------------------------------------------------

AGENT_CAPABILITIES: dict[str, AgentCapability] = {
    "recon": AgentCapability(
        agent_type="recon",
        capabilities=[
            "port_scanning",
            "service_fingerprinting",
            "dns_enumeration",
            "subdomain_discovery",
            "network_mapping",
            "os_detection",
            "smb_enumeration",
            "snmp_enumeration",
            "ssl_analysis",
            "waf_detection",
            "ad_enumeration",
            "netbios_scanning",
            "arp_discovery",
            "scan_chaining",
            "auto_handoff_generation",
        ],
        requires=["target_hosts"],
        produces=[
            "open_ports",
            "service_versions",
            "hostnames",
            "subdomains",
            "network_map",
            "os_info",
            "smb_shares",
            "ssl_certificates",
            "ad_objects",
            "web_service_handoffs",
            "auth_service_handoffs",
            "ad_intelligence",
            "ssl_vulnerability_alerts",
        ],
        max_concurrent=3,
    ),
    "webapp": AgentCapability(
        agent_type="webapp",
        capabilities=[
            "directory_bruteforce",
            "content_discovery",
            "web_crawling",
            "url_discovery",
            "cms_scanning",
            "vulnerability_scanning",
            "parameter_discovery",
            "url_processing",
            "visual_recon",
            "technology_detection",
            "sqli_testing",
            "nosqli_testing",
            "xss_testing",
            "command_injection",
            "ssti_testing",
            "web_fuzzing",
            "jwt_testing",
            "graphql_testing",
            "proxy_scanning",
            "api_fuzzing",
        ],
        requires=["target_hosts", "open_ports", "web_services"],
        produces=[
            "accessible_endpoints",
            "discovered_parameters",
            "web_technologies",
            "cms_info",
            "url_inventory",
            "web_vulnerabilities",
            "injection_points",
            "confirmed_vulnerabilities",
            "data_extraction",
            "auth_bypass",
            "rce_evidence",
        ],
        max_concurrent=2,
    ),
    "browser": AgentCapability(
        agent_type="browser",
        capabilities=[
            "headless_navigation",
            "screenshot_capture",
            "dom_analysis",
            "network_monitoring",
            "security_header_analysis",
            "form_detection",
            "cookie_analysis",
            "javascript_analysis",
            "multi_page_crawling",
            "api_endpoint_discovery",
            "csp_analysis",
            "cors_analysis",
            "mixed_content_detection",
            "supply_chain_analysis",
        ],
        requires=["target_hosts", "web_services"],
        produces=[
            "screenshots",
            "dom_structures",
            "network_traffic",
            "security_headers",
            "security_header_findings",
            "form_inventory",
            "cookie_findings",
            "api_endpoints",
            "javascript_frameworks",
            "csp_weaknesses",
            "cors_misconfigurations",
        ],
        max_concurrent=1,
    ),
    "attack": AgentCapability(
        agent_type="attack",
        capabilities=[
            "exploit_selection",
            "exploit_execution",
            "payload_generation",
            "cve_exploitation",
            "shell_upgrade",
            "linux_privesc",
            "windows_privesc",
            "ad_attack_paths",
            "remote_access",
            "lateral_movement",
            "network_exploitation",
            "network_brute_force",
            "password_cracking",
            "hash_identification",
            "credential_spraying",
            "rainbow_table_attack",
            "hash_lookup",
            "protocol_brute_force",
            "credential_reuse_testing",
            "auto_credential_extraction",
            "privesc_detection",
        ],
        requires=[],
        produces=[
            "shell_access",
            "reverse_shells",
            "footholds",
            "exploitation_evidence",
            "root_access",
            "elevated_credentials",
            "escalation_paths",
            "sensitive_files",
            "valid_credentials",
            "cracked_passwords",
            "hash_types",
            "credential_pairs",
            "access_obtained_handoffs",
            "lateral_movement_intel",
        ],
        max_concurrent=2,
    ),
    "binary": AgentCapability(
        agent_type="binary",
        capabilities=[
            "binary_analysis",
            "reverse_engineering",
            "debugging",
            "rop_chain_generation",
            "format_string_exploitation",
            "heap_exploitation",
            "shellcode_generation",
            "firmware_analysis",
            "symbolic_execution",
            "exploit_development",
            "binary_patching",
            "packing_unpacking",
        ],
        requires=["binary_targets"],
        produces=[
            "exploitable_binaries",
            "custom_exploits",
            "shellcode",
            "binary_vulnerabilities",
            "rop_chains",
            "firmware_secrets",
        ],
        max_concurrent=1,
    ),
    "cloud": AgentCapability(
        agent_type="cloud",
        capabilities=[
            "aws_audit",
            "azure_audit",
            "gcp_audit",
            "iam_analysis",
            "container_scanning",
            "k8s_assessment",
            "iac_scanning",
            "runtime_monitoring",
            "service_mesh_analysis",
            "policy_evaluation",
            "cloud_exploitation",
        ],
        requires=["cloud_credentials", "cloud_endpoints"],
        produces=[
            "cloud_misconfigurations",
            "iam_weaknesses",
            "exposed_storage",
            "cloud_credentials",
            "container_vulnerabilities",
            "k8s_weaknesses",
            "iac_violations",
        ],
        max_concurrent=1,
    ),
    "forensics": AgentCapability(
        agent_type="forensics",
        capabilities=[
            "memory_forensics",
            "file_carving",
            "steganography_detection",
            "steganography_extraction",
            "metadata_extraction",
            "disk_forensics",
            "cryptanalysis",
            "cipher_identification",
            "frequency_analysis",
            "rsa_attacks",
            "hash_cracking",
        ],
        requires=["forensic_targets"],
        produces=[
            "recovered_files",
            "hidden_data",
            "memory_artifacts",
            "decrypted_data",
            "metadata",
            "forensic_timeline",
            "cryptographic_keys",
        ],
        max_concurrent=1,
    ),
    "osint": AgentCapability(
        agent_type="osint",
        capabilities=[
            "email_harvesting",
            "domain_intelligence",
            "employee_enumeration",
            "credential_leak_search",
            "technology_fingerprinting",
            "social_engineering_recon",
            "username_investigation",
            "github_dorking",
            "breach_analysis",
            "subdomain_takeover",
            "people_search",
        ],
        requires=["target_domains", "target_organization"],
        produces=[
            "email_addresses",
            "employee_names",
            "leaked_credentials",
            "technology_stack",
            "social_profiles",
            "document_metadata",
            "takeover_candidates",
        ],
        max_concurrent=1,
    ),
    "reporting": AgentCapability(
        agent_type="reporting",
        capabilities=[
            "finding_compilation",
            "risk_scoring",
            "executive_summary",
            "technical_report",
            "remediation_guidance",
            "evidence_collection",
            "attack_narrative",
            "compliance_mapping",
        ],
        requires=["findings", "exploitation_evidence", "attack_story"],
        produces=[
            "pentest_report",
            "executive_summary",
            "remediation_plan",
            "risk_matrix",
        ],
        max_concurrent=1,
    ),
}


# ---------------------------------------------------------------------------
# Thread-safe, file-backed handoff queue
# ---------------------------------------------------------------------------

class HandoffQueue:
    """
    Thread-safe, file-lock-backed queue for inter-agent handoffs.

    Each engagement gets its own queue persisted as a JSON file inside
    the engagement directory.  A :class:`filelock.FileLock` ensures
    mutual exclusion when multiple agent processes read/write
    concurrently, and a :class:`threading.Lock` guards in-process
    access from multiple threads.

    Usage::

        q = HandoffQueue(engagement_dir="/engagements/abc123")
        q.post(AgentHandoff(
            source_agent="recon",
            target_agent="webapp",
            handoff_type="attack_surface",
            priority="high",
            summary="Found web server on port 8080",
            data={"host": "10.10.10.5", "port": 8080, "service": "Apache 2.4.49"},
            suggested_action="Run directory bruteforce and vulnerability scan",
        ))

        # Later, the webapp agent drains its queue:
        for h in q.get_for_agent("webapp"):
            ...
    """

    QUEUE_FILENAME = "handoff_queue.json"
    LOCK_FILENAME = "handoff_queue.json.lock"
    MIN_QUEUE_CONFIDENCE = 0.55

    def __init__(self, engagement_dir: str | Path) -> None:
        self._dir = Path(engagement_dir)
        self._dir.mkdir(parents=True, exist_ok=True)
        self._queue_path = self._dir / self.QUEUE_FILENAME
        self._lock_path = self._dir / self.LOCK_FILENAME
        self._file_lock = FileLock(str(self._lock_path), timeout=10)
        self._thread_lock = threading.Lock()
        self._scope_validator = None  # Lazily initialized

    # -- Public API -----------------------------------------------------------

    def _get_scope_validator(self):
        """Lazily initialize scope validator from engagement STATE.json."""
        if self._scope_validator is not None:
            return self._scope_validator
        try:
            from memory.scope_validator import ScopeValidator
            import json as _json
            state_path = self._dir / "STATE.json"
            if not state_path.exists():
                return None
            with open(state_path, "r", encoding="utf-8") as f:
                state = _json.load(f)
            engagement = state.get("engagement", {})
            if not isinstance(engagement, dict):
                return None
            target = engagement.get("target", "")
            scope = engagement.get("scope", [])
            oos = engagement.get("out_of_scope", [])
            if target:
                self._scope_validator = ScopeValidator(target, scope, oos)
        except Exception:
            pass
        return self._scope_validator

    def post(self, handoff: AgentHandoff) -> None:
        """
        Append a handoff to the persistent queue.

        Thread-safe and process-safe via dual locking.
        Validates target fidelity before persisting.

        Args:
            handoff: The handoff message to enqueue.
        """
        if handoff.confidence < self.MIN_QUEUE_CONFIDENCE:
            logger.info(
                "Handoff dropped by confidence threshold (%.2f < %.2f): %s",
                handoff.confidence,
                self.MIN_QUEUE_CONFIDENCE,
                handoff.summary,
            )
            return

        # Target-fidelity check: reject handoffs referencing out-of-scope targets
        validator = self._get_scope_validator()
        if validator and handoff.handoff_type in ("attack_surface", "finding", "intelligence"):
            if not validator.validate_handoff_data(handoff.data):
                logger.info(
                    "Handoff dropped by scope filter (OOB target in data): %s -> %s: %s",
                    handoff.source_agent,
                    handoff.target_agent,
                    handoff.summary,
                )
                return

        dedupe_key = self._handoff_dedupe_key(handoff)
        with self._thread_lock, self._file_lock:
            queue = self._read_raw()
            if any(self._entry_dedupe_key(entry) == dedupe_key for entry in queue):
                logger.info("Handoff deduped (key=%s): %s", dedupe_key, handoff.summary)
                return
            queue.append(handoff.to_dict())
            self._write_raw(queue)
        logger.info(
            "Handoff posted: %s -> %s [%s/%s] %s",
            handoff.source_agent,
            handoff.target_agent,
            handoff.handoff_type,
            handoff.priority,
            handoff.summary,
        )

    @staticmethod
    def _entry_dedupe_key(entry: dict[str, Any]) -> str:
        """Build dedupe key from a raw queue entry dict."""
        data = entry.get("data", {}) if isinstance(entry.get("data"), dict) else {}
        title = str(data.get("title") or entry.get("summary") or "").strip().lower()
        host = str(data.get("host") or data.get("target") or "").strip().lower()
        evidence = str(data.get("evidence_hash") or data.get("evidence") or "").strip()
        evidence_hash = hashlib.sha1(evidence.encode("utf-8")).hexdigest()[:12] if evidence else "noevidence"
        return f"{title}|{host}|{evidence_hash}"

    def _handoff_dedupe_key(self, handoff: AgentHandoff) -> str:
        """Build dedupe key from a typed handoff."""
        return self._entry_dedupe_key(handoff.to_dict())

    @staticmethod
    def _sorted_handoffs(raw_entries: list[dict]) -> list[AgentHandoff]:
        """Deserialize and sort handoff entries by priority (highest first)."""
        handoffs = [AgentHandoff.from_dict(d) for d in raw_entries]
        handoffs.sort(key=lambda h: h.priority_rank)
        return handoffs

    def drain(self) -> list[AgentHandoff]:
        """
        Remove and return *all* pending handoffs, sorted by priority.

        Returns:
            A list of :class:`AgentHandoff` instances, highest priority first.
        """
        with self._thread_lock, self._file_lock:
            queue = self._read_raw()
            self._write_raw([])
        return self._sorted_handoffs(queue)

    def get_for_agent(self, agent_type: str) -> list[AgentHandoff]:
        """
        Remove and return handoffs targeting *agent_type* or ``"orchestrator"``.

        Handoffs addressed to other agents are left in the queue.

        Args:
            agent_type: The canonical agent type name (e.g. ``"webapp"``).

        Returns:
            Matching handoffs sorted by priority (highest first).
        """
        matched: list[dict[str, Any]] = []
        remaining: list[dict[str, Any]] = []

        with self._thread_lock, self._file_lock:
            for entry in self._read_raw():
                if entry.get("target_agent") == agent_type:
                    matched.append(entry)
                else:
                    remaining.append(entry)
            self._write_raw(remaining)

        return self._sorted_handoffs(matched)

    def peek(self) -> list[AgentHandoff]:
        """
        Return all pending handoffs *without* removing them.

        Returns:
            All queued handoffs sorted by priority.
        """
        with self._thread_lock, self._file_lock:
            queue = self._read_raw()
        return self._sorted_handoffs(queue)

    def size(self) -> int:
        """Return the number of pending handoffs."""
        with self._thread_lock, self._file_lock:
            return len(self._read_raw())

    # -- Persistence internals ------------------------------------------------

    def _read_raw(self) -> list[dict[str, Any]]:
        """Read the queue file. Returns an empty list if missing or corrupt."""
        if not self._queue_path.exists():
            return []
        try:
            text = self._queue_path.read_text(encoding="utf-8")
            data = json.loads(text)
            if isinstance(data, list):
                return data
            logger.warning("Queue file contained non-list JSON; resetting.")
            return []
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Failed to read handoff queue: %s", exc)
            return []

    def _write_raw(self, queue: list[dict[str, Any]]) -> None:
        """Atomically write the queue list to disk."""
        tmp_path = self._queue_path.with_suffix(".tmp")
        try:
            tmp_path.write_text(
                json.dumps(queue, indent=2, default=str),
                encoding="utf-8",
            )
            tmp_path.replace(self._queue_path)
        except OSError as exc:
            logger.error("Failed to write handoff queue: %s", exc)
            raise


# ---------------------------------------------------------------------------
# Context formatting helper
# ---------------------------------------------------------------------------

_PRIORITY_ICON = {
    "critical": "[!!!]",
    "high": "[!!]",
    "medium": "[!]",
    "low": "[.]",
}


def format_handoff_for_context(handoffs: list[AgentHandoff]) -> str:
    """
    Format a list of handoffs into a concise text block for injection
    into an agent's system prompt or context window.

    The output is designed to be LLM-readable: each handoff is rendered
    as a clearly delimited block with priority indicator, source, type,
    summary, key data fields, and suggested action.

    Args:
        handoffs: Handoffs to format (typically from
                  :meth:`HandoffQueue.get_for_agent`).

    Returns:
        A formatted multi-line string, or an empty string if *handoffs*
        is empty.
    """
    if not handoffs:
        return ""

    # Sort by priority before rendering
    sorted_handoffs = sorted(handoffs, key=lambda h: h.priority_rank)

    lines: list[str] = []
    lines.append(f"=== INTEL FROM OTHER AGENTS ({len(sorted_handoffs)} items) ===")
    lines.append("")

    for idx, h in enumerate(sorted_handoffs, 1):
        icon = _PRIORITY_ICON.get(h.priority, "[?]")
        lines.append(f"--- Handoff #{idx} {icon} {h.priority.upper()} ---")
        lines.append(f"  From:       {h.source_agent}")
        lines.append(f"  Type:       {h.handoff_type}")
        lines.append(f"  Confidence: {h.confidence:.0%}")
        lines.append(f"  Summary:    {h.summary}")

        if h.data:
            lines.append("  Data:")
            for key, value in h.data.items():
                # Truncate long values to keep context window manageable
                val_str = str(value)
                if len(val_str) > 200:
                    val_str = val_str[:197] + "..."
                lines.append(f"    {key}: {val_str}")

        if h.suggested_action:
            lines.append(f"  Action:     {h.suggested_action}")

        lines.append("")

    lines.append("=== END INTEL ===")
    return "\n".join(lines)


def create_handoff_queue(engagement_dir: str, **kwargs) -> "HandoffQueue":
    """Create the HandoffQueue backend. Currently the file-based implementation."""
    return HandoffQueue(engagement_dir, **kwargs)

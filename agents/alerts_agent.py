"""
SnowStrike AI v7.0 - Alerts Agent

Lightweight read-only monitoring agent powered by the compaction tier (Kimi/Haiku).
Scans shared state after each orchestrator iteration and emits structured alerts.
No tools, no tool-calling — just reads state and returns alerts.
"""

import json
import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from agents.model_client import create_model_client, resolve_model_for_role
from memory.shared_state import SharedState

logger = logging.getLogger(__name__)


@dataclass
class Alert:
    """A single alert emitted by the alerts agent."""
    severity: str       # critical, high, medium, low, info
    title: str          # Short headline
    detail: str         # Explanation
    category: str       # vuln, cred, access, agent, budget, scope
    timestamp: str = ""

    def to_dict(self) -> dict:
        return {
            "severity": self.severity,
            "title": self.title,
            "detail": self.detail,
            "category": self.category,
            "timestamp": self.timestamp or datetime.now(timezone.utc).isoformat(),
        }


# Prompt template for the alerts agent
ALERTS_SYSTEM_PROMPT = """You are the SnowStrike Alerts Monitor. You analyze penetration test state data and surface important events that the operator should know about.

You will receive the current engagement state as a snapshot. Compare it against what would be expected at this stage and emit alerts for anything noteworthy.

Alert categories:
- vuln: New critical/high vulnerabilities discovered
- cred: Credentials found, cracked, or validated
- access: Shell obtained, privilege escalation achieved, new access level
- agent: Agent failures, repeated failures on same target, agent stuck in a loop
- budget: Budget burn rate, iterations remaining low
- scope: Potential scope creep, out-of-scope activity

Severity levels: critical, high, medium, low, info

IMPORTANT RULES:
- Only emit alerts for genuinely important events. Do NOT alert on routine activity.
- Be concise. Title should be under 60 characters. Detail under 150 characters.
- If nothing noteworthy happened, return an empty alerts array.
- Never repeat alerts for things that were already reported in previous_alerts.

Return ONLY a JSON object:
{
  "alerts": [
    {"severity": "critical", "title": "Root shell obtained", "detail": "Attack agent achieved root via CVE-2021-4034 on 10.10.10.5", "category": "access"},
    ...
  ]
}

If nothing to alert on, return: {"alerts": []}"""


class AlertsAgent:
    """
    Read-only monitoring agent on the compaction tier.

    Called after each orchestrator iteration. Reads shared state,
    compares against previous state, and emits structured alerts.
    Cheap to run — single LLM call, no tools, small context.
    """

    def __init__(self, engagement_dir: str, model_config: dict = None, engagement_id: int = 1):
        self.engagement_dir = engagement_dir
        self.engagement_id = engagement_id
        self.shared_state = SharedState(engagement_dir)
        self.model_config = model_config or {}

        # Resolve to compaction tier (Kimi/Haiku)
        self.model_id = resolve_model_for_role("compaction", self.model_config)
        self.client = create_model_client(self.model_id)

        # Cost tracking
        from memory.cost_tracker import CostTracker
        db_path = os.path.join(engagement_dir, "snowstrike.db")
        self.cost_tracker = CostTracker(db_path)

        # Alert history file (for deduplication)
        self.alerts_file = os.path.join(engagement_dir, "alerts.json")
        self.previous_alerts: list[dict] = self._load_alerts()

    def _load_alerts(self) -> list[dict]:
        """Load previously emitted alerts."""
        if os.path.exists(self.alerts_file):
            try:
                with open(self.alerts_file) as f:
                    data = json.load(f)
                return data.get("alerts", [])
            except (json.JSONDecodeError, IOError):
                return []
        return []

    def _save_alerts(self, alerts: list[dict]):
        """Persist alerts to disk."""
        try:
            with open(self.alerts_file, "w") as f:
                json.dump({"alerts": alerts}, f, indent=2)
        except IOError as e:
            logger.warning(f"[AlertsAgent] Failed to save alerts: {e}")

    def check(self, iteration: int = 0, last_result: dict = None) -> list[Alert]:
        """
        Run a single alert check against current state.

        Args:
            iteration: Current orchestrator iteration number
            last_result: Summary of the last agent dispatch result

        Returns:
            List of Alert objects (may be empty if nothing noteworthy)
        """
        state = self.shared_state.read()

        # Build a compact state snapshot for the model
        snapshot = self._build_snapshot(state, iteration, last_result)

        # Include recent alert titles so we don't repeat them
        recent_titles = [a.get("title", "") for a in self.previous_alerts[-20:]]

        prompt = f"""Current engagement state snapshot:

{snapshot}

Previously reported alerts (do NOT repeat these):
{json.dumps(recent_titles) if recent_titles else "None"}

Analyze the state and emit any new alerts."""

        try:
            response = self.client.messages.create(
                model=self.model_id,
                max_tokens=512,
                system=ALERTS_SYSTEM_PROMPT,
                messages=[{"role": "user", "content": prompt}],
            )

            # Record cost for this API call
            usage = getattr(response, "usage", None)
            if usage:
                self.cost_tracker.record(
                    engagement_id=self.engagement_id,
                    model=self.model_id,
                    input_tokens=getattr(usage, "input_tokens", 0),
                    output_tokens=getattr(usage, "output_tokens", 0),
                    agent="alerts",
                )

            response_text = ""
            for block in response.content:
                if hasattr(block, "text"):
                    response_text += block.text

            alerts = self._parse_alerts(response_text)

            # Deduplicate against recent alerts
            new_alerts = []
            for alert in alerts:
                if alert.title not in recent_titles:
                    alert.timestamp = datetime.now(timezone.utc).isoformat()
                    new_alerts.append(alert)

            # Persist
            if new_alerts:
                alert_dicts = [a.to_dict() for a in new_alerts]
                self.previous_alerts.extend(alert_dicts)
                self._save_alerts(self.previous_alerts)
                logger.info(f"[AlertsAgent] Emitted {len(new_alerts)} alert(s)")

            return new_alerts

        except Exception as e:
            logger.warning(f"[AlertsAgent] Check failed: {e}")
            return []

    def _build_snapshot(self, state: dict, iteration: int, last_result: dict = None) -> str:
        """Build a compact state snapshot for the alerts model."""
        lines = []

        eng = state.get("engagement", {})
        lines.append(f"Target: {eng.get('target', '?')}")
        lines.append(f"Iteration: {iteration}")

        # Hosts
        hosts = state.get("hosts", {})
        if hosts:
            lines.append(f"Hosts discovered: {len(hosts)}")
            for ip, info in list(hosts.items())[:5]:
                if isinstance(info, dict):
                    svc_count = len(info.get("services", []))
                    lines.append(f"  {ip}: {svc_count} services, OS={info.get('os', '?')}")

        # Credentials
        creds = state.get("credentials_summary") or []
        if isinstance(creds, list) and creds:
            lines.append(f"Credentials: {len(creds)}")
            for c in creds[:5]:
                if isinstance(c, dict):
                    lines.append(f"  {c.get('username', '?')} ({c.get('type', '?')})")

        # Vulns
        vulns = state.get("vulns_summary", [])
        if isinstance(vulns, list) and vulns:
            sev_counts = {}
            for v in vulns:
                sev = v.get("severity", "info") if isinstance(v, dict) else "info"
                sev_counts[sev] = sev_counts.get(sev, 0) + 1
            lines.append(f"Vulnerabilities: {len(vulns)} ({', '.join(f'{c} {s}' for s, c in sev_counts.items())})")

        # Access
        access = state.get("access", {})
        shells = access.get("shells", []) if isinstance(access, dict) else []
        if isinstance(shells, list) and shells:
            lines.append(f"Active shells: {len(shells)}")
            for sh in shells[:3]:
                if isinstance(sh, dict):
                    lines.append(f"  {sh.get('user', '?')}@{sh.get('host', '?')} ({sh.get('type', '?')})")

        # Objectives
        objectives = state.get("objectives", [])
        if objectives:
            completed = sum(1 for o in objectives if isinstance(o, dict) and o.get("status") == "completed")
            lines.append(f"Objectives: {completed}/{len(objectives)} completed")

        # Last result
        if last_result:
            lines.append(f"\nLast agent: {last_result.get('agent', '?')}")
            lines.append(f"  Success: {last_result.get('success', '?')}")
            summary = last_result.get('summary', '')
            if summary:
                lines.append(f"  Summary: {str(summary)[:200]}")
            errors = last_result.get('errors', [])
            if errors:
                lines.append(f"  Errors: {', '.join(str(e)[:80] for e in errors[:3])}")

        return "\n".join(lines)

    def _parse_alerts(self, text: str) -> list[Alert]:
        """Extract alerts from model response."""
        # Try to find JSON in the response
        text = text.strip()

        # Strip markdown fences
        if text.startswith("```"):
            lines = text.split("\n")
            lines = [l for l in lines if not l.strip().startswith("```")]
            text = "\n".join(lines)

        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            # Try to find JSON object in the text
            start = text.find("{")
            end = text.rfind("}") + 1
            if start >= 0 and end > start:
                try:
                    data = json.loads(text[start:end])
                except json.JSONDecodeError:
                    return []
            else:
                return []

        raw_alerts = data.get("alerts", [])
        alerts = []
        for a in raw_alerts:
            if isinstance(a, dict) and a.get("title"):
                alerts.append(Alert(
                    severity=a.get("severity", "info"),
                    title=a["title"][:80],
                    detail=a.get("detail", "")[:200],
                    category=a.get("category", "info"),
                ))
        return alerts

    def get_all_alerts(self) -> list[dict]:
        """Return all historical alerts."""
        return self.previous_alerts.copy()

    def clear_alerts(self):
        """Clear all alerts."""
        self.previous_alerts = []
        self._save_alerts([])

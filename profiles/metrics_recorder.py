"""
SnowStrike AI - Engagement Metrics Recorder

Records per-engagement performance metrics (duration, cost, findings, objectives)
into a metrics.json file alongside the engagement data. Builds on top of the
existing CostTracker — this adds the broader engagement-level metrics.
"""

import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from memory.cost_tracker import CostTracker

logger = logging.getLogger(__name__)


class MetricsRecorder:
    """Records and queries engagement-level metrics for A/B testing comparisons."""

    def __init__(self, engagement_dir: str, engagement_id: int = 1):
        self.engagement_dir = Path(engagement_dir)
        self.engagement_id = engagement_id
        self.metrics_path = self.engagement_dir / "metrics.json"

        # Initialize metrics if they don't exist
        if not self.metrics_path.exists():
            self._write({})

    # ------------------------------------------------------------------
    # Lifecycle — called by orchestrator
    # ------------------------------------------------------------------

    def start_engagement(
        self,
        target_ip: str,
        methodology: str = "standard",
        profile_name: str = "",
        prompt_preset: str = "",
        model_config: str = "",
        ctf_tag: str = "",
    ) -> None:
        """Record engagement start. Called at the beginning of run_autonomous()."""
        metrics = {
            "target_ip": target_ip,
            "ctf_tag": ctf_tag or self._infer_ctf_tag(methodology),
            "methodology": methodology,
            "profile_name": profile_name,
            "prompt_preset": prompt_preset,
            "model_config": model_config,
            "start_time": datetime.now(timezone.utc).isoformat(),
            "end_time": None,
            "duration_seconds": 0,
            "iterations_completed": 0,
            "budget_total": 0,
            "budget_remaining": 0,
            "findings_count": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            "access_achieved": "none",
            "objectives_completed": [],
            "objectives_total": [],
            "agent_dispatches": [],
            "cost": {
                "input_tokens": 0,
                "output_tokens": 0,
                "total_usd": 0.0,
                "breakdown_by_agent": {},
            },
            "success_metrics": {
                "shell_obtained": False,
                "privesc_achieved": False,
                "root_obtained": False,
                "report_generated": False,
                "flag_captured": False,
            },
        }
        self._write(metrics)
        logger.info(f"[MetricsRecorder] Started recording for {target_ip} (profile={profile_name})")

    def record_iteration(
        self,
        iteration: int,
        budget_remaining: int,
        budget_total: int,
        agent_type: str = "",
        task: str = "",
        success: bool = False,
        duration_seconds: float = 0.0,
    ) -> None:
        """Record a single iteration result."""
        metrics = self._read()
        metrics["iterations_completed"] = iteration
        metrics["budget_remaining"] = budget_remaining
        metrics["budget_total"] = budget_total

        if agent_type:
            metrics["agent_dispatches"].append({
                "iteration": iteration,
                "agent": agent_type,
                "task": task[:200],
                "success": success,
                "duration_seconds": round(duration_seconds, 2),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })

        self._write(metrics)

    def record_finding(self, severity: str) -> None:
        """Increment the findings count for a severity level."""
        metrics = self._read()
        sev = severity.lower()
        if sev in metrics.get("findings_count", {}):
            metrics["findings_count"][sev] += 1
        self._write(metrics)

    def record_access(self, level: str) -> None:
        """Record access level achieved (user, admin, root, none)."""
        metrics = self._read()
        # Only upgrade, never downgrade
        levels = ["none", "user", "admin", "root"]
        current = metrics.get("access_achieved", "none")
        if levels.index(level) > levels.index(current):
            metrics["access_achieved"] = level
        self._write(metrics)

    def record_objective_completed(self, objective: str) -> None:
        """Record a completed objective."""
        metrics = self._read()
        if objective not in metrics.get("objectives_completed", []):
            metrics["objectives_completed"].append(objective)
        self._write(metrics)

    def record_success_metric(self, metric: str, value: bool = True) -> None:
        """Record a success metric flag."""
        metrics = self._read()
        if metric in metrics.get("success_metrics", {}):
            metrics["success_metrics"][metric] = value
        self._write(metrics)

    def finish_engagement(self, cost_summary: Optional[Dict] = None) -> Dict:
        """Record engagement completion and finalize metrics.

        Args:
            cost_summary: Output from CostTracker.get_summary()

        Returns:
            The final metrics dict.
        """
        metrics = self._read()
        metrics["end_time"] = datetime.now(timezone.utc).isoformat()

        # Calculate duration
        start = metrics.get("start_time")
        if start:
            from datetime import datetime as dt
            try:
                start_dt = dt.fromisoformat(start)
                end_dt = dt.fromisoformat(metrics["end_time"])
                metrics["duration_seconds"] = round((end_dt - start_dt).total_seconds(), 1)
            except (ValueError, TypeError):
                pass

        # Merge cost data from CostTracker
        if cost_summary:
            total_input = 0
            total_output = 0
            total_usd = cost_summary.get("total_usd", 0.0)

            by_agent = {}
            for provider_data in cost_summary.get("by_provider", {}).values():
                total_input += provider_data.get("input_tokens", 0)
                total_output += provider_data.get("output_tokens", 0)

            # Build agent breakdown from dispatches
            for dispatch in metrics.get("agent_dispatches", []):
                agent = dispatch.get("agent", "unknown")
                if agent not in by_agent:
                    by_agent[agent] = 0.0

            metrics["cost"] = {
                "input_tokens": total_input,
                "output_tokens": total_output,
                "total_usd": round(total_usd, 4),
                "breakdown_by_agent": by_agent,
                "full_summary": cost_summary,
            }

        self._write(metrics)
        logger.info(
            f"[MetricsRecorder] Finished: {metrics.get('target_ip', '?')} | "
            f"{metrics['duration_seconds']}s | ${metrics['cost']['total_usd']} | "
            f"access={metrics['access_achieved']}"
        )
        return metrics

    # ------------------------------------------------------------------
    # Query
    # ------------------------------------------------------------------

    def get_metrics(self) -> Dict:
        """Read the current metrics."""
        return self._read()

    # ------------------------------------------------------------------
    # Class methods for querying across engagements
    # ------------------------------------------------------------------

    @classmethod
    def find_metrics(
        cls,
        engagements_dir: str,
        target_ip: str = "",
        ctf_tag: str = "",
        profile_name: str = "",
    ) -> List[Dict]:
        """Find all metrics.json files, optionally filtered.

        Args:
            engagements_dir: Base engagements directory path.
            target_ip: Filter by target IP.
            ctf_tag: Filter by CTF difficulty tag.
            profile_name: Filter by profile name.

        Returns:
            List of metrics dicts sorted by start_time.
        """
        results = []
        eng_path = Path(engagements_dir)
        if not eng_path.exists():
            return results

        for entry in eng_path.iterdir():
            if not entry.is_dir():
                continue
            metrics_file = entry / "metrics.json"
            if not metrics_file.exists():
                continue

            try:
                with open(metrics_file) as f:
                    data = json.load(f)

                # Apply filters
                if target_ip and data.get("target_ip") != target_ip:
                    continue
                if ctf_tag and data.get("ctf_tag") != ctf_tag:
                    continue
                if profile_name and data.get("profile_name") != profile_name:
                    continue

                data["engagement_dir"] = str(entry)
                data["engagement_name"] = entry.name
                results.append(data)
            except (json.JSONDecodeError, OSError) as e:
                logger.warning(f"Failed to read metrics from {metrics_file}: {e}")

        # Sort by start_time
        results.sort(key=lambda m: m.get("start_time", ""), reverse=True)
        return results

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _read(self) -> Dict:
        if not self.metrics_path.exists():
            return {}
        try:
            with open(self.metrics_path) as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            return {}

    def _write(self, data: Dict) -> None:
        with open(self.metrics_path, "w") as f:
            json.dump(data, f, indent=2)

    @staticmethod
    def _infer_ctf_tag(methodology: str) -> str:
        return "ctf" if methodology == "ctf" else ""

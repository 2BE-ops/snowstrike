"""
SnowStrike AI - Engagement Comparison & Analysis

Generates comparison reports across multiple engagement runs,
analyzing cost, speed, findings, and success metrics.
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from config import ENGAGEMENTS_DIR
from profiles.metrics_recorder import MetricsRecorder

logger = logging.getLogger(__name__)


class EngagementComparison:
    """Compares metrics across multiple engagement runs."""

    def __init__(self, engagements_dir: Optional[str] = None):
        self.engagements_dir = engagements_dir or str(ENGAGEMENTS_DIR)

    # ------------------------------------------------------------------
    # Data Collection
    # ------------------------------------------------------------------

    def get_comparison_data(
        self,
        target_ip: str = "",
        ctf_tag: str = "",
        profile_name: str = "",
    ) -> List[Dict]:
        """Collect all metrics matching the filters."""
        return MetricsRecorder.find_metrics(
            self.engagements_dir,
            target_ip=target_ip,
            ctf_tag=ctf_tag,
            profile_name=profile_name,
        )

    # ------------------------------------------------------------------
    # Analysis
    # ------------------------------------------------------------------

    def analyze(
        self,
        metrics_list: List[Dict],
    ) -> Dict[str, Any]:
        """Analyze a set of engagement metrics and produce comparison stats.

        Returns:
            {
                "summary_table": [...],  # sorted rows for the comparison table
                "cost_analysis": {...},
                "speed_analysis": {...},
                "quality_analysis": {...},
                "recommendations": [...],
            }
        """
        if not metrics_list:
            return {"error": "No metrics to compare"}

        # Build summary rows
        rows = []
        for m in metrics_list:
            profile = m.get("profile_name", "unknown")
            duration = m.get("duration_seconds", 0)
            cost = m.get("cost", {}).get("total_usd", 0.0)
            findings = m.get("findings_count", {})
            total_findings = sum(findings.values())
            access = m.get("access_achieved", "none")
            iterations = m.get("iterations_completed", 0)
            budget = m.get("budget_total", 0)
            success = m.get("success_metrics", {})

            rows.append({
                "profile": profile,
                "prompt_preset": m.get("prompt_preset", ""),
                "model_config": m.get("model_config", ""),
                "duration_seconds": duration,
                "duration_display": self._format_duration(duration),
                "cost_usd": round(cost, 2),
                "total_findings": total_findings,
                "findings_breakdown": findings,
                "access_achieved": access,
                "root_obtained": success.get("root_obtained", False),
                "shell_obtained": success.get("shell_obtained", False),
                "iterations": iterations,
                "budget_total": budget,
                "efficiency": round(iterations / budget * 100, 1) if budget else 0,
                "cost_per_finding": round(cost / total_findings, 2) if total_findings else 0,
                "engagement_name": m.get("engagement_name", ""),
                "start_time": m.get("start_time", ""),
            })

        # Sort by cost efficiency (cost per root shell, then total cost)
        rows.sort(key=lambda r: (not r["root_obtained"], r["cost_usd"]))

        # Cost analysis
        costs = [r["cost_usd"] for r in rows if r["cost_usd"] > 0]
        cost_analysis = {
            "cheapest": min(costs) if costs else 0,
            "most_expensive": max(costs) if costs else 0,
            "average": round(sum(costs) / len(costs), 2) if costs else 0,
            "cheapest_root": None,
            "cheapest_shell": None,
        }
        root_rows = [r for r in rows if r["root_obtained"] and r["cost_usd"] > 0]
        if root_rows:
            cheapest_root = min(root_rows, key=lambda r: r["cost_usd"])
            cost_analysis["cheapest_root"] = {
                "profile": cheapest_root["profile"],
                "cost_usd": cheapest_root["cost_usd"],
            }
        shell_rows = [r for r in rows if r["shell_obtained"] and r["cost_usd"] > 0]
        if shell_rows:
            cheapest_shell = min(shell_rows, key=lambda r: r["cost_usd"])
            cost_analysis["cheapest_shell"] = {
                "profile": cheapest_shell["profile"],
                "cost_usd": cheapest_shell["cost_usd"],
            }

        # Speed analysis
        durations = [r["duration_seconds"] for r in rows if r["duration_seconds"] > 0]
        speed_analysis = {
            "fastest": min(durations) if durations else 0,
            "slowest": max(durations) if durations else 0,
            "average": round(sum(durations) / len(durations), 1) if durations else 0,
            "fastest_root": None,
        }
        if root_rows:
            fastest_root = min(root_rows, key=lambda r: r["duration_seconds"])
            speed_analysis["fastest_root"] = {
                "profile": fastest_root["profile"],
                "duration_seconds": fastest_root["duration_seconds"],
                "duration_display": fastest_root["duration_display"],
            }

        # Quality analysis
        finding_counts = [r["total_findings"] for r in rows]
        quality_analysis = {
            "most_findings": max(finding_counts) if finding_counts else 0,
            "fewest_findings": min(finding_counts) if finding_counts else 0,
            "average_findings": round(sum(finding_counts) / len(finding_counts), 1) if finding_counts else 0,
            "root_rate": round(len(root_rows) / len(rows) * 100, 1) if rows else 0,
            "shell_rate": round(len(shell_rows) / len(rows) * 100, 1) if rows else 0,
        }

        # Recommendations
        recommendations = self._generate_recommendations(rows, cost_analysis, speed_analysis)

        return {
            "target_ip": metrics_list[0].get("target_ip", "") if metrics_list else "",
            "total_runs": len(rows),
            "summary_table": rows,
            "cost_analysis": cost_analysis,
            "speed_analysis": speed_analysis,
            "quality_analysis": quality_analysis,
            "recommendations": recommendations,
        }

    # ------------------------------------------------------------------
    # Report Generation
    # ------------------------------------------------------------------

    def generate_report(
        self,
        target_ip: str = "",
        ctf_tag: str = "",
        output_path: Optional[str] = None,
    ) -> str:
        """Generate a Markdown comparison report.

        Returns:
            The report content as a string. Also writes to output_path if provided.
        """
        metrics = self.get_comparison_data(target_ip=target_ip, ctf_tag=ctf_tag)
        if not metrics:
            return f"No metrics found for target={target_ip} tag={ctf_tag}"

        analysis = self.analyze(metrics)
        rows = analysis["summary_table"]
        cost = analysis["cost_analysis"]
        speed = analysis["speed_analysis"]
        quality = analysis["quality_analysis"]

        lines = []
        lines.append(f"# Test Results: {target_ip or 'All Targets'}")
        if ctf_tag:
            lines.append(f"**CTF Tag:** {ctf_tag}")
        lines.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"**Total Runs:** {analysis['total_runs']}")
        lines.append("")

        # Summary table
        lines.append("## Summary Table")
        lines.append("")
        lines.append("| Profile | Duration | Cost | Findings | Access | Iterations | $/Finding |")
        lines.append("|---------|----------|------|----------|--------|------------|-----------|")
        for r in rows:
            root_marker = " (root)" if r["root_obtained"] else (" (shell)" if r["shell_obtained"] else "")
            lines.append(
                f"| {r['profile'][:35]} | {r['duration_display']} | "
                f"${r['cost_usd']:.2f} | {r['total_findings']} | "
                f"{r['access_achieved']}{root_marker} | "
                f"{r['iterations']}/{r['budget_total']} | "
                f"${r['cost_per_finding']:.2f} |"
            )
        lines.append("")

        # Cost analysis
        lines.append("## Cost Analysis")
        lines.append("")
        lines.append(f"- **Cheapest run:** ${cost['cheapest']:.2f}")
        lines.append(f"- **Most expensive:** ${cost['most_expensive']:.2f}")
        lines.append(f"- **Average cost:** ${cost['average']:.2f}")
        if cost["cheapest_root"]:
            cr = cost["cheapest_root"]
            lines.append(f"- **Cheapest root shell:** {cr['profile']} (${cr['cost_usd']:.2f})")
        lines.append("")

        # Speed analysis
        lines.append("## Speed Analysis")
        lines.append("")
        lines.append(f"- **Fastest:** {self._format_duration(speed['fastest'])}")
        lines.append(f"- **Slowest:** {self._format_duration(speed['slowest'])}")
        lines.append(f"- **Average:** {self._format_duration(speed['average'])}")
        if speed["fastest_root"]:
            fr = speed["fastest_root"]
            lines.append(f"- **Fastest root:** {fr['profile']} ({fr['duration_display']})")

        if speed["fastest"] > 0 and speed["slowest"] > 0:
            pct = round((speed["slowest"] - speed["fastest"]) / speed["fastest"] * 100, 0)
            lines.append(f"- **Speed range:** slowest is {pct:.0f}% slower than fastest")
        lines.append("")

        # Quality analysis
        lines.append("## Quality Analysis")
        lines.append("")
        lines.append(f"- **Most findings:** {quality['most_findings']}")
        lines.append(f"- **Average findings:** {quality['average_findings']}")
        lines.append(f"- **Root success rate:** {quality['root_rate']}%")
        lines.append(f"- **Shell success rate:** {quality['shell_rate']}%")
        lines.append("")

        # Recommendations
        if analysis["recommendations"]:
            lines.append("## Recommendations")
            lines.append("")
            for i, rec in enumerate(analysis["recommendations"], 1):
                lines.append(f"{i}. **{rec['use_case']}:** {rec['profile']} — {rec['reason']}")
            lines.append("")

        report = "\n".join(lines)

        # Write to file if path provided
        if output_path:
            Path(output_path).write_text(report)
            logger.info(f"Comparison report written to {output_path}")
        elif target_ip:
            safe_ip = target_ip.replace(".", "_")
            tag_part = f"_{ctf_tag}" if ctf_tag else ""
            report_path = Path(self.engagements_dir) / f"results_{safe_ip}{tag_part}_comparison.md"
            report_path.write_text(report)
            logger.info(f"Comparison report written to {report_path}")

        return report

    def export_csv(
        self,
        target_ip: str = "",
        ctf_tag: str = "",
        output_path: Optional[str] = None,
    ) -> str:
        """Export comparison data as CSV."""
        metrics = self.get_comparison_data(target_ip=target_ip, ctf_tag=ctf_tag)
        analysis = self.analyze(metrics)
        rows = analysis.get("summary_table", [])

        headers = [
            "profile", "prompt_preset", "model_config", "duration_seconds",
            "cost_usd", "total_findings", "access_achieved", "root_obtained",
            "shell_obtained", "iterations", "budget_total", "cost_per_finding",
            "engagement_name", "start_time",
        ]

        lines = [",".join(headers)]
        for r in rows:
            line = ",".join(str(r.get(h, "")) for h in headers)
            lines.append(line)

        csv_content = "\n".join(lines)
        if output_path:
            Path(output_path).write_text(csv_content)

        return csv_content

    def export_json(
        self,
        target_ip: str = "",
        ctf_tag: str = "",
        output_path: Optional[str] = None,
    ) -> Dict:
        """Export full analysis as JSON."""
        metrics = self.get_comparison_data(target_ip=target_ip, ctf_tag=ctf_tag)
        analysis = self.analyze(metrics)

        if output_path:
            Path(output_path).write_text(json.dumps(analysis, indent=2, default=str))

        return analysis

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _generate_recommendations(
        self,
        rows: List[Dict],
        cost: Dict,
        speed: Dict,
    ) -> List[Dict]:
        """Generate use-case recommendations from the analysis."""
        recs = []

        # Best for HTB farming (cheapest root)
        root_rows = [r for r in rows if r["root_obtained"]]
        if root_rows:
            cheapest = min(root_rows, key=lambda r: r["cost_usd"])
            recs.append({
                "use_case": "HTB farming (volume)",
                "profile": cheapest["profile"],
                "reason": f"Cheapest root at ${cheapest['cost_usd']:.2f}",
            })

            fastest = min(root_rows, key=lambda r: r["duration_seconds"])
            if fastest["profile"] != cheapest["profile"]:
                recs.append({
                    "use_case": "Speed runs / CTF",
                    "profile": fastest["profile"],
                    "reason": f"Fastest root in {fastest['duration_display']}",
                })

        # Best for quality (most findings)
        if rows:
            most_findings = max(rows, key=lambda r: r["total_findings"])
            recs.append({
                "use_case": "High-quality reports",
                "profile": most_findings["profile"],
                "reason": f"Most findings ({most_findings['total_findings']}) for thorough coverage",
            })

            # Best efficiency (cost per finding)
            with_findings = [r for r in rows if r["total_findings"] > 0 and r["cost_usd"] > 0]
            if with_findings:
                most_efficient = min(with_findings, key=lambda r: r["cost_per_finding"])
                recs.append({
                    "use_case": "Cost efficiency",
                    "profile": most_efficient["profile"],
                    "reason": f"Best value at ${most_efficient['cost_per_finding']:.2f}/finding",
                })

        return recs

    @staticmethod
    def _format_duration(seconds: float) -> str:
        """Format seconds as human-readable duration."""
        if seconds <= 0:
            return "N/A"
        minutes = int(seconds // 60)
        secs = int(seconds % 60)
        if minutes > 60:
            hours = minutes // 60
            minutes = minutes % 60
            return f"{hours}h {minutes}m {secs}s"
        return f"{minutes}m {secs}s"

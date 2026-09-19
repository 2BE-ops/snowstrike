"""SnowStrike AI v7.0 - ReportingAgent"""
import json

from agents.base_agent import BaseAgent
from tools.registry_loader import get_registry


class ReportingAgent(BaseAgent):
    agent_name = "Reporting Agent"
    agent_type = "reporting"

    def __init__(
        self,
        engagement_dir,
        anthropic_client=None,
        engagement_id=1,
        model_override="",
        prompt_dir="",
    ):
        super().__init__(
            engagement_dir=engagement_dir,
            anthropic_client=anthropic_client,
            engagement_id=engagement_id,
            model_override=model_override,
            prompt_dir=prompt_dir,
        )
        # Override tools: reporting agent has no security tools, only shared tools
        self.tools = get_registry().get_shared_tools()

    def _build_context(self, task: str) -> str:
        """Build comprehensive context with full DB data for report generation."""
        parts = [f"## Task\n{task}\n"]

        # Engagement info
        engagement = self.db.get_engagement(self.engagement_id)
        if engagement:
            parts.append(
                "## Engagement Details\n```json\n"
                + json.dumps(engagement, indent=2, default=str)
                + "\n```\n"
            )

        # All hosts with their services
        hosts = self.db.get_hosts(self.engagement_id)
        if hosts:
            for host in hosts:
                host["services"] = self.db.get_services(host["id"])
            parts.append(
                "## All Hosts & Services\n```json\n"
                + json.dumps(hosts, indent=2, default=str)
                + "\n```\n"
            )

        # All vulnerabilities
        vulns = self.db.query_findings(self.engagement_id)
        if vulns:
            parts.append(
                f"## All Vulnerabilities ({len(vulns)} total)\n```json\n"
                + json.dumps(vulns, indent=2, default=str)
                + "\n```\n"
            )

        # All credentials (for internal report use)
        creds = self.db.query_credentials(self.engagement_id)
        if creds:
            parts.append(
                f"## All Credentials ({len(creds)} total)\n```json\n"
                + json.dumps(creds, indent=2, default=str)
                + "\n```\n"
            )

        # All tool executions
        tool_execs = self.db.get_tool_executions(self.engagement_id, limit=200)
        if tool_execs:
            parts.append(
                f"## Tool Execution Log ({len(tool_execs)} entries)\n```json\n"
                + json.dumps(tool_execs, indent=2, default=str)
                + "\n```\n"
            )

        # Network edges
        edges = self.db.get_network_edges(self.engagement_id)
        if edges:
            parts.append(
                "## Network Edges\n```json\n"
                + json.dumps(edges, indent=2, default=str)
                + "\n```\n"
            )

        # Full shared state
        state = self.shared_state.read()
        if state:
            parts.append(
                "## Full Shared State\n```json\n"
                + json.dumps(state, indent=2, default=str)
                + "\n```\n"
            )

        # Network map summary
        map_summary = self.network_map.summary()
        if map_summary:
            parts.append(f"## Network Map\n{map_summary}\n")

        # Attack story
        story_text = self.story.read()
        if story_text:
            parts.append(f"## Attack Story\n{story_text}\n")

        parts.append(
            "\n## Instructions\n"
            "Using ALL the data above, generate a comprehensive penetration test report. "
            "Include an executive summary, methodology, detailed findings with severity ratings, "
            "evidence, remediation recommendations, and a conclusion. "
            "Save findings using save_finding if any are missing from the database."
        )

        return "\n".join(parts)

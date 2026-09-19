"""Agent roster + model configuration browser."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Vertical
from textual.widgets import DataTable, Static

from tui.service import get_service


class AgentsView(Vertical):
    BINDINGS = [
        ("r", "refresh", "Refresh"),
    ]

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Static("AGENT ROSTER", classes="section-title")
            yield DataTable(id="agent-table", cursor_type="row", zebra_stripes=True)
            yield Static("MODEL CONFIGS", classes="section-title")
            yield DataTable(id="model-table", cursor_type="row", zebra_stripes=True)

    def on_mount(self) -> None:
        self._columns_ready = False

    def on_show(self) -> None:
        self.call_after_refresh(self._shown_refresh)

    def _shown_refresh(self) -> None:
        if not self.is_mounted or not self.display:
            return
        self._ensure_columns()
        self.action_refresh()

    def _ensure_columns(self) -> None:
        if self._columns_ready:
            return
        self._columns_ready = True
        self.query_one("#agent-table", DataTable).add_columns(
            "agent", "display name", "model", "tools", "concurrency", "description"
        )
        self.query_one("#model-table", DataTable).add_columns(
            "config", "orchestrator", "planning", "tool_calling", "compaction"
        )

    def action_refresh(self) -> None:
        if not self.is_mounted or not self.display:
            return
        service = get_service()

        agent_table = self.query_one("#agent-table", DataTable)
        agent_table.clear()
        roster = service.agent_roster()
        if not roster:
            agent_table.add_row("[dim]agent registry unavailable[/]", "", "", "", "", "")
        for agent in sorted(roster, key=lambda a: a.get("name", "")):
            agent_table.add_row(
                f"[cyan]{agent.get('name', '?')}[/]",
                str(agent.get("display_name", "")),
                str(agent.get("model", "") or "[dim]tier default[/]"),
                str(agent.get("tool_count", 0)),
                str(agent.get("max_concurrent", 1)),
                str(agent.get("description", ""))[:70],
            )

        model_table = self.query_one("#model-table", DataTable)
        model_table.clear()
        configs = service.model_configs()
        if not configs:
            model_table.add_row("[dim]no saved model configs[/]", "", "", "", "")
        for config in configs:
            roles = config.get("roles", {}) or {}
            model_table.add_row(
                f"[cyan]{config.get('name', '?')}[/]",
                str(roles.get("orchestrator", "—")),
                str(roles.get("planning", "—")),
                str(roles.get("tool_calling", "—")),
                str(roles.get("compaction", "—")),
            )

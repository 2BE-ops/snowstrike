"""Engagement overview: stat cards + tabbed intel (hosts, vulns,
timeline, agent activity, story)."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.widgets import DataTable, Static, TabbedContent, TabPane

from tui.service import get_service
from tui.widgets import StatCard, fmt_ts, severity_markup

STATUS_COLORS = {
    "running": "[bold #fbbf24]● RUNNING[/]",
    "complete": "[#4ade80]● COMPLETE[/]",
    "idle": "[dim]○ idle[/]",
}


class OverviewView(Vertical):
    BINDINGS = [
        ("r", "refresh", "Refresh"),
    ]

    def compose(self) -> ComposeResult:
        with VerticalScroll():
            with Horizontal(id="stats-row"):
                yield StatCard("HOSTS", "0")
                yield StatCard("SERVICES", "0")
                yield StatCard("CRIT", "0", "severity-critical")
                yield StatCard("HIGH", "0", "severity-high")
                yield StatCard("CREDS", "0")
                yield StatCard("TOOL RUNS", "0")
                yield StatCard("COST $", "0.00", "accent")
                yield StatCard("STATUS", "idle")
            with TabbedContent():
                with TabPane("Hosts", id="tab-hosts"):
                    yield DataTable(id="hosts-table", cursor_type="row", zebra_stripes=True)
                with TabPane("Vulns", id="tab-vulns"):
                    yield DataTable(id="vulns-table", cursor_type="row", zebra_stripes=True)
                with TabPane("Timeline", id="tab-timeline"):
                    yield DataTable(id="timeline-table", cursor_type="row", zebra_stripes=True)
                with TabPane("Agents", id="tab-agents"):
                    yield DataTable(id="agents-table", cursor_type="row", zebra_stripes=True)
                with TabPane("Story", id="tab-story"):
                    yield Static(id="story-view")

    def on_mount(self) -> None:
        self._columns_ready = False
        self._last_token: tuple | None = None
        self.set_interval(1.5, self._poll)

    def on_show(self) -> None:
        # One frame after reveal — never mutate during the show transition.
        self._last_token = None
        self.call_after_refresh(self._shown_refresh)

    def _shown_refresh(self) -> None:
        if not self.is_mounted or not self.display:
            return
        self._ensure_columns()
        self._poll()

    def _ensure_columns(self) -> None:
        if self._columns_ready:
            return
        self._columns_ready = True
        for table_id, cols in [
            ("hosts-table", ["ip", "hostname", "os", "ports"]),
            ("vulns-table", ["severity", "title", "host", "description"]),
            ("timeline-table", ["time", "event", "agent", "detail"]),
            ("agents-table", ["time", "agent", "tool", "ok", "dur", "summary"]),
        ]:
            self.query_one(f"#{table_id}", DataTable).add_columns(*cols)

    # -- change detection ------------------------------------------------

    def _token(self) -> tuple:
        handle = get_service().current
        if handle is None:
            return ("none",)
        mtimes = handle.files.get_mtimes()
        return (handle.name, tuple(sorted(mtimes.items())), tuple(sorted(handle.counts().items())))

    def _poll(self) -> None:
        if not self.is_mounted or not self.display:
            return
        token = self._token()
        if token == self._last_token:
            return
        self._last_token = token
        self.action_refresh()

    # -- rendering --------------------------------------------------------

    def action_refresh(self) -> None:
        if not self.is_mounted or not self.display:
            return
        handle = get_service().current
        if handle is None:
            self._set_stats({})
            for table_id in ("hosts-table", "vulns-table", "timeline-table", "agents-table"):
                self.query_one(f"#{table_id}", DataTable).clear()
            self.query_one("#story-view", Static).update("[dim]no engagement selected — press 2[/]")
            return
        summary = handle.summary()
        self._set_stats(summary)

        hosts_table = self.query_one("#hosts-table", DataTable)
        hosts_table.clear()
        for host in handle.hosts():
            services = host.get("services", [])
            ports = ", ".join(
                f"{s.get('port', '?')}/{s.get('protocol', '')}" for s in services[:6]
            ) + (" …" if len(services) > 6 else "")
            hosts_table.add_row(
                str(host.get("ip", "?")),
                str(host.get("hostname", "") or "—"),
                str(host.get("os", "") or "—"),
                ports or "—",
            )

        vulns_table = self.query_one("#vulns-table", DataTable)
        vulns_table.clear()
        for vuln in sorted(
            handle.vulnerabilities(),
            key=lambda v: str(v.get("severity", "")).lower(),
        ):
            vulns_table.add_row(
                severity_markup(str(vuln.get("severity", "?")).title()),
                str(vuln.get("title", "") or "?"),
                str(vuln.get("host_ip", "") or "—"),
                str(vuln.get("description", "") or "")[:90],
            )

        timeline_table = self.query_one("#timeline-table", DataTable)
        timeline_table.clear()
        for event in handle.timeline()[-200:]:
            timeline_table.add_row(
                fmt_ts(event.get("ts")),
                str(event.get("event_type", "?")),
                str(event.get("agent", "?")),
                f"{event.get('label', '')} {str(event.get('detail', ''))[:70]}".strip() or "—",
            )

        agents_table = self.query_one("#agents-table", DataTable)
        agents_table.clear()
        for act in handle.agent_activity(limit=100):
            agents_table.add_row(
                fmt_ts(act.get("created_at")),
                str(act.get("agent", "?")),
                str(act.get("tool_name", "?")),
                "[green]ok[/]" if act.get("success") else "[red]fail[/]",
                f"{float(act.get('duration_seconds') or 0):.1f}s",
                str(act.get("compacted_summary", "") or "")[:60],
            )

        story = handle.story()
        self.query_one("#story-view", Static).update(
            story or "[dim]No STORY.md yet — the engagement has not produced a narrative.[/]"
        )

    def _set_stats(self, summary: dict) -> None:
        values = {
            "HOSTS": str(summary.get("hosts", 0)),
            "SERVICES": str(summary.get("services", 0)),
            "CRIT": str(summary.get("critical", 0)),
            "HIGH": str(summary.get("high", 0)),
            "CREDS": str(summary.get("creds", 0)),
            "TOOL RUNS": str(summary.get("tool_runs", 0)),
            "COST $": f"{summary.get('cost', 0.0):.2f}",
            "STATUS": STATUS_COLORS.get(summary.get("status", "idle"), summary.get("status", "idle")),
        }
        for card in self.query(StatCard):
            card.set_value(values.get(card.label, "—"))

"""Engagement browser: list engagements, select one, and launch new
autonomous runs without leaving the terminal."""

from __future__ import annotations

from textual import work
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, DataTable, Input, Label, Static

from tui.service import get_service


class NewRunModal(ModalScreen):
    """Dialog collecting target / scope / methodology for a new run."""

    CSS = """
    NewRunModal { align: center middle; }
    """

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Static("▶ Launch autonomous run", classes="modal-title")
            yield Label("Target (host / IP / domain)")
            yield Input(placeholder="10.10.10.5", id="target")
            yield Label("Scope (comma-separated CIDRs / hosts, blank = target only)")
            yield Input(placeholder="10.10.10.0/24", id="scope")
            yield Label("Methodology")
            yield Input(value="standard", id="methodology")
            with Horizontal():
                yield Button("Start", variant="success", id="start")
                yield Button("Cancel", variant="error", id="cancel")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "start":
            target = self.query_one("#target", Input).value.strip()
            if not target:
                self.query_one("#target", Input).focus()
                return
            self.dismiss({
                "target": target,
                "scope": self.query_one("#scope", Input).value.strip(),
                "methodology": self.query_one("#methodology", Input).value.strip() or "standard",
            })
        else:
            self.dismiss(None)


class EngagementsView(Vertical):
    BINDINGS = [
        ("n", "new_run", "New run"),
        ("enter", "select", "Select"),
        ("r", "refresh", "Refresh"),
    ]

    def compose(self) -> ComposeResult:
        yield DataTable(id="eng-table", cursor_type="row", zebra_stripes=True)
        yield Static("", id="run-status", classes="hint")

    def on_mount(self) -> None:
        self._columns_ready = False
        self.set_interval(2.0, self._tick)

    def on_show(self) -> None:
        # One frame after reveal — never mutate during the show transition.
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
        self.query_one(DataTable).add_columns(
            "engagement", "target", "status", "hosts", "vulns", "crit", "tool runs", "cost $"
        )

    def _tick(self) -> None:
        if not self.is_mounted or not self.display:
            return
        run = get_service().run_state
        status_line = self.query_one("#run-status", Static)
        if run.get("status") in {"starting", "running"}:
            status_line.update(f"[bold #fbbf24]● {run.get('status', '').upper()}[/] {run.get('message', '')}")
        elif run.get("status") == "error":
            status_line.update(f"[bold red]● ERROR[/] {run.get('message', '')}")
        elif run.get("status") == "complete":
            status_line.update(f"[#4ade80]● COMPLETE[/] {run.get('message', '')}")
        else:
            status_line.update("[dim]no local run — press [b]n[/] to launch one[/]")

    def action_refresh(self) -> None:
        if not self.is_mounted or not self.display:
            return
        service = get_service()
        table = self.query_one(DataTable)
        table.clear()
        rows = [h.summary() for h in service.list_engagements()]
        if not rows:
            table.add_row("[dim]no engagements yet — press n to launch a run[/]", "", "", "", "", "", "", "")
            return
        current = service.current.name if service.current else ""
        for summary in rows:
            name = f"[cyan]{summary['name']}[/]" if summary["name"] == current else summary["name"]
            status = summary.get("status", "idle")
            status_fmt = {
                "running": "[#fbbf24]● running[/]",
                "complete": "[#4ade80]● complete[/]",
            }.get(status, f"[dim]{status}[/]")
            table.add_row(
                name,
                summary.get("target", "") or "—",
                status_fmt,
                str(summary.get("hosts", 0)),
                str(summary.get("vulns", 0)),
                str(summary.get("critical", 0)),
                str(summary.get("tool_runs", 0)),
                f"{summary.get('cost', 0.0):.2f}",
            )

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        service = get_service()
        rows = [h.name for h in service.list_engagements()]
        # Row order matches list order; the empty-placeholder row selects nothing.
        if rows and event.cursor_row < len(rows):
            service.select(rows[event.cursor_row])
            self.app.action_go("overview")

    def action_new_run(self) -> None:
        self.app.push_screen(NewRunModal(), self._start_run)

    def _start_run(self, params: dict | None) -> None:
        if not params:
            return
        service = get_service()
        service.run_state.update({"status": "starting", "message": f"engaging {params['target']}", "error": ""})
        self._run_worker(params["target"], params["scope"], params["methodology"])

    @work(thread=True, exclusive=True)
    def _run_worker(self, target: str, scope: str, methodology: str) -> None:
        get_service().launch_run(target, scope, methodology)

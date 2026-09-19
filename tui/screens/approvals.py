"""Operator approvals: agents that hit a DEFER hook block until you
decide. a=approve, d=deny, n=approve with a note."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, DataTable, Input, RichLog, Static

from tui.service import get_service


class NoteModal(ModalScreen):
    """Approve-with-note dialog."""

    CSS = """
    NoteModal { align: center middle; }
    """

    def __init__(self, request_id: str) -> None:
        super().__init__()
        self.request_id = request_id

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Static("▶ Approve with operator note", classes="modal-title")
            yield Input(placeholder="e.g. only against 10.10.10.5, not .6", id="note")
            with Horizontal():
                yield Button("Approve", variant="success", id="ok")
                yield Button("Cancel", variant="error", id="cancel")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "ok":
            self.dismiss(self.query_one("#note", Input).value.strip())
        else:
            self.dismiss(None)


class ApprovalsView(Vertical):
    BINDINGS = [
        ("a", "approve", "Approve"),
        ("d", "deny", "Deny"),
        ("n", "approve_note", "Approve+note"),
    ]

    def compose(self) -> ComposeResult:
        with Vertical():
            yield DataTable(id="approval-table", cursor_type="row", zebra_stripes=True)
            yield Static("", id="approval-detail")
            yield RichLog(id="approval-log", markup=True, wrap=True)

    def on_mount(self) -> None:
        self._columns_ready = False
        self.set_interval(2.0, self._poll)

    def on_show(self) -> None:
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
        self.query_one("#approval-table", DataTable).add_columns(
            "age", "urgency", "agent", "type", "tool", "description"
        )

    def _poll(self) -> None:
        if not self.is_mounted or not self.display:
            return
        service = get_service()
        self._pending = service.pending_approvals()
        table = self.query_one("#approval-table", DataTable)
        table.clear()
        if not self._pending:
            table.add_row("[dim]no pending requests — agents are operating without operator gates[/]", "", "", "", "", "")
        for req in self._pending:
            urgency_style = "bold red" if req["urgency"] == "high" else ""
            age = f"{int(req['age'])}s" if req["age"] < 90 else f"{int(req['age'] // 60)}m"
            table.add_row(
                age,
                f"[{urgency_style}]{req['urgency']}[/]" if urgency_style else req["urgency"],
                req["agent"],
                req["type"].replace("_", " "),
                req["tool"] or "—",
                req["description"][:60],
            )
        self._show_detail()

    def _show_detail(self) -> None:
        if not self.is_mounted:
            return
        table = self.query_one("#approval-table", DataTable)
        detail = self.query_one("#approval-detail", Static)
        if getattr(self, "_pending", None) and 0 <= table.cursor_row < len(self._pending):
            req = self._pending[table.cursor_row]
            detail.update(
                f"[bold]{req['agent']}[/] requests [cyan]{req['type'].replace('_', ' ')}[/]"
                f"{' on ' + req['tool'] if req['tool'] else ''}\n{req['description']}"
            )
        else:
            detail.update("[dim]waiting…[/]")

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        self._show_detail()

    def _log(self, line: str) -> None:
        self.query_one("#approval-log", RichLog).write(line)

    def _current(self) -> dict | None:
        pending = getattr(self, "_pending", [])
        table = self.query_one("#approval-table", DataTable)
        if pending and 0 <= table.cursor_row < len(pending):
            return pending[table.cursor_row]
        self._log("[dim]nothing selected[/]")
        return None

    def action_approve(self) -> None:
        req = self._current()
        if req and get_service().respond_approval(req["id"], True):
            self._log(f"[green]✓ approved[/] {req['description'][:70]}")

    def action_deny(self) -> None:
        req = self._current()
        if req and get_service().respond_approval(req["id"], False):
            self._log(f"[red]✗ denied[/] {req['description'][:70]}")

    def action_approve_note(self) -> None:
        req = self._current()
        if req:
            self.app.push_screen(NoteModal(req["id"]), self._note_done)

    def _note_done(self, note: str | None) -> None:
        if note is None:
            return
        table = self.query_one("#approval-table", DataTable)
        pending = getattr(self, "_pending", [])
        if pending and 0 <= table.cursor_row < len(pending):
            req = pending[table.cursor_row]
            if get_service().respond_approval(req["id"], True, note):
                self._log(f"[green]✓ approved[/] ({note}) {req['description'][:60]}")

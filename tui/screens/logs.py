"""Live feeds: in-process event bus stream, engagement conversation
turns (live_turns.jsonl), and raw tool log viewer."""

from __future__ import annotations

import json

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.widgets import DataTable, RichLog, Static

from tui.service import get_service
from tui.widgets import fmt_ts

FEEDS = ["event bus", "agent turns", "raw logs"]


class LogsView(Vertical):
    BINDINGS = [
        ("e", "feed('event bus')", "Event bus"),
        ("t", "feed('agent turns')", "Agent turns"),
        ("l", "feed('raw logs')", "Raw logs"),
        ("c", "clear", "Clear"),
    ]

    def compose(self) -> ComposeResult:
        with VerticalScroll():
            yield Static(
                "FEED  [b]e[/]=event bus · [b]t[/]=agent turns · [b]l[/]=raw logs · [b]c[/]=clear",
                classes="hint",
            )
            yield RichLog(id="feed-log", markup=True, wrap=True)
            yield DataTable(id="rawlog-table")

    def on_mount(self) -> None:
        self._feed = "event bus"
        self._unsubscribe = None
        self._turn_line = 0
        self._columns_ready = False
        self._activated = False
        self.set_interval(1.0, self._poll)

    def _ensure_columns(self) -> None:
        if self._columns_ready:
            return
        self._columns_ready = True
        self.query_one("#rawlog-table", DataTable).add_columns("raw log", "size", "modified")

    def on_show(self) -> None:
        self.call_after_refresh(self._shown_refresh)

    def _shown_refresh(self) -> None:
        if not self.is_mounted or not self.display:
            return
        self._ensure_columns()
        if not self._activated:
            self._activated = True
            self._activate_feed("event bus")

    # -- feed switching -----------------------------------------------------

    def action_feed(self, feed: str) -> None:
        self._activate_feed(feed)

    def action_clear(self) -> None:
        self.query_one("#feed-log", RichLog).clear()

    def _activate_feed(self, feed: str) -> None:
        log = self.query_one("#feed-log", RichLog)
        log.clear()
        self._feed = feed
        raw_table = self.query_one("#rawlog-table", DataTable)
        raw_table.display = feed == "raw logs"
        if self._unsubscribe is not None:
            self._unsubscribe()
            self._unsubscribe = None
        if feed == "event bus":
            try:
                from memory.event_bus import get_event_bus

                self._unsubscribe = get_event_bus().subscribe(self._on_event)
                log.write("[dim]listening to the in-process event bus…[/]")
            except Exception as exc:  # noqa: BLE001
                log.write(f"[red]event bus unavailable: {exc}[/]")
        elif feed == "agent turns":
            handle = get_service().current
            if handle is None:
                log.write("[dim]no engagement selected — pick one in Engagements (2)[/]")
            else:
                self._turn_line = 0
                log.write(f"[dim]tailing {handle.name}/logs/live_turns.jsonl …[/]")
        else:
            self._render_raw_list()
            log.write("[dim]select a raw log file below[/]")

    def on_unmount(self) -> None:
        if self._unsubscribe is not None:
            self._unsubscribe()

    # -- event bus --------------------------------------------------------

    def _on_event(self, event) -> None:
        if self._feed != "event bus":
            return
        try:
            data = getattr(event, "data", {}) or {}
            summary = data.get("action") or data.get("tool") or data.get("agent") or ""
            extra = data.get("description") or data.get("summary") or ""
            etype = getattr(getattr(event, "type", ""), "value", "?")
            line = f"[dim]{_now()}[/] [cyan]{etype}[/] [b]{getattr(event, 'source', '?')}[/] {summary} {str(extra)[:80]}"
            self.app.call_from_thread(self.query_one("#feed-log", RichLog).write, line)
        except Exception:  # noqa: BLE001 — never let a feed kill the bus
            pass

    # -- polling -----------------------------------------------------------

    def _poll(self) -> None:
        if not self.is_mounted or not self.display:
            return
        if self._feed == "agent turns":
            self._poll_turns()
        elif self._feed == "raw logs":
            self._render_raw_list()

    def _poll_turns(self) -> None:
        handle = get_service().current
        if handle is None:
            return
        log = self.query_one("#feed-log", RichLog)
        fresh = handle.files.read_live_turns(since_line=self._turn_line)
        for turn in fresh:
            self._turn_line += 1
            agent = turn.get("agent") or turn.get("role", "?")
            kind = turn.get("type", "")
            content = turn.get("content") or turn.get("text") or turn.get("summary") or ""
            if isinstance(content, (dict, list)):
                content = json.dumps(content)[:120]
            color = "cyan" if agent == "orchestrator" else "magenta"
            log.write(f"[dim]{_now()}[/] [{color}]{agent}[/] [dim]{kind}[/] {str(content)[:160]}")

    def _render_raw_list(self) -> None:
        if not self.is_mounted:
            return
        handle = get_service().current
        table = self.query_one("#rawlog-table", DataTable)
        table.clear()
        if handle is None:
            return
        import time as _time

        for entry in handle.files.list_raw_logs():
            table.add_row(
                entry["filename"],
                f"{entry['size_bytes'] / 1024:.1f}K",
                _time.strftime("%m-%d %H:%M", _time.localtime(entry["modified"])),
            )

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        if self._feed != "raw logs":
            return
        handle = get_service().current
        table = self.query_one("#rawlog-table", DataTable)
        logs = handle.files.list_raw_logs() if handle else []
        if logs and 0 <= event.cursor_row < len(logs):
            content = handle.files.read_raw_log(logs[event.cursor_row]["path"], tail_lines=400)
            log_widget = self.query_one("#feed-log", RichLog)
            log_widget.clear()
            log_widget.write(f"[dim]── {logs[event.cursor_row]['filename']} (tail 400) ──[/]")
            for line in content.splitlines():
                log_widget.write(line)


def _now() -> str:
    import datetime

    return datetime.datetime.now().strftime("%H:%M:%S")

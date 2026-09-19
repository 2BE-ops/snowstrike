"""SnowStrike TUI — terminal command center.

A Textual application for monitoring engagements, browsing the tool
catalog and agent roster, running flows, and answering approval
requests — the terminal-native replacement for the old web dashboard.

Layout: banner + footer chrome around a single view slot. Exactly one
view is mounted at a time; navigation unmounts the current view and
mounts the next fresh. (ContentSwitcher pane-swapping proved unreliable
under Textual 8.2.8's compositor; fresh mounts render cleanly.)
"""

from __future__ import annotations

from datetime import datetime

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.widgets import Footer, Static

from tui.service import get_service

NAV = [
    ("overview", "Overview"),
    ("engagements", "Engagements"),
    ("agents", "Agents"),
    ("tools", "Tools"),
    ("flows", "Flows"),
    ("approvals", "Approvals"),
    ("logs", "Logs"),
]


class Banner(Static):
    """Branded status bar: wordmark, current engagement, live clock."""

    def on_mount(self) -> None:
        self.set_interval(1.0, self._tick)
        self._tick()

    def _tick(self) -> None:
        # Skip updates while a view swap is in flight: a refresh here can
        # collide with the incoming view's first layout pass.
        if getattr(self.app, "_swap_in_flight", False):
            return
        service = get_service()
        eng = service.current.name if service.current else "no engagement"
        run = service.run_state
        if run.get("status") in {"starting", "running"}:
            run_badge = f" [#fbbf24 on #1a1000]● RUN {run.get('message', '')[:44]}[/]"
        elif run.get("status") == "error":
            run_badge = " [bold red]● RUN ERROR[/]"
        else:
            run_badge = ""
        self.update(
            f"[bold cyan]❄ SNOWSTRIKE[/] [dim]v7 · autonomous pentest runtime[/]"
            f"   [dim]engagement:[/] [b]{eng}[/]"
            f"{run_badge}"
            f"   [dim]{datetime.now():%H:%M:%S}[/]"
        )


def _build_view(key: str):
    from tui.screens.agents import AgentsView
    from tui.screens.approvals import ApprovalsView
    from tui.screens.engagements import EngagementsView
    from tui.screens.flows import FlowsView
    from tui.screens.logs import LogsView
    from tui.screens.overview import OverviewView
    from tui.screens.tools import ToolsView

    views = {
        "overview": OverviewView,
        "engagements": EngagementsView,
        "agents": AgentsView,
        "tools": ToolsView,
        "flows": FlowsView,
        "approvals": ApprovalsView,
        "logs": LogsView,
    }
    cls = views.get(key)
    return cls(id=f"view-{key}") if cls else None


class SnowStrikeApp(App):
    """Main application: persistent banner + footer, one live view."""

    TITLE = "SnowStrike"
    CSS_PATH = "styles.tcss"
    BINDINGS = [
        Binding("q", "quit", "Quit"),
        *[Binding(str(i + 1), f"go('{key.lower()}')", label, show=False)
          for i, (key, label) in enumerate(NAV)]
    ]

    def __init__(self) -> None:
        super().__init__()
        self.service = get_service()
        self._current_key: str | None = None
        self._swap_in_flight = False

    def compose(self) -> ComposeResult:
        with Vertical(id="root"):
            yield Banner(id="banner")
            yield Vertical(id="view-slot")
            yield Footer()

    def on_mount(self) -> None:
        # Default to the most recent engagement, if any exists.
        engagements = self.service.list_engagements()
        if engagements:
            self.service.select(engagements[0].name)
        self.action_go("overview")

    def action_go(self, key: str) -> None:
        """Swap the mounted view. Runs as a task: unmount, then mount."""
        if key == self._current_key:
            return
        self._current_key = key
        self.run_worker(self._swap_view(key), exclusive=True, group="nav")

    async def _swap_view(self, key: str) -> None:
        slot = self.query_one("#view-slot", Vertical)
        view = _build_view(key)
        if view is None:
            return
        self._swap_in_flight = True
        try:
            # Batch the unmount+mount so no partial render happens between them.
            with self.batch_update():
                await slot.remove_children()
                await slot.mount(view)
            self.call_after_refresh(self._focus_view, view)
        finally:
            self._swap_in_flight = False

    def _focus_view(self, view) -> None:
        if not view.is_mounted:
            return
        tables = view.query("DataTable")
        if tables:
            tables.first().focus()
        else:
            inputs = view.query("Input")
            if inputs:
                inputs.first().focus()


def run() -> None:
    """Entry point used by the CLI."""
    SnowStrikeApp().run()

"""Tool catalog browser: searchable, category-filtered, with live
binary availability and a detail pane for the selected tool.

Search opens as a modal ("/") so no inline input widget lives in the
view itself; categories cycle with "c".
"""

from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, DataTable, Input, Static

from tui.service import get_service


class SearchModal(ModalScreen):
    """Filter dialog: type a substring, Enter to apply."""

    CSS = """
    SearchModal { align: center middle; }
    """

    def __init__(self, initial: str = "") -> None:
        super().__init__()
        self._initial = initial

    def compose(self) -> ComposeResult:
        with Vertical(classes="modal"):
            yield Static("Search tool catalog", classes="modal-title")
            yield Input(value=self._initial, placeholder="name or description substring", id="q")
            with Horizontal(classes="modal-buttons"):
                yield Button("Apply", variant="success", id="apply")
                yield Button("Clear", variant="error", id="clear")

    def on_mount(self) -> None:
        self.query_one("#q", Input).focus()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        self.dismiss(event.value.strip())

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "apply":
            self.dismiss(self.query_one("#q", Input).value.strip())
        else:
            self.dismiss("")


class ToolsView(Vertical):
    BINDINGS = [
        ("slash", "search", "Search"),
        ("c", "cycle_category", "Category"),
        ("r", "refresh", "Refresh"),
    ]

    def compose(self) -> ComposeResult:
        with VerticalScroll():
            yield Static("", id="tool-header", classes="hint")
            yield DataTable(id="tool-table", cursor_type="row", zebra_stripes=True)
            yield Static("", id="tool-detail")

    def on_mount(self) -> None:
        self._tools: list[dict] = []
        self._availability: dict[str, bool] = {}
        self._columns_ready = False
        self._category = ""
        self._categories: list[str] = []
        self._needle = ""
        # All widget mutation happens after the first frame settles; touching
        # widgets during mount races pending compositor refreshes.
        self.call_after_refresh(self._late_mount)

    def _late_mount(self) -> None:
        if not self.is_mounted or not self.display:
            return
        self._ensure_columns()
        self.action_refresh()

    def _ensure_columns(self) -> None:
        if self._columns_ready:
            return
        self._columns_ready = True
        self.query_one("#tool-table", DataTable).add_columns(
            "tool", "category", "binary", "here?", "root", "agents"
        )

    def action_refresh(self) -> None:
        if not self.is_mounted or not self.display:
            return
        service = get_service()
        self._tools = service.tool_catalog()
        self._availability = service.binary_availability()
        self._categories = sorted({t.get("category", "utility") for t in self._tools})
        self._render()

    def action_search(self) -> None:
        self.app.push_screen(SearchModal(self._needle), self._search_done)

    def _search_done(self, needle: str | None) -> None:
        if needle is None:
            return
        self._needle = needle
        self._render()

    def action_cycle_category(self) -> None:
        """Cycle the category filter: all → first → … → all."""
        if not self._categories:
            return
        if self._category == "":
            self._category = self._categories[0]
        else:
            idx = self._categories.index(self._category)
            self._category = "" if idx + 1 >= len(self._categories) else self._categories[idx + 1]
        self._render()

    def _render(self) -> None:
        if not self.is_mounted or not self.display:
            return
        needle = self._needle.lower()
        category_filter = self._category != ""
        filter_desc = self._category or "all categories"
        if self._needle:
            filter_desc += f" · search '{self._needle}'"
        self.query_one("#tool-header", Static).update(
            f"[b]{len(self._tools)}[/] tools · [cyan]{filter_desc}[/] "
            f"[dim]· / search · c next category · r refresh[/]"
        )
        table = self.query_one("#tool-table", DataTable)
        table.clear()
        for tool in sorted(self._tools, key=lambda t: (t.get("category", ""), t.get("name", ""))):
            if category_filter and tool.get("category") != self._category:
                continue
            haystack = f"{tool.get('name', '')} {tool.get('description', '')}".lower()
            if needle and needle not in haystack:
                continue
            available = self._availability.get(tool.get("name", ""), True)
            binary = tool.get("binary") or "-"
            here = "[green]✓[/]" if available else "[red]✗[/]"
            root = "[yellow]root[/]" if tool.get("requires_root") else ""
            agents = ", ".join(tool.get("compatible_agents", [])[:4]) or "—"
            table.add_row(
                f"[cyan]{tool.get('name', '?')}[/]",
                str(tool.get("category", "")),
                str(binary),
                here,
                root,
                agents,
            )

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if not self.display:
            return
        shown = self._visible_tools()
        if 0 <= event.cursor_row < len(shown):
            tool = shown[event.cursor_row]
            agents = ", ".join(tool.get("compatible_agents", [])) or "—"
            summary = f"[bold cyan]{tool.get('name')}[/] · {tool.get('category')} · binary: {tool.get('binary') or 'none'}"
            summary += f" — {tool.get('description', '')} [dim]· compatible: {agents}[/]"
            self.query_one("#tool-detail", Static).update(summary)

    def _visible_tools(self) -> list[dict]:
        needle = self._needle.lower()
        category_filter = self._category != ""
        out = []
        for tool in sorted(self._tools, key=lambda t: (t.get("category", ""), t.get("name", ""))):
            if category_filter and tool.get("category") != self._category:
                continue
            haystack = f"{tool.get('name', '')} {tool.get('description', '')}".lower()
            if needle and needle not in haystack:
                continue
            out.append(tool)
        return out

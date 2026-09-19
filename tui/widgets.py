"""Small shared widgets for the TUI screens."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Vertical
from textual.widgets import Static

from tui.service import SEVERITY_STYLES


class StatCard(Vertical):
    """A bordered stat tile: small label over a large accent value."""

    def __init__(self, label: str, value: str = "—", style_class: str = "") -> None:
        super().__init__(classes=f"stat-card {style_class}".strip())
        self.label = label
        self.value = value
        self._style_class = style_class

    def compose(self) -> ComposeResult:
        yield Static(self.label, classes="stat-label", markup=False)
        self._value_widget = Static(self.value, classes="stat-value")
        yield self._value_widget

    def set_value(self, value: str) -> None:
        self._value_widget.update(value)


def severity_markup(severity: str) -> str:
    """Wrap a severity word in its display style."""
    style = SEVERITY_STYLES.get(str(severity).lower(), "dim")
    return f"[{style}]{severity}[/]"


def fmt_ts(ts) -> str:
    """Compact HH:MM:SS rendering of a unix or ISO-ish timestamp."""
    if ts is None:
        return "—"
    try:
        f = float(ts)
        if f > 1_000_000_000:  # unix epoch seconds
            from datetime import datetime

            return datetime.fromtimestamp(f).strftime("%H:%M:%S")
    except (TypeError, ValueError):
        pass
    text = str(ts)
    return text[11:19] if len(text) >= 19 else text

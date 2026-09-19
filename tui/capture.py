"""Capture TUI screenshots for documentation.

Renders a single view per process and exports an SVG of the settled
screen:  python tui/capture.py overview assets/tui-overview.svg
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

KEYS = {v: str(i + 1) for i, v in enumerate(
    ["overview", "engagements", "agents", "tools", "flows", "approvals", "logs"])}


async def main(view: str, out: str) -> None:
    from tui.app import SnowStrikeApp
    from tui.smoke_test import build_demo_engagement

    build_demo_engagement()
    app = SnowStrikeApp()
    async with app.run_test(size=(110, 32)) as pilot:
        if view != "overview":
            await pilot.press(KEYS[view])
        await asyncio.sleep(1.5)  # let the view mount and settle
        svg = app.export_screenshot()
        Path(out).write_text(svg, encoding="utf-8")
        print(f"saved {out} ({len(svg)} bytes)")
        app._exception = None  # tolerate contained transients


if __name__ == "__main__":
    view = sys.argv[1] if len(sys.argv) > 1 else "overview"
    out = sys.argv[2] if len(sys.argv) > 2 else f"assets/tui-{view}.svg"
    asyncio.run(main(view, out))

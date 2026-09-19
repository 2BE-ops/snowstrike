"""Flow control: list definitions, validate, run with inputs, and
inspect recent run workspaces."""

from __future__ import annotations

import time

from textual import work
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, DataTable, Input, Label, RichLog, Static

from tui.service import get_service


class FlowRunModal(ModalScreen):
    """Dialog for a flow's inputs (key=value lines)."""

    CSS = """
    FlowRunModal { align: center middle; }
    """

    def __init__(self, flow_name: str) -> None:
        super().__init__()
        self.flow_name = flow_name

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Static(f"▶ Run flow: {self.flow_name}", classes="modal-title")
            yield Label("Inputs, one per line, as key=value")
            yield Input(placeholder="target=10.10.10.5", id="inputs")
            with Horizontal():
                yield Button("Run", variant="success", id="run")
                yield Button("Cancel", variant="error", id="cancel")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "run":
            inputs: dict[str, str] = {}
            for chunk in self.query_one("#inputs", Input).value.split():
                key, sep, value = chunk.partition("=")
                if sep and key:
                    inputs[key] = value
            self.dismiss({"name": self.flow_name, "inputs": inputs})
        else:
            self.dismiss(None)


class FlowsView(Vertical):
    BINDINGS = [
        ("enter", "run_flow", "Run flow"),
        ("v", "validate_all", "Validate all"),
        ("r", "refresh", "Refresh"),
    ]

    def compose(self) -> ComposeResult:
        with Vertical():
            yield DataTable(id="flow-table", cursor_type="row", zebra_stripes=True)
            yield Static("RECENT RUNS", classes="section-title")
            yield DataTable(id="workspace-table", cursor_type="row", zebra_stripes=True)
            yield Static("CONSOLE", classes="section-title")
            yield RichLog(id="flow-console", markup=True, wrap=True)

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
        self.query_one("#flow-table", DataTable).add_columns(
            "flow", "category", "steps", "mode", "description"
        )
        self.query_one("#workspace-table", DataTable).add_columns(
            "workspace", "flow", "status", "when"
        )

    def action_refresh(self) -> None:
        if not self.is_mounted or not self.display:
            return
        service = get_service()

        flow_table = self.query_one("#flow-table", DataTable)
        flow_table.clear()
        flows = service.flow_list()
        if not flows:
            flow_table.add_row("[dim]no flow definitions in flows/definitions/[/]", "", "", "", "")
        for flow in flows:
            flow_table.add_row(
                f"[cyan]{flow.get('name', '?')}[/]",
                str(flow.get("category", "")),
                str(flow.get("step_count", "?")),
                str(flow.get("execution_mode", "")),
                str(flow.get("description", ""))[:70],
            )

        ws_table = self.query_one("#workspace-table", DataTable)
        ws_table.clear()
        workspaces = service.recent_flow_workspaces()
        if not workspaces:
            ws_table.add_row("[dim]no runs yet[/]", "", "", "")
        for ws in workspaces[:8]:
            when = time.strftime("%m-%d %H:%M", time.localtime(ws.get("mtime", 0)))
            ws_table.add_row(
                ws.get("name", "?"),
                str(ws.get("flow_name", "?")),
                str(ws.get("status", "?")),
                when,
            )

    def _log(self, line: str) -> None:
        self.query_one("#flow-console", RichLog).write(line)

    # -- actions -----------------------------------------------------------

    def action_validate_all(self) -> None:
        service = get_service()
        defs_dir = service.flow_definitions_dir()
        self._log(f"[dim]validating {defs_dir} …[/]")
        ok = 0
        failed = 0
        for yaml_path in sorted(defs_dir.glob("*.yaml")):
            errors = service.flow_validate(str(yaml_path))
            if errors:
                failed += 1
                self._log(f"[red]✗ {yaml_path.name}[/]")
                for err in errors:
                    self._log(f"   {err}")
            else:
                ok += 1
                self._log(f"[green]✓[/] {yaml_path.name}")
        self._log(f"[bold]{ok} valid, {failed} invalid[/]")

    def action_run_flow(self) -> None:
        table = self.query_one("#flow-table", DataTable)
        flows = get_service().flow_list()
        if not flows or table.cursor_row >= len(flows):
            return
        flow = flows[table.cursor_row]
        self.app.push_screen(FlowRunModal(flow["name"]), self._start_flow)

    def _start_flow(self, params: dict | None) -> None:
        if not params:
            return
        self._log(f"[bold cyan]▶ {params['name']}[/] inputs={params['inputs']} — starting…")
        self._flow_worker(params["name"], params["inputs"])

    @work(thread=True, exclusive=True, group="flow-run")
    def _flow_worker(self, name: str, inputs: dict) -> None:
        import traceback

        service = get_service()
        try:
            result = service.flow_run(name, inputs)
            self.app.call_from_thread(self._render_result, result)
        except Exception as exc:  # noqa: BLE001 — report to console
            detail = traceback.format_exc(limit=3)
            self.app.call_from_thread(self._log, f"[bold red]flow failed:[/] {exc}\n{detail}")

    def _render_result(self, result: dict) -> None:
        status_color = "green" if result["status"] == "completed" else "red"
        self._log(
            f"[{status_color}]{result['status'].upper()}[/] {result['flow']} "
            f"in {result['duration']:.1f}s  ${result['cost']:.4f}  ws: {result['workspace']}"
        )
        for step_id, step in result["steps"].items():
            icon = {"completed": "[green]+[/]", "failed": "[red]×[/]", "skipped": "[dim]-[/]"}.get(
                step["status"], "?"
            )
            self._log(f"  {icon} {step_id} ({step['duration']:.1f}s)")
            for err in step.get("errors", []):
                self._log(f"     [red]{str(err)[:120]}[/]")
        if result.get("outputs"):
            for key, value in result["outputs"].items():
                self._log(f"  [cyan]→[/] {key} = {str(value)[:120]}")
        self.action_refresh()

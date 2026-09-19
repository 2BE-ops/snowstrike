# Flows

Flows are user-defined DAG workflows that mix **agentic steps** (dispatch a task
to a SnowStrike specialist agent) with **deterministic steps** (tool execution,
HTTP calls, data transforms, conditionals, parallel forks, subflows, event
waits, template rendering, and artifact persistence).

They complement the orchestrator: the orchestrator decides *what to do next* on
its own each iteration, while a flow pins down a *known-good sequence* you want
to run the same way every time — for example a repeatable recon-to-report
pipeline.

## Anatomy of a flow

A flow is a YAML file in `flows/definitions/`:

```yaml
apiVersion: snowstrike/v1
kind: Flow
metadata:
  name: asset-discovery
  description: Sweep a scope and report live assets
triggers: []          # optional: event / schedule triggers
steps:
  - id: sweep
    type: tool        # deterministic tool execution
    tool: nmap_scan
    inputs:
      target: "{{ flow.target }}"
    outputs: [hosts]

  - id: triage
    type: agent       # agentic step — dispatched to a specialist agent
    agent: recon
    task: "Triage these hosts and rank attack surface: {{ steps.sweep.hosts }}"

  - id: report
    type: template
    template: report.md.j2
    artifacts:
      - "{{ workspace }}/report.md"
```

## Step types

| Type | Handler | Purpose |
|---|---|---|
| `agent` | `agent_handler` | Dispatch a task to a specialist agent |
| `tool` | `tool_handler` | Execute a catalog tool deterministically |
| `http` | `http_handler` | Call an HTTP endpoint |
| `transform` | `transform_handler` | Reshape/combine step outputs |
| `condition` | `condition_handler` | Branch on an expression |
| `parallel_fork` | `parallel_fork_handler` | Fan out steps concurrently |
| `subflow` | `subflow_handler` | Invoke another flow |
| `wait_event` | `wait_event_handler` | Pause until an event fires |
| `template` | `template_handler` | Render a Jinja template |
| `artifact` | `artifact_handler` | Persist outputs to the workspace |

## Triggers

- **Manual** — start via CLI or the TUI
- **Event** — start when a matching event hits the event bus
- **Schedule** — cron expression (via `croniter`)
- **Agent request** — an agent can request a flow mid-engagement

## Running flows

CLI:

```bash
python3 snowstrike_cli.py flow-list
python3 snowstrike_cli.py flow-validate flows/definitions/asset-discovery.yaml
python3 snowstrike_cli.py flow-run asset-discovery --target 10.10.10.5
python3 snowstrike_cli.py flow-status <workspace-dir>
```

The TUI's Flows screen wraps the same engine (list, validate, run, status).

Each run materializes a workspace directory (`flow-workspaces/`) holding step
state and artifacts. Workspaces are runtime data and are gitignored.

## Implementation map

- `flows/schema.py` — flow/step dataclasses and parsing
- `flows/engine.py` — DAG execution engine
- `flows/runner.py` — run lifecycle and workspace management
- `flows/step_executor.py` — step dispatch and retries
- `flows/handlers/` — the ten step handlers above
- `flows/triggers.py` — `TriggerDispatcher` (event, schedule, agent request)
- `flows/registry.py` — definition loading and validation
- `flows/validators.py` — structural checks (cycles, unknown steps, I/O refs)
- `flows/condition_eval.py`, `flows/template_env.py` — expression and templating support
- `flows/hooks.py` — flow lifecycle hooks

Shipped example definitions live in `flows/definitions/`:
`asset-discovery.yaml`, `osint-recon-report.yaml`, `binary-re-report.yaml`.

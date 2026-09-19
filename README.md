# SnowStrike AI v7

SnowStrike is a Python multi-agent penetration testing runtime for authorized security testing.
It combines an LLM-driven orchestrator, specialist task agents, a shared memory layer, a modular
YAML-driven agent/tool registry, a DAG workflow engine (flows), and a FastAPI dashboard with a
visual agent builder.

## How It Works

Each iteration, the orchestrator evaluates a compact **intelligence brief** — current state,
findings, failed approaches — and picks the single highest-value next action. It dispatches
that action to a specialist agent, which executes real security tooling (nmap, nuclei, sqlmap,
hashcat, ...) through a hardened subprocess executor. Results land in a shared memory layer and
feed the next brief. The loop runs until the objective is met or iteration limits hit.

**Flows** complement the loop: user-defined DAG pipelines that mix agentic steps with
deterministic ones (tool runs, HTTP calls, transforms, conditionals, parallel forks) for
repeatable sequences. See [docs/flows.md](docs/flows.md).

## What Is In This Repository

- 1 orchestrator agent
- 10 specialist task agents: `recon`, `webapp`, `browser`, `attack`, `cloud`, `binary`,
  `ghidra`, `forensics`, `osint`, `reporting`
- 1 monitoring agent: `alerts`
- 158 tool wrappers in the YAML tool catalog (`tools/catalog/`)
- 10 YAML agent configs (`agent-configs/agents/`)
- 8 agent templates (`agent-configs/templates/`)
- 4 topology presets (`agent-configs/topologies/`)
- Flow engine with 10 step types, event/schedule/manual triggers, and 3 example definitions
- Dynamic `AgentRegistry` and `ToolRegistry` with hot-reload
- Visual agent builder UI with Cytoscape.js graph editor
- Multi-provider model support through a unified client layer

Scope notes:

- There is no standalone `inject` or `credential` agent; those responsibilities are implemented
  by `webapp` and `attack`.
- The `ghidra` agent is a specialized reverse-engineering agent using the Ghidra MCP bridge.

## Quick Start

### 1) Python Environment

Requires Python 3.12+.

```bash
python3 -m venv snowstrike-env
source snowstrike-env/bin/activate    # Windows: snowstrike-env\Scripts\activate
pip install -e ".[dev]"               # uses pyproject.toml
```

Optional, for browser-driven workflows:

```bash
pip install -e ".[browser]"
playwright install chromium
```

### 2) API Keys

```bash
cp .env.example .env
# edit .env — at minimum one LLM provider key (e.g. ANTHROPIC_API_KEY)
```

All keys are read from the environment; nothing is hardcoded.

### 3) External Security Tooling

Most agent workflows depend on native binaries. Typical examples:

- Recon: `nmap`, `rustscan`, `masscan`, `httpx`, `whatweb`, `wafw00f`, `testssl`
- Web: `gobuster`, `feroxbuster`, `ffuf`, `katana`, `nikto`, `nuclei`, `sqlmap`, `wpscan`, `arjun`
- Attack: `netexec`, `hydra`, `john`, `hashcat`, `searchsploit`, `msfconsole`, `evil-winrm`
- Binary/forensics/cloud: `radare2`, `gdb`, `binwalk`, `trivy`, `prowler`, `kube-hunter`, `kube-bench`

Tool wrappers are compatibility-gated at runtime. Missing or unsupported binaries are skipped
cleanly — the framework runs fine with a partial toolset.

### 4) Run

Dashboard:

```bash
python3 -m dashboard.app --port 8080
```

Then open `http://localhost:8080` (dashboard) or `http://localhost:8080/builder` (agent builder).

CLI:

```bash
python3 snowstrike_cli.py list-presets
python3 snowstrike_cli.py flow-list
python3 snowstrike_cli.py --help
```

Python API:

```python
from agents.orchestrator import OrchestratorAgent

orch = OrchestratorAgent.create_engagement(
    target="10.10.10.1",
    scope="10.10.10.0/24",
    methodology="standard",
)

result = orch.run_autonomous()
print(result)
```

## Agent Catalog

- `orchestrator`: strategy, dispatch, guardrails, iterative control
- `recon`: host/service discovery and environment mapping
- `webapp`: web discovery, fuzzing, and injection testing
- `browser`: rendered page analysis and browser evidence collection
- `attack`: exploitation, credential attacks, post-exploitation
- `cloud`: cloud/container/K8s assessment
- `binary`: reverse engineering and exploit-dev tasks
- `ghidra`: Ghidra-backed reverse engineering via MCP bridge
- `forensics`: memory/file/stego/crypto triage
- `osint`: passive external intelligence
- `reporting`: report synthesis from stored artifacts
- `alerts`: lightweight monitoring and anomaly highlighting

See [docs/agents.md](docs/agents.md) for the agent engineering guide.

## Agent Builder

The visual agent builder (`/builder`) provides:

- **Canvas graph editor**: agents as nodes, handoff edges, topology visualization
- **Config sidebar**: edit agent properties (model, tools, capabilities, handoff targets)
- **Tool marketplace**: searchable catalog with binary availability indicators
- **Topology presets**: hub-and-spoke, pipeline, swarm, red-blue
- **Template library**: 8 pre-built agent templates for quick cloning
- **Live validation**: cycle detection, binary checks, API key checks, prompt existence
- **Hot-reload**: push config changes into the running orchestrator

Builder API endpoints live at `/api/builder/` — see `dashboard/api/builder.py`.

## Modular Configuration

Agents and tools are defined in YAML and loaded at startup by dynamic registries. The system
falls back to hardcoded Python definitions if no YAML configs are found.

Agent config (`agent-configs/agents/recon.yaml`):

```yaml
apiVersion: snowstrike/v1
kind: Agent
metadata:
  name: recon
  version: 1
spec:
  display_name: "Recon Specialist"
  agent_class: agents.recon_agent.ReconAgent
  model: claude-sonnet-4-20250514
  max_turns: 30
  max_concurrent: 3
  prompt:
    template: recon
  tools:
    - nmap_scan
    - masscan_scan
  capabilities:
    produces: [open_ports, service_versions]
    requires: [target_hosts]
  handoff_targets: [webapp, attack, orchestrator]
```

Tool config (`tools/catalog/nmap_scan.yaml`):

```yaml
apiVersion: snowstrike/v1
kind: Tool
metadata:
  name: nmap_scan
  category: network_scanning
  requires_root: true
  binary: nmap
spec:
  description: "Run nmap port scan against target"
  input_schema:
    type: object
    properties:
      target: { type: string }
      ports: { type: string }
    required: [target]
  timeout: 420
  compatible_agents: [recon, attack]
```

Creating a new agent requires no code changes: add YAML to `agent-configs/agents/`, or use the
builder UI, then call `POST /api/builder/reload` to hot-reload.

## Configuration

Runtime configuration is in `config/settings.py`; the model registry is `config/models.yaml`.

Model tiers: `orchestrator`, `planning`, `tool_calling`, `compaction`.

Common environment variables (see `.env.example` for the full list):

- Provider keys: `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `XAI_API_KEY`
- Model tier overrides: `SNOWSTRIKE_ORCHESTRATOR_MODEL`, `SNOWSTRIKE_TOOL_CALLING_MODEL`,
  `SNOWSTRIKE_COMPACTION_MODEL`
- Runtime limits: `SNOWSTRIKE_MAX_PARALLEL`, `SNOWSTRIKE_MAX_TURNS`, `SNOWSTRIKE_MAX_ITERATIONS`
- Registry paths: `AGENT_CONFIG_DIR`, `TOOL_CATALOG_DIR`

## Directory Structure

```
snowstrike/
  agents/
    orchestrator.py         # Orchestrator decision loop
    base_agent.py           # Base agent execute loop
    registry.py             # AgentRegistry (YAML loader)
    protocol.py             # Capabilities, handoff queue
    model_client.py         # Multi-provider model client
    scope_monitor.py        # Scope enforcement monitor
    verification_gate.py    # Verification gate
    *_agent.py              # Specialist agent subclasses
    prompts/*.md            # Agent system prompts
  tools/
    definitions.py          # Tool schemas + command builders
    registry_loader.py      # ToolRegistry (YAML loader)
    executor.py             # Subprocess executor
    compatibility.py        # Binary compatibility probing
    hooks.py                # Hook-based tool interception
    scope_hook.py           # Scope enforcement hook
    browser_backend.py      # Browser automation backend
    ghidra_mcp_client.py    # Ghidra MCP bridge client
    catalog/*.yaml          # Per-tool YAML configs (158 tools)
  flows/
    engine.py               # DAG execution engine
    triggers.py             # Event/schedule/manual triggers
    handlers/               # 10 step-type handlers
    definitions/*.yaml      # Example flow definitions
  memory/
    database.py             # SQLite manager
    shared_state.py         # File-locked coordination state
    event_bus.py            # In-process event bus
    attack_story.py         # Narrative timeline
    network_map.py          # Network graph
    compactor.py            # Context compaction
    cost_tracker.py         # LLM cost accounting
    engagement_memory.py    # Cross-engagement memory
    scope_validator.py      # Scope boundary enforcement
  profiles/                 # Model profile + metrics management
  agent-configs/            # Agent configs, templates, topology presets
  config/                   # Runtime config, model registry, JSON schemas
  dashboard/                # FastAPI app, API routers, UI (templates/static)
  tool_runner/              # Optional remote tool-execution service
  docker/                   # Dockerfiles (snowstrike, ghidra, toolrunner, base)
  tests/                    # Pytest suites
  engagements/              # Per-engagement runtime data (gitignored)
```

## Engagement Data Layout

Each engagement lives under `engagements/<name>/`:

```text
engagements/<name>/
  snowstrike.db          # SQLite artifact store
  STATE.json             # File-locked coordination state
  STORY.md               # Append-only narrative log
  network_map.json
  handoff_queue.json
  metrics.json
  PLAN.md / plan.json
  logs/
    raw/                 # Raw tool output
    conversations/       # Agent transcripts
  loot/                  # Collected findings
```

Not every file exists immediately; some are created lazily.

## Docker

A three-service stack (dashboard + Ghidra MCP + tool runner):

```bash
docker compose up --build
```

The dashboard binds to `127.0.0.1:8080` only. Ghidra and tool-runner are internal services with
health checks. External binaries are expected to be available to the tool-runner image or
network.

## Testing

```bash
pytest -q
```

110 tests across suites in `tests/`: command builders, tool failure hardening, replay harness,
dynamic limits, orchestrator guards, and master profiles.

## Documentation

- [docs/flows.md](docs/flows.md) — flow engine: step types, triggers, CLI, examples
- [docs/agents.md](docs/agents.md) — agent engineering guide and best practices

## Operational Boundaries

- Many integrated security tools need elevated privileges or capabilities.
- Dashboard and CLI operate on the same engagement state and are not isolated sandboxes.
- `STATE.json` is for coordination; SQLite is the better source for structured post-run facts.
- Autonomous quality depends on strict JSON decisions from the orchestrator model.

## Legal and Safety

SnowStrike is built for penetration testers working under explicit authorization. Use only on
systems you are authorized to test. You are responsible for complying with laws, contracts,
and rules of engagement.

## License

Released under the [MIT License](LICENSE).

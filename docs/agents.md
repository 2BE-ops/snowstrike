# SnowStrike Agents Guide

This guide documents how to design, operate, and extend agent workflows in SnowStrike.
It is intentionally implementation-aware: guidance is tied to the current codebase behavior.

## 1. Agentic Design Goals

SnowStrike agents are expected to be:

- goal-directed, not tool-directed
- bounded (time, scope, and retries)
- evidence-first (persist findings early)
- state-aware (reuse prior work, avoid loops)
- composable (clear handoff outputs)
- observable (traceable decisions and outcomes)

In practice this means:

- always formulate a concrete hypothesis before a tool call
- run one high-value action at a time when uncertainty is high
- capture actionable output immediately (`save_finding`, state updates)
- stop repeating low-signal actions and pivot fast

## 2. Agent Roles in This Repository

Dispatchable task agents:

- `recon`
- `webapp`
- `browser`
- `attack`
- `cloud`
- `binary`
- `ghidra`
- `forensics`
- `osint`
- `reporting`

Control/auxiliary agents:

- `orchestrator`: decision-maker, dispatch, guardrails, budget enforcement
- `alerts`: read-only monitor for noteworthy run events

All task agents are defined as YAML configs in `agent-configs/agents/*.yaml` and loaded by `AgentRegistry`. The Python class, model, tools, capabilities, and handoff targets are all configurable per-agent without code changes.

## 3. Execution Contracts

### 3.1 Orchestrator Contract

The orchestrator expects strict JSON decisions from the model.
Primary actions:

- `dispatch`
- `parallel`
- `finish`
- `error`

A dispatch is only valid if:

- agent type exists (in registry or hardcoded fallback)
- task is specific and scoped
- it passes pre-dispatch checks and dedupe/cooldown gates

### 3.2 Sub-Agent Contract

Each sub-agent should return:

- concise summary of what happened
- clear success/failure signal
- enough context for next-step planning
- persisted findings/state updates where applicable

In SnowStrike, this is materialized by `AgentResult` (`success`, `summary`, `tools_used`, `errors`, `suggested_next_steps`, `outcome_class`).

## 4. Task Design Best Practices

A high-quality task should contain all of the following:

1. Hypothesis
- what you expect to validate or disprove

2. Target specificity
- host(s), service(s), port(s), URL(s), parameter(s), credential set(s)

3. Stop condition
- when the agent should stop trying the current path

4. Expected artifact
- what should be produced (credential pair, vuln confirmation, shell, evidence)

Bad task:

- "Try to hack the target"

Good task:

- "Test known credentials against SSH and WinRM on host X; stop after single pass; persist any valid auth and failed matrix summary."

## 5. Tool-Use Discipline

### 5.1 Prefer Incremental Escalation

Use a low-cost discovery/existence check before high-cost deep scans.

Example pattern:

1. identify target and candidate surface
2. run focused probe
3. escalate only on signal

### 5.2 Avoid Redundant Tool Calls

SnowStrike already has session and cross-session dedupe safeguards.
Agent logic should still avoid retries unless one of these changed:

- scope/arguments
- newly discovered evidence
- execution environment compatibility

### 5.3 Respect Budgets

Every tool run consumes shared budget.
Agent behavior should avoid:

- repeating broad scans on unchanged targets
- stacking multiple heavy long-running tools in one turn without reason
- retry storms after wrapper/environment failures

### 5.4 Distinguish Failure Types

Treat these differently:

- wrapper/config errors -> fix parameters or compatibility first
- target refusal/unreachable -> pivot target path
- empty/no-signal -> avoid same approach repetition
- partial success -> extract signal and continue from evidence

## 6. Shared State and Artifact Hygiene

### 6.1 Persist Early

When a finding is credible, persist it immediately.
Do not defer persistence to end-of-run summaries.

Use shared tools deliberately:

- `save_finding`
- `update_shared_state`
- `add_to_network_map`

### 6.2 Keep State Structured and Minimal

Store durable facts, not speculative narratives.

Good:

- host/service/version
- confirmed creds
- confirmed vuln metadata
- validated access levels

Avoid:

- large raw output blobs in state
- speculative claims without evidence

### 6.3 Scope Fidelity

All state/handoff writes should remain in engagement scope.
Out-of-scope pollution reduces orchestrator signal quality and causes bad dispatches.

## 7. Handoff Best Practices

Handoffs should be:

- typed
- concise
- confidence-scored
- actionable by the target agent

A good handoff contains:

- what changed
- why it matters
- what the receiver should do next
- minimum required context (targets, protocol, evidence summary)

Avoid duplicate and low-confidence handoffs.

## 8. Orchestrator-Friendly Agent Summaries

The orchestrator uses recent summaries for subsequent decisions.
Write summaries to optimize downstream planning:

- first line: result status and key outcome
- include concrete evidence references (host/port/path/credential)
- include one or two clear next steps
- explicitly call out blockers and exhaustion conditions

Example summary shape:

- "Confirmed SQLi on X endpoint at Y host; no shell yet; next step is targeted exploit path Z; broad fuzzing no longer useful."

## 9. Loop Avoidance Patterns

To avoid recon/fuzz loops:

- detect no-progress streaks quickly
- switch modality (recon -> exploit, exploit -> credential testing, etc.)
- ban or cool down failing fingerprints
- treat model refusals as control-plane events, not target-side failures

When in doubt:

- prefer one bounded high-probability action over repeated broad scans

## 10. Prompting Patterns for Agentic Reliability

### 10.1 Keep Prompts Role-Clean

Each agent prompt should focus on:

- role scope
- tool ordering
- methodology
- termination expectations

Do not duplicate large global context rules inside every prompt if they are already enforced in orchestration.

### 10.2 Encode Sequencing, Not Scripts

Prompts should define decision order and constraints, not rigid one-size scripts.

Good:

- "If credentials exist, credential reuse is priority before brute-force."

Not ideal:

- long static command sequences that ignore context and prior results

### 10.3 Make Exit Criteria Explicit

Prompts should state when to stop a tactic and escalate/pivot.
This directly reduces dead-end iterations.

## 11. Observability Requirements

Good agentic systems are debuggable.
SnowStrike already captures:

- conversation logs
- live turn feeds
- raw tool output
- outcome classification
- refusal logs
- cost accounting

When extending agent behavior, preserve observability by:

- emitting meaningful summaries
- preserving tool outcome context
- avoiding hidden side effects

## 12. Extending the System: New Agent Checklist

When adding a new agent type:

### Option A: YAML-only (no code changes)

1. Create `agent-configs/agents/<name>.yaml` with the standard schema
2. Set `spec.tools` to tool names from `tools/catalog/`
3. Set `spec.capabilities` (skills, produces, requires)
4. Set `spec.handoff_targets`
5. Create a prompt template at `agents/prompts/<name>.md`
6. Reload: `POST /api/builder/reload` or restart the dashboard
7. The orchestrator will dispatch `BaseAgent` configured by YAML

Or use the builder UI: `http://localhost:8080/builder` → "New Agent" or "Templates".

### Option B: Custom Python class

1. Create `agents/<name>_agent.py` subclassing `BaseAgent`
2. Set `agent_name` and `agent_type`
3. Create YAML config with `spec.agent_class: agents.<name>_agent.<ClassName>`
4. Add tool schemas and command builders to `tools/definitions.py` if needed
5. Add tool YAML configs to `tools/catalog/` for registry-driven resolution
6. Create prompt template at `agents/prompts/<name>.md`
7. Add tests

### Option C: Clone from template

1. `POST /api/builder/templates/<template>/clone?new_name=<name>`
2. Edit the cloned config in the builder UI or directly in YAML
3. Reload

### In all cases, ensure:

- Findings/state updates are structured
- Out-of-scope writes are rejected
- Command builder and failure-mode tests exist
- Architecture docs updated if behavior changes control flow

## 13. Extension Anti-Patterns

Avoid these common mistakes:

- adding broad scanning tools without guardrails
- duplicating existing agent responsibilities
- storing raw logs in shared coordination state
- treating every failure as retryable
- building prompts that encourage unbounded tool loops
- bypassing structured handoff/state paths

## 14. Recommended Engineering Defaults

Use these defaults unless you have explicit reason to diverge:

- bounded tasks with explicit stop conditions
- one hypothesis per high-cost action
- immediate persistence for credible findings
- dedupe-aware retries only on changed context
- concise, structured summaries with concrete next actions

## 15. Relationship to Other Docs

Use this file together with:

- `README.md` for operator/developer setup and runtime entry points
- `docs/ARCHITECTURE.md` for system structure and execution flow

If implementation changes conflict with this guide, update both code and docs in the same change.

#!/usr/bin/env python3
"""
SnowStrike AI v7.0 - CLI Interface

Command-line interface for managing test profiles, model configurations,
prompt presets, and running A/B test engagements.

Usage:
    python3 snowstrike_cli.py <command> [options]

Commands:
    list-presets          List available prompt presets
    list-model-configs    List available model configurations
    list-profiles         List available test profiles
    save-profile          Create/save a test profile
    save-model-config     Create/save a model configuration
    create-preset         Create a new prompt preset (from existing)
    estimate-cost         Estimate cost for a model config
    test                  Run an engagement with a specific profile
    test-matrix           Run all profile combinations on a target
    results               View results for a target
    compare               Compare two profiles on same target
    export-csv            Export results as CSV
"""

import argparse
import json
import logging
import os
import sys
from pathlib import Path

# Ensure project root is on path
sys.path.insert(0, str(Path(__file__).parent))

from config import ENGAGEMENTS_DIR, require_root
from profiles.profile_manager import ProfileManager
from profiles.model_config_manager import ModelConfigManager
from profiles.metrics_recorder import MetricsRecorder
from profiles.comparison import EngagementComparison

logger = logging.getLogger("snowstrike.cli")


def cmd_list_presets(args):
    """List available prompt presets."""
    pm = ProfileManager()
    presets = pm.list_prompt_presets()
    if not presets:
        print("No prompt presets found. Create one with: snowstrike create-preset")
        return

    print(f"\n{'Name':<30} {'Prompts':<10} {'Tags':<30} Description")
    print("-" * 100)
    for p in presets:
        tags = ", ".join(p.get("tags", []))[:28]
        print(f"{p['name']:<30} {p['prompt_count']:<10} {tags:<30} {p.get('description', '')[:40]}")
    print(f"\nTotal: {len(presets)} presets")


def cmd_list_model_configs(args):
    """List available model configurations."""
    mcm = ModelConfigManager()
    configs = mcm.list_configs()
    if not configs:
        print("No model configs found. Create one with: snowstrike save-model-config")
        return

    print(f"\n{'Name':<25} {'Tags':<25} Description")
    print("-" * 90)
    for c in configs:
        tags = ", ".join(c.get("tags", []))[:23]
        print(f"{c['name']:<25} {tags:<25} {c.get('description', '')[:40]}")

    if args.verbose:
        print("\nDetailed role assignments:")
        for c in configs:
            print(f"\n  [{c['name']}]")
            for role, model in c.get("roles", {}).items():
                print(f"    {role:<15} → {model}")

    print(f"\nTotal: {len(configs)} configs")


def cmd_list_profiles(args):
    """List available test profiles."""
    pm = ProfileManager()
    profiles = pm.list_profiles()
    if not profiles:
        print("No profiles found. Create one with: snowstrike save-profile")
        return

    print(f"\n{'Name':<40} {'Prompt Preset':<25} {'Model Config':<20}")
    print("-" * 90)
    for p in profiles:
        print(f"{p['name']:<40} {p.get('prompt_preset', ''):<25} {p.get('model_config', ''):<20}")
    print(f"\nTotal: {len(profiles)} profiles")


def cmd_save_profile(args):
    """Create/save a test profile."""
    pm = ProfileManager()
    try:
        path = pm.save_profile(
            name=args.name,
            prompt_preset=args.prompt_preset,
            model_config=args.model_config,
            description=args.description or "",
        )
        print(f"Profile saved: {args.name} → {path}")
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_save_model_config(args):
    """Create/save a model configuration."""
    mcm = ModelConfigManager()

    # Build roles dict from CLI args
    roles = {}
    role_args = {
        "orchestrator": args.orchestrator,
        "recon": args.recon,
        "webapp": args.webapp,
        "attack": args.attack,
        "cloud": args.cloud,
        "binary": args.binary,
        "osint": args.osint,
        "reporting": args.reporting,
        "alerts": args.alerts,
        "compaction": args.compaction,
    }
    for role, model in role_args.items():
        if model:
            roles[role] = model

    if not roles:
        print("Error: Must specify at least one role → model mapping", file=sys.stderr)
        sys.exit(1)

    path = mcm.save_config(
        name=args.name,
        roles=roles,
        description=args.description or "",
        tags=args.tags.split(",") if args.tags else [],
    )
    print(f"Model config saved: {args.name} → {path}")


def cmd_create_preset(args):
    """Create a new prompt preset."""
    pm = ProfileManager()
    try:
        path = pm.create_prompt_preset(
            name=args.name,
            description=args.description or "",
            source=args.source,
            tags=args.tags.split(",") if args.tags else [],
        )
        print(f"Preset created: {args.name} → {path}")
        print("Edit the .md files in the preset directory to customize the prompts.")
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_estimate_cost(args):
    """Estimate cost for a model configuration."""
    mcm = ModelConfigManager()
    tokens = args.tokens or 100_000

    if args.all:
        configs = mcm.list_configs()
        print(f"\nCost estimates (assuming {tokens:,} tokens per agent):\n")
        print(f"{'Config':<25} {'Estimated Cost':>15}")
        print("-" * 42)
        for c in configs:
            est = mcm.estimate_config_cost(c["name"], tokens)
            total = est.get("total_usd", 0)
            print(f"{c['name']:<25} ${total:>13.2f}")
    else:
        est = mcm.estimate_config_cost(args.config, tokens)
        if "error" in est:
            print(f"Error: {est['error']}")
            return

        print(f"\nCost estimate for '{args.config}' ({tokens:,} tokens per agent):\n")
        print(f"{'Role':<15} {'Model':<35} {'Cost':>10}")
        print("-" * 65)
        for role, data in est["breakdown"].items():
            print(f"{role:<15} {data['model']:<35} ${data['total_usd']:>8.4f}")
        print("-" * 65)
        print(f"{'TOTAL':<50} ${est['total_usd']:>8.4f}")


def cmd_test(args):
    """Run an engagement with a specific profile."""
    require_root()

    from agents.orchestrator import OrchestratorAgent

    pm = ProfileManager()
    resolved = pm.resolve_profile(args.profile)

    print(f"\nStarting test run:")
    print(f"  Profile:       {args.profile}")
    print(f"  Prompt Preset: {resolved['metadata'].get('prompt_preset', '')}")
    print(f"  Model Config:  {resolved['metadata'].get('model_config', '')}")
    print(f"  Target:        {args.target}")
    print(f"  Methodology:   {args.methodology}")
    if args.tag:
        print(f"  CTF Tag:       {args.tag}")
    print()

    # Create engagement with profile (sanitize for safe directory names)
    import re as _re
    _safe = lambda s: _re.sub(r"[^a-zA-Z0-9_-]", "_", s)[:40]
    engagement_name = f"{_safe(args.target)}_{_safe(args.tag or 'test')}_{_safe(args.profile)}"
    orch = OrchestratorAgent.create_engagement(
        target=args.target,
        methodology=args.methodology,
        name=engagement_name,
    )

    # Apply model config overrides
    model_config = resolved["model_config"]
    if model_config:
        orch.model_config = model_config

    # Apply prompt preset (override prompt directory)
    prompt_dir = resolved["prompt_dir"]
    if prompt_dir:
        orch_prompt = prompt_dir / "orchestrator.md"
        if orch_prompt.exists():
            orch.system_prompt = orch_prompt.read_text()

    # Initialize metrics
    recorder = MetricsRecorder(orch.engagement_dir, orch.engagement_id)
    recorder.start_engagement(
        target_ip=args.target,
        methodology=args.methodology,
        profile_name=args.profile,
        prompt_preset=resolved["metadata"].get("prompt_preset", ""),
        model_config=resolved["metadata"].get("model_config", ""),
        ctf_tag=args.tag or "",
    )

    # Store recorder on orchestrator for integration
    orch._metrics_recorder = recorder

    print(f"Engagement started: {engagement_name}")
    print(f"Running autonomous mode...\n")

    # Run
    result = orch.run_autonomous()

    # Finalize metrics
    cost_summary = result.get("cost", {})
    final_metrics = recorder.finish_engagement(cost_summary)

    print(f"\n{'='*60}")
    print(f"COMPLETED: {engagement_name}")
    print(f"  Duration:   {final_metrics.get('duration_seconds', 0):.0f}s")
    print(f"  Cost:       ${final_metrics.get('cost', {}).get('total_usd', 0):.2f}")
    print(f"  Iterations: {final_metrics.get('iterations_completed', 0)}")
    print(f"  Access:     {final_metrics.get('access_achieved', 'none')}")
    print(f"  Findings:   {sum(final_metrics.get('findings_count', {}).values())}")
    print(f"{'='*60}")


def cmd_test_matrix(args):
    """Run all profile combinations on a target."""
    require_root()

    pm = ProfileManager()
    matrix = pm.generate_matrix()

    if args.prompt_preset:
        matrix = [m for m in matrix if m["prompt_preset"] == args.prompt_preset]
    if args.model_config:
        matrix = [m for m in matrix if m["model_config"] == args.model_config]

    print(f"\nTest matrix: {len(matrix)} combinations")
    print(f"Target: {args.target}")
    if args.tag:
        print(f"CTF Tag: {args.tag}")
    print()

    for i, combo in enumerate(matrix, 1):
        print(f"[{i}/{len(matrix)}] {combo['profile_name']}")

    if not args.yes:
        confirm = input(f"\nRun all {len(matrix)} combinations? [y/N] ")
        if confirm.lower() != "y":
            print("Aborted.")
            return

    for i, combo in enumerate(matrix, 1):
        print(f"\n{'='*60}")
        print(f"[{i}/{len(matrix)}] Running: {combo['profile_name']}")
        print(f"{'='*60}")

        # Create a temporary profile if it doesn't exist
        profile_name = combo["profile_name"]
        profile = pm.get_profile(profile_name)
        if not profile:
            try:
                pm.save_profile(
                    name=profile_name,
                    prompt_preset=combo["prompt_preset"],
                    model_config=combo["model_config"],
                    description=f"Auto-generated for matrix test",
                )
            except ValueError as e:
                print(f"  Skipping: {e}")
                continue

        # Run test (reuse cmd_test logic)
        test_args = argparse.Namespace(
            profile=profile_name,
            target=args.target,
            tag=args.tag or "",
            methodology=args.methodology,
        )
        try:
            cmd_test(test_args)
        except Exception as e:
            print(f"  FAILED: {e}")
            continue

    print(f"\n{'='*60}")
    print(f"Matrix complete. {len(matrix)} runs finished.")
    print(f"View results: python3 snowstrike_cli.py results --target={args.target}")


def cmd_results(args):
    """View results for a target."""
    comp = EngagementComparison()
    report = comp.generate_report(
        target_ip=args.target or "",
        ctf_tag=args.tag or "",
    )
    print(report)


def cmd_compare(args):
    """Compare two profiles on the same target."""
    comp = EngagementComparison()
    metrics = comp.get_comparison_data(target_ip=args.target or "")

    # Filter to the two profiles
    m1 = [m for m in metrics if m.get("profile_name") == args.profile1]
    m2 = [m for m in metrics if m.get("profile_name") == args.profile2]

    if not m1:
        print(f"No results found for profile: {args.profile1}")
        return
    if not m2:
        print(f"No results found for profile: {args.profile2}")
        return

    combined = m1 + m2
    analysis = comp.analyze(combined)

    print(f"\nComparison: {args.profile1} vs {args.profile2}")
    if args.target:
        print(f"Target: {args.target}")
    print()

    for row in analysis["summary_table"]:
        print(f"  [{row['profile'][:35]}]")
        print(f"    Duration:  {row['duration_display']}")
        print(f"    Cost:      ${row['cost_usd']:.2f}")
        print(f"    Findings:  {row['total_findings']}")
        print(f"    Access:    {row['access_achieved']}")
        print(f"    Root:      {'Yes' if row['root_obtained'] else 'No'}")
        print()


def cmd_export_csv(args):
    """Export results as CSV."""
    comp = EngagementComparison()
    csv_data = comp.export_csv(
        target_ip=args.target or "",
        ctf_tag=args.tag or "",
        output_path=args.output,
    )
    if args.output:
        print(f"CSV exported to: {args.output}")
    else:
        print(csv_data)


# ---------------------------------------------------------------------------
# Flow Commands
# ---------------------------------------------------------------------------

def _get_flow_registry():
    """Load flow registry from the default definitions directory."""
    from flows.registry import FlowRegistry
    defs_dir = Path(__file__).parent / "flows" / "definitions"
    registry = FlowRegistry(defs_dir)
    registry.load_all()
    return registry


def cmd_flow_list(args):
    """List available flow definitions."""
    registry = _get_flow_registry()
    flows = registry.list_flows()
    if not flows:
        print("No flow definitions found in flows/definitions/")
        return

    print(f"\n{'Name':<30} {'Category':<12} {'Steps':<7} {'Mode':<12} Description")
    print("-" * 100)
    for f in flows:
        print(
            f"{f['name']:<30} {f['category']:<12} {f['step_count']:<7} "
            f"{f['execution_mode']:<12} {f['description'][:40]}"
        )
    print(f"\nTotal: {len(flows)} flows")


def cmd_flow_validate(args):
    """Validate a flow definition YAML file."""
    from flows.registry import FlowRegistry

    if args.all:
        registry = _get_flow_registry()
        defs_dir = Path(__file__).parent / "flows" / "definitions"
        all_ok = True
        for yaml_path in sorted(defs_dir.glob("*.yaml")):
            errors = registry.validate_flow_file(yaml_path)
            if errors:
                print(f"FAIL  {yaml_path.name}:")
                for e in errors:
                    print(f"  - {e}")
                all_ok = False
            else:
                print(f"OK    {yaml_path.name}")
        if all_ok:
            print("\nAll flow definitions are valid.")
        else:
            sys.exit(1)
    elif args.file:
        from flows.registry import FlowRegistry
        registry = FlowRegistry(Path(args.file).parent)
        errors = registry.validate_flow_file(Path(args.file))
        if errors:
            print(f"Validation errors in {args.file}:")
            for e in errors:
                print(f"  - {e}")
            sys.exit(1)
        else:
            print(f"Valid: {args.file}")
    else:
        print("Provide a YAML file path or --all")
        sys.exit(1)


def cmd_flow_run(args):
    """Execute a flow manually."""
    registry = _get_flow_registry()
    try:
        flow_def = registry.get_flow(args.flow)
    except KeyError as exc:
        print(str(exc))
        sys.exit(1)

    # Parse --input key=value pairs
    inputs = {}
    for inp in (args.input or []):
        if "=" not in inp:
            print(f"Invalid input format: '{inp}' (expected key=value)")
            sys.exit(1)
        k, _, v = inp.partition("=")
        inputs[k] = v

    # Check required inputs
    for name, inp_def in flow_def.spec.inputs.items():
        if inp_def.required and name not in inputs and inp_def.default is None:
            print(f"Missing required input: --input {name}=<value>")
            sys.exit(1)

    from flows.runner import FlowRunner
    runner = FlowRunner()

    print(f"Running flow: {flow_def.metadata.display_name or flow_def.metadata.name}")
    print(f"Mode: {flow_def.spec.execution_mode}")
    print(f"Steps: {len(flow_def.spec.steps)}")
    print(f"Inputs: {inputs}")
    print()

    result = runner.execute(flow_def, inputs, workspace=args.workspace or "")

    print(f"\n{'=' * 60}")
    print(f"Flow: {result.flow_name}")
    print(f"Status: {result.status}")
    print(f"Duration: {result.duration_seconds:.1f}s")
    print(f"Cost: ${result.total_cost_usd:.4f}")
    print(f"Workspace: {result.workspace}")
    print(f"\nSteps:")
    for sid, sr in result.step_results.items():
        status_icon = {"completed": "+", "failed": "X", "skipped": "-"}.get(sr.status, "?")
        print(f"  [{status_icon}] {sid}: {sr.status} ({sr.duration_seconds:.1f}s)")
        if sr.errors:
            for err in sr.errors:
                print(f"      Error: {err[:120]}")
    if result.outputs:
        print(f"\nOutputs:")
        for k, v in result.outputs.items():
            print(f"  {k}: {str(v)[:120]}")


def cmd_flow_status(args):
    """Check status of a flow execution."""
    from flows.state import FlowStateStore
    state_store = FlowStateStore(args.workspace)
    state = state_store.read()
    if not state:
        print(f"No flow state found in: {args.workspace}")
        sys.exit(1)

    print(f"Flow: {state.get('flow_name', '?')}")
    print(f"ID: {state.get('flow_id', '?')}")
    print(f"Status: {state.get('status', '?')}")
    print(f"Started: {state.get('started_at', '?')}")
    print(f"Completed: {state.get('completed_at', 'N/A')}")
    print(f"Cost: ${state.get('total_cost_usd', 0):.4f}")
    print(f"\nSteps:")
    for sid, sdata in state.get("steps", {}).items():
        status = sdata.get("status", "?")
        dur = sdata.get("duration_seconds") or 0
        status_icon = {"completed": "+", "failed": "X", "skipped": "-", "running": ">"}.get(status, "?")
        print(f"  [{status_icon}] {sid}: {status} ({dur:.1f}s)")
        if sdata.get("errors"):
            for err in sdata["errors"]:
                print(f"      Error: {err[:120]}")


# ---------------------------------------------------------------------------
# Browser Stack Diagnostics
# ---------------------------------------------------------------------------

def cmd_check_browser(args):
    """Diagnose the browser automation stack."""
    print("\nBrowser Stack Status")
    print("=" * 50)

    # 1. Check Playwright
    pw_ok = False
    pw_version = ""
    try:
        import playwright
        pw_version = getattr(playwright, "__version__", "unknown")
        pw_ok = True
        print(f"  Playwright:              OK  (v{pw_version})")
    except ImportError:
        print("  Playwright:              NOT INSTALLED")
        print("    Fix: pip install 'snowstrike[browser]'")

    # 2. Check Chromium binary
    chromium_ok = False
    if pw_ok:
        try:
            from playwright.sync_api import sync_playwright
            pw = sync_playwright().start()
            browser = pw.chromium.launch(headless=True, args=["--no-sandbox"])
            browser.close()
            pw.stop()
            chromium_ok = True
            print("  Chromium (fallback):     OK")
        except Exception as e:
            err = str(e)
            if "Executable doesn't exist" in err or "not found" in err.lower():
                print("  Chromium (fallback):     NOT INSTALLED")
                print("    Fix: playwright install chromium")
            else:
                print(f"  Chromium (fallback):     ERROR ({err[:80]})")

    # 3. Check Camoufox
    cfox_ok = False
    cfox_version = ""
    try:
        import camoufox
        cfox_version = getattr(camoufox, "__version__", "unknown")
        print(f"  Camoufox (stealth):      OK  (v{cfox_version})")
        cfox_ok = True
    except ImportError:
        print("  Camoufox (stealth):      NOT INSTALLED")
        print("    Fix: pip install 'snowstrike[browser-stealth]' && camoufox fetch")

    # 4. Check Camoufox Firefox binary
    cfox_binary_ok = False
    if cfox_ok:
        try:
            from camoufox.sync_api import Camoufox
            cfox = Camoufox(headless=True)
            browser = cfox.__enter__()
            browser.close()
            cfox.__exit__(None, None, None)
            cfox_binary_ok = True
            print("  Camoufox Firefox:        OK")
        except Exception as e:
            err = str(e)
            if "not found" in err.lower() or "fetch" in err.lower():
                print("  Camoufox Firefox:        NOT DOWNLOADED")
                print("    Fix: camoufox fetch")
            else:
                print(f"  Camoufox Firefox:        ERROR ({err[:80]})")

    # 5. Check Xvfb (for headless="virtual" mode)
    import shutil
    xvfb_ok = shutil.which("Xvfb") is not None or shutil.which("xvfb-run") is not None
    if xvfb_ok:
        print("  Xvfb (virtual display):  OK")
    else:
        print("  Xvfb (virtual display):  NOT INSTALLED")
        print("    Fix: apt install xvfb  (optional, improves stealth)")

    # Summary
    print()
    if cfox_binary_ok:
        engine = "camoufox (auto-selected)"
    elif chromium_ok:
        engine = "chromium (fallback — install camoufox for stealth)"
    else:
        engine = "NONE — browser tools will not work"

    print(f"  Active engine: {engine}")

    if not pw_ok:
        print("\n  Browser tools require at minimum: pip install 'snowstrike[browser]' && playwright install chromium")

    print()


# ---------------------------------------------------------------------------
# Argument Parser
# ---------------------------------------------------------------------------

def build_parser():
    parser = argparse.ArgumentParser(
        prog="snowstrike",
        description="SnowStrike AI - Testing & Profile Management CLI",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # list-presets
    subparsers.add_parser("list-presets", help="List available prompt presets")

    # list-model-configs
    p = subparsers.add_parser("list-model-configs", help="List model configurations")
    p.add_argument("-v", "--verbose", action="store_true", help="Show role assignments")

    # list-profiles
    subparsers.add_parser("list-profiles", help="List test profiles")

    # save-profile
    p = subparsers.add_parser("save-profile", help="Create/save a test profile")
    p.add_argument("--name", required=True, help="Profile name")
    p.add_argument("--prompt-preset", required=True, help="Prompt preset name")
    p.add_argument("--model-config", required=True, help="Model config name")
    p.add_argument("--description", default="", help="Profile description")

    # save-model-config
    p = subparsers.add_parser("save-model-config", help="Create/save model configuration")
    p.add_argument("--name", required=True, help="Config name")
    p.add_argument("--description", default="", help="Description")
    p.add_argument("--tags", default="", help="Comma-separated tags")
    p.add_argument("--orchestrator", help="Model for orchestrator")
    p.add_argument("--recon", help="Model for recon agent")
    p.add_argument("--webapp", help="Model for webapp agent")
    p.add_argument("--attack", help="Model for attack agent")
    p.add_argument("--cloud", help="Model for cloud agent")
    p.add_argument("--binary", help="Model for binary agent")
    p.add_argument("--osint", help="Model for osint agent")
    p.add_argument("--reporting", help="Model for reporting agent")
    p.add_argument("--alerts", help="Model for alerts agent")
    p.add_argument("--compaction", help="Model for compaction")

    # create-preset
    p = subparsers.add_parser("create-preset", help="Create a new prompt preset")
    p.add_argument("--name", required=True, help="Preset name")
    p.add_argument("--description", default="", help="Description")
    p.add_argument("--source", help="Copy prompts from this preset (default: agents/prompts)")
    p.add_argument("--tags", default="", help="Comma-separated tags")

    # estimate-cost
    p = subparsers.add_parser("estimate-cost", help="Estimate cost for a model config")
    p.add_argument("--config", help="Model config name")
    p.add_argument("--tokens", type=int, default=100000, help="Tokens per agent (default: 100k)")
    p.add_argument("--all", action="store_true", help="Estimate all configs")

    # test
    p = subparsers.add_parser("test", help="Run engagement with a profile")
    p.add_argument("--profile", required=True, help="Profile name")
    p.add_argument("--target", required=True, help="Target IP")
    p.add_argument("--tag", default="", help="CTF tag (easy/medium/hard/insane)")
    p.add_argument("--methodology", default="ctf", help="Methodology (default: ctf)")

    # test-matrix
    p = subparsers.add_parser("test-matrix", help="Run all profile combos on a target")
    p.add_argument("--target", required=True, help="Target IP")
    p.add_argument("--tag", default="", help="CTF tag")
    p.add_argument("--methodology", default="ctf", help="Methodology (default: ctf)")
    p.add_argument("--prompt-preset", help="Filter to one prompt preset")
    p.add_argument("--model-config", help="Filter to one model config")
    p.add_argument("-y", "--yes", action="store_true", help="Skip confirmation")

    # results
    p = subparsers.add_parser("results", help="View results for a target")
    p.add_argument("--target", default="", help="Filter by target IP")
    p.add_argument("--tag", default="", help="Filter by CTF tag")

    # compare
    p = subparsers.add_parser("compare", help="Compare two profiles")
    p.add_argument("--profile1", required=True, help="First profile")
    p.add_argument("--profile2", required=True, help="Second profile")
    p.add_argument("--target", default="", help="Filter by target IP")

    # export-csv
    p = subparsers.add_parser("export-csv", help="Export results as CSV")
    p.add_argument("--target", default="", help="Filter by target IP")
    p.add_argument("--tag", default="", help="Filter by CTF tag")
    p.add_argument("--output", help="Output file path")

    # flow-list
    subparsers.add_parser("flow-list", help="List available flow definitions")

    # flow-validate
    p = subparsers.add_parser("flow-validate", help="Validate a flow YAML file")
    p.add_argument("file", nargs="?", help="YAML file to validate")
    p.add_argument("--all", action="store_true", help="Validate all definitions")

    # flow-run
    p = subparsers.add_parser("flow-run", help="Run a flow manually")
    p.add_argument("flow", help="Flow name")
    p.add_argument("--input", "-i", action="append", help="Input as key=value (repeatable)")
    p.add_argument("--workspace", help="Custom workspace directory")

    # flow-status
    p = subparsers.add_parser("flow-status", help="Check flow run status")
    p.add_argument("workspace", help="Flow workspace directory")

    # check-browser
    subparsers.add_parser("check-browser", help="Diagnose browser stack (Camoufox, Chromium, Xvfb)")

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    # Setup logging
    log_level = logging.DEBUG if getattr(args, "verbose", False) else logging.INFO
    logging.basicConfig(level=log_level, format="%(message)s")

    # Dispatch
    commands = {
        "list-presets": cmd_list_presets,
        "list-model-configs": cmd_list_model_configs,
        "list-profiles": cmd_list_profiles,
        "save-profile": cmd_save_profile,
        "save-model-config": cmd_save_model_config,
        "create-preset": cmd_create_preset,
        "estimate-cost": cmd_estimate_cost,
        "test": cmd_test,
        "test-matrix": cmd_test_matrix,
        "results": cmd_results,
        "compare": cmd_compare,
        "export-csv": cmd_export_csv,
        "flow-list": cmd_flow_list,
        "flow-validate": cmd_flow_validate,
        "flow-run": cmd_flow_run,
        "flow-status": cmd_flow_status,
        "check-browser": cmd_check_browser,
    }

    handler = commands.get(args.command)
    if handler:
        handler(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()

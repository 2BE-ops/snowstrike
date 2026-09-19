"""FlowRegistry — loads flow YAML definitions, validates, and caches them."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

import yaml

from flows.schema import FlowDefinition, parse_flow_yaml
from flows.validators import validate_flow, FlowValidationError

logger = logging.getLogger(__name__)


class FlowRegistry:
    """Loads flow YAML definitions from a directory."""

    def __init__(self, definitions_dir: Path | str):
        self._dir = Path(definitions_dir)
        self._flows: dict[str, FlowDefinition] = {}

    def load_all(self) -> None:
        """Scan definitions_dir/*.yaml, validate and cache."""
        self._flows.clear()
        if not self._dir.exists():
            logger.warning("Flow definitions dir %s not found", self._dir)
            return

        for yaml_path in sorted(self._dir.glob("*.yaml")):
            try:
                self._load_one(yaml_path)
            except Exception as exc:
                logger.warning("Failed to load flow %s: %s", yaml_path.name, exc)

    def _load_one(self, yaml_path: Path) -> None:
        """Load, parse, validate one YAML file."""
        with open(yaml_path) as f:
            raw = yaml.safe_load(f)

        if not raw or not isinstance(raw, dict):
            raise ValueError(f"Empty or invalid YAML in {yaml_path}")

        flow_def = parse_flow_yaml(raw)
        errors = validate_flow(flow_def)
        if errors:
            raise FlowValidationError(errors)

        self._flows[flow_def.metadata.name] = flow_def
        logger.debug("Loaded flow: %s (%d steps)", flow_def.metadata.name, len(flow_def.spec.steps))

    def get_flow(self, name: str) -> FlowDefinition:
        """Get flow by name.  Raises KeyError if not found."""
        if name not in self._flows:
            raise KeyError(
                f"Flow '{name}' not found (available: {', '.join(sorted(self._flows))})"
            )
        return self._flows[name]

    def list_flows(self) -> list[dict]:
        """Return summary list of all loaded flows."""
        result = []
        for name, fdef in sorted(self._flows.items()):
            result.append({
                "name": name,
                "display_name": fdef.metadata.display_name,
                "description": fdef.metadata.description,
                "category": fdef.metadata.category,
                "tags": fdef.metadata.tags,
                "step_count": len(fdef.spec.steps),
                "execution_mode": fdef.spec.execution_mode,
                "trigger_type": fdef.spec.trigger.type,
            })
        return result

    def reload(self, name: str | None = None) -> None:
        """Hot-reload one or all flow definitions."""
        if name is None:
            self.load_all()
        else:
            for yaml_path in self._dir.glob("*.yaml"):
                try:
                    with open(yaml_path) as f:
                        raw = yaml.safe_load(f)
                    if raw and raw.get("metadata", {}).get("name") == name:
                        self._load_one(yaml_path)
                        return
                except Exception:
                    pass
            raise KeyError(f"Could not find YAML file for flow '{name}'")

    def validate_flow_file(self, yaml_path: Path) -> list[str]:
        """Validate a YAML file without caching.  Returns error list."""
        try:
            with open(yaml_path) as f:
                raw = yaml.safe_load(f)
        except Exception as exc:
            return [f"YAML parse error: {exc}"]

        if not raw or not isinstance(raw, dict):
            return ["Empty or invalid YAML"]

        try:
            flow_def = parse_flow_yaml(raw)
        except Exception as exc:
            return [f"Schema parse error: {exc}"]

        return validate_flow(flow_def)

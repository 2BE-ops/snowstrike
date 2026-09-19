"""AgentRegistry — loads agent YAML configs and provides dynamic AGENT_CLASSES equivalent.

Replaces the hardcoded AGENT_CLASSES dict in orchestrator.py and
AGENT_CAPABILITIES dict in protocol.py with a dynamic, hot-reloadable registry.

Falls back to hardcoded dicts when no YAML configs are found.
"""

import importlib
import logging
import os
import shutil
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import yaml

logger = logging.getLogger(__name__)


@dataclass
class AgentCapability:
    """Mirror of protocol.AgentCapability for registry use."""

    agent_type: str
    capabilities: list[str] = field(default_factory=list)
    requires: list[str] = field(default_factory=list)
    produces: list[str] = field(default_factory=list)
    max_concurrent: int = 1


class AgentRegistry:
    """Loads agent YAML configs, provides dynamic AGENT_CLASSES equivalent.

    Usage:
        registry = AgentRegistry(Path("agent-configs"))
        registry.load_all()
        AGENT_CLASSES = registry.get_agent_classes()
        AGENT_CAPABILITIES = registry.get_capabilities()
    """

    def __init__(self, config_dir: Path):
        self._config_dir = config_dir
        self._agents_dir = config_dir / "agents"
        self._templates_dir = config_dir / "templates"
        self._versions_dir = config_dir / ".versions"
        self._configs: dict[str, dict] = {}        # name -> raw YAML dict
        self._agent_classes: dict[str, type] = {}   # name -> resolved Python class
        self._capabilities: dict[str, AgentCapability] = {}

    def load_all(self) -> None:
        """Scan config_dir/agents/*.yaml, populate registries."""
        self._configs.clear()
        self._agent_classes.clear()
        self._capabilities.clear()

        if not self._agents_dir.exists():
            logger.warning("Agent config dir %s not found, using fallback", self._agents_dir)
            return

        for yaml_path in sorted(self._agents_dir.glob("*.yaml")):
            try:
                self._load_one(yaml_path)
            except Exception as e:
                logger.error("Failed to load agent config %s: %s", yaml_path.name, e)

        logger.info("AgentRegistry loaded %d agents from YAML", len(self._configs))

    def _load_one(self, yaml_path: Path) -> None:
        """Load a single agent YAML config."""
        with open(yaml_path) as f:
            config = yaml.safe_load(f)

        if not config or config.get("kind") != "Agent":
            return

        meta = config.get("metadata", {})
        spec = config.get("spec", {})
        name = meta.get("name", yaml_path.stem)

        self._configs[name] = config

        # Resolve Python class
        agent_class_path = spec.get("agent_class", "")
        if agent_class_path:
            try:
                cls = self._import_class(agent_class_path)
                self._agent_classes[name] = cls
            except Exception as e:
                logger.warning(
                    "Could not import %s for agent %s, using BaseAgent: %s",
                    agent_class_path, name, e,
                )
                self._agent_classes[name] = self._get_base_agent_class()
        else:
            self._agent_classes[name] = self._get_base_agent_class()

        # Build capability
        caps = spec.get("capabilities", {})
        self._capabilities[name] = AgentCapability(
            agent_type=name,
            capabilities=caps.get("skills", []),
            requires=caps.get("requires", []),
            produces=caps.get("produces", []),
            max_concurrent=spec.get("max_concurrent", 1),
        )

    # Allowed module prefixes for dynamic agent class loading
    _ALLOWED_MODULE_PREFIXES = ("agents.",)

    @staticmethod
    def _import_class(dotted_path: str) -> type:
        """Import a class from a dotted module path like 'agents.recon_agent.ReconAgent'.

        Only modules under allowed prefixes can be imported to prevent
        arbitrary code execution via crafted YAML config files.
        """
        module_path, _, class_name = dotted_path.rpartition(".")
        if not any(module_path.startswith(prefix) for prefix in AgentRegistry._ALLOWED_MODULE_PREFIXES):
            raise ValueError(
                f"Agent class path {dotted_path!r} is not under an allowed module prefix "
                f"({AgentRegistry._ALLOWED_MODULE_PREFIXES})"
            )
        module = importlib.import_module(module_path)
        return getattr(module, class_name)

    @staticmethod
    def _get_base_agent_class() -> type:
        """Lazy import of BaseAgent to avoid circular imports."""
        from agents.base_agent import BaseAgent
        return BaseAgent

    # ── Query methods ──────────────────────────────────────────────────

    def get_agent_classes(self) -> dict[str, type]:
        """Returns dict compatible with orchestrator's AGENT_CLASSES."""
        return dict(self._agent_classes)

    def get_capabilities(self) -> dict[str, AgentCapability]:
        """Returns dict compatible with protocol's AGENT_CAPABILITIES."""
        return dict(self._capabilities)

    def get_config(self, name: str) -> Optional[dict]:
        """Return raw agent config for dashboard display."""
        return self._configs.get(name)

    def list_agents(self) -> list[dict]:
        """Return summary list of all agents for API."""
        result = []
        for name, config in self._configs.items():
            spec = config.get("spec", {})
            meta = config.get("metadata", {})
            result.append({
                "name": name,
                "display_name": spec.get("display_name", name),
                "description": spec.get("description", ""),
                "model": spec.get("model", ""),
                "version": meta.get("version", 1),
                "tool_count": len(spec.get("tools", [])),
                "max_concurrent": spec.get("max_concurrent", 1),
            })
        return result

    def get_agent_tool_names(self, name: str) -> list[str]:
        """Return the tool names configured for an agent."""
        config = self._configs.get(name)
        if not config:
            return []
        return config.get("spec", {}).get("tools", [])

    # ── CRUD methods ───────────────────────────────────────────────────

    def reload(self, name: str = None) -> None:
        """Hot-reload one or all agent configs from disk."""
        if name:
            yaml_path = self._agents_dir / f"{name}.yaml"
            if yaml_path.exists():
                # Remove old entries
                self._configs.pop(name, None)
                self._agent_classes.pop(name, None)
                self._capabilities.pop(name, None)
                self._load_one(yaml_path)
            else:
                logger.warning("Agent config %s not found for reload", name)
        else:
            self.load_all()

    def create(self, config: dict) -> str:
        """Write new agent YAML, register in memory. Returns agent name."""
        meta = config.get("metadata", {})
        name = meta.get("name", "")
        if not name:
            raise ValueError("Agent config must have metadata.name")

        if name in self._configs:
            raise ValueError(f"Agent '{name}' already exists")

        # Ensure required fields
        config.setdefault("apiVersion", "snowstrike/v1")
        config.setdefault("kind", "Agent")
        meta.setdefault("version", 1)
        meta.setdefault("created", datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
        meta.setdefault("author", "user")

        self._agents_dir.mkdir(parents=True, exist_ok=True)
        yaml_path = self._agents_dir / f"{name}.yaml"
        with open(yaml_path, "w") as f:
            yaml.dump(config, f, default_flow_style=False, sort_keys=False)

        self._load_one(yaml_path)
        return name

    def update(self, name: str, config: dict) -> None:
        """Update YAML, bump version, hot-reload."""
        if name not in self._configs:
            raise ValueError(f"Agent '{name}' not found")

        # Save current version to history
        self._save_version(name)

        meta = config.get("metadata", {})
        old_version = self._configs[name].get("metadata", {}).get("version", 1)
        meta["version"] = old_version + 1
        meta["name"] = name  # Prevent name change via update
        config["metadata"] = meta

        yaml_path = self._agents_dir / f"{name}.yaml"
        with open(yaml_path, "w") as f:
            yaml.dump(config, f, default_flow_style=False, sort_keys=False)

        self.reload(name)

    def delete(self, name: str) -> None:
        """Soft-delete: move to agent-configs/.archive/"""
        if name not in self._configs:
            raise ValueError(f"Agent '{name}' not found")

        archive_dir = self._config_dir / ".archive"
        archive_dir.mkdir(parents=True, exist_ok=True)

        src = self._agents_dir / f"{name}.yaml"
        dst = archive_dir / f"{name}.yaml"
        if src.exists():
            shutil.move(str(src), str(dst))

        self._configs.pop(name, None)
        self._agent_classes.pop(name, None)
        self._capabilities.pop(name, None)

    # ── Version history ────────────────────────────────────────────────

    def _save_version(self, name: str) -> None:
        """Copy current config to version history."""
        config = self._configs.get(name)
        if not config:
            return

        version = config.get("metadata", {}).get("version", 1)
        version_dir = self._versions_dir / name
        version_dir.mkdir(parents=True, exist_ok=True)

        path = version_dir / f"v{version}.yaml"
        with open(path, "w") as f:
            yaml.dump(config, f, default_flow_style=False, sort_keys=False)

    def list_versions(self, name: str) -> list[dict]:
        """Return version history for rollback."""
        version_dir = self._versions_dir / name
        if not version_dir.exists():
            return []

        versions = []
        for path in sorted(version_dir.glob("v*.yaml")):
            try:
                with open(path) as f:
                    config = yaml.safe_load(f)
                meta = config.get("metadata", {})
                versions.append({
                    "version": meta.get("version", 0),
                    "created": meta.get("created", ""),
                    "author": meta.get("author", ""),
                    "file": path.name,
                })
            except Exception:
                continue

        return sorted(versions, key=lambda v: v["version"], reverse=True)

    def rollback(self, name: str, version: int) -> None:
        """Restore agent to a previous version."""
        version_path = self._versions_dir / name / f"v{version}.yaml"
        if not version_path.exists():
            raise ValueError(f"Version {version} not found for agent '{name}'")

        # Save current as new version first
        self._save_version(name)

        with open(version_path) as f:
            config = yaml.safe_load(f)

        # Bump version number for the restored config
        current_version = self._configs.get(name, {}).get("metadata", {}).get("version", 1)
        config["metadata"]["version"] = current_version + 1

        yaml_path = self._agents_dir / f"{name}.yaml"
        with open(yaml_path, "w") as f:
            yaml.dump(config, f, default_flow_style=False, sort_keys=False)

        self.reload(name)

    # ── Template operations ────────────────────────────────────────────

    def list_templates(self) -> list[dict]:
        """Return list of available agent templates."""
        if not self._templates_dir.exists():
            return []

        templates = []
        for path in sorted(self._templates_dir.glob("*.yaml")):
            try:
                with open(path) as f:
                    config = yaml.safe_load(f)
                spec = config.get("spec", {})
                meta = config.get("metadata", {})
                templates.append({
                    "name": meta.get("name", path.stem),
                    "display_name": spec.get("display_name", ""),
                    "description": spec.get("description", ""),
                    "tool_count": len(spec.get("tools", [])),
                })
            except Exception:
                continue

        return templates

    def clone_template(self, template_name: str, new_name: str) -> str:
        """Clone a template as a new mutable agent config."""
        template_path = self._templates_dir / f"{template_name}.yaml"
        if not template_path.exists():
            raise ValueError(f"Template '{template_name}' not found")

        with open(template_path) as f:
            config = yaml.safe_load(f)

        config["metadata"]["name"] = new_name
        config["metadata"]["version"] = 1
        config["metadata"]["created"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        config["metadata"]["author"] = "user"

        return self.create(config)

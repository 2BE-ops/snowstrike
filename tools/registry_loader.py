"""ToolRegistry — single source of truth for tool definitions, metadata, and registry.

Loads all tool YAML configs from the catalog directory and provides:
1. Anthropic-compatible tool schemas (name, description, input_schema)
2. Registry metadata (binary, agent, category, transport, endpoint, http_method)
3. Tool lifecycle hints
4. Shared tools (compatible_agents: [all])
5. flag_map definitions for data-driven command building
"""

import logging
import os
import shutil
from pathlib import Path
from typing import Optional

import yaml

logger = logging.getLogger(__name__)

# Lifecycle overrides — tools whose execution model differs from the default "oneshot".
# These are not in YAML because they describe runtime behavior, not tool identity.
_TOOL_LIFECYCLE: dict[str, str] = {
    # Interactive / prompt-based
    "msfconsole_run": "interactive",
    "metasploit_module": "interactive",
    "gdb_analyze": "interactive",
    "gdb_peda": "interactive",
    "radare2_analyze": "interactive",
    "rpcclient_scan": "interactive",
    "smbclient_scan": "interactive",
    "recon_ng_run": "interactive",
    "pacu_run": "interactive",
    # Streaming / long-running but self-terminating
    "responder_scan": "streaming",
    "falco_monitor": "streaming",
    "feroxbuster_scan": "streaming",
    "nikto_scan": "streaming",
    "browser_network_monitor": "streaming",
    "browser_crawl": "streaming",
    # Daemonizing (starts a listener/service)
    "evil_winrm_connect": "daemonizing",
}


class ToolRegistry:
    """Loads tool YAML configs from the catalog directory.

    Usage:
        registry = ToolRegistry(Path("tools/catalog"))
        registry.load_all()
        tools = registry.get_definitions_for_agent("recon", ["nmap_scan", "masscan_scan"])
    """

    def __init__(self, catalog_dir: Path):
        self._catalog_dir = catalog_dir
        self._tools: dict[str, dict] = {}        # tool_name -> full YAML config
        self._schemas: dict[str, dict] = {}       # tool_name -> Anthropic-compatible tool schema
        self._shared_tools: list[dict] = []       # shared tools (available to all agents)
        self._flag_maps: dict[str, list[dict]] = {}  # tool_name -> flag_map entries

    def load_all(self) -> None:
        """Scan catalog_dir/*.yaml, build all internal indices."""
        self._tools.clear()
        self._schemas.clear()
        self._shared_tools.clear()
        self._flag_maps.clear()

        if not self._catalog_dir.exists():
            raise FileNotFoundError(
                f"Tool catalog dir {self._catalog_dir} not found. "
                "YAML catalog is the single source of truth — cannot proceed without it."
            )

        for yaml_path in sorted(self._catalog_dir.glob("*.yaml")):
            try:
                self._load_one(yaml_path)
            except Exception as e:
                logger.error("Failed to load tool config %s: %s", yaml_path.name, e)

        logger.info(
            "ToolRegistry loaded %d tools (%d shared) from YAML",
            len(self._tools), len(self._shared_tools),
        )

    def _load_one(self, yaml_path: Path) -> None:
        """Load a single tool YAML config."""
        with open(yaml_path) as f:
            config = yaml.safe_load(f)

        if not config or config.get("kind") != "Tool":
            return

        meta = config.get("metadata", {})
        spec = config.get("spec", {})
        name = meta.get("name", yaml_path.stem)

        self._tools[name] = config

        # Build Anthropic-compatible tool schema
        schema = {
            "name": name,
            "description": spec.get("description", ""),
            "input_schema": spec.get("input_schema", {"type": "object", "properties": {}}),
        }
        self._schemas[name] = schema

        # Track shared tools
        compatible = spec.get("compatible_agents", [])
        if "all" in compatible:
            self._shared_tools.append(schema)

        # Cache flag_map if present
        fm = spec.get("flag_map")
        if fm and isinstance(fm, list):
            self._flag_maps[name] = fm

    # ── Tool definition queries ───────────────────────────────────────

    def get_definitions_for_agent(self, agent_name: str, agent_tools: list[str]) -> list[dict]:
        """Returns shared tools + agent-specific tools as Anthropic API schemas.

        Args:
            agent_name: The agent type (e.g., "recon").
            agent_tools: List of tool names assigned to this agent.

        Returns:
            List of tool schema dicts compatible with the Anthropic API.
        """
        result = list(self._shared_tools)  # copy shared tools
        seen = {t["name"] for t in result}

        for tool_name in agent_tools:
            if tool_name in seen:
                continue
            schema = self._schemas.get(tool_name)
            if schema:
                result.append(schema)
                seen.add(tool_name)
            else:
                logger.warning("Tool '%s' for agent '%s' not found in catalog", tool_name, agent_name)

        return result

    def get_all_definitions(self) -> list[dict]:
        """Return all tool schemas (shared tools first, then all others)."""
        result = list(self._shared_tools)
        seen = {t["name"] for t in result}
        for name, schema in self._schemas.items():
            if name not in seen:
                result.append(schema)
                seen.add(name)
        return result

    def get_shared_tools(self) -> list[dict]:
        """Return shared tool schemas (compatible_agents: [all])."""
        return list(self._shared_tools)

    def get_tool_config(self, name: str) -> Optional[dict]:
        """Return full tool config for API/dashboard."""
        return self._tools.get(name)

    def get_tool_schema(self, name: str) -> Optional[dict]:
        """Return Anthropic-compatible schema for a single tool."""
        return self._schemas.get(name)

    # ── Registry metadata queries (replaces registry.py) ─────────────

    def get_tools_for_agent(self, agent_name: str) -> list[str]:
        """Get all tool names assigned to a specific agent."""
        result = []
        for name, config in self._tools.items():
            spec = config.get("spec", {})
            compatible = spec.get("compatible_agents", [])
            if agent_name in compatible:
                result.append(name)
        return result

    def get_agent_for_tool(self, tool_name: str) -> Optional[str]:
        """Get the primary agent name that owns a tool."""
        config = self._tools.get(tool_name)
        if not config:
            return None
        spec = config.get("spec", {})
        compatible = spec.get("compatible_agents", [])
        # Return first non-'all' agent, or 'all' if that's all there is
        for agent in compatible:
            if agent != "all":
                return agent
        return "all" if compatible else None

    def get_all_agents(self) -> list[str]:
        """Get list of all unique agent names (excluding 'all')."""
        agents = set()
        for config in self._tools.values():
            spec = config.get("spec", {})
            for agent in spec.get("compatible_agents", []):
                if agent != "all":
                    agents.add(agent)
        return sorted(agents)

    def get_tools_by_category(self, category: str) -> list[str]:
        """Get all tool names in a specific category."""
        return [
            name for name, config in self._tools.items()
            if config.get("metadata", {}).get("category") == category
        ]

    def get_categories_for_agent(self, agent_name: str) -> list[str]:
        """Get all unique categories for a given agent."""
        categories = set()
        for name, config in self._tools.items():
            spec = config.get("spec", {})
            if agent_name in spec.get("compatible_agents", []):
                categories.add(config.get("metadata", {}).get("category", "utility"))
        return sorted(categories)

    def get_binary_for_tool(self, tool_name: str) -> Optional[str]:
        """Get the binary name for a tool."""
        config = self._tools.get(tool_name)
        if not config:
            return None
        return config.get("metadata", {}).get("binary")

    def get_tool_transport(self, tool_name: str) -> str:
        """Return 'http' or 'subprocess' (default)."""
        config = self._tools.get(tool_name)
        if not config:
            return "subprocess"
        return config.get("metadata", {}).get("transport", "subprocess")

    def get_tool_endpoint(self, tool_name: str) -> Optional[str]:
        """Return the HTTP endpoint path for an http-transport tool."""
        config = self._tools.get(tool_name)
        if not config:
            return None
        return config.get("metadata", {}).get("endpoint")

    def get_tool_http_method(self, tool_name: str) -> str:
        """Return the HTTP method for an http-transport tool (default: GET)."""
        config = self._tools.get(tool_name)
        if not config:
            return "GET"
        return config.get("metadata", {}).get("http_method", "GET")

    def get_tool_lifecycle(self, tool_name: str) -> str:
        """Return lifecycle hint: 'oneshot', 'interactive', 'streaming', or 'daemonizing'."""
        return _TOOL_LIFECYCLE.get(tool_name, "oneshot")

    def get_all_binaries(self) -> list[str]:
        """Get a deduplicated list of all tool binaries."""
        binaries = set()
        for config in self._tools.values():
            binary = config.get("metadata", {}).get("binary")
            if binary:
                binaries.add(binary)
        return sorted(binaries)

    def get_agent_summary(self) -> dict[str, dict]:
        """Get a summary of each agent's tool count and categories."""
        summary: dict[str, dict] = {}
        for agent in self.get_all_agents():
            tools = self.get_tools_for_agent(agent)
            categories = self.get_categories_for_agent(agent)
            summary[agent] = {
                "tool_count": len(tools),
                "categories": categories,
                "tools": tools,
            }
        return summary

    # ── Catalog / dashboard queries ───────────────────────────────────

    def get_catalog(self) -> list[dict]:
        """Return all tool metadata for dashboard marketplace."""
        result = []
        for name, config in self._tools.items():
            meta = config.get("metadata", {})
            spec = config.get("spec", {})
            result.append({
                "name": name,
                "category": meta.get("category", "utility"),
                "description": spec.get("description", ""),
                "requires_root": meta.get("requires_root", False),
                "binary": meta.get("binary", ""),
                "passive": meta.get("passive", False),
                "timeout": spec.get("timeout"),
                "cumulative_ceiling": spec.get("cumulative_ceiling"),
                "compatible_agents": spec.get("compatible_agents", []),
            })
        return result

    def check_binary_available(self, tool_name: str) -> bool:
        """Verify required binary is on PATH (shutil.which)."""
        config = self._tools.get(tool_name)
        if not config:
            return False
        binary = config.get("metadata", {}).get("binary", "")
        if not binary:
            return True  # No binary needed (e.g., shared/python tools)
        return shutil.which(binary) is not None

    def check_all_binaries(self) -> dict[str, bool]:
        """Batch availability check for all tools."""
        return {name: self.check_binary_available(name) for name in self._tools}

    def get_tools_for_category(self, category: str) -> list[dict]:
        """Return tools filtered by category (as catalog entries)."""
        return [
            entry for entry in self.get_catalog()
            if entry["category"] == category
        ]

    # ── Flag map queries (for data-driven command building) ───────────

    def get_flag_map(self, tool_name: str) -> Optional[list[dict]]:
        """Return the flag_map for a tool, or None."""
        return self._flag_maps.get(tool_name)

    def get_all_flag_maps(self) -> dict[str, list[dict]]:
        """Return all cached flag_maps."""
        return dict(self._flag_maps)

    @property
    def loaded(self) -> bool:
        """True if any tools have been loaded from YAML."""
        return len(self._tools) > 0


# ---------------------------------------------------------------------------
# Module-level singleton for convenient access
# ---------------------------------------------------------------------------

_registry: Optional[ToolRegistry] = None


def get_registry() -> ToolRegistry:
    """Get or create the module-level ToolRegistry singleton."""
    global _registry
    if _registry is None:
        catalog_dir = Path(os.environ.get(
            "TOOL_CATALOG_DIR",
            Path(__file__).parent / "catalog",
        ))
        _registry = ToolRegistry(catalog_dir)
        _registry.load_all()
    return _registry


def reset_registry() -> None:
    """Reset the singleton (useful for testing or hot-reload)."""
    global _registry
    _registry = None

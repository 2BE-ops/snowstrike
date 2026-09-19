"""
Tool-to-agent mapping registry — thin delegation layer over ToolRegistry.

All data now comes from the YAML catalog via ToolRegistry (registry_loader.py).
This module preserves the same public API for backward compatibility.

Current tool-owning runtime agents:
  recon      - Network reconnaissance, port scanning, DNS, service enumeration
  webapp     - Web discovery, crawling, vulnerability scanning, parameter discovery,
               and web exploitation workflows
  browser    - Headless Chrome automation, DOM analysis, screenshots
  attack     - Exploitation frameworks, payloads, credential attacks, and network exploitation
  binary     - Reverse engineering, debugging, exploit development
  cloud      - Cloud/container/K8s security assessment
  forensics  - Digital forensics, steganography, cryptanalysis
  osint      - Open-source intelligence gathering
  reporting  - Engagement report generation
  ghidra     - Deep reverse engineering via ghidra-mcp
"""

from typing import Optional

from tools.registry_loader import get_registry


# ---------------------------------------------------------------------------
# Lazy-loaded TOOL_REGISTRY dict (backward compatibility for direct imports)
# ---------------------------------------------------------------------------

class _LazyToolRegistry(dict):
    """Dict-like wrapper that loads from YAML on first access."""

    _loaded = False

    def _ensure_loaded(self):
        if not self._loaded:
            self._loaded = True
            reg = get_registry()
            for name, config in reg._tools.items():
                meta = config.get("metadata", {})
                spec = config.get("spec", {})
                compatible = spec.get("compatible_agents", [])
                agent = next((a for a in compatible if a != "all"), "shared")
                entry = {
                    "agent": agent,
                    "category": meta.get("category", "utility"),
                    "binary": meta.get("binary"),
                }
                transport = meta.get("transport")
                if transport:
                    entry["transport"] = transport
                    endpoint = meta.get("endpoint")
                    if endpoint:
                        entry["endpoint"] = endpoint
                    http_method = meta.get("http_method")
                    if http_method:
                        entry["http_method"] = http_method
                dict.__setitem__(self, name, entry)

    def __getitem__(self, key):
        self._ensure_loaded()
        return dict.__getitem__(self, key)

    def __contains__(self, key):
        self._ensure_loaded()
        return dict.__contains__(self, key)

    def get(self, key, default=None):
        self._ensure_loaded()
        return dict.get(self, key, default)

    def keys(self):
        self._ensure_loaded()
        return dict.keys(self)

    def values(self):
        self._ensure_loaded()
        return dict.values(self)

    def items(self):
        self._ensure_loaded()
        return dict.items(self)

    def __iter__(self):
        self._ensure_loaded()
        return dict.__iter__(self)

    def __len__(self):
        self._ensure_loaded()
        return dict.__len__(self)

    def __repr__(self):
        self._ensure_loaded()
        return dict.__repr__(self)


TOOL_REGISTRY: dict[str, dict] = _LazyToolRegistry()


# ---------------------------------------------------------------------------
# Public API — delegates to ToolRegistry singleton
# ---------------------------------------------------------------------------

def get_tools_for_agent(agent_name: str) -> list[str]:
    """Get all tool names assigned to a specific agent."""
    return get_registry().get_tools_for_agent(agent_name)


def get_agent_for_tool(tool_name: str) -> Optional[str]:
    """Get the agent name that owns a tool."""
    return get_registry().get_agent_for_tool(tool_name)


def get_all_agents() -> list[str]:
    """Get list of all unique agent names."""
    return get_registry().get_all_agents()


def get_tools_by_category(category: str) -> list[str]:
    """Get all tool names in a specific category."""
    return get_registry().get_tools_by_category(category)


def get_categories_for_agent(agent_name: str) -> list[str]:
    """Get all unique categories for a given agent."""
    return get_registry().get_categories_for_agent(agent_name)


def get_binary_for_tool(tool_name: str) -> Optional[str]:
    """Get the binary name for a tool."""
    return get_registry().get_binary_for_tool(tool_name)


def get_tool_transport(tool_name: str) -> str:
    """Return the transport type for a tool: 'http' or 'subprocess' (default)."""
    return get_registry().get_tool_transport(tool_name)


def get_tool_endpoint(tool_name: str) -> Optional[str]:
    """Return the HTTP endpoint path for an http-transport tool."""
    return get_registry().get_tool_endpoint(tool_name)


def get_tool_http_method(tool_name: str) -> str:
    """Return the HTTP method for an http-transport tool (default: GET)."""
    return get_registry().get_tool_http_method(tool_name)


def get_all_binaries() -> list[str]:
    """Get a deduplicated list of all tool binaries."""
    return get_registry().get_all_binaries()


def get_tool_lifecycle(tool_name: str) -> str:
    """Return the lifecycle hint for a tool (default: 'oneshot')."""
    return get_registry().get_tool_lifecycle(tool_name)


def get_agent_summary() -> dict[str, dict]:
    """Get a summary of each agent's tool count and categories."""
    return get_registry().get_agent_summary()

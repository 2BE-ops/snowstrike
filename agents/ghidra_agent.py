"""SnowStrike AI v7.0 - GhidraAgent

Dedicated reverse engineering agent backed by ghidra-mcp.
Manages a persistent Ghidra session for deep binary analysis:
decompilation, cross-references, call graphs, annotation, and scripting.
"""
from agents.base_agent import BaseAgent


class GhidraAgent(BaseAgent):
    agent_name = "Ghidra RE Agent"
    agent_type = "ghidra"

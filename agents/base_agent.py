"""
SnowStrike AI v7.0 - Base Agent

LLM-powered sub-agent with tool_use conversation loop via the Anthropic API.
Each sub-agent gets its own Claude session with focused system prompt and tools.

v7.1: Streaming API responses, parallel tool execution, event bus integration.
"""

import json
import hashlib
import logging
import math
import os
import re
import shlex
import threading
import time
import uuid
from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field, is_dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

import anthropic

from config import MAX_AGENT_TURNS, MAX_RAW_OUTPUT_SIZE, get_model_context_window
from memory.database import DatabaseManager
from memory.relevance_scorer import RelevanceScorer
from memory.shared_state import SharedState
from memory.attack_story import AttackStory
from memory.network_map import NetworkMap
from memory.compactor import OutputCompactor
from memory.event_bus import get_event_bus, EventType
from tools.executor import ToolExecutor
from tools.definitions import (
    get_tool_definitions_for_agent,
    build_command,
)
from agents.protocol import AgentHandoff, HandoffQueue, format_handoff_for_context
from memory.cost_tracker import CostTracker
from tools.hooks import get_hook_registry, HookEvent, HookEventType, HookAction

logger = logging.getLogger(__name__)

# Lazy import sentinel for ClaudeCodeError to avoid circular imports.
# The actual class is imported from agents.model_client at runtime.
try:
    from agents.model_client import ClaudeCodeError as _ClaudeCodeErrorType
except ImportError:
    _ClaudeCodeErrorType = type(None)  # Will never match if import fails


@dataclass
class AgentResult:
    """Structured result returned by a sub-agent to the orchestrator."""

    agent_name: str
    task: str
    success: bool
    summary: str
    findings: dict = field(default_factory=dict)
    duration_seconds: float = 0.0
    tools_used: list = field(default_factory=list)
    errors: list = field(default_factory=list)
    suggested_next_steps: list = field(default_factory=list)
    outcome_class: str = "normal"  # normal | model_refusal | provider_error | timeout


# ---------------------------------------------------------------------------
# Model refusal detection
# ---------------------------------------------------------------------------

# Weighted refusal signals — checked only on no-tool end_turn responses
_REFUSAL_SIGNALS = {
    "strong": [
        "i cannot", "i can't", "i'm not able to", "i must decline",
        "against my guidelines", "i'm unable to", "i will not",
        "i cannot assist", "i can't help with", "i'm not going to",
        "goes against my", "violates my", "outside my ethical",
    ],
    "medium": [
        "i'm sorry but", "i apologize but", "not appropriate for me",
        "potentially harmful", "i need to refuse", "cannot comply",
        "i have to decline", "as an ai", "as a language model",
    ],
}


def classify_refusal(text: str, tools_were_used: bool) -> Optional[str]:
    """Classify whether a model response is a refusal.

    Returns a refusal class string ("strong" / "medium") or None.
    Primary gate: if the model used any tools, it did work — not a refusal.
    """
    if tools_were_used:
        return None
    if not text or len(text.strip()) < 20:
        return None

    lower = text.lower()

    for phrase in _REFUSAL_SIGNALS["strong"]:
        if phrase in lower:
            return "strong"

    # Medium signals require multiple hits to reduce false positives
    medium_hits = sum(1 for p in _REFUSAL_SIGNALS["medium"] if p in lower)
    if medium_hits >= 2:
        return "medium"

    return None


class BaseAgent(ABC):
    """
    LLM-powered sub-agent with tool_use conversation loop.

    Each sub-agent:
    - Has its own Claude API session
    - Sees only its assigned tools + shared tools
    - Receives compacted tool output (never raw)
    - Reads/writes shared state, DB, story, and network map
    """

    agent_name: str = "base"
    agent_type: str = "base"  # matches key in TOOL_DEFINITIONS
    model: str = "claude-sonnet-4-20250514"
    max_turns: int = MAX_AGENT_TURNS

    def __init__(
        self,
        engagement_dir: str,
        anthropic_client=None,
        engagement_id: int = 1,
        model_override: str = "",
        prompt_dir: str = "",
        agent_config: dict = None,
    ):
        self.engagement_dir = engagement_dir
        self.engagement_id = engagement_id
        self._prompt_dir = prompt_dir  # override prompt source directory
        self._agent_config = agent_config  # YAML config from AgentRegistry

        # Apply YAML config overrides (agent_config takes lowest priority,
        # then class attributes, then model_override takes highest)
        if agent_config and not model_override:
            spec = agent_config.get("spec", {})
            if spec.get("model"):
                self.model = spec["model"]
            if spec.get("max_turns"):
                self.max_turns = spec["max_turns"]

        # Apply per-engagement model override if provided (highest priority)
        if model_override:
            self.model = model_override

        # Build the correct client for this agent's model
        if anthropic_client is not None and not model_override:
            self.client = anthropic_client
        else:
            from agents.model_client import create_model_client
            self.client = create_model_client(self.model)

        # Memory systems
        self.db = DatabaseManager(engagement_dir)
        self.shared_state = SharedState(engagement_dir)
        self.story = AttackStory(engagement_dir)
        self.network_map = NetworkMap(engagement_dir)

        # Load model hyperparameters (temperature, top_p, max_tokens) from experiment config
        self._model_params = self._load_model_params()

        # Tool execution
        self.tool_executor = ToolExecutor()
        self.compactor = OutputCompactor()

        # Build tool list: get_tool_definitions_for_agent already includes SHARED_TOOLS
        self.tools = get_tool_definitions_for_agent(self.agent_type, agent_config=self._agent_config)

        # Load system prompt
        self.system_prompt = self._load_system_prompt()

        # Conversation log for debugging
        self.conversation_log = []
        self.tools_used = []
        self.errors = []
        self._tool_state_lock = threading.Lock()  # Guards mutable state during parallel tool execution
        self._conversation_session_id = ""
        self._current_turn_number = 0

        # Within-session dedup tracking: set of (tool_name, normalized_args) already executed
        self._session_tool_fingerprints: set[str] = set()
        # Tools exempt from dedup (state management, info-retrieval tools)
        self._dedup_exempt_tools = {
            "save_finding", "read_shared_state", "update_shared_state",
            "add_to_network_map", "log_message", "get_raw_output",
            "query_tool_history", "generic_command",
        }

        # Handoff queue for structured inter-agent communication
        self.handoff_queue = HandoffQueue(engagement_dir)

        # Cost tracking
        self.cost_tracker = CostTracker(self.db.db_path)

        # Per-tool runtime budgets (seconds) and no-signal kill-switch tracking.
        self._tool_timeout_budgets = {
            "generic_command": 120,
            "msfconsole_run": 420,
            "metasploit_module": 420,
            "nikto_scan": 360,
            "feroxbuster_scan": 360,
            "testssl_scan": 360,
            "nmap_advanced": 480,
            "nmap_scan": 420,
        }
        self._no_signal_guard_tools = {
            "msfconsole_run",
            "metasploit_module",
            "nikto_scan",
            "feroxbuster_scan",
            "testssl_scan",
            "nmap_scan",
            "nmap_advanced",
        }
        self._tool_no_signal_runs: dict[str, int] = {}
        self._max_no_signal_runs = 2

        # Phase 3: Per-tool cumulative time ceilings (seconds).
        # If a single tool has already consumed this much cumulative wall-clock
        # time across all invocations in one agent session, further runs are skipped.
        self._tool_cumulative_ceilings = {
            "nmap_scan": 900,        # 15 min total for nmap scans
            "nmap_advanced": 900,
            "nikto_scan": 600,
            "feroxbuster_scan": 600,
            "msfconsole_run": 600,
            "metasploit_module": 600,
            "testssl_scan": 500,
            "gobuster_scan": 500,
            "nuclei_scan": 500,
        }
        self._tool_cumulative_usage: dict[str, float] = {}  # tool -> total seconds used

        # Per-agent total tool-execution budget (seconds).
        # Prevents "wide + deep + exploit" in the same turn from timing out the agent.
        self._agent_tool_budget = float(os.environ.get("AGENT_TOOL_BUDGET", "1800"))
        self._agent_tool_time_used = 0.0
        self._auto_persisted_discoveries: set[str] = set()

        # Compatibility probe: run once at init, acts as hard pre-execution gate.
        from tools.compatibility import CompatibilityProbe, probe_and_persist
        self._compat_probe = probe_and_persist(self.shared_state)

    # Map agent_type to prompt filename for cases where they differ
    _PROMPT_FILENAME_MAP = {
        "binary": "binary_re.md",
    }

    @staticmethod
    def _get_anti_rationalization_preamble() -> str:
        """Return the universal anti-rationalization preamble prepended to all agent prompts."""
        return """\
## Known Reasoning Failures — Read Before Acting

You are an LLM-based penetration testing agent. You have systematic failure modes
that you MUST actively guard against:

1. **Rationalization of completeness**: You will feel that a scan is "complete" after
   running one tool with default settings. It is not. Default nmap scans only 1000 of
   65535 ports. Default Nikto scans miss custom endpoints. Always state what was NOT
   tested.

2. **Version trust fallacy**: Service banners and HTTP headers are attacker-controlled
   strings, not ground truth. Never write "confirmed Apache 2.4.49" — write "banner
   reports Apache 2.4.49 (unverified)".

3. **Success confabulation**: You will want to report findings even when evidence is
   ambiguous. A 200 OK is not proof of exploitation. A timeout is not proof of
   filtering. State your confidence level: CONFIRMED / LIKELY / POSSIBLE / UNVERIFIED.

4. **Loop blindness**: If you are about to run a tool you have already run with the
   same arguments on the same target, STOP. Check your previous results first. If
   you must re-run, state why (e.g., "re-scanning after 30min to check for changes").

5. **Scope drift**: Do not add targets to scope. Do not scan hosts unless they are
   explicitly in the engagement scope. If you discover an adjacent host, report it
   but do NOT scan it.

BEFORE submitting your final summary, verify in your thinking:
- What did I actually CONFIRM (with evidence)?
- What did I ASSUME but not verify?
- What did I NOT test that I should have?
- Am I claiming success because I found something, or because I want to stop?

"""

    def _load_system_prompt(self) -> str:
        """Load the agent's system prompt with anti-rationalization preamble.

        The universal anti-rationalization preamble is prepended to every agent's
        prompt so all agents inherit reasoning-failure guardrails.

        Resolution order for agent-specific prompt:
        1. If a prompt_dir was provided (from master profile), look there first.
        2. Fall back to agents/prompts/{agent_type}.md (or mapped filename).
        """
        preamble = self._get_anti_rationalization_preamble()

        filename = self._PROMPT_FILENAME_MAP.get(self.agent_type, f"{self.agent_type}.md")
        agent_prompt = None

        # Try profile prompt directory first
        if self._prompt_dir:
            profile_path = Path(self._prompt_dir) / filename
            if profile_path.exists():
                agent_prompt = profile_path.read_text()
            else:
                # Also try the unmapped name
                alt_path = Path(self._prompt_dir) / f"{self.agent_type}.md"
                if alt_path.exists():
                    agent_prompt = alt_path.read_text()

        # Default: agents/prompts/
        if agent_prompt is None:
            prompt_path = Path(__file__).parent / "prompts" / filename
            if prompt_path.exists():
                agent_prompt = prompt_path.read_text()
            else:
                # Try unmapped name as last resort
                alt_default = Path(__file__).parent / "prompts" / f"{self.agent_type}.md"
                if alt_default.exists():
                    agent_prompt = alt_default.read_text()

        if agent_prompt is None:
            logger.warning(
                f"No prompt file found for {self.agent_type}, using default prompt"
            )
            agent_prompt = f"You are the {self.agent_name} for SnowStrike AI penetration testing framework."

        return preamble + agent_prompt

    def _load_model_params(self) -> dict:
        """Load per-role model hyperparameters from model_params.json if present.

        Returns the params dict for this agent's role (agent_type or tier),
        or empty dict if no overrides are configured.
        """
        params_path = os.path.join(self.engagement_dir, "model_params.json")
        if not os.path.exists(params_path):
            return {}
        try:
            with open(params_path) as f:
                all_params = json.load(f)
            # Check agent-specific params first, then tier-level
            return all_params.get(self.agent_type, all_params.get("_default", {}))
        except (json.JSONDecodeError, OSError):
            return {}

    def _get_api_kwargs(self) -> dict:
        """Build extra kwargs for API calls from model_params."""
        kwargs = {}
        if not self._model_params:
            return kwargs
        for key in ("temperature", "top_p"):
            if key in self._model_params:
                kwargs[key] = self._model_params[key]
        if "max_tokens" in self._model_params:
            kwargs["max_tokens"] = self._model_params["max_tokens"]
        return kwargs

    def _record_cost(self, response) -> None:
        """Extract token usage from an API response and record cost."""
        try:
            usage = getattr(response, "usage", None)
            if usage is None:
                usage = getattr(response, "usage", {})
            if isinstance(usage, dict):
                inp = usage.get("input_tokens", 0)
                out = usage.get("output_tokens", 0)
            else:
                inp = getattr(usage, "input_tokens", 0)
                out = getattr(usage, "output_tokens", 0)
            if inp or out:
                self.cost_tracker.record(
                    engagement_id=self.engagement_id,
                    model=self.model,
                    input_tokens=inp,
                    output_tokens=out,
                    agent=self.agent_name,
                )
        except Exception as e:
            logger.debug(f"[{self.agent_name}] Cost tracking failed: {e}")

    def _is_anthropic_client(self) -> bool:
        """Check if the current client is a native Anthropic client (supports streaming)."""
        return hasattr(self.client, 'messages') and hasattr(self.client.messages, 'stream')

    def _is_grok_client(self) -> bool:
        """Check if the current client is a Grok client (supports SSE streaming)."""
        return getattr(self.client, 'is_grok', False)

    def _is_claude_code_client(self) -> bool:
        """Check if the current client is a Claude Code CLI client."""
        return getattr(self.client, 'is_claude_code', False)

    def _call_api_streaming(self, messages: list, turn: int = 0) -> object:
        """Call LLM API with streaming, emitting tokens to event bus in real-time.

        Supports three streaming paths:
          1. Anthropic native streaming (messages.stream)
          2. Grok SSE streaming (via GrokStreamContext)
          3. Falls back to non-streaming for other OpenAI-compatible clients

        Returns a complete response object (same shape as messages.create).
        """
        event_bus = get_event_bus()
        event_bus.llm_start(self.agent_name, self.model, turn, self.engagement_id)

        if self._is_claude_code_client():
            return self._call_claude_code(messages, turn, event_bus)

        if self._is_grok_client():
            return self._call_grok_streaming(messages, turn, event_bus)

        if not self._is_anthropic_client():
            # OpenAI-compatible clients: use non-streaming path
            return self._call_api_with_retry(messages)

        import anthropic as _anthropic

        extra_kwargs = self._get_api_kwargs()
        max_tokens = extra_kwargs.pop("max_tokens", 8192)

        for attempt in range(3):
            try:
                with self.client.messages.stream(
                    model=self.model,
                    max_tokens=max_tokens,
                    system=self.system_prompt,
                    tools=self.tools,
                    messages=messages,
                    **extra_kwargs,
                ) as stream:
                    # Emit tokens as they arrive
                    for text in stream.text_stream:
                        event_bus.llm_token(
                            self.agent_name,
                            text,
                            self.engagement_id,
                            turn=turn,
                        )

                    # Get the final accumulated message
                    response = stream.get_final_message()

                self._record_cost(response)

                event_bus.llm_complete(
                    self.agent_name, self.model,
                    getattr(getattr(response, 'usage', None), 'input_tokens', 0),
                    getattr(getattr(response, 'usage', None), 'output_tokens', 0),
                    self.engagement_id,
                    turn=turn,
                )
                return response

            except (_anthropic.RateLimitError, _anthropic.APIConnectionError) as e:
                if attempt == 2:
                    raise
                wait = (2 ** attempt) * 2
                logger.warning(
                    f"[{self.agent_name}] API error (attempt {attempt + 1}/3): {e}. "
                    f"Retrying in {wait}s..."
                )
                time.sleep(wait)
            except _anthropic.APIError:
                raise

    def _call_api_with_retry(self, messages: list, max_retries: int = 3) -> object:
        """Call the LLM API with exponential backoff on transient errors (non-streaming)."""
        import anthropic as _anthropic

        extra_kwargs = self._get_api_kwargs()
        max_tokens = extra_kwargs.pop("max_tokens", 8192)

        for attempt in range(max_retries):
            try:
                response = self.client.messages.create(
                    model=self.model,
                    max_tokens=max_tokens,
                    system=self.system_prompt,
                    tools=self.tools,
                    messages=messages,
                    **extra_kwargs,
                )
                self._record_cost(response)
                return response
            except (_anthropic.RateLimitError, _anthropic.APIConnectionError) as e:
                if attempt == max_retries - 1:
                    raise
                wait = (2 ** attempt) * 2  # 2s, 4s, 8s
                logger.warning(
                    f"[{self.agent_name}] API error (attempt {attempt + 1}/{max_retries}): {e}. "
                    f"Retrying in {wait}s..."
                )
                time.sleep(wait)
            except _anthropic.APIError:
                raise  # Non-transient errors should not retry

    def _call_grok_streaming(self, messages: list, turn: int, event_bus) -> object:
        """Call Grok API with SSE streaming, emitting tokens to event bus in real-time.

        Uses GrokStreamContext which mimics Anthropic's stream interface.
        Supports all Grok models including reasoning and multi-agent.
        """
        from openai import APIStatusError, APIConnectionError, RateLimitError

        for attempt in range(3):
            try:
                with self.client.messages.stream(
                    model=self.model,
                    max_tokens=8192,
                    system=self.system_prompt,
                    tools=self.tools,
                    messages=messages,
                ) as stream:
                    for text in stream.text_stream:
                        event_bus.llm_token(
                            self.agent_name,
                            text,
                            self.engagement_id,
                            turn=turn,
                        )

                    response = stream.get_final_message()

                self._record_cost(response)

                event_bus.llm_complete(
                    self.agent_name, self.model,
                    response.usage.get("input_tokens", 0) if isinstance(response.usage, dict) else getattr(response.usage, "input_tokens", 0),
                    response.usage.get("output_tokens", 0) if isinstance(response.usage, dict) else getattr(response.usage, "output_tokens", 0),
                    self.engagement_id,
                    turn=turn,
                )
                return response

            except (RateLimitError, APIConnectionError) as e:
                if attempt == 2:
                    raise
                wait = (2 ** attempt) * 2
                logger.warning(
                    f"[{self.agent_name}] Grok API error (attempt {attempt + 1}/3): {e}. "
                    f"Retrying in {wait}s..."
                )
                time.sleep(wait)
            except APIStatusError as e:
                if e.status_code in (500, 502, 503, 529) and attempt < 2:
                    wait = (2 ** attempt) * 2
                    logger.warning(
                        f"[{self.agent_name}] Grok server error {e.status_code} "
                        f"(attempt {attempt + 1}/3), retrying in {wait}s..."
                    )
                    time.sleep(wait)
                else:
                    raise

    def _call_claude_code(self, messages: list, turn: int, event_bus) -> object:
        """Call Claude Code CLI (non-streaming), emitting start/complete events.

        The ClaudeCodeClient handles subprocess invocation and response parsing.
        This method wraps it with event bus integration and retry logic.
        """
        from agents.model_client import ClaudeCodeError

        extra_kwargs = self._get_api_kwargs()
        max_tokens = extra_kwargs.pop("max_tokens", 8192)

        for attempt in range(3):
            try:
                response = self.client.messages.create(
                    model=self.model,
                    max_tokens=max_tokens,
                    system=self.system_prompt,
                    tools=self.tools,
                    messages=messages,
                    **extra_kwargs,
                )
                self._record_cost(response)

                event_bus.llm_complete(
                    self.agent_name, self.model,
                    response.usage.get("input_tokens", 0) if isinstance(response.usage, dict) else 0,
                    response.usage.get("output_tokens", 0) if isinstance(response.usage, dict) else 0,
                    self.engagement_id,
                    turn=turn,
                )
                return response

            except ClaudeCodeError as e:
                error_str = str(e)
                if attempt == 2:
                    raise
                # Retry on transient issues (timeout, empty response)
                if "timed out" in error_str.lower() or "empty" in error_str.lower():
                    wait = (2 ** attempt) * 2
                    logger.warning(
                        f"[{self.agent_name}] Claude Code error (attempt {attempt + 1}/3): {e}. "
                        f"Retrying in {wait}s..."
                    )
                    time.sleep(wait)
                else:
                    # Non-transient errors (auth, not installed) — fail immediately
                    raise

    def execute(self, task: str) -> AgentResult:
        """
        Run the agent's tool_use conversation loop.

        v7.1: Uses streaming API calls + parallel tool execution + event bus.

        1. Build initial message with task + context from shared state
        2. Loop: stream from Claude API -> handle tool_use (parallel) -> return compacted results
        3. On end_turn: extract findings from final response
        4. Return AgentResult summary to orchestrator
        """
        start_time = time.time()
        task = str(task) if not isinstance(task, str) else task
        self._current_task = task  # Stored for relevance-scored context trimming
        logger.info(f"[{self.agent_name}] Starting task: {task[:100]}...")

        event_bus = get_event_bus()
        self._conversation_session_id = (
            f"{self.agent_type}-{int(start_time * 1000)}-{uuid.uuid4().hex[:8]}"
        )
        event_bus.agent_start(self.agent_name, task, self.engagement_id)

        # Per-agent execution timeout (seconds). Prevents infinite stalls.
        max_execution_time = max(60, min(7200, int(os.environ.get("AGENT_TIMEOUT", "600"))))

        # Build the initial user message with context (must not crash agent)
        try:
            context = self._build_context(task)
        except Exception as e:
            logger.error(f"[{self.agent_name}] Context build failed: {e}, using task only")
            context = f"## Task\n{task}\n\n(Context unavailable due to error: {e})"
        self._last_built_context = context  # Persist for conversation log
        self._execute_start = start_time
        self._token_estimate_cache = None  # Reset cache for lazy trimming
        self._current_turn_number = 0
        messages = [{"role": "user", "content": context}]
        initial_context_tokens = self._estimate_tokens(messages)
        self.max_turns = self._resolve_dynamic_turn_limit(initial_context_tokens)
        logger.info(
            "[%s] Dynamic turn budget: %s turns (model=%s, context_tokens~%s, window=%s)",
            self.agent_name,
            self.max_turns,
            self.model,
            initial_context_tokens,
            self._get_context_window(),
        )
        self._log_conversation("user", context)  # Log the initial context message

        final_text = ""
        turn_count = 0

        try:
            while turn_count < self.max_turns:
                # Check execution timeout before each turn
                elapsed = time.time() - start_time
                if elapsed > max_execution_time:
                    logger.warning(
                        f"[{self.agent_name}] Execution timeout after {elapsed:.0f}s "
                        f"(limit: {max_execution_time}s)"
                    )
                    self.errors.append(
                        f"Execution timeout after {elapsed:.0f}s"
                    )
                    if not final_text:
                        final_text = (
                            f"Agent timed out after {elapsed:.0f}s. "
                            f"Completed {turn_count} turns before timeout."
                        )
                    break

                turn_count += 1
                self._current_turn_number = turn_count
                logger.info(
                    f"[{self.agent_name}] Turn {turn_count}/{self.max_turns}"
                )

                event_bus.emit(event_bus._make_event(
                    EventType.AGENT_PROGRESS, self.agent_name,
                    {"turn": turn_count, "max_turns": self.max_turns, "elapsed": round(elapsed, 1)},
                    self.engagement_id,
                ))

                # Lazy context trimming: only trim when we've added new content
                messages = self._trim_context_lazy(messages)

                # Call Claude API with streaming
                logger.info(f"[{self.agent_name}] Calling API (streaming)...")
                response = self._call_api_streaming(messages, turn_count)

                # Log the conversation (content blocks only, not full API response)
                self._log_conversation("assistant", response.content)

                # Process the response
                assistant_content = response.content
                messages.append({"role": "assistant", "content": assistant_content})

                # Check if the agent is done
                if response.stop_reason == "end_turn":
                    # Extract text from the final response
                    for block in assistant_content:
                        if block.type == "text":
                            final_text += block.text

                    # Refusal detection: no tools used + refusal language
                    refusal_class = classify_refusal(final_text, bool(self.tools_used))
                    if refusal_class:
                        self._log_refusal_audit(
                            task, final_text, turn_count, response,
                            refusal_class,
                        )
                        self._refusal_raw_text = final_text
                        final_text = (
                            "Model refusal on offensive task; "
                            "no target-side result produced."
                        )
                        self._refusal_class = refusal_class
                        event_bus.emit(event_bus._make_event(
                            EventType.MODEL_REFUSAL, self.agent_name,
                            {
                                "refusal_class": refusal_class,
                                "model": self.model,
                                "turn": turn_count,
                            },
                            self.engagement_id,
                        ))
                    break

                # Collect tool_use blocks
                tool_blocks = [b for b in assistant_content if b.type == "tool_use"]

                if tool_blocks:
                    # Parallel tool execution when multiple tool calls in one response
                    tool_results = self._execute_tools_parallel(tool_blocks)
                    messages.append({"role": "user", "content": tool_results})
                    self._log_conversation("tool_results", tool_results)

            else:
                logger.warning(
                    f"[{self.agent_name}] Hit max turns ({self.max_turns})"
                )
                self.errors.append(f"Hit maximum turn limit ({self.max_turns})")

        except anthropic.APIError as e:
            # Phase 7: Classify provider failures separately
            error_class = "provider_api"
            error_str = str(e)
            if "rate" in error_str.lower() or "429" in error_str:
                error_class = "provider_rate_limit"
            elif "quota" in error_str.lower() or "billing" in error_str.lower() or "402" in error_str:
                error_class = "provider_quota"
            elif "auth" in error_str.lower() or "401" in error_str:
                error_class = "provider_auth"
            logger.error(f"[{self.agent_name}] API error ({error_class}): {e}")
            self.errors.append(f"API error ({error_class}): {error_str}")
            final_text = f"Agent encountered an API error ({error_class}): {e}"
            event_bus.emit(event_bus._make_event(
                EventType.AGENT_ERROR, self.agent_name,
                {"error": error_str, "error_class": error_class},
                self.engagement_id,
            ))

        except _ClaudeCodeErrorType as e:
            # Claude Code CLI failures
            error_str = str(e)
            error_class = "provider_claude_code"
            if "auth" in error_str.lower() or "login" in error_str.lower():
                error_class = "provider_auth"
            elif "timed out" in error_str.lower():
                error_class = "provider_timeout"
            logger.error(f"[{self.agent_name}] Claude Code error ({error_class}): {e}")
            self.errors.append(f"Claude Code error ({error_class}): {error_str}")
            final_text = f"Agent encountered a Claude Code CLI error ({error_class}): {e}"
            event_bus.emit(event_bus._make_event(
                EventType.AGENT_ERROR, self.agent_name,
                {"error": error_str, "error_class": error_class},
                self.engagement_id,
            ))

        except Exception as e:
            # Phase 7: Classify runtime failures
            error_str = str(e)
            error_class = "runtime"
            if "shutdown" in error_str.lower() or "thread" in error_str.lower():
                error_class = "runtime_shutdown"
            elif "timeout" in error_str.lower():
                error_class = "runtime_timeout"
            logger.error(f"[{self.agent_name}] Unexpected error ({error_class}): {e}")
            self.errors.append(f"Unexpected error ({error_class}): {error_str}")
            final_text = f"Agent encountered an error ({error_class}): {e}"
            event_bus.emit(event_bus._make_event(
                EventType.AGENT_ERROR, self.agent_name,
                {"error": error_str, "error_class": error_class},
                self.engagement_id,
            ))

        duration = time.time() - start_time

        # Determine outcome class
        outcome_class = "normal"
        if hasattr(self, '_refusal_class') and self._refusal_class:
            outcome_class = "model_refusal"
        elif any("API error" in e for e in self.errors):
            outcome_class = "provider_error"
        elif any("timeout" in e.lower() for e in self.errors):
            outcome_class = "timeout"

        # Build the result
        result = AgentResult(
            agent_name=self.agent_name,
            task=task,
            success=len(self.errors) == 0 and outcome_class == "normal",
            summary=final_text,
            findings=self._extract_findings(final_text),
            duration_seconds=duration,
            tools_used=list(self.tools_used),
            errors=list(self.errors),
            suggested_next_steps=self._extract_next_steps(final_text),
            outcome_class=outcome_class,
        )

        # Emit completion event
        event_bus.agent_complete(
            self.agent_name, result.success, final_text[:300],
            duration, self.engagement_id,
        )
        event_bus.handoff(
            self.agent_name,
            "Orchestrator",
            "return",
            engagement_id=self.engagement_id,
            session_id=self._conversation_session_id,
            summary=(final_text or "")[:300],
            success=result.success,
            duration=round(duration, 1),
        )

        # Post-execution: story + log (must not crash the agent return)
        story_error = None
        try:
            self._update_story(task, result)
        except Exception as e:
            story_error = str(e)
            logger.error(f"[{self.agent_name}] Failed to update story: {e}", exc_info=True)

        try:
            if story_error:
                self.errors.append(f"Story update failed: {story_error}")
            self._save_conversation_log()
        except Exception as e:
            logger.error(f"[{self.agent_name}] Failed to save conversation log: {e}", exc_info=True)

        logger.info(
            f"[{self.agent_name}] Completed in {duration:.1f}s. "
            f"Tools used: {len(self.tools_used)}, Errors: {len(self.errors)}"
        )

        return result

    def _execute_tools_parallel(self, tool_blocks: list) -> list:
        """Execute tool_use blocks in parallel when multiple are present.

        For a single tool call, runs inline (no thread overhead).
        For multiple tool calls, uses ThreadPoolExecutor for concurrency.
        """
        if len(tool_blocks) == 1:
            block = tool_blocks[0]
            return [self._handle_tool_use(block.name, block.input, block.id)]

        # Separate into parallelizable (security tools) and sequential (state mutations)
        sequential_tools = {"save_finding", "update_shared_state", "add_to_network_map"}
        parallel_blocks = []
        sequential_blocks = []

        for block in tool_blocks:
            if block.name in sequential_tools:
                sequential_blocks.append(block)
            else:
                parallel_blocks.append(block)

        results = {}

        # Execute parallelizable tools concurrently
        if len(parallel_blocks) > 1:
            logger.info(f"[{self.agent_name}] Executing {len(parallel_blocks)} tools in parallel")
            with ThreadPoolExecutor(max_workers=min(len(parallel_blocks), 4)) as executor:
                futures = {
                    executor.submit(self._handle_tool_use, b.name, b.input, b.id): b.id
                    for b in parallel_blocks
                }
                for future in as_completed(futures):
                    tool_id = futures[future]
                    try:
                        results[tool_id] = future.result()
                    except Exception as e:
                        results[tool_id] = {
                            "type": "tool_result",
                            "tool_use_id": tool_id,
                            "content": f"Parallel execution error: {e}",
                        }
        else:
            for block in parallel_blocks:
                results[block.id] = self._handle_tool_use(block.name, block.input, block.id)

        # Execute sequential tools in order
        for block in sequential_blocks:
            results[block.id] = self._handle_tool_use(block.name, block.input, block.id)

        # Return results in original order
        return [results[b.id] for b in tool_blocks]

    def _estimate_tokens(self, messages: list) -> int:
        """Estimate token count for messages, system prompt, and tool definitions.

        Uses ~4 chars/token heuristic for message content, plus a fixed overhead
        for the system prompt and tool schemas which are always sent with each request.
        """
        total_chars = 0
        for msg in messages:
            content = msg.get("content", "")
            if isinstance(content, str):
                total_chars += len(content)
            elif isinstance(content, list):
                for block in content:
                    if isinstance(block, dict):
                        total_chars += len(json.dumps(block))
                    else:
                        total_chars += len(str(block))
        message_tokens = total_chars // 4

        # Account for system prompt + tool definitions (sent every request)
        overhead = len(self.system_prompt) // 4
        overhead += len(json.dumps(self.tools)) // 4
        return message_tokens + overhead

    def _get_context_window(self) -> int:
        """Return the configured context window for the active model."""
        return get_model_context_window(self.model, 150_000)

    def _get_context_limit(self) -> int:
        """Return a safe prompt budget with response headroom reserved."""
        window = self._get_context_window()
        reserve = max(12_000, min(window // 5, 120_000))
        return max(24_000, window - reserve)

    def _resolve_dynamic_turn_limit(self, initial_context_tokens: int) -> int:
        """Adjust agent turn budget to the active model and current context size."""
        base_turns = max(int(self.max_turns), 1)
        hard_cap = int(os.environ.get("SNOWSTRIKE_MAX_TURNS_HARD_CAP", "48"))
        usable_window = max(self._get_context_limit(), 1)
        pressure = initial_context_tokens / usable_window

        scaled = base_turns
        if pressure >= 0.45:
            scaled = round(base_turns * 0.55)
        elif pressure >= 0.30:
            scaled = round(base_turns * 0.75)
        elif pressure <= 0.08 and usable_window >= 800_000:
            scaled = round(base_turns * 1.50)
        elif pressure <= 0.15 and usable_window >= 320_000:
            scaled = round(base_turns * 1.20)

        return max(8, min(hard_cap, scaled))

    def _trim_context_lazy(self, messages: list) -> list:
        """Lazy context trimming: only estimate tokens when messages have grown.

        Caches the last token estimate and message count. Skips the full
        estimation scan if no new messages have been added since the last check.
        """
        cache = getattr(self, '_token_estimate_cache', None)
        if cache and cache['msg_count'] == len(messages):
            # No new messages since last check — skip expensive estimation
            return messages

        estimated = self._estimate_tokens(messages)
        max_tokens = self._get_context_limit()

        # Cache current state
        self._token_estimate_cache = {
            'msg_count': len(messages),
            'estimated_tokens': estimated,
        }

        if estimated <= max_tokens:
            return messages

        # Delegate to full trimming
        return self._trim_context(messages, max_tokens)

    def _trim_context(self, messages: list, max_tokens: int | None = None) -> list:
        """
        Trim conversation messages using relevance-scored pruning.

        Uses RelevanceScorer to rank messages across four dimensions (recency,
        tool success, finding density, task alignment) and drops the lowest-
        scoring messages first.  The system message (index 0) and the last 2
        conversation pairs are never removed.
        """
        if max_tokens is None:
            max_tokens = self._get_context_limit()
        estimated = self._estimate_tokens(messages)
        if estimated <= max_tokens:
            return messages

        logger.info(
            f"[{self.agent_name}] Context too large (~{estimated} tokens), "
            f"running relevance-scored pruning..."
        )

        # Derive current task string for alignment scoring
        current_task = getattr(self, '_current_task', '') or ''
        if not current_task and messages:
            # Fall back to first message content (the task context)
            first_content = messages[0].get("content", "")
            if isinstance(first_content, str):
                current_task = first_content[:500]

        scorer = RelevanceScorer()
        result = scorer.prune(messages, max_tokens, current_task)

        new_estimate = self._estimate_tokens(result)
        logger.info(
            f"[{self.agent_name}] Trimmed context: {estimated} -> {new_estimate} "
            f"tokens ({len(messages)} -> {len(result)} messages)"
        )
        return result

    def _truncate_message_smart(self, msg: dict) -> dict:
        """Smartly truncate a message, preserving high-value content like findings."""
        content = msg.get("content", "")
        if isinstance(content, str):
            # Preserve finding-related content more
            if any(kw in content.lower() for kw in ["vulnerability", "credential", "finding", "save_finding", "critical", "high"]):
                max_len = 2000
            else:
                max_len = 1000
            if len(content) > max_len:
                return {**msg, "content": content[:max_len] + "\n... (trimmed for context)"}
            return msg
        elif isinstance(content, list):
            new_content = []
            for block in content:
                if isinstance(block, dict) and block.get("type") == "tool_result":
                    c = block.get("content", "")
                    if isinstance(c, str):
                        # Preserve save_finding results and error reflections
                        is_finding = any(kw in c.lower() for kw in ["saved", "vulnerability", "credential", "reflection"])
                        max_len = 2000 if is_finding else 1000
                        if len(c) > max_len:
                            block = {**block, "content": c[:max_len] + "\n... (trimmed for context)"}
                new_content.append(block)
            return {**msg, "content": new_content}
        return msg

    def _truncate_message(self, msg: dict, max_content_len: int = 500) -> dict:
        """Truncate tool result content in a message."""
        content = msg.get("content", "")
        if isinstance(content, str):
            if len(content) > max_content_len:
                return {**msg, "content": content[:max_content_len] + "\n... (truncated)"}
            return msg
        elif isinstance(content, list):
            new_content = []
            for block in content:
                if isinstance(block, dict) and block.get("type") == "tool_result":
                    c = block.get("content", "")
                    if isinstance(c, str) and len(c) > max_content_len:
                        block = {**block, "content": c[:max_content_len] + "\n... (truncated)"}
                new_content.append(block)
            return {**msg, "content": new_content}
        return msg

    def _handle_tool_use(
        self, tool_name: str, tool_input: dict, tool_use_id: str
    ) -> dict:
        """
        Route tool calls to the appropriate handler.

        - Security tools -> ToolExecutor.run() -> compact output
        - save_finding -> DatabaseManager
        - read_shared_state -> SharedState
        - update_shared_state -> SharedState
        - add_to_network_map -> NetworkMap
        - log_message -> logger
        """
        logger.info(f"[{self.agent_name}] Tool call: {tool_name}")
        with self._tool_state_lock:
            self.tools_used.append(tool_name)

        # --- Pre-tool hook evaluation ---
        hook_registry = get_hook_registry()
        pre_event = HookEvent(
            event_type=HookEventType.PRE_TOOL_USE,
            tool_name=tool_name,
            tool_args=tool_input,
            agent_name=self.agent_name,
            engagement_id=self.engagement_id,
        )
        pre_action, pre_rule, inject_context = hook_registry.evaluate(pre_event)

        if pre_action == HookAction.BLOCK:
            reason = f"Blocked by hook '{pre_rule.name}'" if pre_rule else "Blocked"
            event_bus = get_event_bus()
            event_bus.emit(event_bus._make_event(
                EventType.HOOK_BLOCK, self.agent_name,
                {"tool": tool_name, "reason": reason},
                self.engagement_id,
            ))
            return {
                "type": "tool_result",
                "tool_use_id": tool_use_id,
                "tool_name": tool_name,
                "content": f"[HOOK BLOCKED] {reason}",
            }

        if pre_action == HookAction.DEFER:
            # Escalate to operator via approval queue
            import uuid as _uuid
            from memory.approvals import ApprovalRequest, ApprovalType, get_approval_queue
            event_bus = get_event_bus()
            event_bus.emit(event_bus._make_event(
                EventType.HOOK_DEFER, self.agent_name,
                {"tool": tool_name, "rule": pre_rule.name if pre_rule else ""},
                self.engagement_id,
            ))
            approval_req = ApprovalRequest(
                id=str(_uuid.uuid4()),
                approval_type=ApprovalType.TOOL_EXECUTION,
                description=f"Hook '{pre_rule.name}' deferred {tool_name}" if pre_rule else f"Deferred {tool_name}",
                agent_name=self.agent_name,
                tool_name=tool_name,
                tool_args=tool_input,
                urgency="normal",
            )
            result = get_approval_queue().request_approval(approval_req, timeout=300)
            if not result.approved:
                reason = result.operator_note or "Operator timeout — auto-denied"
                return {
                    "type": "tool_result",
                    "tool_use_id": tool_use_id,
                    "tool_name": tool_name,
                    "content": f"[HOOK BLOCKED] {reason}",
                }

        if pre_action == HookAction.MODIFY_ARGS and pre_rule and pre_rule.modify_fn:
            reason = f"Args modified by hook '{pre_rule.name}'"
            event_bus = get_event_bus()
            event_bus.emit(event_bus._make_event(
                EventType.HOOK_MODIFY, self.agent_name,
                {"tool": tool_name, "reason": reason},
                self.engagement_id,
            ))
            tool_input = pre_event.tool_args

        try:
            if tool_name == "save_finding":
                result_text = self._handle_save_finding(tool_input)
            elif tool_name == "read_shared_state":
                result_text = self._handle_read_shared_state(tool_input)
            elif tool_name == "update_shared_state":
                result_text = self._handle_update_shared_state(tool_input)
            elif tool_name == "add_to_network_map":
                result_text = self._handle_add_to_network_map(tool_input)
            elif tool_name == "log_message":
                result_text = self._handle_log_message(tool_input)
            elif tool_name == "get_raw_output":
                result_text = self._handle_get_raw_output(tool_input)
            elif tool_name == "query_tool_history":
                result_text = self._handle_query_tool_history(tool_input)
            elif tool_name == "request_flow":
                result_text = self._handle_request_flow(tool_input)
            else:
                result_text = self._handle_security_tool(tool_name, tool_input)

        except Exception as e:
            logger.error(
                f"[{self.agent_name}] Tool {tool_name} error: {e}"
            )
            self.errors.append(f"Tool {tool_name} error: {str(e)}")
            result_text = f"Error executing {tool_name}: {str(e)}"
            # Phase 4: log internal tool exceptions as synthetic execution rows
            self._log_synthetic_execution(
                tool_name, "agent_loop", "internal_tool_exception",
                result_text, tool_input,
            )

        # --- INJECT: prepend hook context to result ---
        if pre_action == HookAction.INJECT and inject_context:
            event_bus = get_event_bus()
            event_bus.emit(event_bus._make_event(
                EventType.HOOK_INJECT, self.agent_name,
                {"tool": tool_name, "rule": pre_rule.name if pre_rule else ""},
                self.engagement_id,
            ))
            result_text = f"[HOOK CONTEXT] {inject_context}\n---\n{result_text}"

        # --- Post-tool hook evaluation ---
        post_event = HookEvent(
            event_type=HookEventType.POST_TOOL_USE,
            tool_name=tool_name,
            tool_args=tool_input,
            agent_name=self.agent_name,
            engagement_id=self.engagement_id,
            tool_result=result_text,
        )
        hook_registry.evaluate(post_event)

        # --- POST_TOOL_FAILURE: fire only when the tool actually failed ---
        if isinstance(result_text, str) and (
            result_text.startswith("Error executing ")
            or result_text.startswith("[HOOK BLOCKED]")
        ):
            try:
                failure_event = HookEvent(
                    event_type=HookEventType.POST_TOOL_FAILURE,
                    tool_name=tool_name,
                    tool_args=tool_input,
                    agent_name=self.agent_name,
                    engagement_id=self.engagement_id,
                    tool_result=result_text,
                )
                hook_registry.evaluate(failure_event)
            except Exception as e:
                logger.debug("[%s] POST_TOOL_FAILURE hook error: %s", self.agent_name, e)

        return {
            "type": "tool_result",
            "tool_use_id": tool_use_id,
            "tool_name": tool_name,
            "content": result_text,
        }

    def _sanitize_tool_output(self, output: str) -> str:
        """Strip potential prompt injection patterns from tool output.

        Removes patterns that could be mistaken for system instructions
        when injected into the LLM context.
        """
        import re
        # Remove patterns that look like system instructions
        sanitized = re.sub(
            r'(?i)(you are|you must|ignore previous|system prompt|<\|?system\|?>|<\|?assistant\|?>|<\|?user\|?>)',
            '[FILTERED]',
            output
        )
        # Remove XML-like injection attempts
        sanitized = re.sub(r'</?(?:system|instruction|prompt|role|context)[^>]*>', '[FILTERED]', sanitized, flags=re.IGNORECASE)
        return sanitized

    def _post_handoff_with_hooks(self, handoff) -> None:
        """Post a handoff to the queue with PRE_HANDOFF / POST_HANDOFF hook evaluation."""
        try:
            hook_registry = get_hook_registry()
            pre_event = HookEvent(
                event_type=HookEventType.PRE_HANDOFF,
                tool_name=handoff.handoff_type,
                tool_args={
                    "source_agent": handoff.source_agent,
                    "target_agent": handoff.target_agent,
                    "summary": handoff.summary,
                },
                agent_name=self.agent_name,
                engagement_id=self.engagement_id,
            )
            action, rule, _ = hook_registry.evaluate(pre_event)
            if action == HookAction.BLOCK:
                logger.info("[Hook] PRE_HANDOFF blocked by '%s': %s",
                            rule.name if rule else "?", handoff.summary[:80])
                return
        except Exception as e:
            logger.debug("[%s] PRE_HANDOFF hook error: %s", self.agent_name, e)

        self.handoff_queue.post(handoff)

        try:
            post_event = HookEvent(
                event_type=HookEventType.POST_HANDOFF,
                tool_name=handoff.handoff_type,
                tool_args={
                    "source_agent": handoff.source_agent,
                    "target_agent": handoff.target_agent,
                    "summary": handoff.summary,
                },
                agent_name=self.agent_name,
                engagement_id=self.engagement_id,
            )
            hook_registry.evaluate(post_event)
        except Exception as e:
            logger.debug("[%s] POST_HANDOFF hook error: %s", self.agent_name, e)

    def _make_tool_fingerprint(self, tool_name: str, tool_input: dict) -> str:
        """Create a normalized fingerprint for a tool call to detect duplicates.

        Normalizes by sorting keys and stripping whitespace so that
        {"target": "10.0.0.1", "ports": "1-1000"} and
        {"ports": "1-1000", "target": "10.0.0.1"} produce the same fingerprint.
        """
        import hashlib
        # Extract the key identifying parameters (ignore metadata like timeout)
        dedup_keys = {}
        skip_keys = {"timeout", "extra_args", "threads", "output_format", "verbose"}
        for k, v in sorted(tool_input.items()):
            if k not in skip_keys and v is not None and v != "":
                dedup_keys[k] = str(v).strip().lower()
        raw = f"{tool_name}:{json.dumps(dedup_keys, sort_keys=True)}"
        return hashlib.md5(raw.encode()).hexdigest()[:16]

    def _check_tool_dedup(self, tool_name: str, tool_input: dict, cmd_args: list[str]) -> str | None:
        """Check if this tool call is a duplicate of a prior successful execution.

        Returns a dedup message string if duplicate found, or None if the tool should run.

        Checks two layers:
        1. Within-session: same tool+args already called in this agent execution
        2. Cross-session: same tool+args already succeeded in this engagement (any agent)
        """
        if tool_name in self._dedup_exempt_tools:
            return None

        fingerprint = self._make_tool_fingerprint(tool_name, tool_input)

        # 1. Within-session dedup (catches same-turn and multi-turn repeats)
        if fingerprint in self._session_tool_fingerprints:
            logger.warning(
                f"[{self.agent_name}] DEDUP BLOCKED (session): {tool_name} with same args already called this session"
            )
            return (
                f"[DEDUP BLOCKED] {tool_name} was already called with identical arguments "
                f"in this session. The results are already available above in the conversation. "
                f"Use get_raw_output to re-read previous results, or modify your arguments "
                f"(different target, ports, wordlist, etc.) to gather new information."
            )

        # 2. Cross-session dedup (catches cross-agent repeats via DB)
        cmd_str = " ".join(cmd_args) if cmd_args else ""
        prior = self.db.find_duplicate_execution(
            self.engagement_id, tool_name, cmd_str, tool_input
        )
        if prior:
            match_type = prior.get("_match_type", "unknown")
            prior_agent = prior.get("agent", "unknown")
            prior_summary = prior.get("compacted_summary", "")[:300]
            raw_path = prior.get("raw_output_path", "")

            # For exact/normalized matches: hard block
            if match_type in ("exact", "normalized"):
                logger.warning(
                    f"[{self.agent_name}] DEDUP BLOCKED (DB {match_type}): "
                    f"{tool_name} already succeeded by {prior_agent}"
                )
                result_msg = (
                    f"[DEDUP BLOCKED] {tool_name} was already run successfully by {prior_agent} "
                    f"with the same arguments.\n"
                    f"Previous result summary: {prior_summary}\n"
                )
                if raw_path:
                    result_msg += f"Full output available at: {raw_path}\n"
                result_msg += (
                    "Do NOT re-run this tool. Use get_raw_output to read the existing results, "
                    "or modify your approach (different target, scope, wordlist, etc.)."
                )
                # Still record the fingerprint so we don't check DB again
                self._session_tool_fingerprints.add(fingerprint)
                return result_msg

            # For target_overlap: soft warning (allow but inform)
            if match_type == "target_overlap":
                logger.info(
                    f"[{self.agent_name}] DEDUP WARNING (target overlap): "
                    f"{tool_name} on same target already run by {prior_agent}"
                )
                # Don't block — different args on same target may be intentional
                # (e.g., nmap -sV vs nmap --script vuln)
                # Just track it for within-session dedup going forward

        # Record fingerprint for within-session dedup
        self._session_tool_fingerprints.add(fingerprint)
        return None

    def _handle_security_tool(self, tool_name: str, tool_input: dict) -> str:
        """Execute a security tool via subprocess and return compacted output.

        v7.1: Uses streaming execution with live output to event bus.
        v7.1.1: Dedup guard — blocks duplicate tool calls.
        """
        event_bus = get_event_bus()

        quarantine_reason = self._get_quarantined_tool_reason(tool_name, tool_input)
        if quarantine_reason:
            msg = f"[SKIPPED] {tool_name}: quarantined for this engagement ({quarantine_reason})."
            self._log_synthetic_execution(tool_name, "quarantine_check", "tool_quarantined", msg, tool_input)
            return msg

        # Inject compatibility profile into params so builders can adapt flags
        compat_profile = self._compat_probe.get_profile(tool_name)
        if compat_profile:
            tool_input = {**tool_input, "_compat_profile": compat_profile.to_dict()}

        # Build the command
        try:
            cmd_args = build_command(tool_name, tool_input)
        except Exception as e:
            msg = f"Error building command for {tool_name}: {e}"
            self._maybe_quarantine_tool(tool_name, str(e), tool_input=tool_input)
            self._log_synthetic_execution(tool_name, "build_command", "command_build_failure", msg, tool_input)
            return msg

        # Dedup check: block if this tool+args already ran successfully
        dedup_msg = self._check_tool_dedup(tool_name, tool_input, cmd_args)
        if dedup_msg:
            self._log_synthetic_execution(
                tool_name, "dedup_check", "dedup_skip", dedup_msg, tool_input,
                command=" ".join(cmd_args) if cmd_args else "",
            )
            return dedup_msg

        run_id = f"{self.agent_type}-{tool_name}-{uuid.uuid4().hex[:10]}"
        command_display = " ".join(cmd_args) if cmd_args else tool_name

        # Create streaming callback that feeds tool output to event bus
        def on_tool_output(line: str):
            event_bus.tool_output(
                tool_name,
                self.agent_name,
                line,
                self.engagement_id,
                run_id=run_id,
            )

        def _skip_runtime_limit(failure_category: str, message: str) -> str:
            self._log_synthetic_execution(tool_name, "budget_check", failure_category, message, tool_input)
            return message

        # Special handling for generic_command: execute directly via bash
        if tool_name == "generic_command":
            shell = tool_input.get("shell", "bash")
            command = tool_input.get("command", "")
            if not command:
                msg = "Error: generic_command requires a 'command' parameter."
                self._log_synthetic_execution(tool_name, "build_command", "missing_command", msg, tool_input)
                return msg
            if not self.tool_executor.check_available(shell):
                msg = f"[SKIPPED] generic_command: shell '{shell}' is not available in this environment."
                self._log_synthetic_execution(tool_name, "compat_check", "missing_shell", msg, tool_input)
                return msg
            from config import get_tool_env

            # Phase 6: lifecycle hint for generic_command
            lifecycle_hint = tool_input.get("lifecycle", "oneshot")
            gc_timeout = self._resolve_tool_timeout(tool_name, tool_input.get("timeout"))
            if lifecycle_hint == "daemonizing":
                # For daemon-launching commands, cap timeout aggressively.
                gc_timeout = min(gc_timeout, 60)

            gc_timeout, runtime_skip = self._enforce_runtime_budget(tool_name, gc_timeout, tool_input)
            if runtime_skip:
                return _skip_runtime_limit(runtime_skip["failure_category"], runtime_skip["message"])

            command_display = command
            event_bus.tool_start(
                tool_name,
                self.agent_name,
                command[:200],
                self.engagement_id,
                run_id=run_id,
            )
            tool_result = self.tool_executor.run(
                tool_name=shell,
                args=["-c", command],
                cwd=tool_input.get("cwd") or None,
                env=get_tool_env() or None,
                timeout=gc_timeout,
                on_output=on_tool_output,
            )
        else:
            # Check transport type: HTTP (ghidra-mcp) vs subprocess (default)
            from tools.registry import get_tool_transport, get_tool_endpoint, get_tool_http_method

            transport = get_tool_transport(tool_name)

            if transport == "http":
                # ── HTTP-transport tool (e.g., ghidra-mcp REST API) ──
                endpoint = get_tool_endpoint(tool_name)
                http_method = get_tool_http_method(tool_name)
                if not endpoint:
                    msg = f"Error: No endpoint mapping for HTTP tool '{tool_name}'. Check tools/registry.py."
                    self._log_synthetic_execution(tool_name, "build_command", "no_endpoint_mapping", msg, tool_input)
                    return msg

                effective_timeout = self._resolve_tool_timeout(tool_name, tool_input.get("timeout"))
                effective_timeout, runtime_skip = self._enforce_runtime_budget(tool_name, effective_timeout, tool_input)
                if runtime_skip:
                    return _skip_runtime_limit(runtime_skip["failure_category"], runtime_skip["message"])

                command_display = f"{http_method} {endpoint}"
                event_bus.tool_start(
                    tool_name,
                    self.agent_name,
                    command_display[:200],
                    self.engagement_id,
                    run_id=run_id,
                )

                from tools.registry import get_http_client_for_tool
                client = get_http_client_for_tool(tool_name)
                # Strip internal keys (e.g., _compat_profile) from params sent to API
                api_params = {k: v for k, v in tool_input.items() if not k.startswith("_")}
                tool_result = client.call(
                    endpoint=endpoint,
                    method=http_method,
                    params=api_params,
                    timeout=int(effective_timeout),
                )
                # Override tool_name in result to match the canonical name
                tool_result.tool_name = tool_name
            else:
                # ── Subprocess-transport tool (default path) ──
                # Resolve tool name to actual binary (e.g., "nmap_scan" → "nmap")
                from tools.registry import get_binary_for_tool
                binary_name = get_binary_for_tool(tool_name)
                if not binary_name:
                    msg = f"Error: No binary mapping found for tool '{tool_name}'. Check tools/registry.py."
                    self._log_synthetic_execution(tool_name, "build_command", "no_binary_mapping", msg, tool_input)
                    return msg

                # Hard pre-execution gate: compatibility probe decides
                skip_reason = self._compat_probe.get_skip_reason(tool_name)
                if skip_reason:
                    profile = self._compat_probe.get_profile(tool_name)
                    version = profile.version if profile else "unknown"
                    msg = (
                        f"[SKIPPED] {tool_name}: unsupported in this environment "
                        f"(reason={skip_reason}, binary={binary_name}, version={version}). "
                        f"Try an alternative tool."
                    )
                    self._log_synthetic_execution(tool_name, "compat_check", "incompatible_binary", msg, tool_input)
                    return msg

                no_signal_runs = self._tool_no_signal_runs.get(tool_name, 0)
                if tool_name in self._no_signal_guard_tools and no_signal_runs >= self._max_no_signal_runs:
                    msg = (
                        f"[SKIPPED] {tool_name}: stopped after {no_signal_runs} consecutive no-signal runs "
                        f"(kill-switch to prevent dead-end retries)."
                    )
                    self._log_synthetic_execution(tool_name, "compat_check", "no_signal_killswitch", msg, tool_input)
                    return msg

                effective_timeout = self._resolve_tool_timeout(tool_name, tool_input.get("timeout"))

                # Phase 6: Lifecycle-aware handling
                from tools.registry import get_tool_lifecycle
                lifecycle = get_tool_lifecycle(tool_name)

                effective_timeout, runtime_skip = self._enforce_runtime_budget(tool_name, effective_timeout, tool_input)
                if runtime_skip:
                    return _skip_runtime_limit(runtime_skip["failure_category"], runtime_skip["message"])

                # Execute with streaming (pass API keys as env vars for tools that need them)
                from config import get_tool_env

                event_bus.tool_start(
                    tool_name,
                    self.agent_name,
                    command_display[:200],
                    self.engagement_id,
                    run_id=run_id,
                )
                tool_result = self.tool_executor.run(
                    tool_name=binary_name,
                    args=cmd_args,
                    env=get_tool_env() or None,
                    timeout=effective_timeout,
                    on_output=on_tool_output,
                )

        event_bus.tool_complete(
            tool_name,
            self.agent_name,
            tool_result.success,
            tool_result.duration_seconds,
            self.engagement_id,
            run_id=run_id,
        )

        # Phase 3: Track cumulative tool and agent budget usage
        self._tool_cumulative_usage[tool_name] = (
            self._tool_cumulative_usage.get(tool_name, 0.0) + tool_result.duration_seconds
        )
        self._agent_tool_time_used += tool_result.duration_seconds

        def _warn_nonfatal(step: str, exc: Exception) -> None:
            logger.warning(
                "[%s] Non-fatal %s error for %s: %s",
                self.agent_name,
                step,
                tool_name,
                exc,
            )

        # Save raw output to disk
        raw_output = tool_result.stdout + (
            f"\n--- STDERR ---\n{tool_result.stderr}" if tool_result.stderr else ""
        )
        raw_path = ""
        try:
            raw_path = self._save_raw_output(tool_name, raw_output)
        except Exception as e:
            _warn_nonfatal("raw output persistence", e)

        # Compact the output for LLM context (increased limits for better reasoning)
        try:
            compacted = self.compactor.compact(tool_name, raw_output, max_lines=150)
            compacted = self._sanitize_tool_output(compacted)
        except Exception as e:
            _warn_nonfatal("output compaction", e)
            compacted = self._sanitize_tool_output(raw_output[:8000] or tool_result.output[:8000])
        # Hard cap to prevent context bloat, but generous enough for rich findings
        if len(compacted) > 8000:
            compacted = compacted[:8000] + "\n... (output truncated to save context)"
        # Append raw output path so agent can reference full output if needed
        if raw_path:
            compacted += f"\n[Full raw output saved to: {raw_path}]"

        # Log to database with richer outcome state
        outcome_kind = getattr(tool_result, "outcome_kind", "")
        signal_detected = getattr(tool_result, "signal_detected", False)
        exec_id = None
        try:
            exec_id = self.db.log_tool_execution(
                engagement_id=self.engagement_id,
                agent=self.agent_name,
                tool_name=tool_name,
                command=command_display,
                parameters=tool_input,
                raw_output_path=raw_path,
                compacted_summary=compacted,
                success=tool_result.success,
                duration=tool_result.duration_seconds,
                outcome_kind=outcome_kind,
                signal_detected=signal_detected,
                return_code=tool_result.return_code,
                timed_out=tool_result.timed_out,
                run_id=run_id,
                agent_turn=self._current_turn_number,
            )
        except Exception as e:
            _warn_nonfatal("tool execution logging", e)
        raw_bytes = len(raw_output.encode("utf-8", errors="replace"))
        raw_preview = raw_output[:8192]
        try:
            event_bus.emit(event_bus._make_event(
                EventType.NEW_EXECUTION,
                self.agent_name,
                {
                    "id": exec_id,
                    "agent": self.agent_name,
                    "tool_name": tool_name,
                    "command": command_display,
                    "success": tool_result.success,
                    "outcome_kind": outcome_kind,
                    "signal_detected": signal_detected,
                    "duration_seconds": tool_result.duration_seconds,
                    "created_at": datetime.now().isoformat(),
                    "raw_preview": raw_preview,
                    "raw_total_bytes": raw_bytes,
                    "raw_truncated": raw_bytes > len(raw_preview.encode("utf-8", errors="replace")),
                    "run_id": run_id,
                },
                self.engagement_id,
            ))
        except Exception as e:
            _warn_nonfatal("execution event emission", e)

        # Agent reflection on failure: append guidance to help agent reconsider
        # partial_success still gets reflection but less aggressive
        if not tool_result.success:
            reflection = self._build_failure_reflection(tool_name, tool_result, tool_input)
            compacted = compacted + "\n\n" + reflection

        # Also extract from partial_success runs that had signal
        is_usable = tool_result.success or outcome_kind in ("partial_success", "timeout_with_signal")
        if is_usable and tool_name in ("nmap_scan", "rustscan_scan", "masscan_scan"):
            try:
                self._auto_extract_hosts_services(tool_result.stdout)
            except Exception as e:
                _warn_nonfatal("scan auto-extraction", e)
        if is_usable:
            try:
                self._capture_high_signal_discovery(
                    tool_name=tool_name,
                    tool_input=tool_input,
                    command_display=command_display,
                    raw_output=raw_output,
                )
            except Exception as e:
                _warn_nonfatal("high-signal discovery capture", e)

        # Update no-signal counters for long-running tools.
        try:
            self._update_no_signal_counter(
                tool_name,
                raw_output,
                tool_result.success,
                outcome_kind=outcome_kind,
                signal_detected=signal_detected,
            )
        except Exception as e:
            _warn_nonfatal("no-signal bookkeeping", e)
        try:
            self._maybe_quarantine_tool(tool_name, raw_output, outcome_kind=outcome_kind, tool_input=tool_input)
        except Exception as e:
            _warn_nonfatal("quarantine bookkeeping", e)

        # Add status prefix for the agent — use richer outcome classification
        status_map = {
            "success": "SUCCESS",
            "partial_success": "PARTIAL_SUCCESS",
            "timeout_with_signal": "TIMED_OUT_WITH_SIGNAL",
            "empty_result": "NO_SIGNAL",
            "wrapper_error": "WRAPPER_ERROR",
            "env_error": "ENV_ERROR",
            "interactive_hang": "INTERACTIVE_HANG",
            "target_refused": "TARGET_REFUSED",
            "skipped": "SKIPPED",
        }
        status = status_map.get(outcome_kind, "FAILED" if not tool_result.success else "SUCCESS")
        if tool_result.timed_out and outcome_kind != "timeout_with_signal":
            status = "TIMED_OUT"

        return f"[{status}] {tool_name} ({tool_result.duration_seconds:.1f}s)\n{compacted}"

    @staticmethod
    def _generic_command_quarantine_scope(command: str) -> str:
        """Return a scoped identity for generic_command quarantines."""
        text = (command or "").strip()
        if not text:
            return ""
        try:
            parts = shlex.split(text, posix=True)
        except ValueError:
            parts = text.split()
        if not parts:
            return ""

        executable = Path(parts[0]).name.lower()
        if executable in {"bash", "sh", "zsh", "python", "python2", "python3", "perl", "ruby"}:
            for candidate in parts[1:]:
                if candidate and not candidate.startswith("-"):
                    return f"{executable}:{candidate}"
        return f"exec:{executable}"

    @classmethod
    def _quarantine_key(cls, tool_name: str, tool_input: Optional[dict] = None) -> str:
        """Build the lookup key for a quarantined tool or wrapper scope."""
        if tool_name != "generic_command":
            return tool_name
        command = str((tool_input or {}).get("command") or "")
        scope = cls._generic_command_quarantine_scope(command)
        return f"{tool_name}::{scope}" if scope else tool_name

    @staticmethod
    def _clamp_timeout_to_budget(
        effective_timeout: int,
        remaining_agent_budget: float,
        remaining_tool_budget: float,
    ) -> int:
        """Clamp a timeout to finite remaining budgets without choking on infinity."""
        candidates = [max(int(effective_timeout), 1)]
        for budget in (remaining_agent_budget, remaining_tool_budget):
            try:
                numeric_budget = float(budget)
            except (TypeError, ValueError):
                continue
            if math.isfinite(numeric_budget):
                candidates.append(max(int(numeric_budget), 0))
        return max(min(candidates), 10)

    def _enforce_runtime_budget(
        self,
        tool_name: str,
        effective_timeout: int,
        tool_input: Optional[dict] = None,
    ) -> tuple[int, Optional[dict]]:
        """Apply per-tool and per-agent runtime budgets before execution."""
        tool_cumulative = self._tool_cumulative_usage.get(tool_name, 0.0)
        tool_ceiling = self._tool_cumulative_ceilings.get(tool_name, float("inf"))
        if tool_cumulative >= tool_ceiling:
            msg = (
                f"[BUDGET_EXCEEDED] {tool_name}: cumulative runtime {tool_cumulative:.0f}s "
                f"has reached the {tool_ceiling:.0f}s ceiling for this session. "
                f"Use a different tool or refine your approach."
            )
            return effective_timeout, {
                "failure_category": "tool_ceiling_exceeded",
                "message": msg,
            }
        if self._agent_tool_time_used >= self._agent_tool_budget:
            msg = (
                f"[BUDGET_EXCEEDED] Agent tool budget exhausted "
                f"({self._agent_tool_time_used:.0f}s / {self._agent_tool_budget:.0f}s). "
                f"Summarize findings and stop scheduling new tools."
            )
            return effective_timeout, {
                "failure_category": "agent_budget_exceeded",
                "message": msg,
            }

        remaining_agent_budget = self._agent_tool_budget - self._agent_tool_time_used
        remaining_tool_budget = tool_ceiling - tool_cumulative
        clamped = self._clamp_timeout_to_budget(
            effective_timeout,
            remaining_agent_budget,
            remaining_tool_budget,
        )
        return clamped, None

    def _get_quarantined_tool_reason(self, tool_name: str, tool_input: Optional[dict] = None) -> str:
        """Return an engagement-level quarantine reason for a broken tool."""
        try:
            quarantines = self.shared_state.read_section("tool_quarantines") or {}
        except Exception:
            quarantines = {}

        if not isinstance(quarantines, dict):
            return ""

        keys = []
        scoped_key = self._quarantine_key(tool_name, tool_input)
        if scoped_key:
            keys.append(scoped_key)
        if tool_name not in keys:
            keys.append(tool_name)

        for key in keys:
            entry = quarantines.get(key)
            if isinstance(entry, dict):
                return str(entry.get("reason", "") or "").strip()
            if entry:
                return str(entry).strip()
        return ""

    def _maybe_quarantine_tool(
        self,
        tool_name: str,
        detail: str,
        outcome_kind: str = "",
        tool_input: Optional[dict] = None,
    ) -> None:
        """Quarantine tools that failed for deterministic internal reasons."""
        reason = self._deterministic_tool_failure_reason(detail, outcome_kind=outcome_kind)
        if not reason:
            return

        try:
            quarantines = self.shared_state.read_section("tool_quarantines") or {}
        except Exception:
            quarantines = {}
        if not isinstance(quarantines, dict):
            quarantines = {}

        quarantine_key = self._quarantine_key(tool_name, tool_input)
        if quarantine_key in quarantines:
            return

        quarantines[quarantine_key] = {
            "reason": reason,
            "source_agent": self.agent_name,
            "timestamp": datetime.now().isoformat(),
            "tool_name": tool_name,
        }
        self.shared_state.update_section("tool_quarantines", quarantines)
        logger.warning("[%s] Quarantined %s (%s): %s", self.agent_name, quarantine_key, tool_name, reason)

    def _get_scope_validator(self):
        """Return the shared state's scope validator when available."""
        getter = getattr(self.shared_state, "_get_scope_validator", None)
        if callable(getter):
            try:
                return getter()
            except Exception as e:
                logger.debug("[%s] Failed to read shared scope validator: %s", self.agent_name, e)

        try:
            from memory.scope_validator import ScopeValidator

            state = self.shared_state.read()
            engagement = state.get("engagement", {}) if isinstance(state, dict) else {}
            target = str(engagement.get("target", "") or "")
            scope = engagement.get("scope", []) or []
            out_of_scope = engagement.get("out_of_scope", []) or []
            if target:
                return ScopeValidator(target, scope, out_of_scope)
        except Exception as e:
            logger.debug("[%s] Failed to construct scope validator: %s", self.agent_name, e)
        return None

    def _is_in_scope_candidate(self, value: str) -> bool:
        """Return True when a discovered host/url should be promoted into state."""
        validator = self._get_scope_validator()
        if validator is None:
            return True
        try:
            return validator.is_in_scope(value)
        except Exception as e:
            logger.debug("[%s] Scope validation failed for %r: %s", self.agent_name, value, e)
            return False

    @staticmethod
    def _deterministic_tool_failure_reason(detail: str, outcome_kind: str = "") -> str:
        """Classify deterministic internal tool failures worth quarantining."""
        lower = (detail or "").lower()
        if "non-finite numeric parameter" in lower or "cannot convert float infinity to integer" in lower:
            return "builder rejected non-finite numeric input"
        if "not executable in the current runtime" in lower:
            return "tool has no executable builder in this runtime"
        if "can only join an iterable" in lower:
            return "tool returned no command and broke before execution"
        if outcome_kind in ("wrapper_error", "env_error"):
            deterministic_markers = (
                "unrecognized arguments",
                "unknown flag",
                "traceback",
                "exception:",
                "usage:",
            )
            if any(marker in lower for marker in deterministic_markers):
                return f"deterministic {outcome_kind}: {detail.strip()[:200]}"
        return ""

    @staticmethod
    def _is_probable_ip(value: str) -> bool:
        return bool(re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", value or ""))

    @classmethod
    def _is_probable_hostname(cls, value: str) -> bool:
        text = (value or "").strip().strip(".")
        if not text or cls._is_probable_ip(text):
            return False
        return bool(re.fullmatch(r"[a-z0-9][a-z0-9.-]*\.[a-z]{2,}", text, re.IGNORECASE))

    def _extract_high_signal_hosts_and_urls(
        self,
        tool_input: dict,
        command_display: str,
        raw_output: str,
    ) -> tuple[list[str], list[str]]:
        """Extract candidate hosts and URLs from tool output and inputs."""
        from urllib.parse import urlparse

        combined = "\n".join(
            part for part in (
                command_display or "",
                raw_output or "",
                str(tool_input.get("target") or ""),
                str(tool_input.get("url") or ""),
                str(tool_input.get("host") or ""),
                str(tool_input.get("domain") or ""),
            )
            if part
        )

        urls = []
        seen_urls = set()
        for match in re.findall(r"https?://[^\s'\"<>]+", combined, flags=re.IGNORECASE):
            cleaned = match.rstrip(").,;]'\"")
            if cleaned not in seen_urls:
                seen_urls.add(cleaned)
                urls.append(cleaned)

        hosts = []
        seen_hosts = set()

        def _add_host(candidate: str) -> None:
            host = (candidate or "").strip().strip(".").lower()
            if not host or host in seen_hosts:
                return
            if self._is_probable_hostname(host) or self._is_probable_ip(host):
                seen_hosts.add(host)
                hosts.append(host)

        for url in urls:
            try:
                parsed = urlparse(url)
            except ValueError:
                continue
            if parsed.hostname:
                _add_host(parsed.hostname)

        for match in re.findall(r"\b(?:[a-z0-9][a-z0-9-]*\.)+[a-z]{2,}\b", combined, flags=re.IGNORECASE):
            _add_host(match)

        for key in ("target", "host", "hostname", "domain"):
            value = str(tool_input.get(key) or "").strip()
            if not value:
                continue
            if value.startswith(("http://", "https://")):
                try:
                    parsed = urlparse(value)
                except ValueError:
                    continue
                if parsed.hostname:
                    _add_host(parsed.hostname)
            else:
                _add_host(value)

        return hosts, urls

    @staticmethod
    def _extract_product_version(text: str) -> tuple[str, str]:
        """Extract a product/version banner from raw output when present."""
        patterns = (
            re.compile(r"\b([A-Z][A-Za-z0-9 ._/-]{2,60}?)\s+v(?:ersion)?\s*([0-9][A-Za-z0-9._-]{1,20})\b"),
            re.compile(r"\bServer:\s*([A-Za-z0-9 ._/-]{2,60}?)[/ ]([0-9][A-Za-z0-9._-]{1,20})\b", re.IGNORECASE),
        )
        for pattern in patterns:
            match = pattern.search(text or "")
            if match:
                product = re.sub(r"\s+", " ", match.group(1)).strip(" -:")
                version = match.group(2).strip()
                if len(product) >= 3:
                    return product, version
        return "", ""

    @staticmethod
    def _extract_web_endpoints(text: str) -> list[str]:
        """Extract notable web endpoints from output."""
        from urllib.parse import urlparse

        endpoints = []
        seen = set()
        for match in re.findall(r"/?[A-Za-z0-9._/-]+\.(?:html|php|aspx|jsp|json|xml)", text or "", flags=re.IGNORECASE):
            endpoint = match if match.startswith("/") else f"/{match}"
            if endpoint.startswith("//"):
                parts = endpoint[2:].split("/", 1)
                if len(parts) < 2:
                    continue
                endpoint = f"/{parts[1]}"
            if "://" in endpoint:
                try:
                    endpoint = urlparse(endpoint).path or "/"
                except ValueError:
                    continue
            endpoint = endpoint.rstrip(").,;]'\"")
            if endpoint not in seen:
                seen.add(endpoint)
                endpoints.append(endpoint)
        return endpoints[:12]

    @staticmethod
    def _detect_authenticated_access(text: str) -> tuple[bool, str]:
        """Detect authenticated application access from raw output."""
        lower = (text or "").lower()
        auth_markers = 0
        if "anonymous" in lower:
            auth_markers += 1
        if any(marker in lower for marker in ("main.html", "dir.html", "logout", "<readfile>1</readfile>", "<writefile>1</writefile>")):
            auth_markers += 1
        if any(marker in lower for marker in ("web client", "set-cookie:", "cookie:", "login successful", "logged in")):
            auth_markers += 1
        if auth_markers >= 2:
            return True, "anonymous" if "anonymous" in lower else "authenticated"
        return False, ""

    def _capture_high_signal_discovery(
        self,
        tool_name: str,
        tool_input: dict,
        command_display: str,
        raw_output: str,
    ) -> None:
        """Persist high-signal discoveries that should not rely on model summaries."""
        from urllib.parse import urlparse

        hosts, urls = self._extract_high_signal_hosts_and_urls(tool_input, command_display, raw_output)
        product, version = self._extract_product_version(raw_output)
        endpoints = self._extract_web_endpoints(raw_output)
        auth_detected, auth_level = self._detect_authenticated_access(raw_output)

        if not hosts and not product and not auth_detected:
            return

        target_hint = self._get_engagement_target().strip().lower()
        scoped_hosts = [h for h in hosts if self._is_in_scope_candidate(h)]
        if not scoped_hosts:
            return

        primary_host = next((h for h in scoped_hosts if h != target_hint), scoped_hosts[0])
        if not primary_host:
            return

        primary_url = ""
        for url in urls:
            try:
                parsed = urlparse(url)
            except ValueError:
                continue
            if (
                parsed.hostname
                and parsed.hostname.lower() == primary_host
                and self._is_in_scope_candidate(parsed.hostname)
            ):
                primary_url = url
                break
        if not primary_url and str(tool_input.get("url") or "").startswith(("http://", "https://")):
            try:
                candidate_url = str(tool_input.get("url")).strip()
                parsed = urlparse(candidate_url)
                if parsed.hostname and parsed.hostname.lower() == primary_host and self._is_in_scope_candidate(parsed.hostname):
                    primary_url = candidate_url
            except ValueError:
                primary_url = ""

        discovery_key = "|".join([
            tool_name,
            primary_host,
            primary_url,
            product,
            version,
            auth_level,
            ",".join(endpoints[:3]),
        ])
        if discovery_key in self._auto_persisted_discoveries:
            return
        self._auto_persisted_discoveries.add(discovery_key)

        state = self.shared_state.read()

        if self._is_probable_hostname(primary_host):
            self.shared_state.append_to_list("domains", primary_host)
        self.shared_state.append_to_list("attack_surfaces", f"webapp:{primary_host}")

        web_apps = state.get("web_apps") or {}
        if not isinstance(web_apps, dict):
            web_apps = {}
        app_entry = dict(web_apps.get(primary_host) or {})
        app_entry["host"] = primary_host
        if primary_url:
            app_entry["url"] = primary_url
        if product:
            app_entry["product"] = product
        if version:
            app_entry["version"] = version
        if auth_detected:
            app_entry["authenticated"] = True
            app_entry["auth_level"] = auth_level
        if endpoints:
            existing_endpoints = list(app_entry.get("authenticated_endpoints") or [])
            merged = []
            for endpoint in existing_endpoints + endpoints:
                if endpoint not in merged:
                    merged.append(endpoint)
            app_entry["authenticated_endpoints"] = merged[:12]
        app_entry["last_seen_by"] = self.agent_name
        app_entry["last_updated"] = datetime.now().isoformat()
        web_apps[primary_host] = app_entry
        self.shared_state.update_section("web_apps", web_apps)

        if product:
            technologies = state.get("technologies") or {}
            if not isinstance(technologies, dict):
                technologies = {}
            techs = list(technologies.get(primary_host) or [])
            tech_label = f"{product} {version}".strip()
            if tech_label and tech_label not in techs:
                techs.append(tech_label)
                technologies[primary_host] = techs
                self.shared_state.update_section("technologies", technologies)

        service_port = None
        if primary_url:
            parsed = urlparse(primary_url)
            if parsed.port:
                service_port = parsed.port
            elif parsed.scheme == "https":
                service_port = 443
            elif parsed.scheme == "http":
                service_port = 80
        if service_port:
            try:
                self.network_map.add_service(
                    host_ip=primary_host,
                    port=service_port,
                    service_name="https" if primary_url.startswith("https://") else "http",
                    version=f"{product} {version}".strip() or None,
                )
            except Exception as e:
                logger.debug("[%s] Failed to add inferred web service for %s: %s", self.agent_name, primary_host, e)

        try:
            self.network_map.add_web_app(
                host_ip=primary_host,
                app_url=primary_url or None,
                product=product or None,
                version=version or None,
                auth_level=auth_level or None,
                notes=", ".join(endpoints[:3]) if endpoints else None,
            )
        except Exception as e:
            logger.debug("[%s] Failed to add web app to network map for %s: %s", self.agent_name, primary_host, e)

        summary_bits = []
        if product:
            summary_bits.append(f"{product} {version}".strip())
        if auth_detected:
            summary_bits.append(f"{auth_level} access confirmed")
        if endpoints:
            summary_bits.append(f"endpoints: {', '.join(endpoints[:3])}")
        summary_text = "; ".join(summary_bits) or "New web surface discovered"

        self._post_handoff_with_hooks(AgentHandoff(
            source_agent=self.agent_name,
            target_agent="orchestrator",
            handoff_type="intelligence",
            priority="high" if auth_detected else "medium",
            summary=f"High-signal web discovery on {primary_host}: {summary_text}",
            data={
                "host": primary_host,
                "url": primary_url,
                "product": product,
                "version": version,
                "auth_level": auth_level,
                "evidence_hash": hashlib.sha1(raw_output[:4000].encode("utf-8", errors="replace")).hexdigest()[:12],
            },
            suggested_action="Prioritize authenticated enumeration and exploitation on this application surface.",
            confidence=0.92 if auth_detected else 0.74,
        ))

        if auth_detected:
            access_record = {
                "host": primary_host,
                "url": primary_url,
                "access_level": auth_level,
                "username": "anonymous" if auth_level == "anonymous" else "",
                "product": product,
                "agent": self.agent_name,
                "tool": tool_name,
            }
            self.shared_state.append_to_list("authenticated_access", access_record)

            evidence_excerpt = "\n".join((raw_output or "").splitlines()[:25])[:1600]
            finding_payload = {
                "finding_type": "vulnerability",
                "data": {
                    "title": (
                        f"Anonymous authenticated access to {product} web client"
                        if auth_level == "anonymous" and product
                        else f"Authenticated access to {product or 'web application'}"
                    ),
                    "severity": "medium" if auth_level == "anonymous" else "low",
                    "category": "misconfiguration",
                    "description": (
                        f"{self.agent_name} confirmed {auth_level} access on {primary_host}"
                        + (f" ({product} {version})" if product or version else "")
                        + "."
                    ),
                    "target": primary_host,
                    "host": primary_host,
                    "evidence": evidence_excerpt,
                    "confirmed": True,
                    "exploitable": auth_level == "anonymous",
                    "tool_source": tool_name,
                    "remediation": "Disable anonymous/default access and require authenticated, least-privilege access.",
                    "metadata": {
                        "url": primary_url,
                        "authenticated_endpoints": endpoints[:5],
                    },
                },
            }
            save_result = self._handle_save_finding(finding_payload)
            logger.info("[%s] Auto-persisted auth discovery on %s: %s", self.agent_name, primary_host, save_result)

    def _resolve_tool_timeout(self, tool_name: str, requested_timeout: Optional[int]) -> int:
        """Resolve per-tool timeout with hard budget caps."""
        budget = self._tool_timeout_budgets.get(tool_name, 300)
        if requested_timeout is None:
            return budget
        try:
            return min(int(requested_timeout), budget)
        except Exception:
            return budget

    def _log_synthetic_execution(
        self,
        tool_name: str,
        failure_phase: str,
        failure_category: str,
        message: str,
        tool_input: Optional[dict] = None,
        command: str = "",
    ) -> None:
        """Log a synthetic tool_execution row for pre-execution failures.

        Phase 4: ensures command-build failures, compatibility skips, dedup
        skips, budget exhaustion, and internal tool exceptions all leave a
        searchable durable record in the database.
        """
        outcome_kind = self._map_synthetic_outcome_kind(
            failure_phase=failure_phase,
            failure_category=failure_category,
            message=message,
        )
        try:
            self.db.log_tool_execution(
                engagement_id=self.engagement_id,
                agent=self.agent_name,
                tool_name=tool_name,
                command=command or f"(not built: {failure_phase})",
                parameters=tool_input,
                raw_output_path="",
                compacted_summary=message,
                success=False,
                duration=0.0,
                outcome_kind=outcome_kind,
                signal_detected=False,
                return_code=None,
                timed_out=False,
                failure_phase=failure_phase,
                failure_category=failure_category,
                stderr_preview=message[:500],
                agent_turn=self._current_turn_number,
            )
        except Exception as e:
            logger.error("Failed to log synthetic execution for %s: %s", tool_name, e)

    @staticmethod
    def _map_synthetic_outcome_kind(
        failure_phase: str,
        failure_category: str,
        message: str,
    ) -> str:
        """Map pre-execution failures into stable outcome buckets for analytics."""
        phase = str(failure_phase or "").strip().lower()
        category = str(failure_category or "").strip().lower()
        text = str(message or "").strip().lower()

        category_map = {
            "agent_budget_exceeded": "budget_block",
            "tool_ceiling_exceeded": "budget_block",
            "dedup_skip": "dedup_block",
            "tool_quarantined": "quarantine_block",
            "command_build_failure": "build_failure",
            "missing_command": "build_failure",
            "no_binary_mapping": "build_failure",
            "internal_tool_exception": "internal_failure",
            "missing_shell": "compatibility_block",
            "incompatible_binary": "compatibility_block",
            "no_signal_killswitch": "compatibility_block",
        }
        if category in category_map:
            return category_map[category]

        phase_map = {
            "budget_check": "budget_block",
            "dedup_check": "dedup_block",
            "quarantine_check": "quarantine_block",
            "build_command": "build_failure",
            "agent_loop": "internal_failure",
            "compat_check": "compatibility_block",
        }
        if phase in phase_map:
            return phase_map[phase]

        if "[budget_exceeded]" in text or "budget exhausted" in text:
            return "budget_block"
        if "[dedup blocked]" in text or "already run successfully" in text:
            return "dedup_block"
        if "quarantined for this engagement" in text:
            return "quarantine_block"
        if "error building command" in text or "requires a 'command' parameter" in text:
            return "build_failure"
        if "unsupported in this environment" in text or "shell '" in text and "not available" in text:
            return "compatibility_block"
        if "error executing " in text:
            return "internal_failure"
        return "skipped"

    def _update_no_signal_counter(
        self,
        tool_name: str,
        raw_output: str,
        success: bool,
        outcome_kind: str = "",
        signal_detected: bool = False,
    ) -> None:
        """Track consecutive no-signal runs per tool and reset on meaningful signal."""
        if tool_name not in self._no_signal_guard_tools:
            return

        useful_outcomes = {"success", "partial_success", "timeout_with_signal"}
        terminal_dead_ends = {"empty_result", "target_refused", "interactive_hang"}

        if signal_detected and outcome_kind in useful_outcomes:
            self._tool_no_signal_runs[tool_name] = 0
            return

        if outcome_kind in terminal_dead_ends:
            self._tool_no_signal_runs[tool_name] = self._tool_no_signal_runs.get(tool_name, 0) + 1
            return

        if success and signal_detected:
            self._tool_no_signal_runs[tool_name] = 0

    def _get_tool_compatibility_status(self, tool_name: str, binary_name: str) -> dict:
        """Read compatibility status from the startup probe.

        Kept for backward compatibility — delegates to _compat_probe.
        """
        profile = self._compat_probe.get_profile(tool_name)
        if profile:
            return profile.to_dict()

        # Tool wasn't probed — basic availability check.
        if not self.tool_executor.check_available(binary_name):
            return {"compatible": False, "available": False, "version": "", "reason": "binary_missing"}
        return {"compatible": True, "available": True, "version": "unknown", "reason": ""}

    def _build_failure_reflection(self, tool_name: str, tool_result, tool_input: dict) -> str:
        """Build a reflection prompt when a tool fails, guiding the agent to try alternatives."""
        reflections = []
        reflections.append("--- REFLECTION: Tool failed. Consider these alternatives ---")

        if "permission denied" in (tool_result.stderr or "").lower() or "operation not permitted" in (tool_result.stderr or "").lower():
            reflections.append("- Permission error despite running as root. Check if the target is reachable or if a security policy is blocking access.")
            reflections.append("- Verify the tool arguments are correct and the target is within scope.")

        if "not found" in (tool_result.stderr or "").lower() or tool_result.return_code == 127:
            reflections.append("- This tool binary is not installed.")
            reflections.append("- Try an alternative tool that achieves the same goal.")

        if tool_result.timed_out:
            reflections.append("- The tool timed out. Consider:")
            reflections.append("  - Reducing scope (fewer ports, specific targets)")
            reflections.append("  - Using a faster tool alternative")
            reflections.append("  - Breaking the task into smaller chunks")

        if "unrecognized arguments" in (tool_result.stderr or "").lower() or "usage:" in (tool_result.stderr or "").lower():
            reflections.append("- The tool rejected the arguments. Check the correct syntax.")
            reflections.append("- Re-read the tool's help output and adjust parameters.")

        reflections.append("- Do NOT retry with the exact same command. Adapt your approach.")
        reflections.append("- If multiple tools failed, consider what information you can gather with the tools that DO work.")

        return "\n".join(reflections)

    def _auto_extract_hosts_services(self, output: str):
        """Parse nmap/scan output to auto-populate hosts and services in DB + network map."""
        import re
        # Match nmap-style output: "Nmap scan report for <ip>" or "Nmap scan report for <hostname> (<ip>)"
        host_re = re.compile(r"Nmap scan report for (?:(\S+)\s+\()?(\d+\.\d+\.\d+\.\d+)\)?")
        port_re = re.compile(r"(\d+)/(tcp|udp)\s+(open|filtered)\s+(\S+)(?:\s+(.*))?")
        os_re = re.compile(r"OS details?:\s*(.+)", re.IGNORECASE)
        service_info_re = re.compile(r"Service Info:\s*OS:\s*(\S+)", re.IGNORECASE)

        current_ip = None
        current_hostname = None
        current_os = None
        current_services = []  # collect services per host

        for line in output.splitlines():
            m = host_re.search(line)
            if m:
                # Save previous host + services
                if current_ip:
                    self._save_extracted_host_and_services(
                        current_ip, current_hostname, current_os, current_services
                    )
                current_hostname = m.group(1)
                current_ip = m.group(2)
                current_os = None
                current_services = []
                continue

            m = port_re.match(line.strip())
            if m and current_ip:
                port = int(m.group(1))
                proto = m.group(2)
                state = m.group(3)
                service_name = m.group(4) or ""
                version = (m.group(5) or "").strip()
                if state == "open":
                    current_services.append({
                        "port": port, "proto": proto,
                        "service_name": service_name, "version": version,
                    })
                continue

            m = os_re.search(line)
            if m:
                current_os = m.group(1).strip()
                continue

            m = service_info_re.search(line)
            if m and not current_os:
                current_os = m.group(1).strip()

        # Save last host + services
        if current_ip:
            self._save_extracted_host_and_services(
                current_ip, current_hostname, current_os, current_services
            )

    def _save_extracted_host_and_services(
        self, ip: str, hostname: str = None, os: str = None, services: list = None
    ):
        """Upsert a host and its services into DB, shared state, and network map."""
        try:
            host_id = self.db.upsert_host(
                engagement_id=self.engagement_id,
                ip=ip,
                hostname=hostname,
                os=os,
            )
            self.network_map.add_host(ip=ip, hostname=hostname, os=os)

            # Build services list for shared state (format matches update_host expectation)
            state_services = []
            for svc in (services or []):
                state_services.append({
                    "port": svc["port"],
                    "proto": svc.get("proto", "tcp"),
                    "name": svc.get("service_name", ""),
                    "service_name": svc.get("service_name", ""),
                    "version": svc.get("version", ""),
                })

            # Update shared state with host AND services in one call
            self.shared_state.update_host(
                ip=ip, hostname=hostname, os=os,
                services=state_services if state_services else None,
            )
            logger.info(f"[AutoExtract] Host saved: {ip} (id={host_id}, {len(state_services)} services)")
        except Exception as e:
            logger.warning(f"Auto-extract host error: {e}")
            return

        for svc in (services or []):
            try:
                self.db.upsert_service(
                    host_id=host_id,
                    port=svc["port"],
                    protocol=svc["proto"],
                    service_name=svc["service_name"],
                    version=svc["version"],
                )
                self.network_map.add_service(
                    host_ip=ip,
                    port=svc["port"],
                    service_name=svc["service_name"],
                    version=svc["version"],
                )
            except Exception as e:
                logger.warning(f"Auto-extract service error for {ip}:{svc['port']}: {e}")

    def _handle_save_finding(self, tool_input: dict) -> str:
        """Save a vulnerability, credential, or loot to the database."""
        raw_type = str(
            tool_input.get("finding_type", tool_input.get("category", "vulnerability")) or "vulnerability"
        ).strip().lower()
        # Normalize: most categories map to "vulnerability" in our DB
        if raw_type in ("credential", "password", "secret"):
            finding_type = "credential"
        elif raw_type in ("loot", "sensitive_data", "file"):
            finding_type = "loot"
        elif raw_type in ("agent_note", "blocker", "constraint", "policy", "refusal", "blocked"):
            finding_type = "constraint"
        else:
            finding_type = "vulnerability"
        # Support both flat schema (title at top level) and nested schema (data.title)
        data = tool_input.get("data", tool_input)

        # Catch policy/refusal notes even when category is omitted/misclassified.
        if finding_type == "vulnerability" and self._is_blocker_or_constraint_note(data):
            finding_type = "constraint"

        if finding_type == "vulnerability":
            if self._is_non_vulnerability_note(data):
                finding_type = "constraint"
            else:
                severity = data.get("severity", "info") or "info"  # Guard against None
                title = data.get("title", "Unknown") or "Unknown"
                evidence_text = str(data.get("evidence", "") or "")
                evidence_hash = (
                    hashlib.sha1(evidence_text.encode("utf-8")).hexdigest()[:12]
                    if evidence_text else "no_evidence"
                )
                host_ip = (
                    data.get("host_ip")
                    or data.get("host")
                    or data.get("target")
                    or data.get("ip")
                    or self._get_engagement_target()
                    or "unknown"
                )

                if self._is_duplicate_vulnerability(title, host_ip, evidence_hash):
                    return (
                        f"Duplicate vulnerability suppressed: {title} on {host_ip} "
                        f"(evidence_hash={evidence_hash})"
                    )

                vuln_id = self.db.add_vulnerability(
                    engagement_id=self.engagement_id,
                    host_id=data.get("host_id"),
                    service_id=data.get("service_id"),
                    title=title,
                    severity=severity,
                    cvss_score=data.get("cvss_score"),
                    cve_id=data.get("cve_id"),
                    description=data.get("description"),
                    evidence=data.get("evidence"),
                    remediation=data.get("remediation"),
                    tool_source=data.get("tool_source", self.agent_name),
                    agent_source=self.agent_name,
                    confirmed=data.get("confirmed", False),
                    exploitable=data.get("exploitable", False),
                    metadata={
                        **(data.get("metadata") or {}),
                        "evidence_hash": evidence_hash,
                        "host": host_ip,
                    },
                )
                # Update shared state summary — try multiple key names for host IP
                self.shared_state.append_to_list(
                    "vulns_summary",
                    {
                        "id": vuln_id,
                        "title": title,
                        "severity": severity,
                        "host": host_ip,
                    },
                )
                # Post handoff for cross-agent awareness
                self._post_handoff_with_hooks(AgentHandoff(
                    source_agent=self.agent_name,
                    target_agent="orchestrator",
                    handoff_type="finding",
                    priority="critical" if severity in ("critical", "high") else "medium",
                    summary=f"{severity.upper()} vulnerability: {title}",
                    data={
                        "vuln_id": vuln_id,
                        "title": title,
                        "severity": severity,
                        "host": host_ip,
                        "evidence_hash": evidence_hash,
                    },
                    suggested_action=f"Prioritize exploitation of {title} on {host_ip}" if severity in ("critical", "high") else "",
                    confidence=0.9 if data.get("confirmed") else (0.7 if evidence_hash else 0.55),
                ))
                get_event_bus().finding(self.agent_name, title, severity, self.engagement_id)
                return f"Vulnerability saved (id={vuln_id}): {title}"

        if finding_type == "vulnerability":
            finding_type = "constraint"

        if finding_type == "credential":
            cred_id = self.db.add_credential(
                engagement_id=self.engagement_id,
                host_id=data.get("host_id"),
                service_id=data.get("service_id"),
                username=data.get("username"),
                password_hash=data.get("password_hash"),
                password_clear=data.get("password_clear"),
                credential_type=data.get("credential_type", "password"),
                source=data.get("source", self.agent_name),
                confirmed=data.get("confirmed", False),
            )
            # Update shared state (no passwords in state!)
            self.shared_state.append_to_list(
                "credentials_summary",
                {
                    "username": data.get("username"),
                    "type": data.get("credential_type"),
                    "source": data.get("source", self.agent_name),
                },
            )
            # Post handoff for cross-agent credential sharing
            self._post_handoff_with_hooks(AgentHandoff(
                source_agent=self.agent_name,
                target_agent="exploit",
                handoff_type="credential",
                priority="high",
                summary=f"Credential found: {data.get('username')}",
                data={"cred_id": cred_id, "username": data.get("username"), "type": data.get("credential_type")},
                suggested_action="Test credential against all discovered services (SMB, WinRM, MSSQL, RDP, SSH)",
                confidence=0.9 if data.get("confirmed") else 0.6,
            ))
            return f"Credential saved (id={cred_id}): {data.get('username')}"

        elif finding_type == "loot":
            loot_id = self.db.add_loot(
                engagement_id=self.engagement_id,
                host_id=data.get("host_id"),
                loot_type=data.get("loot_type", "file"),
                file_path=data.get("file_path"),
                description=data.get("description"),
            )
            return f"Loot saved (id={loot_id}): {data.get('description')}"

        if finding_type == "constraint":
            reason = (
                str(data.get("description", "")).strip()
                or str(data.get("title", "")).strip()
                or "Agent reported a blocker/constraint."
            )
            blocker = {
                "agent": self.agent_name,
                "category": raw_type or "constraint",
                "reason": reason[:1200],
                "next_action": str(data.get("suggested_action", "") or data.get("next_action", "")).strip()[:500],
                "timestamp": datetime.now().isoformat(),
            }
            self.shared_state.append_to_list("agent_blockers", blocker)

            # Keep agent_notes concise and structured to avoid prompt pollution.
            try:
                notes = self.shared_state.read_section("agent_notes") or {}
                notes[self.agent_name] = self._format_agent_note_summary(
                    finding=str(data.get("title", "")).strip() or "Constraint reported",
                    blocker=reason,
                    next_action=blocker["next_action"],
                )
                self.shared_state.update_section("agent_notes", notes)
            except Exception as e:
                logger.warning("[%s] Failed to update agent_notes for blocker: %s", self.agent_name, e)

            self._post_handoff_with_hooks(AgentHandoff(
                source_agent=self.agent_name,
                target_agent="orchestrator",
                handoff_type="intelligence",
                priority="medium",
                summary=f"BLOCKER from {self.agent_name}: {reason[:120]}",
                data={
                    "title": str(data.get("title", "Agent blocker")).strip() or "Agent blocker",
                    "host": str(data.get("host") or data.get("target") or self._get_engagement_target() or "").strip(),
                    "evidence_hash": hashlib.sha1(reason.encode("utf-8")).hexdigest()[:12],
                    "category": raw_type or "constraint",
                },
                suggested_action=blocker["next_action"],
                confidence=0.9,
            ))
            return f"Constraint saved: {reason[:120]}"

        return f"Unknown finding type: {finding_type}"

    def _is_duplicate_vulnerability(self, title: str, host: str, evidence_hash: str) -> bool:
        """Deduplicate vulnerability saves by title+host+evidence hash."""
        try:
            existing = self.db.query_findings(self.engagement_id) or []
        except Exception:
            return False

        t_norm = (title or "").strip().lower()
        h_norm = (host or "").strip().lower()
        e_norm = (evidence_hash or "").strip().lower()

        for row in existing:
            row_title = str(row.get("title", "")).strip().lower()
            row_host = str(row.get("host_ip", "") or "").strip().lower()
            if not row_host:
                row_meta = row.get("metadata") or {}
                if isinstance(row_meta, dict):
                    row_host = str(row_meta.get("host", "")).strip().lower()

            row_evidence = str(row.get("evidence", "") or "")
            row_meta = row.get("metadata") or {}
            row_hash = ""
            if isinstance(row_meta, dict):
                row_hash = str(row_meta.get("evidence_hash", "") or "").strip().lower()
            if not row_hash and row_evidence:
                row_hash = hashlib.sha1(row_evidence.encode("utf-8")).hexdigest()[:12]
            if not row_hash:
                row_hash = "no_evidence"

            if row_title == t_norm and row_host == h_norm and row_hash == e_norm:
                return True
        return False

    @staticmethod
    def _is_non_vulnerability_note(data: dict) -> bool:
        """Detect note/refusal/status entries that should never be stored as vulns."""
        title = str(data.get("title", "") or "").lower()
        desc = str(data.get("description", "") or "").lower()
        category = str(data.get("category", "") or "").lower()
        severity = str(data.get("severity", "") or "").lower()
        combined = " ".join([title, desc, category, severity])
        markers = (
            "agent refusal",
            "refusal",
            "blocked",
            "policy",
            "constraint",
            "out of scope",
            "cannot comply",
            "can't help",
            "non-vuln",
            "informational note",
        )
        return any(m in combined for m in markers)

    def _handle_read_shared_state(self, tool_input: dict) -> str:
        """Read the shared state (or a section of it)."""
        section = tool_input.get("section")
        if section and section != "all":
            try:
                data = self.shared_state.read_section(section)
            except KeyError:
                available = list(self.shared_state.read().keys())
                data = {"error": f"Section '{section}' not found", "available_sections": available}
        else:
            # "all" or no section specified → return full state
            data = self.shared_state.read()
        return json.dumps(data, indent=2, default=str)

    def _handle_update_shared_state(self, tool_input: dict) -> str:
        """Update a section of shared state."""
        section = tool_input.get("section", "")
        data = tool_input.get("data")

        if not section:
            return "Error: 'section' is required"

        if section == "hosts" and isinstance(data, dict):
            # Special handling for host updates
            for ip, host_info in data.items():
                self.shared_state.update_host(
                    ip=ip,
                    hostname=host_info.get("hostname"),
                    os=host_info.get("os"),
                    services=host_info.get("services"),
                )
                # Also upsert in DB
                self.db.upsert_host(
                    engagement_id=self.engagement_id,
                    ip=ip,
                    hostname=host_info.get("hostname"),
                    os=host_info.get("os"),
                )
            return f"Updated hosts: {list(data.keys())}"

        elif isinstance(data, list):
            for item in data:
                self.shared_state.append_to_list(section, item)
            return f"Appended {len(data)} items to {section}"
        else:
            self.shared_state.update_section(section, data)
            return f"Updated section: {section}"

    def _handle_add_to_network_map(self, tool_input: dict) -> str:
        """Add nodes/edges to the network map."""
        action = tool_input.get("action", "add_host")

        if action == "add_host":
            self.network_map.add_host(
                ip=tool_input.get("ip", ""),
                hostname=tool_input.get("hostname"),
                os=tool_input.get("os"),
            )
            return f"Added host to network map: {tool_input.get('ip')}"

        elif action == "add_service":
            self.network_map.add_service(
                host_ip=tool_input.get("host_ip", ""),
                port=tool_input.get("port", 0),
                service_name=tool_input.get("service_name"),
                version=tool_input.get("version"),
            )
            return f"Added service: {tool_input.get('host_ip')}:{tool_input.get('port')}"

        elif action == "add_edge":
            self.network_map.add_edge(
                source_ip=tool_input.get("source_ip", ""),
                target_ip=tool_input.get("target_ip", ""),
                relationship=tool_input.get("relationship", "connects_to"),
                label=tool_input.get("label"),
            )
            return f"Added edge: {tool_input.get('source_ip')} -> {tool_input.get('target_ip')}"

        elif action == "add_vuln":
            self.network_map.add_vuln(
                host_ip=tool_input.get("host_ip", ""),
                vuln_title=tool_input.get("vuln_title", ""),
                severity=tool_input.get("severity", "info"),
            )
            return f"Added vuln to map: {tool_input.get('vuln_title')}"

        elif action == "add_web_app":
            self.network_map.add_web_app(
                host_ip=tool_input.get("host_ip", "") or tool_input.get("host", ""),
                app_url=tool_input.get("app_url") or tool_input.get("url"),
                product=tool_input.get("product"),
                version=tool_input.get("version"),
                auth_level=tool_input.get("auth_level"),
                notes=tool_input.get("notes"),
            )
            return f"Added web app to map: {tool_input.get('host_ip') or tool_input.get('host')}"

        return f"Unknown network map action: {action}"

    def _handle_log_message(self, tool_input: dict) -> str:
        """Log a message from the agent."""
        level = tool_input.get("level", "info")
        message = tool_input.get("message", "")
        getattr(logger, level, logger.info)(
            f"[{self.agent_name}] {message}"
        )
        return f"Logged: {message}"

    def _handle_get_raw_output(self, tool_input: dict) -> str:
        """Retrieve raw tool output from disk for deeper analysis."""
        tool_name = tool_input.get("tool_name", "")
        search_keyword = tool_input.get("search_keyword", "")
        max_lines = tool_input.get("max_lines", 200)

        raw_dir = Path(self.engagement_dir) / "logs" / "raw"
        if not raw_dir.exists():
            return f"No raw output directory found for this engagement."

        # Find matching output files (most recent first)
        matching_files = sorted(
            [f for f in raw_dir.glob(f"{tool_name}*") if f.is_file()],
            key=lambda f: f.stat().st_mtime,
            reverse=True,
        )

        if not matching_files:
            return f"No raw output found for tool '{tool_name}'. Available tools: {', '.join(set(f.name.rsplit('_', 2)[0] for f in raw_dir.iterdir() if f.is_file()))}"

        # Read the most recent output file
        target_file = matching_files[0]
        try:
            content = target_file.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            return f"Error reading raw output: {e}"

        lines = content.splitlines()

        # Apply keyword filter
        if search_keyword:
            keyword_lower = search_keyword.lower()
            lines = [l for l in lines if keyword_lower in l.lower()]
            if not lines:
                return f"No lines matching '{search_keyword}' in {target_file.name} ({len(content.splitlines())} total lines)"

        # Apply line limit
        total = len(lines)
        if total > max_lines:
            lines = lines[:max_lines]
            truncation_note = f"\n... ({total - max_lines} more lines, use search_keyword to filter)"
        else:
            truncation_note = ""

        return f"[Raw output from {target_file.name}] ({total} lines)\n" + "\n".join(lines) + truncation_note

    def _handle_query_tool_history(self, tool_input: dict) -> str:
        """Query tool execution history to check what's been done and avoid duplicates."""
        agent_filter = tool_input.get("agent_filter", "")
        tool_filter = tool_input.get("tool_filter", "")
        limit = tool_input.get("limit", 20)

        execs = self.db.get_tool_executions(self.engagement_id, limit=100)

        # Apply filters
        if agent_filter:
            execs = [e for e in execs if agent_filter.lower() in e.get("agent", "").lower()]
        if tool_filter:
            execs = [e for e in execs if tool_filter.lower() in e.get("tool_name", "").lower()]

        execs = execs[:limit]

        if not execs:
            return "No matching tool executions found."

        lines = [f"Tool execution history ({len(execs)} results):"]
        for e in execs:
            outcome_kind = str(e.get("outcome_kind", "") or "")
            status = "OK" if e.get("success") else (outcome_kind or "failed").upper()
            qualifiers = []
            if outcome_kind and not e.get("success"):
                qualifiers.append(outcome_kind.replace("_", " "))
            if e.get("failure_phase"):
                qualifiers.append(f"phase={e.get('failure_phase')}")
            if e.get("failure_category"):
                qualifiers.append(f"category={e.get('failure_category')}")
            duration = e.get("duration_seconds", 0)
            qualifier_text = f" [{' | '.join(qualifiers)}]" if qualifiers else ""
            lines.append(
                f"  [{status}] {e.get('tool_name')} by {e.get('agent')} "
                f"({duration:.1f}s){qualifier_text} - {e.get('compacted_summary', '')[:150]}"
            )

        return "\n".join(lines)

    def _handle_request_flow(self, tool_input: dict) -> str:
        """Post a flow_request handoff so the trigger dispatcher picks it up."""
        flow_name = tool_input.get("flow_name", "")
        reason = tool_input.get("reason", "")
        inputs = tool_input.get("inputs", {})
        priority = tool_input.get("priority", "medium")

        if not flow_name:
            return "Error: flow_name is required."

        handoff = AgentHandoff(
            source_agent=self.agent_name,
            target_agent="orchestrator",
            handoff_type="flow_request",
            priority=priority,
            summary=f"Flow request: {flow_name} — {reason}",
            data={
                "flow_name": flow_name,
                "inputs": inputs,
            },
            suggested_action=f"trigger_flow:{flow_name}",
            confidence=0.8,
        )
        self.handoff_queue.post(handoff)
        return f"Flow request posted: {flow_name} (priority={priority}). The trigger dispatcher will pick this up."

    def _build_context(self, task: str) -> str:
        """
        Build the initial user message with task + context.

        Each section is filtered by agent type so agents only see what they
        need.  Methodology / constraints / summary format live in the system
        prompt (agents/prompts/*.md) and are NOT repeated here.
        """
        parts = [f"## Task\n{task}\n"]

        state = self.shared_state.read()
        if state:
            engagement_info = state.get("engagement", {})
            parts.append(
                f"## Engagement Context\n"
                f"- Target: {engagement_info.get('target', 'unknown')}\n"
                f"- Scope: {json.dumps(engagement_info.get('scope', []))}\n"
                f"- Out of scope: {json.dumps(engagement_info.get('out_of_scope', []))}\n"
                f"- Methodology: {engagement_info.get('methodology', 'standard')}\n"
                f"- Current phase: {state.get('current_phase', 'unknown')}\n"
            )

            # Per-agent context specialization (hosts, vulns, creds, etc.)
            context_sections = self._get_context_sections_for_agent(state)
            parts.extend(context_sections)

            # Agent notes — only from agents whose output feeds this agent
            notes = state.get("agent_notes", {})
            if notes:
                related_notes = [
                    (agent, note) for agent, note in notes.items()
                    if self._is_related_agent(agent)
                ]
                if related_notes:
                    parts.append("## Notes from Other Agents\n")
                    for agent, note in related_notes[:4]:
                        summary = self._summarize_agent_note(str(note or ""))
                        parts.append(f"**{agent}:**\n")
                        if summary.get("finding"):
                            parts.append(f"- finding: {summary['finding']}\n")
                        if summary.get("blocker"):
                            parts.append(f"- blocker: {summary['blocker']}\n")
                        if summary.get("next_action"):
                            parts.append(f"- next_action: {summary['next_action']}\n")

        # Structured handoffs from other agents
        handoffs = self.handoff_queue.get_for_agent(self.agent_type)
        if handoffs:
            parts.append(format_handoff_for_context(handoffs))

        # Recent tool executions — only tools this agent type can use
        own_tool_names = {
            t["name"]
            for t in get_tool_definitions_for_agent(self.agent_type)
        }
        recent_execs = self.db.get_tool_executions(
            self.engagement_id, limit=30
        )
        if recent_execs:
            relevant = [
                ex for ex in recent_execs
                if ex.get("tool_name") in own_tool_names
            ][:10]
            if relevant:
                parts.append(
                    "## Recent Tool Results\n"
                    "**Do NOT re-run tools that already succeeded with the "
                    "same arguments.**\n"
                )
                for ex in relevant:
                    status = 'OK' if ex.get('success') else 'FAILED'
                    tool = ex.get('tool_name', '?')
                    cmd = ex.get('command', '')
                    cmd_display = (cmd[:120] + '...') if len(cmd) > 120 else cmd
                    summary = (ex.get('compacted_summary') or '')[:160]
                    parts.append(
                        f"- [{status}] **{tool}**: `{cmd_display}`\n"
                        f"  {summary}\n"
                    )

        # Network map summary (always compact — one line)
        self.network_map.load()
        map_summary = self.network_map.summary()
        if map_summary:
            parts.append(f"## Network Map Status\n{map_summary}\n")

        return "\n".join(parts)

    @staticmethod
    def _ensure_list(val, default=None):
        """Safely coerce a value to a list. Dicts become a list of their values."""
        if val is None:
            return default or []
        if isinstance(val, list):
            return val
        if isinstance(val, dict):
            return list(val.values())
        if isinstance(val, str):
            return [val]
        return list(val) if hasattr(val, '__iter__') else [val]

    # Which state sections each agent type needs.  Agents not listed get
    # only the compact host table (IP + open ports).
    _CONTEXT_NEEDS: dict[str, set[str]] = {
        "recon":      {"hosts_full", "domains", "technologies", "attack_surfaces", "web_apps"},
        "osint":      {"hosts_full", "domains"},
        "webapp":     {"hosts_compact", "domains", "technologies", "vulns", "attack_surfaces", "web_apps", "auth_access"},
        "attack":     {"hosts_compact", "vulns", "creds", "attack_surfaces", "web_apps", "auth_access"},
        "browser":    {"hosts_compact", "technologies", "web_apps"},
        "cloud":      {"hosts_compact"},
        "binary":     {"hosts_compact", "vulns"},
        "forensics":  {"hosts_compact"},
        "reporting":  {"hosts_compact", "vulns", "creds", "web_apps", "auth_access"},
    }

    def _get_context_sections_for_agent(self, state: dict) -> list:
        """Return only the state sections this agent type actually needs.

        Hosts are rendered in two modes:
        - ``hosts_full``:    full JSON (recon/osint need service versions, scripts, etc.)
        - ``hosts_compact``: one-line-per-host table (IP | OS | open ports) — much smaller
        If neither is in the need set the agent gets nothing.
        """
        needs = self._CONTEXT_NEEDS.get(self.agent_type, {"hosts_compact"})
        parts: list[str] = []

        hosts = state.get("hosts", {})

        # ---- Hosts (full JSON or compact table) ----------------------------
        if "hosts_full" in needs and hosts:
            parts.append(
                "## Known Hosts\n```json\n"
                + json.dumps(hosts, indent=2)
                + "\n```\n"
            )
        elif "hosts_compact" in needs and hosts:
            lines = [f"## Known Hosts ({len(hosts)})\n"]
            for ip, info in list(hosts.items())[:40]:
                if not isinstance(info, dict):
                    lines.append(f"- {ip}\n")
                    continue
                os_info = info.get("os", "")
                svcs = info.get("services", [])
                port_list = ", ".join(
                    f"{s.get('port')}/{s.get('name') or s.get('service', '?')}"
                    for s in svcs[:12]
                    if isinstance(s, dict)
                )
                extra = f" (+{len(svcs) - 12} more)" if len(svcs) > 12 else ""
                os_tag = f" [{os_info}]" if os_info else ""
                lines.append(f"- {ip}{os_tag}: {port_list}{extra}\n")
            parts.append("".join(lines))

        # ---- Domains -------------------------------------------------------
        if "domains" in needs:
            domains = state.get("domains", [])
            if domains:
                if isinstance(domains, dict):
                    # Show only domain names, not full records
                    names = list(domains.keys())[:40]
                    parts.append(f"## Known Domains ({len(domains)})\n{', '.join(names)}\n")
                elif isinstance(domains, list):
                    parts.append(f"## Known Domains\n{', '.join(str(d) for d in domains[:40])}\n")

        # ---- Technologies --------------------------------------------------
        if "technologies" in needs:
            techs = state.get("technologies", {})
            if techs:
                # Flatten to "host: tech1, tech2" lines instead of full JSON
                lines = ["## Detected Technologies\n"]
                for host, tech_info in list(techs.items())[:20]:
                    if isinstance(tech_info, list):
                        lines.append(f"- {host}: {', '.join(str(t) for t in tech_info[:8])}\n")
                    elif isinstance(tech_info, dict):
                        lines.append(f"- {host}: {', '.join(tech_info.keys())}\n")
                    else:
                        lines.append(f"- {host}: {tech_info}\n")
                parts.append("".join(lines))

        if "web_apps" in needs:
            web_apps = state.get("web_apps", {})
            if isinstance(web_apps, dict) and web_apps:
                lines = ["## Web Applications\n"]
                for host, app in list(web_apps.items())[:20]:
                    if not isinstance(app, dict):
                        lines.append(f"- {host}\n")
                        continue
                    bits = [host]
                    if app.get("product"):
                        product = str(app.get("product"))
                        if app.get("version"):
                            product += f" {app.get('version')}"
                        bits.append(product)
                    if app.get("auth_level"):
                        bits.append(f"auth={app.get('auth_level')}")
                    if app.get("url"):
                        bits.append(str(app.get("url")))
                    endpoints = list(app.get("authenticated_endpoints") or [])
                    if endpoints:
                        bits.append(f"endpoints={', '.join(endpoints[:3])}")
                    lines.append(f"- {' | '.join(bits)}\n")
                parts.append("".join(lines))

        # ---- Vulnerabilities -----------------------------------------------
        if "vulns" in needs:
            vulns = self._ensure_list(state.get("vulns_summary", []))
            if vulns:
                severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
                sorted_vulns = sorted(
                    vulns,
                    key=lambda v: severity_rank.get(
                        v.get("severity", "info").lower(), 5
                    ),
                )
                # Attack/binary agents only need critical+high; reporting/webapp get more
                limit = 15 if self.agent_type in ("attack", "binary") else 25
                parts.append("## Known Vulnerabilities\n")
                for v in sorted_vulns[:limit]:
                    parts.append(
                        f"- [{v.get('severity', '?').upper()}] "
                        f"{v.get('title', '?')} on {v.get('host', '?')}\n"
                    )

        # ---- Credentials ---------------------------------------------------
        if "creds" in needs:
            creds = self._ensure_list(state.get("credentials_summary", []))
            if creds:
                parts.append(f"## Known Credentials ({len(creds)} found)\n")
                for c in creds[:15]:
                    if isinstance(c, dict):
                        parts.append(
                            f"- {c.get('username', '?')} | "
                            f"{c.get('type', '?')} | "
                            f"Source: {c.get('source', '?')}\n"
                        )

        # ---- Attack surfaces -----------------------------------------------
        if "attack_surfaces" in needs:
            surfaces = self._ensure_list(state.get("attack_surfaces", []))
            if surfaces:
                parts.append(
                    f"## Attack Surfaces\n"
                    f"{', '.join(str(s) for s in surfaces[:20])}\n"
                )

        if "auth_access" in needs:
            accesses = self._ensure_list(state.get("authenticated_access", []))
            if accesses:
                parts.append("## Confirmed Authenticated Access\n")
                for entry in accesses[:15]:
                    if isinstance(entry, dict):
                        parts.append(
                            f"- {entry.get('host', '?')} | "
                            f"{entry.get('access_level', '?')} | "
                            f"{entry.get('product', '') or 'application'} | "
                            f"{entry.get('url', '')}\n"
                        )

        return parts

    def _get_engagement_target(self) -> str:
        """Get the engagement target IP from shared state."""
        try:
            state = self.shared_state.read()
            return state.get("engagement", {}).get("target", "")
        except Exception:
            return ""

    def _is_related_agent(self, agent_name: str) -> bool:
        """Check if another agent's notes are highly relevant to this agent."""
        relevance_map: dict[str, list[str]] = {
            "recon":      ["OSINT Agent"],
            "osint":      ["Recon Agent"],
            "webapp":     ["Recon Agent", "OSINT Agent"],
            "attack":     ["Recon Agent", "WebApp Agent", "OSINT Agent"],
            "browser":    ["Recon Agent", "WebApp Agent"],
            "cloud":      ["Recon Agent", "OSINT Agent"],
            "binary":     ["Recon Agent", "Attack Agent"],
            "forensics":  ["Recon Agent", "Attack Agent"],
            "reporting":  [],  # reporting reads all notes via _build_context
        }
        # Reporting agent needs full cross-agent visibility
        if self.agent_type == "reporting":
            return True
        related = relevance_map.get(self.agent_type, [])
        return agent_name in related

    @staticmethod
    def _is_blocker_or_constraint_note(data: dict) -> bool:
        """Detect refusal/policy/blocker notes that should not be vulnerability findings."""
        text = " ".join([
            str(data.get("title", "") or ""),
            str(data.get("description", "") or ""),
            str(data.get("summary", "") or ""),
        ]).lower()
        blocker_markers = (
            "can't help",
            "cannot help",
            "cannot comply",
            "won't provide",
            "will not provide",
            "disallowed",
            "actionable exploitation guidance",
            "status: blocked",
            "blocked",
            "policy",
            "constraint",
        )
        return any(m in text for m in blocker_markers)

    @staticmethod
    def _format_agent_note_summary(finding: str, blocker: str = "", next_action: str = "") -> str:
        """Store agent notes in a compact structured format."""
        finding = finding.strip()[:220]
        blocker = blocker.strip()[:320]
        next_action = next_action.strip()[:320]
        return (
            f"finding: {finding}\n"
            f"blocker: {blocker}\n"
            f"next_action: {next_action}"
        ).strip()

    @staticmethod
    def _summarize_agent_note(note: str) -> dict:
        """Extract compact (finding/blocker/next_action) fields from free-form notes."""
        text = re.sub(r"\s+", " ", (note or "")).strip()
        if not text:
            return {"finding": "", "blocker": "", "next_action": ""}

        # If note already follows structured format, parse directly.
        finding = ""
        blocker = ""
        next_action = ""
        for part in note.splitlines():
            p = part.strip()
            if p.lower().startswith("finding:"):
                finding = p.split(":", 1)[1].strip()
            elif p.lower().startswith("blocker:"):
                blocker = p.split(":", 1)[1].strip()
            elif p.lower().startswith("next_action:"):
                next_action = p.split(":", 1)[1].strip()

        if not finding:
            finding = text[:220]

        if not blocker:
            blocker_sent = re.search(
                r"([^.!?]*\b(blocked|cannot help|can't help|cannot comply|disallowed|policy)\b[^.!?]*[.!?]?)",
                text,
                re.IGNORECASE,
            )
            blocker = blocker_sent.group(1).strip()[:260] if blocker_sent else ""

        if not next_action:
            next_sent = re.search(
                r"([^.!?]*\b(next|recommend|should|consider|assign)\b[^.!?]*[.!?]?)",
                text,
                re.IGNORECASE,
            )
            next_action = next_sent.group(1).strip()[:260] if next_sent else ""

        return {
            "finding": finding[:220],
            "blocker": blocker[:260],
            "next_action": next_action[:260],
        }

    def _extract_findings(self, text: str) -> dict:
        """Extract structured findings from the agent's final text response."""
        if not text:
            return {"raw_summary": "", "agent": self.agent_name, "tools_used_count": 0}

        # Count finding types from tools used
        save_finding_count = self.tools_used.count("save_finding")
        tool_failures = len(self.errors)
        unique_tools = list(set(self.tools_used))

        # Extract key metrics from the text
        import re
        vuln_mentions = len(re.findall(r"(?:vulnerability|vuln|CVE-\d{4}-\d+)", text, re.IGNORECASE))
        cred_mentions = len(re.findall(r"(?:credential|password|username|login|hash)", text, re.IGNORECASE))
        host_mentions = len(re.findall(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", text))

        return {
            "raw_summary": text[:3000] if text else "",
            "agent": self.agent_name,
            "tools_used_count": len(self.tools_used),
            "unique_tools": unique_tools,
            "findings_saved": save_finding_count,
            "errors_encountered": tool_failures,
            "vuln_references": vuln_mentions,
            "credential_references": cred_mentions,
            "host_references": host_mentions,
        }

    def _extract_next_steps(self, text: str) -> list:
        """Extract suggested next steps from the agent's response."""
        steps = []
        if not text:
            return steps

        # Look for common patterns in the agent's output
        lines = text.split("\n")
        in_next_steps = False
        for line in lines:
            lower = line.lower().strip()
            if any(kw in lower for kw in ["next step", "suggested", "recommend", "follow-up", "investigate further", "priority"]):
                in_next_steps = True
                # Check if the keyword line itself is a step
                if line.strip().startswith(("-", "*", "•", "1", "2", "3")):
                    step = line.strip().lstrip("-*•0123456789. ")
                    if step and len(step) > 10:
                        steps.append(step)
                continue
            if in_next_steps:
                stripped = line.strip()
                if stripped.startswith(("-", "*", "•", "1", "2", "3", "4", "5")):
                    step = stripped.lstrip("-*•0123456789. ")
                    if step and len(step) > 5:
                        steps.append(step)
                elif not stripped:
                    in_next_steps = False

        return steps[:15]

    def _update_story(self, task: str, result: AgentResult):
        """Append this agent's work to the attack story."""
        # Count artifacts
        vuln_count = len(
            [t for t in self.tools_used if t == "save_finding"]
        )
        # Defensive str() coercion — task/summary could be non-string in edge cases
        safe_task = str(task) if not isinstance(task, str) else task
        safe_summary = str(result.summary) if not isinstance(result.summary, str) else (result.summary or "")
        self.story.add_phase_section(
            phase=safe_task[:50],
            agent=self.agent_name,
            duration_seconds=result.duration_seconds,
            narrative=safe_summary[:1000] if safe_summary else "No summary available.",
            key_findings=result.suggested_next_steps[:5],
            artifacts_count={
                "tools_executed": len(self.tools_used),
                "errors": len(self.errors),
            },
        )

        # Save agent notes to shared state (generous limit for cross-agent knowledge transfer)
        if safe_summary:
            notes = self.shared_state.read_section("agent_notes") or {}
            notes[self.agent_name] = safe_summary[:2000]
            self.shared_state.update_section("agent_notes", notes)

    def _save_raw_output(self, tool_name: str, raw_output: str) -> str:
        """Save raw tool output to disk, return the file path."""
        raw_dir = Path(self.engagement_dir) / "logs" / "raw"
        raw_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{tool_name}_{timestamp}.txt"
        filepath = raw_dir / filename

        # Truncate if too large
        output = raw_output[:MAX_RAW_OUTPUT_SIZE]
        filepath.write_text(output, encoding="utf-8", errors="replace")

        return str(filepath)

    def _log_refusal_audit(self, task: str, raw_text: str, turn: int,
                           response: Any, refusal_class: str):
        """Write a structured refusal audit record to logs/model_refusals.jsonl.

        Points to the full conversation log rather than duplicating prompt/context.
        """
        import fcntl

        log_dir = Path(self.engagement_dir) / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)

        # Build a stable hash of system_prompt + context for grouping
        prompt_material = (self.system_prompt or "") + (getattr(self, '_last_built_context', '') or "")
        context_hash = hashlib.sha256(prompt_material.encode(errors="replace")).hexdigest()[:16]

        record = {
            "timestamp": datetime.now().isoformat(),
            "engagement_id": self.engagement_id,
            "session_id": self._conversation_session_id,
            "agent_type": self.agent_type,
            "agent_name": self.agent_name,
            "model": self.model,
            "provider": getattr(self, 'provider', 'anthropic'),
            "task": str(task)[:500],
            "refusal_class": refusal_class,
            "refusal_excerpt": raw_text[:300],
            "turn": turn,
            "stop_reason": getattr(response, 'stop_reason', 'unknown'),
            "context_hash": context_hash,
            "conversation_log_path": str(
                log_dir / "conversations"
                / f"{self.agent_type}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            ),
        }

        refusal_path = log_dir / "model_refusals.jsonl"
        try:
            with open(refusal_path, "a") as f:
                fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                try:
                    f.write(json.dumps(record, default=str) + "\n")
                finally:
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)
            logger.warning(
                f"[{self.agent_name}] Model refusal logged ({refusal_class}): "
                f"{raw_text[:80]}"
            )
        except Exception as e:
            logger.error(f"[{self.agent_name}] Failed to write refusal audit: {e}")

    def _save_conversation_log(self):
        """Save both summary (JSONL) and full conversation (per-agent JSON)."""
        import fcntl

        log_dir = Path(self.engagement_dir) / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        ts_iso = datetime.now().isoformat()
        duration = round(time.time() - getattr(self, '_execute_start', time.time()), 1)

        # 1. Summary line (backward-compatible)
        summary_entry = {
            "timestamp": ts_iso,
            "agent": self.agent_name,
            "session_id": self._conversation_session_id,
            "tools_used": self.tools_used,
            "errors": self.errors,
            "turns": len(self.conversation_log),
            "duration_seconds": duration,
        }

        log_path = log_dir / "agent_conversations.jsonl"
        with open(log_path, "a") as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            try:
                f.write(json.dumps(summary_entry) + "\n")
            finally:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)

        # 2. Full conversation dump (system prompt + built context + all turns)
        conv_dir = log_dir / "conversations"
        conv_dir.mkdir(parents=True, exist_ok=True)

        full_entry = {
            "timestamp": ts_iso,
            "agent": self.agent_name,
            "agent_type": self.agent_type,
            "session_id": self._conversation_session_id,
            "model": self.model,
            "duration_seconds": duration,
            "tools_used": self.tools_used,
            "errors": self.errors,
            "system_prompt": self.system_prompt[:10000],  # Cap to avoid huge files
            "built_context": getattr(self, '_last_built_context', None),
            "conversation": self.conversation_log,
        }

        conv_path = conv_dir / f"{self.agent_type}_{timestamp}.json"
        try:
            with open(conv_path, "w") as f:
                json.dump(full_entry, f, indent=2, default=str)
            logger.info(f"[{self.agent_name}] Full conversation saved to {conv_path}")
        except Exception as e:
            logger.error(f"[{self.agent_name}] Failed to save full conversation: {e}")

    def _log_conversation(self, role: str, content: Any):
        """Log a conversation turn with full content."""
        entry = {
            "role": role,
            "turn": self._current_turn_number,
            "timestamp": datetime.now().isoformat(),
            "content": self._serialize_content(content),
        }
        self.conversation_log.append(entry)

        # Write to live turns file for real-time streaming to the TUI
        self._write_live_turn(entry)

    def _route_for_live_turn(self, role: str) -> tuple[str, str, str, str]:
        """Return source, target, direction, and stream kind for a logged turn."""
        if role == "user":
            return "Orchestrator", self.agent_name, "outbound", "context"
        if role == "assistant":
            return self.agent_name, "Orchestrator", "return", "response"
        if role == "tool_results":
            return "Tool Runner", self.agent_name, "inbound", "tool_results"
        return self.agent_name, "Orchestrator", "return", role or "unknown"

    def _write_live_turn(self, entry: dict):
        """Append a conversation turn to the live turns log for SSE streaming."""
        try:
            import fcntl
            log_dir = Path(self.engagement_dir) / "logs"
            log_dir.mkdir(parents=True, exist_ok=True)
            live_path = log_dir / "live_turns.jsonl"
            source, target, direction, stream_kind = self._route_for_live_turn(entry["role"])

            # Compact the content for streaming (cap at 2KB per turn)
            stream_entry = {
                "session_id": self._conversation_session_id,
                "agent": self.agent_name,
                "source": source,
                "target": target,
                "direction": direction,
                "stream_kind": stream_kind,
                "model": self.model,
                "role": entry["role"],
                "turn": entry.get("turn", 0),
                "timestamp": entry["timestamp"],
                "content": self._compact_turn_content(entry["content"]),
            }

            with open(live_path, "a") as f:
                fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                try:
                    f.write(json.dumps(stream_entry, default=str) + "\n")
                finally:
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)
            get_event_bus().emit(get_event_bus()._make_event(
                EventType.AGENT_TURN,
                self.agent_name,
                stream_entry,
                self.engagement_id,
            ))
        except Exception as e:
            logger.debug(f"[{self.agent_name}] Failed to write live turn: {e}")

    @staticmethod
    def _compact_turn_content(content: Any) -> Any:
        """Compact content for live streaming (keep it small for SSE)."""
        if isinstance(content, str):
            return content[:2000] + ("..." if len(content) > 2000 else "")
        if isinstance(content, list):
            compacted = []
            for block in content:
                if isinstance(block, dict):
                    if block.get("type") == "text":
                        text = block.get("text", "")
                        compacted.append({
                            "type": "text",
                            "text": text[:2000] + ("..." if len(text) > 2000 else ""),
                        })
                    elif block.get("type") == "tool_use":
                        compacted.append({
                            "type": "tool_use",
                            "name": block.get("name", ""),
                            "input_summary": str(block.get("input", {}))[:500],
                        })
                    elif block.get("type") == "tool_result":
                        content_val = block.get("content", "")
                        if isinstance(content_val, str):
                            content_val = content_val[:500]
                        compacted.append({
                            "type": "tool_result",
                            "tool_use_id": block.get("tool_use_id", ""),
                            "tool_name": block.get("tool_name", ""),
                            "content": content_val,
                        })
                    elif block.get("type") == "provider_assistant_message":
                        raw_message = block.get("message", {})
                        compacted.append({
                            "type": "provider_assistant_message",
                            "provider": block.get("provider", "openai_compatible"),
                            "has_tool_calls": bool(isinstance(raw_message, dict) and raw_message.get("tool_calls")),
                            "has_reasoning_content": bool(isinstance(raw_message, dict) and raw_message.get("reasoning_content")),
                        })
                    else:
                        compacted.append(block)
                else:
                    compacted.append(block)
            return compacted
        return content

    @staticmethod
    def _serialize_content(content: Any) -> Any:
        """Serialize API response content to JSON-safe format."""
        if content is None:
            return None
        if isinstance(content, str):
            return content
        if isinstance(content, list):
            return [BaseAgent._serialize_content(item) for item in content]
        if isinstance(content, dict):
            return {
                k: BaseAgent._serialize_content(v)
                for k, v in content.items()
            }
        if is_dataclass(content):
            return BaseAgent._serialize_content(asdict(content))
        # Handle Anthropic API objects (ContentBlock, ToolUseBlock, etc.)
        if hasattr(content, 'model_dump'):
            try:
                return BaseAgent._serialize_content(content.model_dump(exclude_none=True))
            except TypeError:
                return BaseAgent._serialize_content(content.model_dump())
        if hasattr(content, '__dict__'):
            return {
                k: BaseAgent._serialize_content(v)
                for k, v in content.__dict__.items()
                if not k.startswith('_')
            }
        return str(content)[:2000]

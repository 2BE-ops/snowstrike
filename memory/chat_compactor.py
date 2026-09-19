"""
SnowStrike AI v7 — Chat History Compactor

Compresses older conversation turns into structured memory for the LLM,
preserving full raw history on disk for audit/replay. Uses the project's
compaction model tier to produce the compressed representation.
"""

import json
import logging
import os
import time
from typing import Optional

from config import MODELS, get_model_context_window
from agents.model_client import create_model_client, resolve_model_for_role

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Minimum recent messages to always keep verbatim (never compact these)
MIN_VERBATIM_TAIL = 12

# Compaction triggers when chat history uses this fraction of usable budget
COMPACTION_THRESHOLD = 0.55

# After compaction, aim to leave this fraction of usable budget free
COMPACTION_TARGET = 0.35

# Minimum message count before compaction is even considered
MIN_MESSAGES_FOR_COMPACTION = 16

# Maximum chars for the compacted memory block
MAX_COMPACTED_CHARS = 12_000

# File names within engagement directory
COMPACTION_STATE_FILE = "chat_compaction_state.json"

# ---------------------------------------------------------------------------
# Prompt for the compaction model
# ---------------------------------------------------------------------------

COMPACTION_SYSTEM_PROMPT = """\
You are a context compactor for a penetration testing orchestrator chat.
Your job is to compress older conversation turns into a structured memory
block that preserves all operationally important information.

You MUST preserve with exact values (no paraphrasing):
- Target IPs, hostnames, URLs, ports, CIDR ranges
- Usernames, passwords, hashes, tokens, API keys found
- CVE identifiers and vulnerability titles
- File paths, tool output snippets still relevant
- Service names and versions
- Scope constraints and rules of engagement
- User instructions, preferences, and explicit decisions
- Open questions and unresolved blockers
- Attack paths identified or attempted
- Findings and their severities
- Report constraints or format requirements
- Action items and next steps agreed upon

You MUST correctly represent tool-use sequences: if the user asked for
something, the assistant called a tool, and the tool returned a result,
your summary must preserve that causal chain accurately. Do not attribute
tool results to the wrong request.

Output format — use this exact structure:

## Engagement Context
<target, scope, methodology, constraints>

## Key Decisions & Instructions
<numbered list of user decisions/instructions still in effect>

## Findings So Far
<grouped by severity: critical, high, medium, low — include exact IPs, CVEs, services>

## Credentials & Access
<any credentials, shells, tokens discovered>

## Current State
<what phase we're in, what's been done, what's pending>

## Important Details
<anything else operationally important that doesn't fit above>

Be thorough but concise. Omit pleasantries, greetings, and redundant
back-and-forth. Focus on facts and decisions."""

COMPACTION_USER_PROMPT = """\
Compress the following older conversation turns into a structured memory block.
The recent turns (not shown here) will be kept verbatim, so focus only on
information from these older turns that would be lost if they were removed.

If there is an existing compacted memory from a previous round, integrate
its information with the new turns being compacted — do not lose prior facts.

{existing_memory_section}

## Older turns to compact:

{turns_text}"""


# ---------------------------------------------------------------------------
# State management
# ---------------------------------------------------------------------------

def _load_compaction_state(eng_dir: str) -> dict:
    """Load compaction state from disk."""
    path = os.path.join(eng_dir, COMPACTION_STATE_FILE)
    if not os.path.exists(path):
        return {
            "enabled": False,
            "compacted_memory": None,
            "compacted_up_to_index": 0,
            "compaction_count": 0,
            "last_compacted_at": None,
        }
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Failed to load compaction state: {e}")
        return {
            "enabled": False,
            "compacted_memory": None,
            "compacted_up_to_index": 0,
            "compaction_count": 0,
            "last_compacted_at": None,
        }


def _save_compaction_state(eng_dir: str, state: dict) -> None:
    """Save compaction state atomically."""
    import fcntl

    path = os.path.join(eng_dir, COMPACTION_STATE_FILE)
    tmp_path = path + ".tmp"
    lock_path = path + ".lock"

    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(lock_path, "w") as lock_file:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        try:
            with open(tmp_path, "w") as f:
                json.dump(state, f, indent=2, default=str)
                f.write("\n")
            os.replace(tmp_path, path)
        finally:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


# ---------------------------------------------------------------------------
# Token estimation (matches base_agent heuristic)
# ---------------------------------------------------------------------------

def _estimate_tokens(text: str) -> int:
    """Quick token estimate: ~4 chars per token."""
    return len(text) // 4


def _estimate_messages_tokens(messages: list[dict], system_prompt: str = "") -> int:
    """Estimate total tokens for a message list plus system prompt."""
    total = _estimate_tokens(system_prompt) if system_prompt else 0
    for msg in messages:
        content = msg.get("content", "")
        if isinstance(content, str):
            total += _estimate_tokens(content)
        elif isinstance(content, list):
            for block in content:
                if isinstance(block, dict):
                    if block.get("type") == "text":
                        total += _estimate_tokens(block.get("text", ""))
                    elif block.get("type") == "tool_use":
                        total += _estimate_tokens(json.dumps(block.get("input", {})))
                        total += 50  # overhead for tool name, id, etc.
                    elif block.get("type") == "tool_result":
                        total += _estimate_tokens(str(block.get("content", "")))
                        total += 30  # overhead
                    else:
                        total += _estimate_tokens(json.dumps(block, default=str))
        total += 10  # per-message overhead
    return total


# ---------------------------------------------------------------------------
# Message serialization for compaction prompt
# ---------------------------------------------------------------------------

def _messages_to_text(messages: list[dict]) -> str:
    """Convert message dicts to readable text for the compaction prompt."""
    lines = []
    for msg in messages:
        role = msg.get("role", "unknown").upper()
        content = msg.get("content", "")

        if isinstance(content, str):
            lines.append(f"[{role}]: {content}")
        elif isinstance(content, list):
            parts = []
            for block in content:
                if isinstance(block, dict):
                    btype = block.get("type", "")
                    if btype == "text":
                        parts.append(block.get("text", ""))
                    elif btype == "tool_use":
                        tool_name = block.get("name", "unknown")
                        tool_input = json.dumps(block.get("input", {}), default=str)
                        parts.append(f"[Called tool: {tool_name}({tool_input})]")
                    elif btype == "tool_result":
                        tool_content = str(block.get("content", ""))
                        # Truncate very long tool results for the compaction prompt
                        if len(tool_content) > 3000:
                            tool_content = tool_content[:3000] + "... (truncated)"
                        parts.append(f"[Tool result: {tool_content}]")
                    else:
                        parts.append(json.dumps(block, default=str)[:500])
            lines.append(f"[{role}]: {' '.join(parts)}")
        lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Core compaction logic
# ---------------------------------------------------------------------------

def _find_safe_split_point(messages: list[dict], target_idx: int) -> int:
    """Find a split point that doesn't break tool-use sequences.

    A tool-use sequence is: assistant message with tool_use blocks followed
    by a user message with tool_result blocks. We must not split in the middle.
    """
    idx = target_idx

    # Walk backward to find a safe boundary
    while idx > 0:
        msg = messages[idx]
        content = msg.get("content", "")

        # If this is a tool_result user message, we need to include the
        # preceding assistant message too — move split point before both
        if (
            msg.get("role") == "user"
            and isinstance(content, list)
            and content
            and all(
                isinstance(b, dict) and b.get("type") == "tool_result"
                for b in content
            )
        ):
            idx -= 1
            continue

        # If this is an assistant message with tool_use, the next message
        # is a tool_result — keep them together
        if (
            msg.get("role") == "assistant"
            and isinstance(content, list)
            and any(
                isinstance(b, dict) and b.get("type") == "tool_use"
                for b in content
            )
        ):
            idx -= 1
            continue

        break

    return max(idx, 0)


def run_compaction(
    eng_dir: str,
    messages: list[dict],
    chat_model: str,
    system_prompt: str,
    model_config: dict,
) -> Optional[dict]:
    """Run compaction on chat history if needed.

    Returns the compaction state dict (with compacted_memory set) if compaction
    was performed, or None if no compaction was needed.
    """
    state = _load_compaction_state(eng_dir)
    if not state.get("enabled"):
        return None

    # Check if there are enough messages to consider compaction
    if len(messages) < MIN_MESSAGES_FOR_COMPACTION:
        return state

    # Calculate context budget
    context_window = get_model_context_window(chat_model, 150_000)
    reserve = max(12_000, min(context_window // 5, 120_000))
    usable_window = max(12_000, context_window - reserve)

    # Estimate current token usage
    system_tokens = _estimate_tokens(system_prompt)
    # Include existing compacted memory in the estimate if we have one
    compacted_memory = state.get("compacted_memory")
    memory_tokens = _estimate_tokens(compacted_memory) if compacted_memory else 0

    messages_tokens = _estimate_messages_tokens(messages)
    total_tokens = system_tokens + memory_tokens + messages_tokens

    # Check if we're over the threshold
    pressure = total_tokens / usable_window if usable_window > 0 else 1.0
    if pressure < COMPACTION_THRESHOLD:
        return state

    logger.info(
        f"[ChatCompactor] Compaction triggered: {total_tokens} tokens, "
        f"{pressure:.1%} of {usable_window} usable window"
    )

    # Determine how many messages to compact (keep tail verbatim)
    # We want to compact enough to get below COMPACTION_TARGET
    target_tokens = int(usable_window * COMPACTION_TARGET)
    tokens_to_free = total_tokens - target_tokens

    # Walk from oldest to newest, accumulating tokens to free
    tokens_accumulated = 0
    split_idx = 0
    for i, msg in enumerate(messages):
        if len(messages) - i <= MIN_VERBATIM_TAIL:
            break
        content = msg.get("content", "")
        if isinstance(content, str):
            tokens_accumulated += _estimate_tokens(content)
        elif isinstance(content, list):
            tokens_accumulated += _estimate_messages_tokens([msg])
        if tokens_accumulated >= tokens_to_free:
            split_idx = i + 1
            break
    else:
        # Went through all non-tail messages
        split_idx = max(0, len(messages) - MIN_VERBATIM_TAIL)

    if split_idx <= 0:
        return state

    # Ensure we don't split tool-use sequences
    split_idx = _find_safe_split_point(messages, split_idx)
    if split_idx <= 0:
        return state

    # Only compact messages we haven't already compacted
    already_compacted_idx = state.get("compacted_up_to_index", 0)
    if split_idx <= already_compacted_idx:
        # Nothing new to compact; the old memory still covers these
        return state

    messages_to_compact = messages[already_compacted_idx:split_idx]
    if not messages_to_compact:
        return state

    # Build compaction prompt
    turns_text = _messages_to_text(messages_to_compact)
    existing_section = ""
    if compacted_memory:
        existing_section = (
            f"## Existing compacted memory (from previous compaction rounds):\n\n"
            f"{compacted_memory}\n\n"
            f"---\n"
        )

    user_prompt = COMPACTION_USER_PROMPT.format(
        existing_memory_section=existing_section,
        turns_text=turns_text,
    )

    # Use the compaction model tier
    compaction_model = resolve_model_for_role("compaction", model_config)

    try:
        client = create_model_client(compaction_model)
        response = client.messages.create(
            model=compaction_model,
            system=COMPACTION_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_prompt}],
            max_tokens=4096,
        )

        compacted_text = ""
        for block in response.content:
            if block.type == "text":
                compacted_text += block.text

        if not compacted_text.strip():
            logger.warning("[ChatCompactor] Compaction model returned empty output")
            return state

        # Enforce max chars
        if len(compacted_text) > MAX_COMPACTED_CHARS:
            compacted_text = compacted_text[:MAX_COMPACTED_CHARS] + "\n\n(memory truncated)"

        # Update state
        state["compacted_memory"] = compacted_text
        state["compacted_up_to_index"] = split_idx
        state["compaction_count"] = state.get("compaction_count", 0) + 1
        state["last_compacted_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        _save_compaction_state(eng_dir, state)

        logger.info(
            f"[ChatCompactor] Compacted {len(messages_to_compact)} messages "
            f"(indices {already_compacted_idx}-{split_idx}), "
            f"memory size: {len(compacted_text)} chars"
        )
        return state

    except Exception as e:
        logger.error(f"[ChatCompactor] Compaction failed: {e}")
        return state


def build_compacted_messages(
    messages: list[dict],
    compaction_state: dict,
) -> list[dict]:
    """Build the message list for the LLM, replacing compacted turns with memory.

    Full history remains in `messages` (and on disk). This function returns a
    new list where older compacted turns are replaced by a single memory block,
    and recent turns are kept verbatim.
    """
    if not compaction_state or not compaction_state.get("enabled"):
        return messages

    compacted_memory = compaction_state.get("compacted_memory")
    compacted_up_to = compaction_state.get("compacted_up_to_index", 0)

    if not compacted_memory or compacted_up_to <= 0:
        return messages

    # Clamp index to actual message count
    compacted_up_to = min(compacted_up_to, len(messages))

    # Build: memory block + verbatim tail
    memory_message = {
        "role": "user",
        "content": (
            f"[CONTEXT MEMORY — Compacted summary of earlier conversation]\n\n"
            f"{compacted_memory}\n\n"
            f"[END CONTEXT MEMORY — Recent conversation follows verbatim]"
        ),
    }
    # Need an assistant ack so the alternation stays valid
    memory_ack = {
        "role": "assistant",
        "content": [{"type": "text", "text": "Understood. I have the compacted context from our earlier conversation. Continuing with the recent messages."}],
    }

    verbatim_tail = messages[compacted_up_to:]

    return [memory_message, memory_ack] + verbatim_tail


# ---------------------------------------------------------------------------
# Public API for dashboard endpoints
# ---------------------------------------------------------------------------

def get_compaction_state(eng_dir: str) -> dict:
    """Get the current compaction state for an engagement."""
    return _load_compaction_state(eng_dir)


def set_compaction_enabled(eng_dir: str, enabled: bool) -> dict:
    """Enable or disable compaction for an engagement."""
    state = _load_compaction_state(eng_dir)
    state["enabled"] = enabled
    _save_compaction_state(eng_dir, state)
    return state


def get_compaction_info(eng_dir: str) -> dict:
    """Get compaction info suitable for the frontend."""
    state = _load_compaction_state(eng_dir)
    return {
        "enabled": state.get("enabled", False),
        "compaction_count": state.get("compaction_count", 0),
        "last_compacted_at": state.get("last_compacted_at"),
        "has_memory": bool(state.get("compacted_memory")),
        "compacted_up_to_index": state.get("compacted_up_to_index", 0),
    }

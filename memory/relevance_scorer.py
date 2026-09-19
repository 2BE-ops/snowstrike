"""Relevance-scored context pruning for agent conversation messages."""

import json
import math
import re

_FINDING_KW = re.compile(
    r"credential|password|shell|access|vulnerability|CVE-|exploit|root|admin"
    r"|token|secret|private.key|session|authenticated|reverse.shell",
    re.IGNORECASE,
)
_FAILURE_KW = re.compile(
    r"error|failed|timeout|timed.out|connection refused|no results|not found",
    re.IGNORECASE,
)


class RelevanceScorer:
    """Scores messages across recency, tool success, finding density, and task alignment."""

    W_RECENCY, W_TOOL_SUCCESS, W_FINDING, W_ALIGNMENT = 0.30, 0.15, 0.30, 0.25

    def score(self, message: dict, current_task: str, turn_index: int, total_turns: int) -> float:
        """Return a 0.0–1.0 relevance score for a single message."""
        text = self._text(message)
        r = 1.0 if total_turns <= 1 else 1.0 - math.exp(-3.0 * turn_index / (total_turns - 1))
        t = self._tool_success(message, text)
        f = self._finding_density(text)
        a = self._task_alignment(text, current_task)
        return self.W_RECENCY * r + self.W_TOOL_SUCCESS * t + self.W_FINDING * f + self.W_ALIGNMENT * a

    @staticmethod
    def _find_tool_pairs(messages: list[dict]) -> set[int]:
        """Find indices that are part of tool_use/tool_result pairs.

        These must be kept or removed together to avoid breaking the API
        message sequence.
        """
        paired: set[int] = set()
        for i, msg in enumerate(messages):
            content = msg.get("content", "")
            if isinstance(content, list):
                has_tool = any(
                    isinstance(b, dict) and b.get("type") in ("tool_use", "tool_result")
                    for b in content
                )
                if has_tool:
                    paired.add(i)
                    # Also protect the adjacent message (tool_use assistant -> tool_result user)
                    if i > 0:
                        paired.add(i - 1)
                    if i + 1 < len(messages):
                        paired.add(i + 1)
        return paired

    def prune(self, messages: list[dict], token_budget: int, current_task: str) -> list[dict]:
        """Remove lowest-scoring messages until estimated tokens <= budget.

        Never removes: index 0 (system/task message), last 2 user/assistant pairs,
        or messages that are part of tool_use/tool_result pairs (to avoid breaking
        the API message sequence).
        """
        if not messages:
            return messages
        total = len(messages)
        protect_tail = min(4, total - 1)
        tool_paired = self._find_tool_pairs(messages)
        # Score middle messages
        scored = [(i, self.score(messages[i], current_task, i, total))
                  for i in range(1, total - protect_tail)
                  if i not in tool_paired]  # Never prune tool pairs individually
        scored.sort(key=lambda x: x[1])
        keep = set(range(total))
        for idx, _ in scored:
            if self._tokens(messages, keep) <= token_budget:
                break
            keep.discard(idx)
        # Safety net: always keep first and tail
        keep.add(0)
        keep.update(range(max(1, total - protect_tail), total))
        # Ensure all tool pairs stay intact
        keep.update(tool_paired)
        return [messages[i] for i in sorted(keep)]

    # -- scoring dimensions --------------------------------------------------

    @staticmethod
    def _tool_success(message: dict, text: str) -> float:
        if message.get("role") == "assistant":
            return 0.5
        if _FAILURE_KW.search(text):
            return 0.2
        return 0.8 if len(text) > 50 else 0.5

    @staticmethod
    def _finding_density(text: str) -> float:
        if not text:
            return 0.0
        hits = len(_FINDING_KW.findall(text))
        return 1.0 if hits >= 3 else (0.6 if hits >= 1 else 0.1)

    @staticmethod
    def _task_alignment(text: str, task: str) -> float:
        if not task or not text:
            return 0.3
        words = {w.lower() for w in re.findall(r"[a-zA-Z0-9_.-]{4,}", task)}
        if not words:
            return 0.3
        tl = text.lower()
        return min(1.0, 0.2 + 0.8 * sum(1 for w in words if w in tl) / len(words))

    # -- helpers --------------------------------------------------------------

    @staticmethod
    def _text(message: dict) -> str:
        c = message.get("content", "")
        if isinstance(c, str):
            return c
        if isinstance(c, list):
            return " ".join(
                b.get("content", "") if isinstance(b, dict) and isinstance(b.get("content"), str)
                else json.dumps(b, default=str) if isinstance(b, dict) else str(b)
                for b in c
            )
        return str(c)

    @staticmethod
    def _tokens(messages: list[dict], keep: set[int]) -> int:
        chars = 0
        for i in keep:
            c = messages[i].get("content", "")
            if isinstance(c, str):
                chars += len(c)
            elif isinstance(c, list):
                chars += sum(len(json.dumps(b, default=str)) if isinstance(b, dict)
                             else len(str(b)) for b in c)
        return chars // 4

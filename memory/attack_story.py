"""
Append-only markdown narrative builder for penetration test engagements.

Produces a human-readable STORY.md that chronicles every phase, event,
and finding across the engagement lifetime.  The file is strictly
append-only so that concurrent agents never overwrite each other's
contributions.
"""

import os
import re
import hashlib
from pathlib import Path
from datetime import datetime, timezone
from filelock import FileLock


class AttackStory:
    """Append-only markdown narrative of the penetration test."""

    def __init__(self, engagement_dir: str):
        self._dir = Path(engagement_dir)
        self._story_path = self._dir / "STORY.md"
        self._lock_path = self._dir / "STORY.md.lock"
        self._lock = FileLock(str(self._lock_path), timeout=30)
        self._ensure_integrity()

    # ------------------------------------------------------------------
    # Initialization
    # ------------------------------------------------------------------

    def initialize(self, target: str, methodology: str):
        """Create (or overwrite) the story header for a new engagement."""
        self._dir.mkdir(parents=True, exist_ok=True)

        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        header = (
            f"# Penetration Test: {target}\n"
            f"\n"
            f"**Started:** {now} | **Methodology:** {methodology}\n"
            f"\n"
            f"---\n\n"
        )

        with self._lock:
            self._atomic_write(header)

    # ------------------------------------------------------------------
    # Append helpers
    # ------------------------------------------------------------------

    def add_phase_section(
        self,
        phase: str,
        agent: str,
        duration_seconds: float,
        narrative: str,
        key_findings: list,
        artifacts_count: dict,
    ):
        """Append a complete phase section to the story.

        Parameters
        ----------
        phase : str
            Phase name (e.g. "recon", "enumeration", "exploitation").
        agent : str
            Name of the agent that executed this phase.
        duration_seconds : float
            Wall-clock time the phase took.
        narrative : str
            Free-form markdown narrative of what happened.
        key_findings : list[str]
            Bullet-point findings to highlight.
        artifacts_count : dict
            Mapping of artifact type -> count, e.g.
            {"credentials": 3, "vulns": 5, "screenshots": 1}.
        """
        duration_str = self._format_duration(duration_seconds)
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        sig_raw = f"{phase}|{agent}|{narrative.strip()}|{json_safe_list(key_findings)}"
        phase_sig = hashlib.sha1(sig_raw.encode("utf-8")).hexdigest()[:16]

        lines = [
            f"## Phase: {phase}\n",
            f"\n",
            f"*Agent: {agent} | Duration: {duration_str} | Completed: {now}*\n",
            f"\n",
            f"{narrative.rstrip()}\n",
            f"\n",
        ]

        if key_findings:
            lines.append("**Key Findings:**\n\n")
            for finding in key_findings:
                lines.append(f"- {finding}\n")
            lines.append("\n")

        if artifacts_count:
            parts = [f"{count} {atype}" for atype, count in artifacts_count.items() if count]
            if parts:
                lines.append(f"**Artifacts:** {', '.join(parts)}\n\n")

        lines.append(f"<!-- phase_sig:{phase_sig} -->\n")
        lines.append("---\n\n")

        with self._lock:
            current = self.read()
            if f"<!-- phase_sig:{phase_sig} -->" in current:
                return
        self._append("".join(lines))

    def add_event(self, event: str):
        """Add a single timestamped event line."""
        now = datetime.now(timezone.utc).strftime("%H:%M:%S")
        self._append(f"> `[{now}]` {event}\n\n")

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    def read(self) -> str:
        """Read the full story markdown."""
        if not self._story_path.exists():
            return ""
        with open(self._story_path, "r", encoding="utf-8") as fh:
            return fh.read()

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _append(self, text: str):
        """Append text to the story file under a file lock."""
        with self._lock:
            existing = ""
            if self._story_path.exists():
                try:
                    existing = self._story_path.read_text(encoding="utf-8", errors="replace")
                except Exception:
                    existing = ""
            repaired = self._repair_story_content(existing)
            updated = repaired + text
            if not self._is_valid_story_markdown(updated):
                # Safe fallback: do not write malformed markdown.
                return
            self._atomic_write(updated)

    def _ensure_integrity(self):
        """Repair story file on startup if it contains broken or duplicate sections."""
        with self._lock:
            if not self._story_path.exists():
                return
            try:
                content = self._story_path.read_text(encoding="utf-8", errors="replace")
            except Exception:
                return
            repaired = self._repair_story_content(content)
            if repaired != content and self._is_valid_story_markdown(repaired):
                self._atomic_write(repaired)

    def _repair_story_content(self, content: str) -> str:
        """Repair truncated tail and dedupe duplicate phase blocks."""
        if not content:
            return content

        repaired = content.replace("\x00", "")

        # If trailing phase block is incomplete (missing section delimiter), truncate safely.
        last_phase_idx = repaired.rfind("## Phase:")
        last_sep_idx = repaired.rfind("\n---\n")
        if last_phase_idx != -1 and (last_sep_idx == -1 or last_sep_idx < last_phase_idx):
            repaired = repaired[:last_phase_idx].rstrip() + "\n\n"

        # Deduplicate phase sections by embedded signature markers.
        marker_re = re.compile(r"<!--\s*phase_sig:([a-f0-9]{16})\s*-->", re.IGNORECASE)
        seen = set()
        deduped_lines = []
        skip_until_sep = False
        for line in repaired.splitlines(keepends=True):
            marker = marker_re.search(line)
            if marker:
                sig = marker.group(1).lower()
                if sig in seen:
                    skip_until_sep = True
                    continue
                seen.add(sig)
            if skip_until_sep:
                if line.strip() == "---":
                    skip_until_sep = False
                continue
            deduped_lines.append(line)

        return "".join(deduped_lines)

    def _is_valid_story_markdown(self, content: str) -> bool:
        """Basic markdown integrity checks before atomic writes."""
        if "\x00" in content:
            return False
        if content and not content.lstrip().startswith("#"):
            return False
        return True

    def _atomic_write(self, content: str) -> None:
        """Atomically write full story content."""
        tmp_path = self._story_path.with_suffix(".tmp")
        with open(tmp_path, "w", encoding="utf-8") as fh:
            fh.write(content)
        os.replace(str(tmp_path), str(self._story_path))

    @staticmethod
    def _format_duration(seconds: float) -> str:
        """Convert seconds to a human-friendly duration string."""
        if seconds < 60:
            return f"{seconds:.0f}s"
        minutes, secs = divmod(int(seconds), 60)
        if minutes < 60:
            return f"{minutes}m {secs}s"
        hours, minutes = divmod(minutes, 60)
        return f"{hours}h {minutes}m {secs}s"


def json_safe_list(values: list) -> str:
    """Stable representation for phase signature hashing."""
    if not values:
        return "[]"
    return "|".join(str(v).strip() for v in values)

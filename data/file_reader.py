"""Read engagement files: STATE.json, STORY.md, network_map.json, raw logs."""

import json
import os
from typing import Any, Optional


class FileReader:
    """Read-only access to engagement directory files."""

    def __init__(self, engagement_dir: str):
        self.engagement_dir = engagement_dir

    def _path(self, *parts: str) -> str:
        return os.path.join(self.engagement_dir, *parts)

    def _mtime(self, *parts: str) -> float:
        path = self._path(*parts)
        try:
            return os.path.getmtime(path)
        except OSError:
            return 0.0

    def _read_json(self, *parts: str) -> Any:
        path = self._path(*parts)
        try:
            with open(path, "r") as f:
                return json.load(f)
        except (OSError, json.JSONDecodeError):
            return {}

    def _read_text(self, *parts: str) -> str:
        path = self._path(*parts)
        try:
            with open(path, "r") as f:
                return f.read()
        except OSError:
            return ""

    # ------------------------------------------------------------------
    # Public
    # ------------------------------------------------------------------

    def read_state(self) -> dict:
        return self._read_json("STATE.json")

    def read_story(self) -> str:
        return self._read_text("STORY.md")

    def read_network_map(self) -> dict:
        return self._read_json("network_map.json")

    def read_plan(self) -> dict | str | None:
        """Read attack plan (JSON preferred, MD fallback)."""
        json_path = os.path.join(self.engagement_dir, "plan.json")
        if os.path.exists(json_path):
            try:
                with open(json_path, "r") as f:
                    return json.load(f)
            except Exception:
                pass
        md_path = os.path.join(self.engagement_dir, "PLAN.md")
        if os.path.exists(md_path):
            try:
                with open(md_path, "r") as f:
                    return f.read()
            except Exception:
                pass
        return None

    def read_raw_log(self, relative_path: str, tail_lines: int = 2000) -> str:
        """Read a raw log file, optionally limiting to last N lines."""
        path = self._path(relative_path)
        # Prevent path traversal: resolved path must stay within engagement dir
        real_path = os.path.realpath(path)
        real_base = os.path.realpath(self.engagement_dir)
        if not real_path.startswith(real_base + os.sep) and real_path != real_base:
            return f"[Access denied: path escapes engagement directory]"
        if not os.path.isfile(path):
            return f"[File not found: {relative_path}]"
        try:
            with open(path, "r", errors="replace") as f:
                lines = f.readlines()
            if len(lines) > tail_lines:
                return (
                    f"[... truncated {len(lines) - tail_lines} lines ...]\n"
                    + "".join(lines[-tail_lines:])
                )
            return "".join(lines)
        except OSError as e:
            return f"[Error reading {relative_path}: {e}]"

    def list_raw_logs(self) -> list[dict]:
        """List all raw log files with metadata."""
        raw_dir = self._path("logs", "raw")
        if not os.path.isdir(raw_dir):
            return []
        logs = []
        for fname in sorted(os.listdir(raw_dir)):
            fpath = os.path.join(raw_dir, fname)
            if os.path.isfile(fpath):
                logs.append({
                    "filename": fname,
                    "path": os.path.join("logs", "raw", fname),
                    "size_bytes": os.path.getsize(fpath),
                    "modified": os.path.getmtime(fpath),
                })
        return logs

    def read_agent_conversations(self) -> list[dict]:
        """Read agent_conversations.jsonl."""
        path = self._path("logs", "agent_conversations.jsonl")
        results = []
        try:
            with open(path, "r") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            results.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue
        except OSError:
            pass
        return results

    def read_alerts(self) -> list:
        """Read alerts from alerts.json."""
        data = self._read_json("alerts.json")
        return data.get("alerts", []) if isinstance(data, dict) else []

    def get_mtimes(self) -> dict:
        """Get modification times of key files for change detection."""
        return {
            "state": self._mtime("STATE.json"),
            "story": self._mtime("STORY.md"),
            "network_map": self._mtime("network_map.json"),
            "plan": max(self._mtime("PLAN.md"), self._mtime("plan.json")),
            "alerts": self._mtime("alerts.json"),
            "live_turns": self._mtime("logs", "live_turns.jsonl"),
        }

    def read_live_turns(self, since_line: int = 0) -> list[dict]:
        """Read new live conversation turns since a given line number."""
        path = self._path("logs", "live_turns.jsonl")
        if not os.path.isfile(path):
            return []
        results = []
        try:
            with open(path, "r", errors="replace") as f:
                for i, line in enumerate(f):
                    if i < since_line:
                        continue
                    line = line.strip()
                    if line:
                        try:
                            results.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue
        except OSError:
            pass
        return results

    def count_live_turns(self) -> int:
        """Count lines in live turns file for change detection."""
        path = self._path("logs", "live_turns.jsonl")
        if not os.path.isfile(path):
            return 0
        try:
            with open(path, "r") as f:
                return sum(1 for _ in f)
        except OSError:
            return 0

    def list_loot_files(self) -> list[dict]:
        """List files in loot/ directory."""
        loot_dir = self._path("loot")
        if not os.path.isdir(loot_dir):
            return []
        files = []
        for fname in sorted(os.listdir(loot_dir)):
            fpath = os.path.join(loot_dir, fname)
            if os.path.isfile(fpath):
                files.append({
                    "filename": fname,
                    "size_bytes": os.path.getsize(fpath),
                    "modified": os.path.getmtime(fpath),
                })
        return files

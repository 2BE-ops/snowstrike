"""
Engagement session forking for SnowStrike.

Creates point-in-time snapshots of engagement state that can be forked into
independent branches, restored, or compared. Fork storage lives inside the
engagement directory at {engagement_dir}/.forks/{fork_id}/.

Forked state files: snowstrike.db, STATE.json, network_map.json,
handoff_queue.json, STORY.md.  Shared (not forked): tool binaries,
agent configs, cross-engagement memory.
"""

import hashlib
import json
import logging
import os
import shutil
import sqlite3
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

_STATE_FILES = [
    "snowstrike.db",
    "STATE.json",
    "network_map.json",
    "handoff_queue.json",
    "STORY.md",
]


@dataclass
class ForkPoint:
    """A snapshot point in the engagement timeline."""
    fork_id: str
    parent_engagement_dir: str
    fork_engagement_dir: str
    created_at: str
    iteration: int
    state_hash: str
    description: str
    metadata: dict = field(default_factory=dict)


def _compute_state_hash(engagement_dir: str) -> str:
    """Hash STATE.json content for quick comparison."""
    state_path = os.path.join(engagement_dir, "STATE.json")
    if not os.path.exists(state_path):
        return ""
    with open(state_path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()[:16]


def _checkpoint_sqlite(db_path: str) -> None:
    """Flush WAL to main database file before copying."""
    if not os.path.exists(db_path):
        return
    try:
        conn = sqlite3.connect(db_path)
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        conn.close()
    except Exception as e:
        logger.debug("WAL checkpoint failed for %s: %s", db_path, e)


class EngagementForker:
    """Creates and manages engagement forks."""

    def __init__(self, engagement_dir: str):
        self.engagement_dir = engagement_dir
        self.forks_dir = os.path.join(engagement_dir, ".forks")
        self._metadata_path = os.path.join(self.forks_dir, "forks.json")
        os.makedirs(self.forks_dir, exist_ok=True)

    def create_fork(self, description: str, iteration: int = 0,
                    metadata: Optional[dict] = None) -> ForkPoint:
        """Create an atomic fork of the current engagement state."""
        fork_id = f"fork_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{os.urandom(4).hex()}"
        fork_dir = os.path.join(self.forks_dir, fork_id)

        try:
            os.makedirs(fork_dir, exist_ok=True)

            # Checkpoint SQLite WAL before copying
            _checkpoint_sqlite(os.path.join(self.engagement_dir, "snowstrike.db"))

            # Copy the 5 mutable state files
            for filename in _STATE_FILES:
                src = os.path.join(self.engagement_dir, filename)
                if os.path.exists(src):
                    shutil.copy2(src, os.path.join(fork_dir, filename))

            state_hash = _compute_state_hash(self.engagement_dir)

            fork_point = ForkPoint(
                fork_id=fork_id,
                parent_engagement_dir=self.engagement_dir,
                fork_engagement_dir=fork_dir,
                created_at=datetime.now(timezone.utc).isoformat(),
                iteration=iteration,
                state_hash=state_hash,
                description=description,
                metadata=metadata or {},
            )

            self._save_fork_metadata(fork_point)
            logger.info("Fork created: %s — %s", fork_id, description)
            return fork_point

        except Exception:
            # Atomic cleanup on failure
            if os.path.exists(fork_dir):
                shutil.rmtree(fork_dir, ignore_errors=True)
            raise

    @staticmethod
    def _validate_fork_id(fork_id: str) -> None:
        """Reject fork IDs that could cause path traversal."""
        if not fork_id or "/" in fork_id or "\\" in fork_id or ".." in fork_id or "\x00" in fork_id:
            raise ValueError(f"Invalid fork_id: {fork_id!r}")

    def restore_fork(self, fork_id: str) -> str:
        """Restore state from a fork. Auto-backs up current state first."""
        self._validate_fork_id(fork_id)
        fork_dir = os.path.join(self.forks_dir, fork_id)
        if not os.path.isdir(fork_dir):
            raise ValueError(f"Fork {fork_id} not found")

        # Auto-backup current state
        self.create_fork(description=f"Auto-backup before restoring {fork_id}")

        # Checkpoint SQLite in the fork before copying back
        _checkpoint_sqlite(os.path.join(fork_dir, "snowstrike.db"))

        for filename in _STATE_FILES:
            src = os.path.join(fork_dir, filename)
            if os.path.exists(src):
                shutil.copy2(src, os.path.join(self.engagement_dir, filename))

        logger.info("Restored fork: %s", fork_id)
        return fork_dir

    def list_forks(self) -> list[ForkPoint]:
        """List all fork points for this engagement."""
        if not os.path.exists(self._metadata_path):
            return []
        try:
            with open(self._metadata_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return [ForkPoint(**fp) for fp in data.get("forks", [])]
        except (json.JSONDecodeError, TypeError):
            return []

    def compare_forks(self, fork_id_a: str, fork_id_b: str) -> dict:
        """Compare two forks by host/cred/vuln/shell counts."""
        def _counts(fork_dir: str) -> dict:
            state_path = os.path.join(fork_dir, "STATE.json")
            if not os.path.exists(state_path):
                return {"hosts": 0, "creds": 0, "vulns": 0, "shells": 0}
            with open(state_path, "r", encoding="utf-8") as f:
                state = json.load(f)
            access = state.get("access", {}) if isinstance(state.get("access"), dict) else {}
            return {
                "hosts": len(state.get("hosts", {})) if isinstance(state.get("hosts"), dict) else 0,
                "creds": len(state.get("credentials_summary", [])),
                "vulns": len(state.get("vulns_summary", [])),
                "shells": len(access.get("shells", [])),
            }

        self._validate_fork_id(fork_id_a)
        self._validate_fork_id(fork_id_b)
        dir_a = os.path.join(self.forks_dir, fork_id_a)
        dir_b = os.path.join(self.forks_dir, fork_id_b)
        ca, cb = _counts(dir_a), _counts(dir_b)
        return {
            "fork_a": fork_id_a, "fork_b": fork_id_b,
            **{f"{k}_a": v for k, v in ca.items()},
            **{f"{k}_b": v for k, v in cb.items()},
        }

    def _save_fork_metadata(self, fork_point: ForkPoint) -> None:
        """Append fork metadata to forks.json."""
        data = {"forks": []}
        if os.path.exists(self._metadata_path):
            try:
                with open(self._metadata_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
            except (json.JSONDecodeError, TypeError):
                data = {"forks": []}
        data.setdefault("forks", []).append(asdict(fork_point))
        with open(self._metadata_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

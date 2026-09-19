"""
Cross-engagement memory store.

Persists lessons learned across engagements in ~/.snowstrike/memory.db (SQLite).
Four memory types: technique_feedback, tool_reliability, target_patterns,
engagement_summaries. No credentials or sensitive target data are stored.
"""

import logging
import sqlite3
import threading
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

DB_PATH = Path.home() / ".snowstrike" / "memory.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS technique_feedback (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    technique TEXT NOT NULL, target_type TEXT NOT NULL,
    success_rate REAL DEFAULT 0.0, notes TEXT, last_seen TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS tool_reliability (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tool_name TEXT NOT NULL, failure_rate REAL DEFAULT 0.0,
    common_errors TEXT, workarounds TEXT, last_seen TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS target_patterns (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pattern_name TEXT NOT NULL, indicators TEXT,
    recommended_approach TEXT, confidence REAL DEFAULT 0.5, last_seen TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS engagement_summaries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id TEXT NOT NULL UNIQUE, target TEXT NOT NULL,
    methodology TEXT, duration_hours REAL, findings_count INTEGER DEFAULT 0,
    key_lessons TEXT, created_at TEXT NOT NULL);
"""


class EngagementMemory:
    """Global cross-engagement memory backed by SQLite."""

    def __init__(self, db_path: Optional[Path] = None):
        self._db_path = db_path or DB_PATH
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        # Initialize schema on the creating thread
        conn = self._conn
        conn.executescript(_SCHEMA)
        conn.commit()

    @property
    def _conn(self) -> sqlite3.Connection:
        """Return a per-thread connection (lazy-created) for thread safety."""
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(str(self._db_path), timeout=30)
            conn.row_factory = sqlite3.Row
            try:
                conn.execute("PRAGMA journal_mode=WAL")
            except sqlite3.OperationalError:
                pass
            conn.execute("PRAGMA busy_timeout=10000")
            self._local.conn = conn
        return conn

    def _now(self):
        return datetime.now(timezone.utc).isoformat()

    # --- Record helpers ---------------------------------------------------

    def record_technique(self, technique: str, target_type: str,
                         success: bool, notes: str = "") -> None:
        now = self._now()
        row = self._conn.execute(
            "SELECT id, success_rate FROM technique_feedback "
            "WHERE technique = ? AND target_type = ?",
            (technique, target_type),
        ).fetchone()
        if row:
            new_rate = row["success_rate"] * 0.7 + (1.0 if success else 0.0) * 0.3
            self._conn.execute(
                "UPDATE technique_feedback SET success_rate=?, notes=?, last_seen=? WHERE id=?",
                (new_rate, notes or row["success_rate"], now, row["id"]),
            )
        else:
            self._conn.execute(
                "INSERT INTO technique_feedback (technique,target_type,success_rate,notes,last_seen) "
                "VALUES (?,?,?,?,?)",
                (technique, target_type, 1.0 if success else 0.0, notes, now),
            )
        self._conn.commit()

    def record_tool_issue(self, tool_name: str, error_type: str,
                          workaround: str = "") -> None:
        now = self._now()
        row = self._conn.execute(
            "SELECT id, failure_rate, common_errors FROM tool_reliability WHERE tool_name=?",
            (tool_name,),
        ).fetchone()
        if row:
            new_rate = min(1.0, row["failure_rate"] * 0.7 + 0.3)
            errors = row["common_errors"] or ""
            if error_type and error_type not in errors:
                errors = f"{errors}; {error_type}" if errors else error_type
            self._conn.execute(
                "UPDATE tool_reliability SET failure_rate=?, common_errors=?, "
                "workarounds=?, last_seen=? WHERE id=?",
                (new_rate, errors, workaround or None, now, row["id"]),
            )
        else:
            self._conn.execute(
                "INSERT INTO tool_reliability (tool_name,failure_rate,common_errors,workarounds,last_seen) "
                "VALUES (?,?,?,?,?)",
                (tool_name, 1.0, error_type, workaround or None, now),
            )
        self._conn.commit()

    def record_pattern(self, pattern_name: str, indicators: str,
                       approach: str, confidence: float = 0.5) -> None:
        now = self._now()
        row = self._conn.execute(
            "SELECT id FROM target_patterns WHERE pattern_name=?", (pattern_name,),
        ).fetchone()
        if row:
            self._conn.execute(
                "UPDATE target_patterns SET indicators=?, recommended_approach=?, "
                "confidence=?, last_seen=? WHERE id=?",
                (indicators, approach, confidence, now, row["id"]),
            )
        else:
            self._conn.execute(
                "INSERT INTO target_patterns (pattern_name,indicators,recommended_approach,confidence,last_seen) "
                "VALUES (?,?,?,?,?)",
                (pattern_name, indicators, approach, confidence, now),
            )
        self._conn.commit()

    def record_engagement_summary(self, engagement_id: str, summary: dict) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO engagement_summaries "
            "(engagement_id,target,methodology,duration_hours,findings_count,key_lessons,created_at) "
            "VALUES (?,?,?,?,?,?,?)",
            (engagement_id, summary.get("target", ""), summary.get("methodology", ""),
             summary.get("duration_hours", 0.0), summary.get("findings_count", 0),
             summary.get("key_lessons", ""), self._now()),
        )
        self._conn.commit()

    # --- Query helpers ----------------------------------------------------

    def query_for_target(self, target_type: str) -> dict:
        techniques = self._conn.execute(
            "SELECT technique, success_rate, notes FROM technique_feedback "
            "WHERE target_type=? ORDER BY last_seen DESC LIMIT 20", (target_type,),
        ).fetchall()
        patterns = self._conn.execute(
            "SELECT pattern_name, indicators, recommended_approach, confidence "
            "FROM target_patterns ORDER BY last_seen DESC LIMIT 20",
        ).fetchall()
        return {"techniques": [dict(r) for r in techniques],
                "patterns": [dict(r) for r in patterns]}

    def query_tool_history(self, tool_name: str) -> dict:
        row = self._conn.execute(
            "SELECT * FROM tool_reliability WHERE tool_name=?", (tool_name,),
        ).fetchone()
        return dict(row) if row else {}

    def query_all_tool_issues(self) -> list:
        rows = self._conn.execute(
            "SELECT tool_name, failure_rate, common_errors, workarounds "
            "FROM tool_reliability WHERE failure_rate > 0.2 "
            "ORDER BY failure_rate DESC LIMIT 10",
        ).fetchall()
        return [dict(r) for r in rows]

    def query_recent_engagements(self, limit: int = 5) -> list:
        rows = self._conn.execute(
            "SELECT * FROM engagement_summaries ORDER BY created_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]

    # --- Maintenance ------------------------------------------------------

    def prune_stale(self, days: int = 30) -> int:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        deleted = 0
        for table in ("technique_feedback", "tool_reliability", "target_patterns"):
            deleted += self._conn.execute(
                f"DELETE FROM {table} WHERE last_seen < ?", (cutoff,),
            ).rowcount
        deleted += self._conn.execute(
            "DELETE FROM engagement_summaries WHERE created_at < ?", (cutoff,),
        ).rowcount
        self._conn.commit()
        return deleted

    def close(self):
        self._conn.close()


class MemoryConsolidator:
    """Periodic consolidation of cross-engagement memories.

    Called from orchestrator run_autonomous finalization.
    Operations: dedup → decay → prune → report.
    """

    def consolidate(self, store: EngagementMemory) -> dict:
        """Run the full consolidation pipeline. Return summary counts."""
        deduped = self._dedup_techniques(store) + self._dedup_tool_reliability(store)
        decayed = self._decay_stale(store)
        pruned = self._prune_low_confidence(store)
        return {"deduped": deduped, "decayed": decayed, "pruned": pruned}

    def _dedup_techniques(self, store: EngagementMemory) -> int:
        """Merge technique_feedback rows with identical (technique, target_type)."""
        conn = store._conn
        dupes = conn.execute(
            "SELECT technique, target_type FROM technique_feedback "
            "GROUP BY technique, target_type HAVING COUNT(*) > 1"
        ).fetchall()
        merged = 0
        for row in dupes:
            entries = conn.execute(
                "SELECT id, success_rate, notes, last_seen FROM technique_feedback "
                "WHERE technique = ? AND target_type = ? ORDER BY success_rate DESC",
                (row["technique"], row["target_type"]),
            ).fetchall()
            keep = entries[0]
            combined_notes = keep["notes"] or ""
            for dup in entries[1:]:
                if dup["notes"] and dup["notes"] not in combined_notes:
                    combined_notes = f"{combined_notes}; {dup['notes']}" if combined_notes else dup["notes"]
                conn.execute("DELETE FROM technique_feedback WHERE id = ?", (dup["id"],))
                merged += 1
            conn.execute(
                "UPDATE technique_feedback SET notes = ? WHERE id = ?",
                (combined_notes, keep["id"]),
            )
        conn.commit()
        return merged

    def _dedup_tool_reliability(self, store: EngagementMemory) -> int:
        """Merge tool_reliability rows with identical tool_name."""
        conn = store._conn
        dupes = conn.execute(
            "SELECT tool_name FROM tool_reliability "
            "GROUP BY tool_name HAVING COUNT(*) > 1"
        ).fetchall()
        merged = 0
        for row in dupes:
            entries = conn.execute(
                "SELECT id, failure_rate, common_errors, workarounds, last_seen "
                "FROM tool_reliability WHERE tool_name = ? "
                "ORDER BY last_seen DESC",
                (row["tool_name"],),
            ).fetchall()
            keep = entries[0]
            best_failure = max(e["failure_rate"] for e in entries)
            # Combine common_errors, dedup semicolon-separated entries
            all_errors: set[str] = set()
            all_workarounds: set[str] = set()
            for e in entries:
                if e["common_errors"]:
                    all_errors.update(
                        s.strip() for s in e["common_errors"].split(";") if s.strip()
                    )
                if e["workarounds"]:
                    all_workarounds.update(
                        s.strip() for s in e["workarounds"].split(";") if s.strip()
                    )
            for dup in entries[1:]:
                conn.execute("DELETE FROM tool_reliability WHERE id = ?", (dup["id"],))
                merged += 1
            conn.execute(
                "UPDATE tool_reliability SET failure_rate = ?, common_errors = ?, "
                "workarounds = ? WHERE id = ?",
                (best_failure, "; ".join(sorted(all_errors)),
                 "; ".join(sorted(all_workarounds)) or None, keep["id"]),
            )
        conn.commit()
        return merged

    def _decay_stale(self, store: EngagementMemory, days: int = 30) -> int:
        """Apply 20% confidence decay to entries not seen in `days`."""
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        conn = store._conn
        decayed = 0
        decayed += conn.execute(
            "UPDATE technique_feedback SET success_rate = success_rate * 0.8 "
            "WHERE last_seen < ?", (cutoff,),
        ).rowcount
        decayed += conn.execute(
            "UPDATE tool_reliability SET failure_rate = failure_rate * 0.8 "
            "WHERE last_seen < ?", (cutoff,),
        ).rowcount
        decayed += conn.execute(
            "UPDATE target_patterns SET confidence = confidence * 0.8 "
            "WHERE last_seen < ?", (cutoff,),
        ).rowcount
        conn.commit()
        return decayed

    def _prune_low_confidence(self, store: EngagementMemory,
                              threshold: float = 0.1) -> int:
        """Delete entries whose confidence/success_rate fell below threshold."""
        conn = store._conn
        pruned = 0
        pruned += conn.execute(
            "DELETE FROM technique_feedback WHERE success_rate < ?", (threshold,),
        ).rowcount
        pruned += conn.execute(
            "DELETE FROM target_patterns WHERE confidence < ?", (threshold,),
        ).rowcount
        conn.commit()
        return pruned

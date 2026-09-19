"""
SnowStrike AI v7.0 - LLM Cost Tracker

Tracks token usage and estimated USD cost per engagement, broken down by
provider and model.  Data is stored in the engagement's SQLite database
(llm_costs table) so it persists across restarts.
"""

import logging
import sqlite3
import threading
from datetime import datetime
from typing import Dict, Optional

from config import MODEL_PRICING

logger = logging.getLogger(__name__)


class CostTracker:
    """Per-engagement LLM cost tracker backed by SQLite."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._local = threading.local()
        self._ensure_table()

    # ------------------------------------------------------------------
    # Connection (reuse the same per-thread pattern as DatabaseManager)
    # ------------------------------------------------------------------

    @property
    def _conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self.db_path, check_same_thread=False, timeout=30)
            conn.row_factory = sqlite3.Row
            try:
                conn.execute("PRAGMA journal_mode=WAL")
            except sqlite3.OperationalError:
                pass  # Read-only DB
            conn.execute("PRAGMA busy_timeout=10000")
            self._local.conn = conn
        return conn

    def _ensure_table(self) -> None:
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS llm_costs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL,
                model TEXT NOT NULL,
                provider TEXT NOT NULL,
                agent TEXT NOT NULL DEFAULT '',
                input_tokens INTEGER NOT NULL DEFAULT 0,
                output_tokens INTEGER NOT NULL DEFAULT 0,
                cost_usd REAL NOT NULL DEFAULT 0.0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        self._conn.commit()

    # ------------------------------------------------------------------
    # Record
    # ------------------------------------------------------------------

    def record(
        self,
        engagement_id: int,
        model: str,
        input_tokens: int,
        output_tokens: int,
        agent: str = "",
    ) -> float:
        """Record a single LLM call and return its estimated cost in USD."""
        pricing = MODEL_PRICING.get(model, {})
        provider = pricing.get("provider", "unknown")
        input_rate = pricing.get("input", 0.0)
        output_rate = pricing.get("output", 0.0)

        cost = (input_tokens * input_rate + output_tokens * output_rate) / 1_000_000

        self._conn.execute(
            """INSERT INTO llm_costs
               (engagement_id, model, provider, agent, input_tokens, output_tokens, cost_usd)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (engagement_id, model, provider, agent, input_tokens, output_tokens, cost),
        )
        self._conn.commit()

        logger.debug(
            "[CostTracker] %s | %s | in=%d out=%d | $%.6f",
            agent or "orchestrator", model, input_tokens, output_tokens, cost,
        )
        return cost

    # ------------------------------------------------------------------
    # Query
    # ------------------------------------------------------------------

    def get_summary(self, engagement_id: int) -> Dict:
        """Return cost summary for an engagement."""
        rows = self._conn.execute(
            """SELECT
                   provider,
                   model,
                   SUM(input_tokens)  AS input_tokens,
                   SUM(output_tokens) AS output_tokens,
                   SUM(cost_usd)      AS cost_usd,
                   COUNT(*)           AS calls
               FROM llm_costs
               WHERE engagement_id = ?
               GROUP BY provider, model
               ORDER BY cost_usd DESC""",
            (engagement_id,),
        ).fetchall()

        total_usd = 0.0
        total_tokens = 0
        by_provider: Dict[str, dict] = {}

        for row in rows:
            provider = row["provider"]
            tokens = row["input_tokens"] + row["output_tokens"]
            total_usd += row["cost_usd"]
            total_tokens += tokens

            if provider not in by_provider:
                by_provider[provider] = {
                    "cost_usd": 0.0,
                    "input_tokens": 0,
                    "output_tokens": 0,
                    "calls": 0,
                    "models": {},
                }
            p = by_provider[provider]
            p["cost_usd"] += row["cost_usd"]
            p["input_tokens"] += row["input_tokens"]
            p["output_tokens"] += row["output_tokens"]
            p["calls"] += row["calls"]
            p["models"][row["model"]] = {
                "cost_usd": round(row["cost_usd"], 6),
                "input_tokens": row["input_tokens"],
                "output_tokens": row["output_tokens"],
                "calls": row["calls"],
            }

        # Round provider totals
        for p in by_provider.values():
            p["cost_usd"] = round(p["cost_usd"], 6)

        return {
            "engagement_id": engagement_id,
            "total_usd": round(total_usd, 6),
            "total_tokens": total_tokens,
            "by_provider": by_provider,
        }

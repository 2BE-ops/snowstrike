"""Read-only SQLite access to engagement databases. Never writes."""

import json
import os
import sqlite3
from typing import Any, Optional


class DBReader:
    """Read-only access to an engagement's SQLite database."""

    def __init__(self, db_path: str, busy_timeout: int = 5000):
        self.db_path = db_path
        self.busy_timeout = busy_timeout

    def _connect(self) -> sqlite3.Connection:
        # Use read-write connection so SQLite can create WAL/SHM files if needed.
        # A WAL-mode DB requires write access even for SELECT queries.
        conn = sqlite3.connect(self.db_path, timeout=self.busy_timeout / 1000)
        conn.row_factory = sqlite3.Row
        conn.execute(f"PRAGMA busy_timeout={int(self.busy_timeout)}")
        return conn

    def _query(self, sql: str, params: tuple = ()) -> list[dict]:
        conn = self._connect()
        try:
            rows = conn.execute(sql, params).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def _query_one(self, sql: str, params: tuple = ()) -> Optional[dict]:
        rows = self._query(sql, params)
        return rows[0] if rows else None

    # ------------------------------------------------------------------
    # Engagement
    # ------------------------------------------------------------------

    def get_engagement(self) -> Optional[dict]:
        return self._query_one(
            "SELECT * FROM engagement ORDER BY id DESC LIMIT 1"
        )

    # ------------------------------------------------------------------
    # Hosts & Services
    # ------------------------------------------------------------------

    def get_hosts(self, engagement_id: int) -> list[dict]:
        hosts = self._query(
            "SELECT * FROM hosts WHERE engagement_id = ? ORDER BY first_seen",
            (engagement_id,),
        )
        for h in hosts:
            h["services"] = self._query(
                "SELECT * FROM services WHERE host_id = ? ORDER BY port",
                (h["id"],),
            )
        return hosts

    # ------------------------------------------------------------------
    # Vulnerabilities
    # ------------------------------------------------------------------

    def get_vulnerabilities(
        self, engagement_id: int, severity: str = ""
    ) -> list[dict]:
        sql = """
            SELECT v.*, h.ip as host_ip, h.hostname
            FROM vulnerabilities v
            LEFT JOIN hosts h ON v.host_id = h.id
            WHERE v.engagement_id = ?
        """
        params: list = [engagement_id]
        if severity:
            sql += " AND LOWER(v.severity) = LOWER(?)"
            params.append(severity)
        sql += " ORDER BY v.created_at DESC"
        return self._query(sql, tuple(params))

    # ------------------------------------------------------------------
    # Credentials
    # ------------------------------------------------------------------

    def get_credentials(self, engagement_id: int) -> list[dict]:
        creds = self._query(
            """SELECT c.*, h.ip as host_ip
               FROM credentials c
               LEFT JOIN hosts h ON c.host_id = h.id
               WHERE c.engagement_id = ?
               ORDER BY c.created_at DESC""",
            (engagement_id,),
        )
        # Mask sensitive fields
        for c in creds:
            if c.get("password_clear"):
                c["password_clear"] = "***REDACTED***"
            if c.get("password_hash") and len(c["password_hash"]) > 12:
                c["password_hash"] = c["password_hash"][:12] + "..."
        return creds

    # ------------------------------------------------------------------
    # Loot
    # ------------------------------------------------------------------

    def get_loot(self, engagement_id: int) -> list[dict]:
        return self._query(
            "SELECT * FROM loot WHERE engagement_id = ? ORDER BY created_at DESC",
            (engagement_id,),
        )

    # ------------------------------------------------------------------
    # Tool Executions
    # ------------------------------------------------------------------

    def get_tool_executions(
        self,
        engagement_id: int,
        agent: str = "",
        since_id: int = 0,
    ) -> list[dict]:
        sql = "SELECT * FROM tool_executions WHERE engagement_id = ?"
        params: list = [engagement_id]
        if agent:
            sql += " AND agent = ?"
            params.append(agent)
        if since_id:
            sql += " AND id > ?"
            params.append(since_id)
        sql += " ORDER BY created_at ASC"
        return self._query(sql, tuple(params))

    def get_agents(self, engagement_id: int) -> list[str]:
        rows = self._query(
            "SELECT DISTINCT agent FROM tool_executions WHERE engagement_id = ? ORDER BY agent",
            (engagement_id,),
        )
        return [r["agent"] for r in rows]

    # ------------------------------------------------------------------
    # Network edges
    # ------------------------------------------------------------------

    def get_network_edges(self, engagement_id: int) -> list[dict]:
        return self._query(
            """SELECT ne.*,
                      sh.ip as source_ip, th.ip as target_ip
               FROM network_edges ne
               LEFT JOIN hosts sh ON ne.source_host_id = sh.id
               LEFT JOIN hosts th ON ne.target_host_id = th.id
               WHERE ne.engagement_id = ?
               ORDER BY ne.created_at""",
            (engagement_id,),
        )

    # ------------------------------------------------------------------
    # Timeline (unified events for replay)
    # ------------------------------------------------------------------

    def get_timeline(self, engagement_id: int) -> list[dict]:
        """Build a unified, chronologically sorted event stream."""
        sql = """
            SELECT created_at as ts, 'tool_execution' as event_type,
                   agent, tool_name as label,
                   compacted_summary as detail,
                   success, id as ref_id
            FROM tool_executions WHERE engagement_id = ?

            UNION ALL

            SELECT first_seen as ts, 'host_discovered' as event_type,
                   'system' as agent, ip as label,
                   COALESCE(hostname, '') || ' ' || COALESCE(os, '') as detail,
                   1 as success, id as ref_id
            FROM hosts WHERE engagement_id = ?

            UNION ALL

            SELECT created_at as ts, 'vuln_found' as event_type,
                   COALESCE(agent_source, 'unknown') as agent, title as label,
                   severity || ': ' || COALESCE(description, '') as detail,
                   1 as success, id as ref_id
            FROM vulnerabilities WHERE engagement_id = ?

            UNION ALL

            SELECT created_at as ts, 'credential_found' as event_type,
                   COALESCE(source, 'unknown') as agent,
                   COALESCE(username, '?') as label,
                   credential_type as detail,
                   1 as success, id as ref_id
            FROM credentials WHERE engagement_id = ?

            UNION ALL

            SELECT created_at as ts, 'network_edge' as event_type,
                   relationship as agent, COALESCE(label, relationship) as label,
                   '' as detail,
                   1 as success, id as ref_id
            FROM network_edges WHERE engagement_id = ?

            ORDER BY ts ASC
        """
        params = (engagement_id,) * 5
        return self._query(sql, params)

    # ------------------------------------------------------------------
    # Counts (for SSE change detection)
    # ------------------------------------------------------------------

    def get_counts(self, engagement_id: int) -> dict:
        """Quick counts for change detection."""
        counts = {}
        for table in ["hosts", "services", "vulnerabilities", "credentials", "loot", "tool_executions", "network_edges"]:
            if table == "services":
                row = self._query_one(
                    f"SELECT COUNT(*) as cnt FROM {table} s JOIN hosts h ON s.host_id = h.id WHERE h.engagement_id = ?",
                    (engagement_id,),
                )
            else:
                row = self._query_one(
                    f"SELECT COUNT(*) as cnt FROM {table} WHERE engagement_id = ?",
                    (engagement_id,),
                )
            counts[table] = row["cnt"] if row else 0
        return counts

    def get_agent_activity(self, engagement_id: int, limit: int = 200) -> list:
        """Get recent agent tool executions with details."""
        rows = self._query(
            """SELECT id, agent, tool_name, command, compacted_summary,
                      success, duration_seconds, created_at, parameters
               FROM tool_executions
               WHERE engagement_id = ?
               ORDER BY created_at DESC
               LIMIT ?""",
            (engagement_id, limit),
        )
        return [dict(r) for r in rows]

    def get_stats(self, engagement_id: int) -> dict:
        """Get aggregate statistics for the engagement."""
        host_count = self._query_one("SELECT COUNT(*) as c FROM hosts WHERE engagement_id = ?", (engagement_id,))
        svc_count = self._query_one("SELECT COUNT(*) as c FROM services s JOIN hosts h ON s.host_id = h.id WHERE h.engagement_id = ?", (engagement_id,))
        vuln_counts = self._query(
            """SELECT severity, COUNT(*) as c FROM vulnerabilities
               WHERE engagement_id = ? GROUP BY severity""",
            (engagement_id,),
        )
        cred_count = self._query_one("SELECT COUNT(*) as c FROM credentials WHERE engagement_id = ?", (engagement_id,))
        tool_count = self._query_one("SELECT COUNT(*) as c FROM tool_executions WHERE engagement_id = ?", (engagement_id,))

        # Agent stats
        agent_stats = self._query(
            """SELECT agent, COUNT(*) as tool_runs,
                      SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) as successes,
                      ROUND(SUM(duration_seconds), 1) as total_duration
               FROM tool_executions WHERE engagement_id = ?
               GROUP BY agent""",
            (engagement_id,),
        )

        severity_map = {r["severity"]: r["c"] for r in vuln_counts}

        return {
            "hosts": host_count["c"] if host_count else 0,
            "services": svc_count["c"] if svc_count else 0,
            "vulnerabilities": {
                "critical": severity_map.get("critical", 0),
                "high": severity_map.get("high", 0),
                "medium": severity_map.get("medium", 0),
                "low": severity_map.get("low", 0),
                "info": severity_map.get("info", 0),
                "total": sum(severity_map.values()),
            },
            "credentials": cred_count["c"] if cred_count else 0,
            "tool_executions": tool_count["c"] if tool_count else 0,
            "agents": [dict(r) for r in agent_stats],
        }

    # ------------------------------------------------------------------
    # Phase 5: Failure observability
    # ------------------------------------------------------------------

    def get_tool_executions_filtered(
        self,
        engagement_id: int,
        agent: str = "",
        tool_name: str = "",
        outcome_kind: str = "",
        failure_category: str = "",
        since_id: int = 0,
        run_id: str = "",
        agent_turn: int | None = None,
    ) -> list[dict]:
        """Get tool executions with rich filtering by outcome/failure category."""
        sql = "SELECT * FROM tool_executions WHERE engagement_id = ?"
        params: list = [engagement_id]
        if agent:
            sql += " AND agent = ?"
            params.append(agent)
        if tool_name:
            sql += " AND tool_name = ?"
            params.append(tool_name)
        if outcome_kind:
            sql += " AND outcome_kind = ?"
            params.append(outcome_kind)
        if failure_category:
            sql += " AND failure_category = ?"
            params.append(failure_category)
        if since_id:
            sql += " AND id > ?"
            params.append(since_id)
        if run_id:
            sql += " AND run_id = ?"
            params.append(run_id)
        if agent_turn is not None:
            sql += " AND agent_turn = ?"
            params.append(agent_turn)
        sql += " ORDER BY created_at ASC"
        return self._query(sql, tuple(params))

    def get_failure_summary(self, engagement_id: int) -> dict:
        """Get failure breakdown by category, tool, and agent.

        Returns metrics for 'top failing wrappers', 'top timeout producers',
        and 'useful but marked failed' counts.
        """
        # By outcome kind
        by_outcome = self._query(
            """SELECT COALESCE(outcome_kind, '') as outcome_kind, COUNT(*) as count
               FROM tool_executions WHERE engagement_id = ?
               GROUP BY outcome_kind ORDER BY count DESC""",
            (engagement_id,),
        )
        # Top failing tools
        top_failing_tools = self._query(
            """SELECT tool_name, COUNT(*) as failures
               FROM tool_executions
               WHERE engagement_id = ? AND success = 0
               GROUP BY tool_name ORDER BY failures DESC LIMIT 10""",
            (engagement_id,),
        )
        # Top timeout-producing tools
        top_timeout_tools = self._query(
            """SELECT tool_name, COUNT(*) as timeouts
               FROM tool_executions
               WHERE engagement_id = ? AND timed_out = 1
               GROUP BY tool_name ORDER BY timeouts DESC LIMIT 10""",
            (engagement_id,),
        )
        # Useful output but marked failed (partial_success)
        useful_but_failed = self._query(
            """SELECT tool_name, COUNT(*) as count
               FROM tool_executions
               WHERE engagement_id = ? AND outcome_kind = 'partial_success'
               GROUP BY tool_name ORDER BY count DESC""",
            (engagement_id,),
        )
        # By failure category (for synthetic/pre-exec failures)
        by_failure_category = self._query(
            """SELECT COALESCE(failure_category, '') as category, COUNT(*) as count
               FROM tool_executions
               WHERE engagement_id = ? AND failure_category != ''
               GROUP BY failure_category ORDER BY count DESC""",
            (engagement_id,),
        )
        # By failure phase
        by_failure_phase = self._query(
            """SELECT COALESCE(failure_phase, '') as phase, COUNT(*) as count
               FROM tool_executions
               WHERE engagement_id = ? AND failure_phase != ''
               GROUP BY failure_phase ORDER BY count DESC""",
            (engagement_id,),
        )
        synthetic_by_outcome = self._query(
            """SELECT COALESCE(outcome_kind, '') as outcome_kind, COUNT(*) as count
               FROM tool_executions
               WHERE engagement_id = ? AND failure_phase != ''
               GROUP BY outcome_kind ORDER BY count DESC""",
            (engagement_id,),
        )
        # Wrapper errors specifically
        wrapper_errors = self._query(
            """SELECT tool_name, COUNT(*) as count
               FROM tool_executions
               WHERE engagement_id = ? AND outcome_kind = 'wrapper_error'
               GROUP BY tool_name ORDER BY count DESC""",
            (engagement_id,),
        )
        return {
            "by_outcome": [dict(r) for r in by_outcome],
            "top_failing_tools": [dict(r) for r in top_failing_tools],
            "top_timeout_tools": [dict(r) for r in top_timeout_tools],
            "useful_but_failed": [dict(r) for r in useful_but_failed],
            "by_failure_category": [dict(r) for r in by_failure_category],
            "by_failure_phase": [dict(r) for r in by_failure_phase],
            "synthetic_by_outcome": [dict(r) for r in synthetic_by_outcome],
            "wrapper_errors": [dict(r) for r in wrapper_errors],
        }

    def get_outcome_stats(self, engagement_id: int) -> dict:
        """Quick summary of outcome distribution for overview cards."""
        total = self._query_one(
            "SELECT COUNT(*) as c FROM tool_executions WHERE engagement_id = ?",
            (engagement_id,),
        )
        success = self._query_one(
            "SELECT COUNT(*) as c FROM tool_executions WHERE engagement_id = ? AND outcome_kind = 'success'",
            (engagement_id,),
        )
        partial = self._query_one(
            "SELECT COUNT(*) as c FROM tool_executions WHERE engagement_id = ? AND outcome_kind = 'partial_success'",
            (engagement_id,),
        )
        wrapper = self._query_one(
            "SELECT COUNT(*) as c FROM tool_executions WHERE engagement_id = ? AND outcome_kind = 'wrapper_error'",
            (engagement_id,),
        )
        empty = self._query_one(
            "SELECT COUNT(*) as c FROM tool_executions WHERE engagement_id = ? AND outcome_kind = 'empty_result'",
            (engagement_id,),
        )
        timeout = self._query_one(
            "SELECT COUNT(*) as c FROM tool_executions WHERE engagement_id = ? AND timed_out = 1",
            (engagement_id,),
        )
        pre_execution_failures = self._query_one(
            "SELECT COUNT(*) as c FROM tool_executions WHERE engagement_id = ? AND failure_phase != ''",
            (engagement_id,),
        )
        skipped = self._query_one(
            """SELECT COUNT(*) as c FROM tool_executions
               WHERE engagement_id = ? AND (outcome_kind = 'skipped' OR failure_phase != '')""",
            (engagement_id,),
        )
        return {
            "total": total["c"] if total else 0,
            "success": success["c"] if success else 0,
            "partial_success": partial["c"] if partial else 0,
            "wrapper_error": wrapper["c"] if wrapper else 0,
            "empty_result": empty["c"] if empty else 0,
            "timeout": timeout["c"] if timeout else 0,
            "pre_execution_failures": pre_execution_failures["c"] if pre_execution_failures else 0,
            "skipped": skipped["c"] if skipped else 0,
        }

    def get_max_tool_execution_id(self, engagement_id: int) -> int:
        row = self._query_one(
            "SELECT MAX(id) as max_id FROM tool_executions WHERE engagement_id = ?",
            (engagement_id,),
        )
        return row["max_id"] if row and row["max_id"] else 0

    def get_agent_dispatch_summary(self, engagement_id: int) -> dict:
        """Per-agent breakdown of tool executions for experiment analytics.

        Returns:
            {agent_type: {dispatches, tools_used, success_count, failure_count,
                          success_rate, total_duration}}
        """
        rows = self._query(
            """SELECT agent,
                      COUNT(*) as dispatches,
                      COUNT(DISTINCT tool_name) as tools_used,
                      SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) as success_count,
                      SUM(CASE WHEN success = 0 THEN 1 ELSE 0 END) as failure_count,
                      ROUND(SUM(duration_seconds), 1) as total_duration
               FROM tool_executions
               WHERE engagement_id = ?
               GROUP BY agent
               ORDER BY dispatches DESC""",
            (engagement_id,),
        )
        result = {}
        for r in rows:
            agent = r["agent"]
            dispatches = r["dispatches"]
            success = r["success_count"]
            result[agent] = {
                "dispatches": dispatches,
                "tools_used": r["tools_used"],
                "success_count": success,
                "failure_count": r["failure_count"],
                "success_rate": round(success / dispatches * 100, 1) if dispatches else 0,
                "total_duration": r["total_duration"] or 0,
            }
        return result

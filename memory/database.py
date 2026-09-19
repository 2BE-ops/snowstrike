"""
SnowStrike AI v7.0 - SQLite Database Manager

Manages persistent storage for engagements, hosts, services, vulnerabilities,
credentials, loot, tool execution logs, and network topology edges.
"""

import json
import os
import sqlite3
import threading
from datetime import datetime
from typing import Any, Dict, List, Optional


class DatabaseManager:
    """Thread-safe SQLite database manager with WAL mode and automatic schema creation."""

    def __init__(self, engagement_dir: str):
        os.makedirs(engagement_dir, exist_ok=True)
        self.db_path = os.path.join(engagement_dir, "snowstrike.db")
        self._local = threading.local()
        self._init_schema()
        # Restrict database file permissions (contains credentials and findings)
        try:
            os.chmod(self.db_path, 0o600)
        except OSError:
            pass

    # ------------------------------------------------------------------
    # Connection helpers
    # ------------------------------------------------------------------

    @property
    def _conn(self) -> sqlite3.Connection:
        """Return a per-thread connection (lazy-created)."""
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self.db_path, check_same_thread=False, timeout=30)
            conn.row_factory = sqlite3.Row
            try:
                conn.execute("PRAGMA journal_mode=WAL")
            except sqlite3.OperationalError:
                pass  # Read-only DB — skip WAL mode
            conn.execute("PRAGMA busy_timeout=10000")
            conn.execute("PRAGMA foreign_keys=ON")
            self._local.conn = conn
        return conn

    def close(self) -> None:
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            conn.close()
            self._local.conn = None

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _init_schema(self) -> None:
        schema = """
        CREATE TABLE IF NOT EXISTS engagement (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            target TEXT NOT NULL,
            scope TEXT,
            out_of_scope TEXT,
            methodology TEXT DEFAULT 'standard',
            status TEXT DEFAULT 'active',
            group_name TEXT DEFAULT 'Default',
            tags TEXT DEFAULT '[]',
            model_config TEXT DEFAULT '{}',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS hosts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER REFERENCES engagement(id),
            ip TEXT NOT NULL,
            hostname TEXT,
            os TEXT,
            status TEXT DEFAULT 'up',
            first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            notes TEXT,
            UNIQUE(engagement_id, ip)
        );

        CREATE TABLE IF NOT EXISTS services (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id INTEGER REFERENCES hosts(id),
            port INTEGER NOT NULL,
            protocol TEXT DEFAULT 'tcp',
            service_name TEXT,
            version TEXT,
            banner TEXT,
            state TEXT DEFAULT 'open',
            metadata TEXT,
            UNIQUE(host_id, port, protocol)
        );

        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER REFERENCES engagement(id),
            host_id INTEGER REFERENCES hosts(id),
            service_id INTEGER REFERENCES services(id),
            title TEXT NOT NULL,
            severity TEXT NOT NULL,
            cvss_score REAL,
            cve_id TEXT,
            description TEXT,
            evidence TEXT,
            remediation TEXT,
            tool_source TEXT,
            agent_source TEXT,
            confirmed BOOLEAN DEFAULT FALSE,
            exploitable BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            metadata TEXT
        );

        CREATE TABLE IF NOT EXISTS credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER REFERENCES engagement(id),
            host_id INTEGER REFERENCES hosts(id),
            service_id INTEGER REFERENCES services(id),
            username TEXT,
            password_hash TEXT,
            password_clear TEXT,
            credential_type TEXT,
            source TEXT,
            confirmed BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS loot (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER REFERENCES engagement(id),
            host_id INTEGER REFERENCES hosts(id),
            loot_type TEXT,
            file_path TEXT,
            description TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS tool_executions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER REFERENCES engagement(id),
            agent TEXT NOT NULL,
            tool_name TEXT NOT NULL,
            command TEXT NOT NULL,
            parameters TEXT,
            raw_output_path TEXT,
            compacted_summary TEXT NOT NULL,
            success BOOLEAN,
            duration_seconds REAL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS network_edges (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER REFERENCES engagement(id),
            source_host_id INTEGER REFERENCES hosts(id),
            target_host_id INTEGER REFERENCES hosts(id),
            relationship TEXT,
            label TEXT,
            metadata TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

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
        """
        conn = self._conn
        try:
            conn.executescript(schema)
            conn.commit()
        except sqlite3.OperationalError:
            pass  # Read-only DB — schema already exists
        
        try:
            conn.execute("ALTER TABLE engagement ADD COLUMN group_name TEXT DEFAULT 'Default'")
        except sqlite3.OperationalError:
            pass
        try:
            conn.execute("ALTER TABLE engagement ADD COLUMN tags TEXT DEFAULT '[]'")
        except sqlite3.OperationalError:
            pass
        try:
            conn.execute("ALTER TABLE engagement ADD COLUMN model_config TEXT DEFAULT '{}'")
        except sqlite3.OperationalError:
            pass
        # Phase 2: richer outcome columns on tool_executions
        for col_def in [
            "outcome_kind TEXT DEFAULT ''",
            "signal_detected BOOLEAN DEFAULT 0",
            "return_code INTEGER",
            "timed_out BOOLEAN DEFAULT 0",
            "failure_phase TEXT DEFAULT ''",
            "failure_category TEXT DEFAULT ''",
            "stderr_preview TEXT DEFAULT ''",
            "run_id TEXT DEFAULT ''",
            "agent_turn INTEGER",
        ]:
            try:
                conn.execute(f"ALTER TABLE tool_executions ADD COLUMN {col_def}")
            except sqlite3.OperationalError:
                pass  # Column already exists

        # Flow execution tracking tables
        conn.execute("""
        CREATE TABLE IF NOT EXISTS flow_executions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER,
            flow_id TEXT NOT NULL,
            flow_name TEXT NOT NULL,
            trigger_type TEXT DEFAULT 'manual',
            trigger_source TEXT DEFAULT '',
            inputs TEXT DEFAULT '{}',
            status TEXT DEFAULT 'running',
            started_at TEXT,
            completed_at TEXT,
            duration_seconds REAL DEFAULT 0,
            total_cost_usd REAL DEFAULT 0,
            error TEXT DEFAULT '',
            workspace TEXT DEFAULT '',
            created_at TEXT DEFAULT (datetime('now'))
        )
        """)
        conn.execute("""
        CREATE TABLE IF NOT EXISTS flow_step_executions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            flow_execution_id INTEGER REFERENCES flow_executions(id),
            step_id TEXT NOT NULL,
            step_type TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            started_at TEXT,
            completed_at TEXT,
            duration_seconds REAL DEFAULT 0,
            cost_usd REAL DEFAULT 0,
            output_summary TEXT DEFAULT '',
            error TEXT DEFAULT ''
        )
        """)
        conn.commit()

    # ------------------------------------------------------------------
    # JSON helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _serialize(value: Any) -> Optional[str]:
        if value is None:
            return None
        return json.dumps(value) if not isinstance(value, str) else value

    @staticmethod
    def _deserialize(value: Optional[str]) -> Any:
        if value is None:
            return None
        try:
            return json.loads(value)
        except (json.JSONDecodeError, TypeError):
            return value

    @staticmethod
    def _encode_sensitive(value: str) -> str:
        """Base64-encode a sensitive value for storage obfuscation."""
        if not value:
            return value
        import base64
        return base64.b64encode(value.encode('utf-8')).decode('utf-8')

    @staticmethod
    def _decode_sensitive(value: str) -> str:
        """Decode a base64-encoded sensitive value."""
        if not value:
            return value
        import base64
        try:
            return base64.b64decode(value.encode('utf-8')).decode('utf-8')
        except Exception:
            return value  # Return as-is if not encoded

    @staticmethod
    def _row_to_dict(row: Optional[sqlite3.Row]) -> Optional[Dict]:
        if row is None:
            return None
        return dict(row)

    def _rows_to_list(self, rows: List[sqlite3.Row]) -> List[Dict]:
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Engagement CRUD
    # ------------------------------------------------------------------

    def create_engagement(
        self,
        name: str,
        target: str,
        scope=None,
        out_of_scope=None,
        methodology: str = "standard",
    ) -> int:
        cur = self._conn.execute(
            """INSERT INTO engagement (name, target, scope, out_of_scope, methodology)
               VALUES (?, ?, ?, ?, ?)""",
            (name, target, self._serialize(scope), self._serialize(out_of_scope), methodology),
        )
        self._conn.commit()
        return cur.lastrowid

    def get_engagement(self, engagement_id: int) -> Optional[Dict]:
        row = self._conn.execute(
            "SELECT * FROM engagement WHERE id = ?", (engagement_id,)
        ).fetchone()
        return self._row_to_dict(row)

    def update_engagement_status(self, engagement_id: int, status: str) -> None:
        self._conn.execute(
            """UPDATE engagement SET status = ?, updated_at = CURRENT_TIMESTAMP
               WHERE id = ?""",
            (status, engagement_id),
        )
        self._conn.commit()

    def update_engagement_metadata(self, engagement_id: int, group_name: str, tags: list) -> None:
        self._conn.execute(
            """UPDATE engagement SET group_name = ?, tags = ?, updated_at = CURRENT_TIMESTAMP
               WHERE id = ?""",
            (group_name, self._serialize(tags), engagement_id),
        )
        self._conn.commit()

    def get_model_config(self, engagement_id: int) -> Dict:
        """Get per-engagement model configuration. Returns dict mapping role -> model_id."""
        row = self._conn.execute(
            "SELECT model_config FROM engagement WHERE id = ?", (engagement_id,)
        ).fetchone()
        if row and row["model_config"]:
            try:
                return json.loads(row["model_config"])
            except (json.JSONDecodeError, TypeError):
                pass
        return {}

    def update_model_config(self, engagement_id: int, model_config: Dict) -> None:
        """Update per-engagement model configuration."""
        self._conn.execute(
            """UPDATE engagement SET model_config = ?, updated_at = CURRENT_TIMESTAMP
               WHERE id = ?""",
            (json.dumps(model_config), engagement_id),
        )
        self._conn.commit()

    # ------------------------------------------------------------------
    # Hosts (upsert)
    # ------------------------------------------------------------------

    def upsert_host(
        self,
        engagement_id: int,
        ip: str,
        hostname: Optional[str] = None,
        os: Optional[str] = None,
        status: str = "up",
        notes: Optional[str] = None,
    ) -> int:
        self._conn.execute(
            """INSERT INTO hosts (engagement_id, ip, hostname, os, status, notes)
               VALUES (?, ?, ?, ?, ?, ?)
               ON CONFLICT(engagement_id, ip) DO UPDATE SET
                   hostname = COALESCE(excluded.hostname, hosts.hostname),
                   os = COALESCE(excluded.os, hosts.os),
                   status = excluded.status,
                   notes = COALESCE(excluded.notes, hosts.notes),
                   last_seen = CURRENT_TIMESTAMP""",
            (engagement_id, ip, hostname, os, status, notes),
        )
        self._conn.commit()
        # Always query for the actual ID (lastrowid is unreliable with ON CONFLICT)
        row = self._conn.execute(
            "SELECT id FROM hosts WHERE engagement_id = ? AND ip = ?",
            (engagement_id, ip),
        ).fetchone()
        return row["id"]

    def get_hosts(self, engagement_id: int) -> List[Dict]:
        rows = self._conn.execute(
            "SELECT * FROM hosts WHERE engagement_id = ? ORDER BY ip",
            (engagement_id,),
        ).fetchall()
        return self._rows_to_list(rows)

    # ------------------------------------------------------------------
    # Services (upsert)
    # ------------------------------------------------------------------

    def upsert_service(
        self,
        host_id: int,
        port: int,
        protocol: str = "tcp",
        service_name: Optional[str] = None,
        version: Optional[str] = None,
        banner: Optional[str] = None,
        state: str = "open",
        metadata: Optional[Any] = None,
    ) -> int:
        meta_json = self._serialize(metadata)
        cur = self._conn.execute(
            """INSERT INTO services (host_id, port, protocol, service_name, version, banner, state, metadata)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(host_id, port, protocol) DO UPDATE SET
                   service_name = COALESCE(excluded.service_name, services.service_name),
                   version = COALESCE(excluded.version, services.version),
                   banner = COALESCE(excluded.banner, services.banner),
                   state = excluded.state,
                   metadata = COALESCE(excluded.metadata, services.metadata)""",
            (host_id, port, protocol, service_name, version, banner, state, meta_json),
        )
        self._conn.commit()
        if cur.lastrowid:
            return cur.lastrowid
        row = self._conn.execute(
            "SELECT id FROM services WHERE host_id = ? AND port = ? AND protocol = ?",
            (host_id, port, protocol),
        ).fetchone()
        return row["id"]

    def get_services(self, host_id: int) -> List[Dict]:
        rows = self._conn.execute(
            "SELECT * FROM services WHERE host_id = ? ORDER BY port",
            (host_id,),
        ).fetchall()
        results = self._rows_to_list(rows)
        for r in results:
            r["metadata"] = self._deserialize(r.get("metadata"))
        return results

    # ------------------------------------------------------------------
    # Vulnerabilities
    # ------------------------------------------------------------------

    def add_vulnerability(
        self,
        engagement_id: int,
        host_id: int,
        service_id: Optional[int],
        title: str,
        severity: str,
        cvss_score: Optional[float] = None,
        cve_id: Optional[str] = None,
        description: Optional[str] = None,
        evidence: Optional[str] = None,
        remediation: Optional[str] = None,
        tool_source: Optional[str] = None,
        agent_source: Optional[str] = None,
        confirmed: bool = False,
        exploitable: bool = False,
        metadata: Optional[Any] = None,
    ) -> int:
        meta_json = self._serialize(metadata)
        cur = self._conn.execute(
            """INSERT INTO vulnerabilities
               (engagement_id, host_id, service_id, title, severity, cvss_score,
                cve_id, description, evidence, remediation, tool_source, agent_source,
                confirmed, exploitable, metadata)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                engagement_id, host_id, service_id, title, severity, cvss_score,
                cve_id, description, evidence, remediation, tool_source, agent_source,
                confirmed, exploitable, meta_json,
            ),
        )
        self._conn.commit()
        return cur.lastrowid

    # ------------------------------------------------------------------
    # Credentials
    # ------------------------------------------------------------------

    def add_credential(
        self,
        engagement_id: int,
        host_id: Optional[int] = None,
        service_id: Optional[int] = None,
        username: Optional[str] = None,
        password_hash: Optional[str] = None,
        password_clear: Optional[str] = None,
        credential_type: Optional[str] = None,
        source: Optional[str] = None,
        confirmed: bool = False,
    ) -> int:
        # Encode cleartext password before storage to prevent casual exposure in DB dumps
        encoded_password = self._encode_sensitive(password_clear) if password_clear else password_clear
        cur = self._conn.execute(
            """INSERT INTO credentials
               (engagement_id, host_id, service_id, username, password_hash,
                password_clear, credential_type, source, confirmed)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                engagement_id, host_id, service_id, username, password_hash,
                encoded_password, credential_type, source, confirmed,
            ),
        )
        self._conn.commit()
        return cur.lastrowid

    def query_credentials(self, engagement_id: int, redact: bool = True) -> List[Dict]:
        """Query credentials for an engagement.

        Args:
            engagement_id: Engagement to query.
            redact: If True (default), replace password_clear with '[REDACTED]'.
                    Useful for logging and non-privileged access.
                    If False, decode the base64-obfuscated password_clear value.
        """
        rows = self._conn.execute(
            """SELECT c.*, h.ip AS host_ip, s.port AS service_port
               FROM credentials c
               LEFT JOIN hosts h ON c.host_id = h.id
               LEFT JOIN services s ON c.service_id = s.id
               WHERE c.engagement_id = ?
               ORDER BY c.created_at DESC""",
            (engagement_id,),
        ).fetchall()
        results = self._rows_to_list(rows)
        for r in results:
            if redact:
                if r.get("password_clear"):
                    r["password_clear"] = "[REDACTED]"
            else:
                if r.get("password_clear"):
                    r["password_clear"] = self._decode_sensitive(r["password_clear"])
        return results

    # ------------------------------------------------------------------
    # Loot
    # ------------------------------------------------------------------

    def add_loot(
        self,
        engagement_id: int,
        host_id: Optional[int] = None,
        loot_type: Optional[str] = None,
        file_path: Optional[str] = None,
        description: Optional[str] = None,
    ) -> int:
        cur = self._conn.execute(
            """INSERT INTO loot (engagement_id, host_id, loot_type, file_path, description)
               VALUES (?, ?, ?, ?, ?)""",
            (engagement_id, host_id, loot_type, file_path, description),
        )
        self._conn.commit()
        return cur.lastrowid

    # ------------------------------------------------------------------
    # Tool Executions
    # ------------------------------------------------------------------

    def log_tool_execution(
        self,
        engagement_id: int,
        agent: str,
        tool_name: str,
        command: str,
        parameters: Optional[Any] = None,
        raw_output_path: Optional[str] = None,
        compacted_summary: str = "",
        success: Optional[bool] = None,
        duration: Optional[float] = None,
        outcome_kind: str = "",
        signal_detected: bool = False,
        return_code: Optional[int] = None,
        timed_out: bool = False,
        failure_phase: str = "",
        failure_category: str = "",
        stderr_preview: str = "",
        run_id: str = "",
        agent_turn: Optional[int] = None,
    ) -> int:
        params_json = self._serialize(parameters)
        cur = self._conn.execute(
            """INSERT INTO tool_executions
               (engagement_id, agent, tool_name, command, parameters,
                raw_output_path, compacted_summary, success, duration_seconds,
                outcome_kind, signal_detected, return_code, timed_out,
                failure_phase, failure_category, stderr_preview, run_id, agent_turn)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                engagement_id, agent, tool_name, command, params_json,
                raw_output_path, compacted_summary, success, duration,
                outcome_kind, signal_detected, return_code, timed_out,
                failure_phase, failure_category, stderr_preview[:500] if stderr_preview else "",
                run_id, agent_turn,
            ),
        )
        self._conn.commit()
        return cur.lastrowid

    def get_tool_executions(
        self,
        engagement_id: int,
        agent: Optional[str] = None,
        limit: int = 50,
    ) -> List[Dict]:
        if agent:
            rows = self._conn.execute(
                """SELECT * FROM tool_executions
                   WHERE engagement_id = ? AND agent = ?
                   ORDER BY created_at DESC LIMIT ?""",
                (engagement_id, agent, limit),
            ).fetchall()
        else:
            rows = self._conn.execute(
                """SELECT * FROM tool_executions
                   WHERE engagement_id = ?
                   ORDER BY created_at DESC LIMIT ?""",
                (engagement_id, limit),
            ).fetchall()
        results = self._rows_to_list(rows)
        for r in results:
            r["parameters"] = self._deserialize(r.get("parameters"))
        return results

    def find_duplicate_execution(
        self,
        engagement_id: int,
        tool_name: str,
        command: str,
        parameters: Optional[Any] = None,
    ) -> Optional[Dict]:
        """Check if a tool was already run successfully with the same or similar args.

        Returns the matching prior execution dict, or None if no duplicate found.

        Matching strategy (ordered by strictness):
        1. Exact command match (same tool + same args string)
        2. Normalized command match (sorted args, stripped whitespace)
        3. Target overlap match (same tool + same target IP/URL)
        """
        # 1. Exact command match (fastest — indexed)
        rows = self._conn.execute(
            """SELECT * FROM tool_executions
               WHERE engagement_id = ? AND tool_name = ? AND command = ? AND success = 1
               ORDER BY created_at DESC LIMIT 1""",
            (engagement_id, tool_name, command),
        ).fetchall()
        if rows:
            result = self._rows_to_list(rows)[0]
            result["parameters"] = self._deserialize(result.get("parameters"))
            result["_match_type"] = "exact"
            return result

        # 2. Normalized command match (handles arg reordering)
        def _normalize_cmd(cmd: str) -> str:
            parts = cmd.split()
            if parts:
                binary = parts[0]
                args = sorted(parts[1:])
                return f"{binary} {' '.join(args)}"
            return cmd

        normalized = _normalize_cmd(command)
        all_rows = self._conn.execute(
            """SELECT * FROM tool_executions
               WHERE engagement_id = ? AND tool_name = ? AND success = 1
               ORDER BY created_at DESC LIMIT 20""",
            (engagement_id, tool_name),
        ).fetchall()

        for row in self._rows_to_list(all_rows):
            prior_cmd = row.get("command", "")
            if _normalize_cmd(prior_cmd) == normalized:
                row["parameters"] = self._deserialize(row.get("parameters"))
                row["_match_type"] = "normalized"
                return row

        # 3. Target overlap — same tool on same target (for scan tools)
        if parameters and isinstance(parameters, dict):
            target = (
                parameters.get("target")
                or parameters.get("url")
                or parameters.get("host")
                or parameters.get("ip")
                or ""
            )
            if target:
                for row in self._rows_to_list(all_rows):
                    prior_params = self._deserialize(row.get("parameters"))
                    if isinstance(prior_params, dict):
                        prior_target = (
                            prior_params.get("target")
                            or prior_params.get("url")
                            or prior_params.get("host")
                            or prior_params.get("ip")
                            or ""
                        )
                        if prior_target and prior_target == target:
                            row["parameters"] = prior_params
                            row["_match_type"] = "target_overlap"
                            return row

        return None

    # ------------------------------------------------------------------
    # Network Edges
    # ------------------------------------------------------------------

    def add_network_edge(
        self,
        engagement_id: int,
        source_host_id: int,
        target_host_id: int,
        relationship: Optional[str] = None,
        label: Optional[str] = None,
        metadata: Optional[Any] = None,
    ) -> int:
        meta_json = self._serialize(metadata)
        cur = self._conn.execute(
            """INSERT INTO network_edges
               (engagement_id, source_host_id, target_host_id, relationship, label, metadata)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (engagement_id, source_host_id, target_host_id, relationship, label, meta_json),
        )
        self._conn.commit()
        return cur.lastrowid

    def get_network_edges(self, engagement_id: int) -> List[Dict]:
        rows = self._conn.execute(
            """SELECT ne.*,
                      sh.ip AS source_ip, sh.hostname AS source_hostname,
                      th.ip AS target_ip, th.hostname AS target_hostname
               FROM network_edges ne
               LEFT JOIN hosts sh ON ne.source_host_id = sh.id
               LEFT JOIN hosts th ON ne.target_host_id = th.id
               WHERE ne.engagement_id = ?
               ORDER BY ne.created_at""",
            (engagement_id,),
        ).fetchall()
        results = self._rows_to_list(rows)
        for r in results:
            r["metadata"] = self._deserialize(r.get("metadata"))
        return results

    # ------------------------------------------------------------------
    # Flow Executions
    # ------------------------------------------------------------------

    def log_flow_execution(
        self,
        engagement_id: int,
        flow_id: str,
        flow_name: str,
        trigger_type: str = "manual",
        trigger_source: str = "",
        inputs: Optional[Any] = None,
        status: str = "running",
        started_at: str = "",
        completed_at: str = "",
        duration_seconds: float = 0,
        total_cost_usd: float = 0,
        error: str = "",
        workspace: str = "",
    ) -> int:
        inputs_json = self._serialize(inputs)
        cur = self._conn.execute(
            """INSERT INTO flow_executions
               (engagement_id, flow_id, flow_name, trigger_type, trigger_source,
                inputs, status, started_at, completed_at, duration_seconds,
                total_cost_usd, error, workspace)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                engagement_id, flow_id, flow_name, trigger_type, trigger_source,
                inputs_json, status, started_at, completed_at, duration_seconds,
                total_cost_usd, error, workspace,
            ),
        )
        self._conn.commit()
        return cur.lastrowid

    def update_flow_execution(
        self, flow_db_id: int, status: str, completed_at: str = "",
        duration_seconds: float = 0, total_cost_usd: float = 0, error: str = "",
    ) -> None:
        self._conn.execute(
            """UPDATE flow_executions
               SET status=?, completed_at=?, duration_seconds=?, total_cost_usd=?, error=?
               WHERE id=?""",
            (status, completed_at, duration_seconds, total_cost_usd, error, flow_db_id),
        )
        self._conn.commit()

    def log_flow_step(
        self,
        flow_execution_id: int,
        step_id: str,
        step_type: str,
        status: str = "pending",
        started_at: str = "",
        completed_at: str = "",
        duration_seconds: float = 0,
        cost_usd: float = 0,
        output_summary: str = "",
        error: str = "",
    ) -> int:
        cur = self._conn.execute(
            """INSERT INTO flow_step_executions
               (flow_execution_id, step_id, step_type, status, started_at,
                completed_at, duration_seconds, cost_usd, output_summary, error)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                flow_execution_id, step_id, step_type, status, started_at,
                completed_at, duration_seconds, cost_usd,
                output_summary[:2000] if output_summary else "", error,
            ),
        )
        self._conn.commit()
        return cur.lastrowid

    def get_flow_executions(
        self, engagement_id: int, limit: int = 50,
    ) -> List[Dict]:
        rows = self._conn.execute(
            """SELECT * FROM flow_executions
               WHERE engagement_id = ?
               ORDER BY created_at DESC LIMIT ?""",
            (engagement_id, limit),
        ).fetchall()
        results = self._rows_to_list(rows)
        for r in results:
            r["inputs"] = self._deserialize(r.get("inputs"))
        return results

    # ------------------------------------------------------------------
    # Query / Search
    # ------------------------------------------------------------------

    def query_findings(
        self,
        engagement_id: int,
        severity: Optional[str] = None,
        host: Optional[str] = None,
        finding_type: Optional[str] = None,
    ) -> List[Dict]:
        """Query vulnerabilities with optional filters.

        Args:
            engagement_id: Engagement to query.
            severity: Filter by severity level (critical, high, medium, low, info).
            host: Filter by host IP address.
            finding_type: Reserved for future use (e.g. 'vuln', 'misconfig').

        Returns:
            List of vulnerability dicts enriched with host/service info.
        """
        query = """
            SELECT v.*, h.ip AS host_ip, h.hostname,
                   s.port AS service_port, s.protocol AS service_protocol,
                   s.service_name
            FROM vulnerabilities v
            LEFT JOIN hosts h ON v.host_id = h.id
            LEFT JOIN services s ON v.service_id = s.id
            WHERE v.engagement_id = ?
        """
        params: list = [engagement_id]

        if severity:
            query += " AND LOWER(v.severity) = LOWER(?)"
            params.append(severity)

        if host:
            query += " AND h.ip = ?"
            params.append(host)

        query += " ORDER BY v.cvss_score DESC, v.created_at DESC"

        rows = self._conn.execute(query, params).fetchall()
        results = self._rows_to_list(rows)
        for r in results:
            r["metadata"] = self._deserialize(r.get("metadata"))
        return results

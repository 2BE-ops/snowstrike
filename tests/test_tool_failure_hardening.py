import sys
import types
import sqlite3


anthropic_stub = types.ModuleType("anthropic")
anthropic_stub.APIError = Exception
anthropic_stub.APIConnectionError = Exception
anthropic_stub.RateLimitError = Exception
sys.modules.setdefault("anthropic", anthropic_stub)

from agents.base_agent import BaseAgent
from data.db_reader import DBReader
from tools.executor import OutcomeKind, ToolResult


class _FakeAgent(BaseAgent):
    agent_name = "Test Agent"
    agent_type = "recon"

    def execute(self, task):
        raise NotImplementedError


class _DummySharedState:
    def __init__(self, state):
        self._state = state
        self.sections = {"tool_quarantines": {}}
        self.appended = []
        self.updated = []

    def read(self):
        return self._state

    def read_section(self, key: str):
        if key in self.sections:
            return self.sections[key]
        raise KeyError(key)

    def update_section(self, key: str, value):
        self.sections[key] = value
        self.updated.append((key, value))

    def append_to_list(self, key: str, item):
        self.appended.append((key, item))


class _DummyNetworkMap:
    def add_service(self, **kwargs):
        return None

    def add_web_app(self, **kwargs):
        return None


class _DummyHandoffQueue:
    def __init__(self):
        self.posts = []

    def post(self, item):
        self.posts.append(item)


class _DummyDB:
    def __init__(self, executions):
        self._executions = executions

    def get_tool_executions(self, engagement_id, limit=100, agent=None):
        return list(self._executions)[:limit]


class _RecordingDB(_DummyDB):
    def __init__(self, executions=None):
        super().__init__(executions or [])
        self.logged = []

    def log_tool_execution(self, **kwargs):
        self.logged.append(kwargs)
        return len(self.logged)


def _make_agent(state=None):
    agent = _FakeAgent.__new__(_FakeAgent)
    agent.agent_name = "Test Agent"
    agent.agent_type = "recon"
    agent.engagement_id = 1
    agent.engagement_dir = "/tmp"
    agent.shared_state = _DummySharedState(
        state
        or {
            "engagement": {
                "target": "10.129.24.121",
                "scope": ["10.129.24.121"],
                "out_of_scope": [],
            }
        }
    )
    agent.network_map = _DummyNetworkMap()
    agent.handoff_queue = _DummyHandoffQueue()
    agent._auto_persisted_discoveries = set()
    agent._tool_no_signal_runs = {}
    agent._no_signal_guard_tools = {"feroxbuster_scan", "nmap_scan"}
    agent._tool_cumulative_usage = {}
    agent._tool_cumulative_ceilings = {}
    agent._agent_tool_time_used = 0.0
    agent._agent_tool_budget = 1800.0
    agent._current_turn_number = 0
    agent.db = _DummyDB([])
    return agent


def test_clamp_timeout_ignores_infinite_tool_budget():
    timeout = BaseAgent._clamp_timeout_to_budget(
        effective_timeout=120,
        remaining_agent_budget=600,
        remaining_tool_budget=float("inf"),
    )
    assert timeout == 120


def test_generic_command_quarantine_is_scoped_to_wrapper():
    agent = _make_agent()

    agent._maybe_quarantine_tool(
        "generic_command",
        "--- STDERR ---\nusage: debug_exploit.py [-h]\ndebug_exploit.py: error: unrecognized arguments: -P",
        outcome_kind="wrapper_error",
        tool_input={"command": 'python3 /tmp/debug_exploit.py -u http://ftp.wingdata.htb -P ""'},
    )

    reason_same_wrapper = agent._get_quarantined_tool_reason(
        "generic_command",
        {"command": 'python3 /tmp/debug_exploit.py -u http://ftp.wingdata.htb -c "whoami"'},
    )
    reason_other_command = agent._get_quarantined_tool_reason(
        "generic_command",
        {"command": 'echo "test to see if generic_command works"'},
    )

    quarantine_keys = set(agent.shared_state.sections["tool_quarantines"].keys())
    assert "generic_command" not in quarantine_keys
    assert "deterministic wrapper_error" in reason_same_wrapper
    assert reason_other_command == ""


def test_query_tool_history_surfaces_failure_phase_and_category():
    agent = _make_agent()
    agent.db = _DummyDB([
        {
            "agent": "Recon Agent",
            "tool_name": "rustscan_scan",
            "success": False,
            "duration_seconds": 0.0,
            "compacted_summary": "Error executing rustscan_scan: cannot convert float infinity to integer",
            "outcome_kind": "internal_failure",
            "failure_phase": "agent_loop",
            "failure_category": "internal_tool_exception",
        }
    ])

    history = agent._handle_query_tool_history({"tool_filter": "rustscan", "limit": 5})

    assert "[INTERNAL_FAILURE]" in history
    assert "phase=agent_loop" in history
    assert "category=internal_tool_exception" in history


def test_synthetic_outcome_mapping_distinguishes_pre_execution_failures():
    assert BaseAgent._map_synthetic_outcome_kind("compat_check", "incompatible_binary", "") == "compatibility_block"
    assert BaseAgent._map_synthetic_outcome_kind("budget_check", "tool_ceiling_exceeded", "") == "budget_block"
    assert BaseAgent._map_synthetic_outcome_kind("dedup_check", "dedup_skip", "") == "dedup_block"
    assert BaseAgent._map_synthetic_outcome_kind("quarantine_check", "tool_quarantined", "") == "quarantine_block"
    assert BaseAgent._map_synthetic_outcome_kind("build_command", "command_build_failure", "") == "build_failure"
    assert BaseAgent._map_synthetic_outcome_kind("agent_loop", "internal_tool_exception", "") == "internal_failure"
    assert BaseAgent._map_synthetic_outcome_kind("", "", "[BUDGET_EXCEEDED] nmap: cumulative runtime 300s has reached the 300s ceiling.") == "budget_block"


def test_log_synthetic_execution_persists_mapped_outcome_kind():
    agent = _make_agent()
    agent.db = _RecordingDB()

    agent._log_synthetic_execution(
        "nmap_scan",
        "budget_check",
        "tool_ceiling_exceeded",
        "[BUDGET_EXCEEDED] nmap_scan: cumulative runtime 300s has reached the 300s ceiling.",
    )
    agent._log_synthetic_execution(
        "rustscan_scan",
        "agent_loop",
        "internal_tool_exception",
        "Error executing rustscan_scan: cannot convert float infinity to integer",
    )

    assert agent.db.logged[0]["outcome_kind"] == "budget_block"
    assert agent.db.logged[1]["outcome_kind"] == "internal_failure"


def test_outcome_summary_surfaces_new_synthetic_outcomes(tmp_path):
    db_path = tmp_path / "tool_execs.sqlite"
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            """CREATE TABLE tool_executions (
                   id INTEGER PRIMARY KEY AUTOINCREMENT,
                   engagement_id INTEGER,
                   agent TEXT,
                   tool_name TEXT,
                   command TEXT,
                   parameters TEXT,
                   raw_output_path TEXT,
                   compacted_summary TEXT,
                   success INTEGER,
                   duration_seconds REAL,
                   outcome_kind TEXT,
                   signal_detected INTEGER,
                   return_code INTEGER,
                   timed_out INTEGER,
                   failure_phase TEXT,
                   failure_category TEXT,
                   stderr_preview TEXT,
                   run_id TEXT,
                   agent_turn INTEGER,
                   created_at TEXT DEFAULT CURRENT_TIMESTAMP
               )"""
        )
        rows = [
            (1, "Recon Agent", "nmap_scan", "", "", "", "ok", 1, 1.2, "success", 1, 0, 0, "", "", "", "", None),
            (1, "Recon Agent", "rustscan_scan", "", "", "", "budget hit", 0, 0.0, "budget_block", 0, None, 0, "budget_check", "tool_ceiling_exceeded", "", "", None),
            (1, "Recon Agent", "ffuf_scan", "", "", "", "unsupported", 0, 0.0, "compatibility_block", 0, None, 0, "compat_check", "incompatible_binary", "", "", None),
            (1, "Recon Agent", "httpx_probe", "", "", "", "duplicate", 0, 0.0, "dedup_block", 0, None, 0, "dedup_check", "dedup_skip", "", "", None),
            (1, "Recon Agent", "feroxbuster_scan", "", "", "", "internal", 0, 0.0, "internal_failure", 0, None, 0, "agent_loop", "internal_tool_exception", "", "", None),
        ]
        conn.executemany(
            """INSERT INTO tool_executions
               (engagement_id, agent, tool_name, command, parameters, raw_output_path,
                compacted_summary, success, duration_seconds, outcome_kind, signal_detected,
                return_code, timed_out, failure_phase, failure_category, stderr_preview,
                run_id, agent_turn)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            rows,
        )
        conn.commit()
    finally:
        conn.close()

    reader = DBReader(str(db_path))
    summary = reader.get_failure_summary(1)
    stats = reader.get_outcome_stats(1)

    synthetic_counts = {row["outcome_kind"]: row["count"] for row in summary["synthetic_by_outcome"]}
    assert synthetic_counts == {
        "budget_block": 1,
        "compatibility_block": 1,
        "dedup_block": 1,
        "internal_failure": 1,
    }
    assert stats["pre_execution_failures"] == 4
    assert stats["skipped"] == 4


def test_high_signal_discovery_drops_out_of_scope_hosts():
    agent = _make_agent()

    agent._capture_high_signal_discovery(
        tool_name="generic_command",
        tool_input={"command": "curl -s https://github.com/4m3rr0r"},
        command_display="curl -s https://github.com/4m3rr0r",
        raw_output="anonymous access enabled\nloginok.html\nhttps://github.com/4m3rr0r",
    )

    assert agent.shared_state.appended == []
    assert agent.shared_state.updated == []
    assert agent.handoff_queue.posts == []


def test_no_signal_counter_uses_structured_outcomes():
    agent = _make_agent()

    agent._update_no_signal_counter(
        "feroxbuster_scan",
        raw_output="no results",
        success=True,
        outcome_kind="empty_result",
        signal_detected=False,
    )
    assert agent._tool_no_signal_runs["feroxbuster_scan"] == 1

    agent._update_no_signal_counter(
        "feroxbuster_scan",
        raw_output="200 GET /admin",
        success=False,
        outcome_kind="partial_success",
        signal_detected=True,
    )
    assert agent._tool_no_signal_runs["feroxbuster_scan"] == 0


def test_executor_does_not_treat_documentation_words_as_signal():
    result = ToolResult(
        tool_name="generic_command",
        command="cat README.md",
        stdout=(
            "This documentation explains how the tool found a vulnerable target.\n"
            "The example file shows a password parameter and an endpoint path.\n"
        ),
        stderr="",
        return_code=0,
        duration_seconds=0.1,
        success=True,
    )

    assert result.signal_detected is False
    assert result.outcome_kind == OutcomeKind.SUCCESS.value


def test_connection_timed_out_is_not_target_refused():
    result = ToolResult(
        tool_name="httpx",
        command="httpx http://10.0.0.1:9999",
        stdout="",
        stderr="connection timed out",
        return_code=1,
        duration_seconds=2.0,
        success=False,
    )

    assert result.outcome_kind == OutcomeKind.EMPTY_RESULT.value

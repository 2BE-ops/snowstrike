import sys
import types


anthropic_stub = types.ModuleType("anthropic")
anthropic_stub.APIError = Exception
sys.modules.setdefault("anthropic", anthropic_stub)

from agents.orchestrator import OrchestratorAgent


class _DummySharedState:
    def __init__(self, state):
        self._state = state

    def read(self):
        return self._state


class _DummyDb:
    def __init__(self, findings=None):
        self._findings = findings or []

    def query_findings(self, engagement_id):
        return list(self._findings)


def _make_orchestrator(state, findings=None):
    orchestrator = OrchestratorAgent.__new__(OrchestratorAgent)
    orchestrator.shared_state = _DummySharedState(state)
    orchestrator.db = _DummyDb(findings)
    orchestrator.engagement_id = 1
    return orchestrator


def test_attack_chain_objective_requires_strong_evidence():
    orchestrator = _make_orchestrator({
        "authenticated_access": [],
        "credentials_summary": [],
        "vulns_summary": [],
    })

    allowed = orchestrator._objective_has_required_evidence(
        "Identify the intended vulnerability or attack chain"
    )

    assert allowed is False


def test_attack_chain_objective_allows_authenticated_access():
    orchestrator = _make_orchestrator({
        "authenticated_access": [{"host": "ftp.wingdata.htb", "access_level": "anonymous"}],
        "credentials_summary": [],
        "vulns_summary": [],
    })

    allowed = orchestrator._objective_has_required_evidence(
        "Identify the intended vulnerability or attack chain"
    )

    assert allowed is True

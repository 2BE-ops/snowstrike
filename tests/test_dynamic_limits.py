import sys
import types


anthropic_stub = types.ModuleType("anthropic")
anthropic_stub.APIError = Exception
anthropic_stub.APIConnectionError = Exception
anthropic_stub.RateLimitError = Exception
sys.modules.setdefault("anthropic", anthropic_stub)

from agents.base_agent import BaseAgent
from agents.orchestrator import OrchestratorAgent


class _FakeAgent(BaseAgent):
    agent_name = "test"
    agent_type = "recon"

    def execute(self, task):
        raise NotImplementedError


class _DummySharedState:
    def __init__(self, state):
        self._state = state

    def read(self):
        return self._state


def _make_agent(model: str, max_turns: int = 30):
    agent = _FakeAgent.__new__(_FakeAgent)
    agent.model = model
    agent.max_turns = max_turns
    return agent


def test_agent_turn_budget_scales_down_under_context_pressure():
    agent = _make_agent("gpt-5", max_turns=30)
    turns = agent._resolve_dynamic_turn_limit(45_000)
    assert turns < 30


def test_agent_turn_budget_scales_up_for_roomy_model():
    agent = _make_agent("gpt-4.1", max_turns=30)
    turns = agent._resolve_dynamic_turn_limit(20_000)
    assert turns > 30


def _make_orchestrator(model: str, system_prompt: str, brief_text: str, state: dict):
    orchestrator = OrchestratorAgent.__new__(OrchestratorAgent)
    orchestrator.orchestrator_model = model
    orchestrator.system_prompt = system_prompt
    orchestrator.shared_state = _DummySharedState(state)
    orchestrator._build_intelligence_brief = lambda iteration, max_iterations: brief_text
    return orchestrator


def test_orchestrator_budget_scales_down_for_tight_context():
    orch = _make_orchestrator(
        model="gpt-5",
        system_prompt="A" * 40_000,
        brief_text="B" * 80_000,
        state={},
    )
    budget = orch._resolve_dynamic_iteration_budget()
    assert budget < 30


def test_orchestrator_budget_scales_up_for_large_context_and_complexity():
    orch = _make_orchestrator(
        model="gpt-4.1",
        system_prompt="A" * 4_000,
        brief_text="B" * 8_000,
        state={
            "hosts": {"10.0.0.1": {}, "10.0.0.2": {}},
            "vulns_summary": [{"severity": "high"}],
            "credentials_summary": [{"username": "a"}],
            "web_apps": {"app.internal": {}},
            "authenticated_access": [{"host": "app.internal"}],
        },
    )
    budget = orch._resolve_dynamic_iteration_budget()
    assert budget > 30

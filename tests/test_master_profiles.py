"""Tests for the master profile system."""

import os
import shutil
import tempfile
from pathlib import Path

import pytest

# Patch config paths before importing the module
import config
_ORIG_PROJECT_ROOT = config.PROJECT_ROOT
_ORIG_AGENTS_PROMPTS = config.AGENTS_PROMPTS_DIR


@pytest.fixture
def tmproot(tmp_path):
    """Create a temporary project root with stub prompt files."""
    # Create agents/prompts with stub files
    prompts_dir = tmp_path / "agents" / "prompts"
    prompts_dir.mkdir(parents=True)
    for name in ["orchestrator", "recon", "webapp", "attack", "browser",
                  "cloud", "binary_re", "forensics", "osint", "reporting"]:
        (prompts_dir / f"{name}.md").write_text(f"# {name} prompt\nTest prompt for {name}.")

    # Monkeypatch config paths
    config.PROJECT_ROOT = tmp_path
    config.AGENTS_PROMPTS_DIR = prompts_dir

    import profiles.master_profile_manager as mpm_mod
    mpm_mod.AGENTS_PROMPTS_DIR = prompts_dir  # rebind module-level copy (import-order safety)
    mpm_mod.MASTER_PROFILES_DIR = tmp_path / "engagements" / "presets" / "master_profiles"
    mpm_mod.PROMPTS_PRESETS_DIR = tmp_path / "engagements" / "presets" / "prompts"
    mpm_mod.MODELS_PRESETS_DIR = tmp_path / "engagements" / "presets" / "models"
    mpm_mod.RUN_HISTORY_DIR = tmp_path / "engagements" / "presets" / "run_history"

    import profiles.model_config_manager as mcm_mod
    mcm_mod.MODELS_DIR = mpm_mod.MODELS_PRESETS_DIR

    yield tmp_path

    # Restore
    config.PROJECT_ROOT = _ORIG_PROJECT_ROOT
    config.AGENTS_PROMPTS_DIR = _ORIG_AGENTS_PROMPTS
    import profiles.master_profile_manager as _mpm_restore
    _mpm_restore.AGENTS_PROMPTS_DIR = _ORIG_AGENTS_PROMPTS


@pytest.fixture
def mpm(tmproot):
    from profiles.master_profile_manager import MasterProfileManager
    import profiles.master_profile_manager as mpm_mod
    mgr = MasterProfileManager(
        master_dir=mpm_mod.MASTER_PROFILES_DIR,
        prompts_dir=mpm_mod.PROMPTS_PRESETS_DIR,
        models_dir=mpm_mod.MODELS_PRESETS_DIR,
    )
    mgr.history_dir = mpm_mod.RUN_HISTORY_DIR
    mgr.history_dir.mkdir(parents=True, exist_ok=True)
    return mgr


@pytest.fixture
def mcm(tmproot):
    from profiles.model_config_manager import ModelConfigManager
    import profiles.master_profile_manager as mpm_mod
    return ModelConfigManager(models_dir=mpm_mod.MODELS_PRESETS_DIR)


class TestPromptProfiles:
    def test_bootstrap_default(self, mpm):
        dp = mpm.ensure_default_prompt_profile()
        assert dp.is_dir()
        assert (dp / "orchestrator.md").exists()
        assert (dp / "binary_re.md").exists()
        assert (dp / "preset.yaml").exists()

    def test_list_prompt_profiles(self, mpm):
        mpm.ensure_default_prompt_profile()
        profiles = mpm.list_prompt_profiles()
        assert len(profiles) == 1
        assert profiles[0]["name"] == "default"
        assert profiles[0]["prompt_count"] == 10

    def test_create_prompt_profile(self, mpm):
        mpm.ensure_default_prompt_profile()
        result = mpm.create_prompt_profile("test1", "Test profile", tags=["t1"])
        assert result["name"] == "test1"
        profiles = mpm.list_prompt_profiles()
        assert len(profiles) == 2

    def test_duplicate_prompt_profile(self, mpm):
        mpm.ensure_default_prompt_profile()
        mpm.create_prompt_profile("src", "Source")
        result = mpm.duplicate_prompt_profile("src", "copy")
        assert result["name"] == "copy"

    def test_delete_prompt_profile(self, mpm):
        mpm.ensure_default_prompt_profile()
        mpm.create_prompt_profile("todelete")
        assert mpm.delete_prompt_profile("todelete")
        assert not mpm.delete_prompt_profile("nonexistent")

    def test_cannot_delete_default(self, mpm):
        mpm.ensure_default_prompt_profile()
        with pytest.raises(ValueError, match="Cannot delete"):
            mpm.delete_prompt_profile("default")

    def test_get_agent_prompt(self, mpm):
        mpm.ensure_default_prompt_profile()
        content = mpm.get_agent_prompt("default", "orchestrator")
        assert "orchestrator" in content.lower()

    def test_get_agent_prompt_binary(self, mpm):
        """The binary agent maps to binary_re.md."""
        mpm.ensure_default_prompt_profile()
        content = mpm.get_agent_prompt("default", "binary")
        assert content is not None
        assert "binary_re" in content.lower()

    def test_save_agent_prompt(self, mpm):
        mpm.ensure_default_prompt_profile()
        mpm.save_agent_prompt("default", "recon", "# Custom recon\nNew content.")
        content = mpm.get_agent_prompt("default", "recon")
        assert "New content" in content

    def test_rename_prompt_profile(self, mpm):
        mpm.ensure_default_prompt_profile()
        mpm.create_prompt_profile("old_name")
        assert mpm.rename_prompt_profile("old_name", "new_name")
        assert mpm.get_prompt_profile("new_name") is not None
        assert mpm.get_prompt_profile("old_name") is None


class TestMasterProfiles:
    def test_create_and_list(self, mpm, mcm):
        mpm.ensure_default_prompt_profile()
        mcm.save_config("mc1", {"orchestrator": "claude-opus-4-20250514"})
        mpm.save_master_profile("mp1", "mc1", "default", "Test master")
        profiles = mpm.list_master_profiles()
        assert len(profiles) == 1
        assert profiles[0]["name"] == "mp1"

    def test_resolve(self, mpm, mcm):
        mpm.ensure_default_prompt_profile()
        mcm.save_config("mc1", {"orchestrator": "opus", "recon": "sonnet"})
        mpm.save_master_profile("mp1", "mc1", "default",
                                agent_overrides={"recon": {"model": "gpt5"}})
        resolved = mpm.resolve("mp1")
        assert resolved["effective_models"]["orchestrator"] == "opus"
        assert resolved["effective_models"]["recon"] == "gpt5"  # overridden
        assert resolved["effective_prompts"]["orchestrator"] == "default"

    def test_resolve_prompt_override(self, mpm, mcm):
        mpm.ensure_default_prompt_profile()
        mpm.create_prompt_profile("custom")
        mcm.save_config("mc1", {})
        mpm.save_master_profile("mp1", "mc1", "default",
                                agent_overrides={"recon": {"prompt_profile": "custom"}})
        resolved = mpm.resolve("mp1")
        assert resolved["effective_prompts"]["recon"] == "custom"
        assert resolved["effective_prompts"]["orchestrator"] == "default"

    def test_delete(self, mpm, mcm):
        mpm.ensure_default_prompt_profile()
        mcm.save_config("mc1", {})
        mpm.save_master_profile("mp1", "mc1", "default")
        assert mpm.delete_master_profile("mp1")
        assert mpm.get_master_profile("mp1") is None


class TestRunHistory:
    def test_record_and_retrieve(self, mpm, mcm):
        mpm.ensure_default_prompt_profile()
        mcm.save_config("mc1", {})
        mpm.save_master_profile("mp1", "mc1", "default")
        resolved = mpm.resolve("mp1")
        snapshot = mpm.snapshot_effective_config(resolved)

        mpm.record_run("mp1", "eng1", "10.0.0.1", "standard", snapshot,
                        duration_seconds=60, cost_usd=0.5, tokens=10000)
        mpm.record_run("mp1", "eng2", "10.0.0.2", "ctf", snapshot,
                        duration_seconds=120, cost_usd=1.0, tokens=20000)

        history = mpm.get_history("mp1")
        assert len(history) == 2

        stats = mpm.get_aggregated_stats("mp1")
        assert stats["run_count"] == 2
        assert stats["total_cost_usd"] == 1.5
        assert stats["avg_cost_usd"] == 0.75
        assert stats["total_tokens"] == 30000

    def test_snapshot_contains_key_fields(self, mpm, mcm):
        mpm.ensure_default_prompt_profile()
        mcm.save_config("mc1", {"recon": "sonnet"})
        mpm.save_master_profile("mp1", "mc1", "default")
        resolved = mpm.resolve("mp1")
        snapshot = mpm.snapshot_effective_config(resolved)
        assert "master_profile" in snapshot
        assert "effective_models" in snapshot
        assert "effective_prompts" in snapshot
        assert "snapshot_time" in snapshot


class TestBaseAgentPromptDir:
    def test_prompt_dir_override(self, tmproot):
        """BaseAgent._load_system_prompt should use prompt_dir when set."""
        from agents.base_agent import BaseAgent

        class FakeAgent(BaseAgent):
            agent_name = "test"
            agent_type = "recon"
            def execute(self, task): pass

        # Create a custom prompt dir with overridden prompt
        custom_dir = tmproot / "custom_prompts"
        custom_dir.mkdir()
        (custom_dir / "recon.md").write_text("# Custom recon prompt")

        # Instantiate with prompt_dir — we need an engagement dir with DB
        eng_dir = tmproot / "test_eng"
        eng_dir.mkdir()
        from memory.database import DatabaseManager
        db = DatabaseManager(str(eng_dir))
        db.create_engagement("test", "127.0.0.1", methodology="standard")
        db.close()

        agent = FakeAgent(str(eng_dir), anthropic_client=object(), prompt_dir=str(custom_dir))
        assert "Custom recon prompt" in agent.system_prompt

    def test_binary_re_mapping(self, tmproot):
        """binary agent_type should find binary_re.md."""
        from agents.base_agent import BaseAgent

        class FakeBinary(BaseAgent):
            agent_name = "binary"
            agent_type = "binary"
            def execute(self, task): pass

        # Write binary_re.md but not binary.md
        prompt_dir = tmproot / "prompts_test"
        prompt_dir.mkdir()
        (prompt_dir / "binary_re.md").write_text("# Binary RE prompt")

        eng_dir = tmproot / "test_eng2"
        eng_dir.mkdir()
        from memory.database import DatabaseManager
        db = DatabaseManager(str(eng_dir))
        db.create_engagement("test2", "127.0.0.1", methodology="standard")
        db.close()

        agent = FakeBinary(str(eng_dir), anthropic_client=object(), prompt_dir=str(prompt_dir))
        assert "Binary RE prompt" in agent.system_prompt

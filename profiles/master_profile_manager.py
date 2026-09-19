"""
SnowStrike AI - Master Profile Manager

A master profile combines a model config + prompt profile + optional per-agent
overrides for either models or prompts.  Master profiles are stored as YAML
files under engagements/presets/master_profiles/.

Directory layout:
    engagements/presets/
        models/           ← saved model configs (existing)
        prompts/          ← saved prompt profiles (existing)
        master_profiles/  ← master profile YAML files (new)
"""

import json
import logging
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from config import PROJECT_ROOT, AGENTS_PROMPTS_DIR, AGENT_TYPES

logger = logging.getLogger(__name__)

MASTER_PROFILES_DIR = PROJECT_ROOT / "engagements" / "presets" / "master_profiles"
PROMPTS_PRESETS_DIR = PROJECT_ROOT / "engagements" / "presets" / "prompts"
MODELS_PRESETS_DIR = PROJECT_ROOT / "engagements" / "presets" / "models"
RUN_HISTORY_DIR = PROJECT_ROOT / "engagements" / "presets" / "run_history"

# Map agent_type → prompt filename (handles mismatches like binary → binary_re)
AGENT_PROMPT_FILENAMES = {
    "orchestrator": "orchestrator.md",
    "recon": "recon.md",
    "webapp": "webapp.md",
    "browser": "browser.md",
    "attack": "attack.md",
    "cloud": "cloud.md",
    "binary": "binary_re.md",
    "forensics": "forensics.md",
    "osint": "osint.md",
    "reporting": "reporting.md",
}

ALL_PROMPT_ROLES = list(AGENT_PROMPT_FILENAMES.keys())


class MasterProfileManager:
    """CRUD and resolution for master profiles."""

    def __init__(
        self,
        master_dir: Optional[Path] = None,
        prompts_dir: Optional[Path] = None,
        models_dir: Optional[Path] = None,
    ):
        self.master_dir = master_dir or MASTER_PROFILES_DIR
        self.prompts_dir = prompts_dir or PROMPTS_PRESETS_DIR
        self.models_dir = models_dir or MODELS_PRESETS_DIR
        self.history_dir = RUN_HISTORY_DIR

        self.master_dir.mkdir(parents=True, exist_ok=True)
        self.prompts_dir.mkdir(parents=True, exist_ok=True)
        self.models_dir.mkdir(parents=True, exist_ok=True)
        self.history_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Bootstrap: ensure default prompt profile exists
    # ------------------------------------------------------------------

    def ensure_default_prompt_profile(self) -> Path:
        """Create the 'default' prompt profile from agents/prompts/ if missing."""
        default_dir = self.prompts_dir / "default"
        if default_dir.is_dir() and any(default_dir.glob("*.md")):
            return default_dir
        default_dir.mkdir(parents=True, exist_ok=True)
        for md in AGENTS_PROMPTS_DIR.glob("*.md"):
            shutil.copy2(md, default_dir / md.name)
        metadata = {
            "description": "Default prompts (copy of agents/prompts/)",
            "created_date": datetime.now().strftime("%Y-%m-%d"),
            "author": "system",
            "tags": ["default"],
            "source": "agents/prompts",
        }
        _save_yaml(default_dir / "preset.yaml", metadata)
        logger.info("Bootstrapped default prompt profile")
        return default_dir

    # ------------------------------------------------------------------
    # Prompt Profiles — CRUD
    # ------------------------------------------------------------------

    def list_prompt_profiles(self) -> List[Dict[str, Any]]:
        self.ensure_default_prompt_profile()
        profiles = []
        for entry in sorted(self.prompts_dir.iterdir()):
            if not entry.is_dir():
                continue
            meta = _load_yaml(entry / "preset.yaml") if (entry / "preset.yaml").exists() else {}
            prompt_files = list(entry.glob("*.md"))
            profiles.append({
                "name": entry.name,
                "description": meta.get("description", ""),
                "tags": meta.get("tags", []),
                "created_date": meta.get("created_date", ""),
                "author": meta.get("author", ""),
                "prompt_count": len(prompt_files),
                "prompts": sorted(p.stem for p in prompt_files),
            })
        return profiles

    def get_prompt_profile(self, name: str) -> Optional[Dict[str, Any]]:
        """Return metadata + per-agent prompt content for a prompt profile."""
        pdir = self.prompts_dir / name
        if not pdir.is_dir():
            return None
        meta = _load_yaml(pdir / "preset.yaml") if (pdir / "preset.yaml").exists() else {}
        prompts = {}
        for md in sorted(pdir.glob("*.md")):
            prompts[md.stem] = md.read_text()
        return {
            "name": name,
            "metadata": meta,
            "prompts": prompts,
        }

    def get_agent_prompt(self, profile_name: str, agent_type: str) -> Optional[str]:
        """Read a single agent's prompt from a profile. Returns None if missing."""
        pdir = self.prompts_dir / profile_name
        if not pdir.is_dir():
            return None
        filename = AGENT_PROMPT_FILENAMES.get(agent_type, f"{agent_type}.md")
        path = pdir / filename
        if path.exists():
            return path.read_text()
        # Fallback: try {agent_type}.md directly
        alt = pdir / f"{agent_type}.md"
        if alt.exists():
            return alt.read_text()
        return None

    def save_agent_prompt(self, profile_name: str, agent_type: str, content: str) -> Path:
        """Write a single agent's prompt in a profile."""
        pdir = self.prompts_dir / profile_name
        pdir.mkdir(parents=True, exist_ok=True)
        filename = AGENT_PROMPT_FILENAMES.get(agent_type, f"{agent_type}.md")
        path = pdir / filename
        path.write_text(content)
        return path

    def create_prompt_profile(
        self,
        name: str,
        description: str = "",
        source: str = "default",
        tags: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Create a new prompt profile by copying from source (or default prompts)."""
        dest = self.prompts_dir / name
        if dest.exists():
            raise ValueError(f"Prompt profile '{name}' already exists")

        if source == "default" or not source:
            src = self.ensure_default_prompt_profile()
        else:
            src = self.prompts_dir / source
            if not src.is_dir():
                raise ValueError(f"Source prompt profile '{source}' not found")

        dest.mkdir(parents=True, exist_ok=True)
        for md in src.glob("*.md"):
            shutil.copy2(md, dest / md.name)

        meta = {
            "description": description or f"Prompt profile: {name}",
            "created_date": datetime.now().strftime("%Y-%m-%d"),
            "author": "user",
            "tags": tags or [],
            "source": source or "default",
        }
        _save_yaml(dest / "preset.yaml", meta)
        return {"name": name, "metadata": meta}

    def duplicate_prompt_profile(self, source: str, new_name: str) -> Dict[str, Any]:
        """Duplicate an existing prompt profile under a new name."""
        return self.create_prompt_profile(new_name, source=source,
                                          description=f"Duplicate of {source}")

    def rename_prompt_profile(self, old_name: str, new_name: str) -> bool:
        old_dir = self.prompts_dir / old_name
        new_dir = self.prompts_dir / new_name
        if not old_dir.is_dir() or new_dir.exists():
            return False
        old_dir.rename(new_dir)
        return True

    def delete_prompt_profile(self, name: str) -> bool:
        if name == "default":
            raise ValueError("Cannot delete the default prompt profile")
        path = self.prompts_dir / name
        if path.is_dir():
            shutil.rmtree(path)
            return True
        return False

    # ------------------------------------------------------------------
    # Master Profiles — CRUD
    # ------------------------------------------------------------------

    def list_master_profiles(self) -> List[Dict[str, Any]]:
        profiles = []
        for path in sorted(self.master_dir.glob("*.yaml")):
            try:
                data = _load_yaml(path)
                # Attach aggregated history stats
                history = self._load_history(path.stem)
                data["name"] = path.stem
                data["run_count"] = len(history)
                data["total_cost_usd"] = round(
                    sum(r.get("cost_usd", 0) for r in history), 4
                )
                profiles.append(data)
            except Exception as e:
                logger.warning(f"Failed to load master profile {path}: {e}")
        return profiles

    def get_master_profile(self, name: str) -> Optional[Dict[str, Any]]:
        path = self.master_dir / f"{name}.yaml"
        if not path.exists():
            return None
        data = _load_yaml(path)
        data["name"] = name
        data["history"] = self._load_history(name)
        return data

    def save_master_profile(
        self,
        name: str,
        model_config: str,
        prompt_profile: str,
        description: str = "",
        tags: Optional[List[str]] = None,
        agent_overrides: Optional[Dict[str, Dict[str, str]]] = None,
    ) -> Path:
        """Create or overwrite a master profile.

        Args:
            name: Profile name (becomes filename).
            model_config: Name of a saved model config preset.
            prompt_profile: Name of a saved prompt profile.
            description: Human-readable description.
            tags: Optional tags.
            agent_overrides: Per-agent overrides, e.g.
                {"recon": {"model": "gpt-5.2", "prompt_profile": "aggressive"}}
        """
        data = {
            "description": description,
            "model_config": model_config,
            "prompt_profile": prompt_profile,
            "agent_overrides": agent_overrides or {},
            "tags": tags or [],
            "created_date": datetime.now().strftime("%Y-%m-%d"),
            "updated_date": datetime.now().strftime("%Y-%m-%d"),
        }
        path = self.master_dir / f"{name}.yaml"
        _save_yaml(path, data)
        logger.info(f"Saved master profile: {name}")
        return path

    def delete_master_profile(self, name: str) -> bool:
        path = self.master_dir / f"{name}.yaml"
        if path.exists():
            path.unlink()
            return True
        return False

    # ------------------------------------------------------------------
    # Master Profile Resolution (used at runtime)
    # ------------------------------------------------------------------

    def resolve(self, name: str) -> Dict[str, Any]:
        """Fully resolve a master profile into effective model + prompt mappings.

        Returns:
            {
                "name": str,
                "model_config": dict,       # role → model_id
                "prompt_profile": str,       # name of prompt profile
                "prompt_dir": Path,          # directory containing .md files
                "agent_overrides": dict,     # per-agent overrides
                "effective_models": dict,    # final role → model_id after overrides
                "effective_prompts": dict,   # agent_type → prompt_profile_name
                "metadata": dict,
            }
        """
        profile = self.get_master_profile(name)
        if not profile:
            raise ValueError(f"Master profile '{name}' not found")

        # Resolve base model config
        model_config_name = profile.get("model_config", "")
        base_models = {}
        if model_config_name:
            mc_path = self.models_dir / f"{model_config_name}.yaml"
            if mc_path.exists():
                mc_data = _load_yaml(mc_path)
                base_models = mc_data.get("roles", {})

        # Resolve base prompt profile
        prompt_profile_name = profile.get("prompt_profile", "default")
        prompt_dir = self.prompts_dir / prompt_profile_name
        if not prompt_dir.is_dir():
            self.ensure_default_prompt_profile()
            prompt_profile_name = "default"
            prompt_dir = self.prompts_dir / "default"

        # Apply per-agent overrides
        agent_overrides = profile.get("agent_overrides", {})
        effective_models = dict(base_models)
        effective_prompts = {role: prompt_profile_name for role in ALL_PROMPT_ROLES}

        for agent_type, overrides in agent_overrides.items():
            if "model" in overrides and overrides["model"]:
                effective_models[agent_type] = overrides["model"]
            if "prompt_profile" in overrides and overrides["prompt_profile"]:
                effective_prompts[agent_type] = overrides["prompt_profile"]

        return {
            "name": name,
            "model_config": base_models,
            "prompt_profile": prompt_profile_name,
            "prompt_dir": prompt_dir,
            "agent_overrides": agent_overrides,
            "effective_models": effective_models,
            "effective_prompts": effective_prompts,
            "metadata": profile,
        }

    # ------------------------------------------------------------------
    # Run History per Master Profile
    # ------------------------------------------------------------------

    def record_run(
        self,
        master_profile_name: str,
        engagement_name: str,
        target: str,
        methodology: str,
        effective_snapshot: Dict[str, Any],
        duration_seconds: float = 0,
        cost_usd: float = 0,
        tokens: int = 0,
        findings_summary: Optional[Dict] = None,
        outcome_summary: str = "",
    ) -> Path:
        """Record a completed run for a master profile."""
        profile_history_dir = self.history_dir / master_profile_name
        profile_history_dir.mkdir(parents=True, exist_ok=True)

        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        run_data = {
            "master_profile": master_profile_name,
            "engagement_name": engagement_name,
            "target": target,
            "methodology": methodology,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "duration_seconds": round(duration_seconds, 1),
            "cost_usd": round(cost_usd, 4),
            "tokens": tokens,
            "findings_summary": findings_summary or {},
            "outcome_summary": outcome_summary,
            "effective_snapshot": effective_snapshot,
        }

        path = profile_history_dir / f"{ts}_{engagement_name}.yaml"
        _save_yaml(path, run_data)
        logger.info(f"Recorded run for master profile '{master_profile_name}': {path.name}")
        return path

    def get_history(self, master_profile_name: str) -> List[Dict[str, Any]]:
        """Get all run history for a master profile, newest first."""
        return self._load_history(master_profile_name)

    def get_aggregated_stats(self, master_profile_name: str) -> Dict[str, Any]:
        """Aggregate cost and run stats for a master profile."""
        history = self._load_history(master_profile_name)
        if not history:
            return {"run_count": 0, "total_cost_usd": 0, "avg_cost_usd": 0,
                    "avg_duration_seconds": 0, "total_tokens": 0}

        total_cost = sum(r.get("cost_usd", 0) for r in history)
        total_duration = sum(r.get("duration_seconds", 0) for r in history)
        total_tokens = sum(r.get("tokens", 0) for r in history)
        n = len(history)

        return {
            "run_count": n,
            "total_cost_usd": round(total_cost, 4),
            "avg_cost_usd": round(total_cost / n, 4) if n else 0,
            "avg_duration_seconds": round(total_duration / n, 1) if n else 0,
            "total_tokens": total_tokens,
            "runs": history,
        }

    def _load_history(self, master_profile_name: str) -> List[Dict[str, Any]]:
        hdir = self.history_dir / master_profile_name
        if not hdir.is_dir():
            return []
        runs = []
        for path in sorted(hdir.glob("*.yaml"), reverse=True):
            try:
                runs.append(_load_yaml(path))
            except Exception:
                pass
        return runs

    # ------------------------------------------------------------------
    # Snapshot: freeze effective config for a run
    # ------------------------------------------------------------------

    def snapshot_effective_config(self, resolved: Dict[str, Any]) -> Dict[str, Any]:
        """Create a serializable snapshot of the resolved config for archival."""
        return {
            "master_profile": resolved["name"],
            "model_config": resolved["model_config"],
            "prompt_profile": resolved["prompt_profile"],
            "effective_models": resolved["effective_models"],
            "effective_prompts": resolved["effective_prompts"],
            "agent_overrides": resolved["agent_overrides"],
            "snapshot_time": datetime.now(timezone.utc).isoformat(),
        }


# ------------------------------------------------------------------
# YAML helpers (module-level)
# ------------------------------------------------------------------

def _load_yaml(path: Path) -> Dict:
    with open(path) as f:
        return yaml.safe_load(f) or {}


def _save_yaml(path: Path, data: Dict):
    with open(path, "w") as f:
        yaml.dump(data, f, default_flow_style=False, sort_keys=False)

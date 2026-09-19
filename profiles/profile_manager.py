"""
SnowStrike AI - Test Profile Manager

A profile = prompt_preset + model_config.
Profiles are named combinations stored as YAML under engagements/profiles/.
"""

import logging
import os
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from config import PROJECT_ROOT, AGENTS_PROMPTS_DIR

logger = logging.getLogger(__name__)

PROFILES_DIR = PROJECT_ROOT / "engagements" / "profiles"
PROMPTS_PRESETS_DIR = PROJECT_ROOT / "engagements" / "presets" / "prompts"
MODELS_PRESETS_DIR = PROJECT_ROOT / "engagements" / "presets" / "models"


class ProfileManager:
    """Manages test profiles — named (prompt_preset, model_config) pairs."""

    def __init__(
        self,
        profiles_dir: Optional[Path] = None,
        prompts_dir: Optional[Path] = None,
        models_dir: Optional[Path] = None,
    ):
        self.profiles_dir = profiles_dir or PROFILES_DIR
        self.prompts_dir = prompts_dir or PROMPTS_PRESETS_DIR
        self.models_dir = models_dir or MODELS_PRESETS_DIR

        self.profiles_dir.mkdir(parents=True, exist_ok=True)
        self.prompts_dir.mkdir(parents=True, exist_ok=True)
        self.models_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Profiles (prompt_preset + model_config combo)
    # ------------------------------------------------------------------

    def list_profiles(self) -> List[Dict[str, Any]]:
        """List all test profiles."""
        profiles = []
        for path in sorted(self.profiles_dir.glob("*.yaml")):
            try:
                data = self._load_yaml(path)
                profiles.append({
                    "name": path.stem,
                    "prompt_preset": data.get("prompt_preset", ""),
                    "model_config": data.get("model_config", ""),
                    "description": data.get("description", ""),
                    "tags": data.get("tags", []),
                    "created_date": data.get("created_date", ""),
                    "path": str(path),
                })
            except Exception as e:
                logger.warning(f"Failed to load profile {path}: {e}")
        return profiles

    def get_profile(self, name: str) -> Optional[Dict[str, Any]]:
        """Load a profile by name."""
        path = self.profiles_dir / f"{name}.yaml"
        if not path.exists():
            return None
        return self._load_yaml(path)

    def save_profile(
        self,
        name: str,
        prompt_preset: str,
        model_config: str,
        description: str = "",
        tags: Optional[List[str]] = None,
    ) -> Path:
        """Create or overwrite a test profile."""
        # Validate that the prompt preset and model config exist
        if not self._prompt_preset_exists(prompt_preset):
            raise ValueError(f"Prompt preset '{prompt_preset}' not found in {self.prompts_dir}")
        if not self._model_config_exists(model_config):
            raise ValueError(f"Model config '{model_config}' not found in {self.models_dir}")

        data = {
            "name": name,
            "prompt_preset": prompt_preset,
            "model_config": model_config,
            "description": description or f"{prompt_preset} + {model_config}",
            "tags": tags or [],
            "created_date": datetime.now().strftime("%Y-%m-%d"),
        }
        path = self.profiles_dir / f"{name}.yaml"
        self._save_yaml(path, data)
        logger.info(f"Saved profile: {name} → {path}")
        return path

    def delete_profile(self, name: str) -> bool:
        """Delete a profile."""
        path = self.profiles_dir / f"{name}.yaml"
        if path.exists():
            path.unlink()
            return True
        return False

    # ------------------------------------------------------------------
    # Prompt Presets
    # ------------------------------------------------------------------

    def list_prompt_presets(self) -> List[Dict[str, Any]]:
        """List all prompt preset directories."""
        presets = []
        for entry in sorted(self.prompts_dir.iterdir()):
            if entry.is_dir():
                metadata_path = entry / "preset.yaml"
                metadata = {}
                if metadata_path.exists():
                    metadata = self._load_yaml(metadata_path)
                # Count prompt files
                prompt_files = list(entry.glob("*.md"))
                presets.append({
                    "name": entry.name,
                    "description": metadata.get("description", ""),
                    "tags": metadata.get("tags", []),
                    "created_date": metadata.get("created_date", ""),
                    "author": metadata.get("author", ""),
                    "prompt_count": len(prompt_files),
                    "prompts": [p.stem for p in prompt_files],
                    "path": str(entry),
                })
        return presets

    def get_prompt_preset_dir(self, name: str) -> Optional[Path]:
        """Get the directory path for a prompt preset."""
        path = self.prompts_dir / name
        if path.is_dir():
            return path
        return None

    def create_prompt_preset(
        self,
        name: str,
        description: str = "",
        tags: Optional[List[str]] = None,
        source: Optional[str] = None,
        author: str = "user",
    ) -> Path:
        """Create a new prompt preset directory.

        If source is provided, copies all .md files from that preset.
        Otherwise copies from the main agents/prompts/ directory.
        """
        preset_dir = self.prompts_dir / name
        preset_dir.mkdir(parents=True, exist_ok=True)

        # Determine source directory
        if source:
            src_dir = self.prompts_dir / source
            if not src_dir.is_dir():
                raise ValueError(f"Source preset '{source}' not found")
        else:
            src_dir = AGENTS_PROMPTS_DIR

        # Copy all .md prompt files
        for md_file in src_dir.glob("*.md"):
            shutil.copy2(md_file, preset_dir / md_file.name)

        # Write metadata
        metadata = {
            "description": description or f"Prompt preset: {name}",
            "created_date": datetime.now().strftime("%Y-%m-%d"),
            "author": author,
            "tags": tags or [],
            "source": source or "agents/prompts",
        }
        self._save_yaml(preset_dir / "preset.yaml", metadata)

        logger.info(f"Created prompt preset: {name} ({len(list(preset_dir.glob('*.md')))} prompts)")
        return preset_dir

    def delete_prompt_preset(self, name: str) -> bool:
        """Delete a prompt preset directory."""
        path = self.prompts_dir / name
        if path.is_dir():
            shutil.rmtree(path)
            return True
        return False

    # ------------------------------------------------------------------
    # Profile Resolution (used by orchestrator at runtime)
    # ------------------------------------------------------------------

    def resolve_profile(self, profile_name: str) -> Dict[str, Any]:
        """Fully resolve a profile into its prompt directory and model mapping.

        Returns:
            {
                "profile_name": str,
                "prompt_dir": Path,    # directory containing .md prompt files
                "model_config": dict,  # role → model_id mapping
                "metadata": dict,      # full profile YAML
            }
        """
        profile = self.get_profile(profile_name)
        if not profile:
            raise ValueError(f"Profile '{profile_name}' not found")

        prompt_preset = profile.get("prompt_preset", "")
        model_config_name = profile.get("model_config", "")

        # Resolve prompt directory
        prompt_dir = self.get_prompt_preset_dir(prompt_preset)
        if not prompt_dir:
            raise ValueError(f"Prompt preset '{prompt_preset}' not found")

        # Resolve model config
        model_config_path = self.models_dir / f"{model_config_name}.yaml"
        if not model_config_path.exists():
            raise ValueError(f"Model config '{model_config_name}' not found")
        model_data = self._load_yaml(model_config_path)
        model_mapping = model_data.get("roles", {})

        return {
            "profile_name": profile_name,
            "prompt_dir": prompt_dir,
            "model_config": model_mapping,
            "metadata": profile,
        }

    # ------------------------------------------------------------------
    # Generate all profile combinations (for test matrix)
    # ------------------------------------------------------------------

    def generate_matrix(self) -> List[Dict[str, str]]:
        """Generate all combinations of prompt_preset × model_config.

        Returns a list of dicts with keys: prompt_preset, model_config, profile_name.
        """
        presets = self.list_prompt_presets()
        configs = [p.stem for p in sorted(self.models_dir.glob("*.yaml"))]

        matrix = []
        for preset in presets:
            for config in configs:
                matrix.append({
                    "prompt_preset": preset["name"],
                    "model_config": config,
                    "profile_name": f"{config}-{preset['name']}",
                })
        return matrix

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _prompt_preset_exists(self, name: str) -> bool:
        return (self.prompts_dir / name).is_dir()

    def _model_config_exists(self, name: str) -> bool:
        return (self.models_dir / f"{name}.yaml").exists()

    @staticmethod
    def _load_yaml(path: Path) -> Dict:
        with open(path, "r") as f:
            return yaml.safe_load(f) or {}

    @staticmethod
    def _save_yaml(path: Path, data: Dict):
        with open(path, "w") as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False)

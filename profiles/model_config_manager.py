"""
SnowStrike AI - Model Configuration Manager

Manages named model configurations that map agent roles → model IDs.
Configurations are stored as YAML files under engagements/presets/models/.
"""

import logging
import os
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from config import PROJECT_ROOT, AGENT_TYPES, AVAILABLE_MODELS

logger = logging.getLogger(__name__)

MODELS_DIR = PROJECT_ROOT / "engagements" / "presets" / "models"
MODEL_COSTS_PATH = PROJECT_ROOT / "config" / "model_costs.yaml"

# All roles that can have model assignments
ALL_ROLES = AGENT_TYPES + ["orchestrator", "tool_calling", "alerts", "compaction", "planning"]


class ModelConfigManager:
    """CRUD operations for model configuration presets."""

    def __init__(self, models_dir: Optional[Path] = None):
        self.models_dir = models_dir or MODELS_DIR
        self.models_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    def list_configs(self) -> List[Dict[str, Any]]:
        """List all available model configurations with metadata."""
        configs = []
        for path in sorted(self.models_dir.glob("*.yaml")):
            try:
                data = self._load_yaml(path)
                configs.append({
                    "name": path.stem,
                    "description": data.get("description", ""),
                    "tags": data.get("tags", []),
                    "created_date": data.get("created_date", ""),
                    "author": data.get("author", ""),
                    "roles": data.get("roles", {}),
                    "path": str(path),
                })
            except Exception as e:
                logger.warning(f"Failed to load model config {path}: {e}")
        return configs

    def get_config(self, name: str) -> Optional[Dict[str, Any]]:
        """Load a model config by name. Returns the full YAML data."""
        path = self.models_dir / f"{name}.yaml"
        if not path.exists():
            return None
        return self._load_yaml(path)

    def get_role_mapping(self, name: str) -> Dict[str, str]:
        """Load just the role→model mapping for a config. This is the dict
        that gets passed to resolve_model_for_role() as model_config."""
        config = self.get_config(name)
        if not config:
            return {}
        return config.get("roles", {})

    def save_config(
        self,
        name: str,
        roles: Dict[str, str],
        description: str = "",
        tags: Optional[List[str]] = None,
        author: str = "user",
    ) -> Path:
        """Create or overwrite a model configuration."""
        # Validate model IDs
        for role, model_id in roles.items():
            if role not in ALL_ROLES:
                logger.warning(f"Unknown role '{role}' in model config '{name}'")
            # We don't hard-fail on unknown models — they might be added to
            # AVAILABLE_MODELS later, or be accessible via OpenAI-compatible endpoints.

        data = {
            "description": description,
            "created_date": datetime.now().strftime("%Y-%m-%d"),
            "author": author,
            "tags": tags or [],
            "roles": roles,
        }
        path = self.models_dir / f"{name}.yaml"
        self._save_yaml(path, data)
        logger.info(f"Saved model config: {name} → {path}")
        return path

    def delete_config(self, name: str) -> bool:
        """Delete a model configuration."""
        path = self.models_dir / f"{name}.yaml"
        if path.exists():
            path.unlink()
            logger.info(f"Deleted model config: {name}")
            return True
        return False

    # ------------------------------------------------------------------
    # Model Costs Registry
    # ------------------------------------------------------------------

    def get_model_costs(self) -> Dict[str, Dict]:
        """Load the full model costs registry from config/model_costs.yaml."""
        if not MODEL_COSTS_PATH.exists():
            return {}
        data = self._load_yaml(MODEL_COSTS_PATH)
        return data.get("models", {})

    def estimate_config_cost(
        self,
        config_name: str,
        tokens_per_agent: int = 100_000,
    ) -> Dict[str, Any]:
        """Estimate total cost for a config given equal token usage per agent.

        Returns per-role cost estimates and totals. Useful for comparing
        configurations before running actual engagements.
        """
        roles = self.get_role_mapping(config_name)
        if not roles:
            return {"error": f"Config '{config_name}' not found"}

        costs = self.get_model_costs()
        # Also check config.MODEL_PRICING for legacy models
        from config import MODEL_PRICING

        breakdown = {}
        total_input = 0.0
        total_output = 0.0

        for role, model_id in roles.items():
            model_cost = costs.get(model_id, {})
            if not model_cost:
                # Fallback to config.MODEL_PRICING
                legacy = MODEL_PRICING.get(model_id, {})
                input_rate = legacy.get("input", 0.0)
                output_rate = legacy.get("output", 0.0)
            else:
                input_rate = model_cost.get("input_cost_per_mtok", 0.0)
                output_rate = model_cost.get("output_cost_per_mtok", 0.0)

            input_cost = (tokens_per_agent * input_rate) / 1_000_000
            output_cost = (tokens_per_agent * output_rate) / 1_000_000
            role_total = input_cost + output_cost

            breakdown[role] = {
                "model": model_id,
                "input_cost_usd": round(input_cost, 4),
                "output_cost_usd": round(output_cost, 4),
                "total_usd": round(role_total, 4),
            }
            total_input += input_cost
            total_output += output_cost

        return {
            "config_name": config_name,
            "tokens_per_agent": tokens_per_agent,
            "breakdown": breakdown,
            "total_input_usd": round(total_input, 4),
            "total_output_usd": round(total_output, 4),
            "total_usd": round(total_input + total_output, 4),
        }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _load_yaml(path: Path) -> Dict:
        with open(path, "r") as f:
            return yaml.safe_load(f) or {}

    @staticmethod
    def _save_yaml(path: Path, data: Dict):
        with open(path, "w") as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False)

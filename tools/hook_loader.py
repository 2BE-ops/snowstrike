"""Load hook rules from YAML configuration files."""

import logging
import re
from pathlib import Path
from typing import Optional

import yaml

from tools.hooks import (
    ArgPatternMatcher, CompoundMatcher, HookAction, HookMatcher,
    HookRule, ToolNameMatcher, get_hook_registry,
)

logger = logging.getLogger(__name__)

_VALID_ACTIONS = {a.value.upper(): a for a in HookAction}
_VALID_ACTIONS.update({
    "LOG_ONLY": HookAction.LOG_ONLY,
    "MODIFY_ARGS": HookAction.MODIFY_ARGS,
    "DEFER": HookAction.DEFER,
    "INJECT": HookAction.INJECT,
})


class _ToolNamePatternMatcher(HookMatcher):
    """Match tool_name against a glob/regex pattern."""
    def __init__(self, pattern: str):
        regex = pattern.replace("*", ".*")
        self._pattern = re.compile(f"^(?:{regex})$")

    @property
    def name(self) -> str:
        return f"tool_pattern:{self._pattern.pattern}"

    def match(self, event) -> bool:
        return bool(self._pattern.match(event.tool_name))


class _ArgMissingMatcher(HookMatcher):
    """Match when a required argument is absent from tool_args."""
    def __init__(self, arg_name: str):
        self._arg_name = arg_name

    @property
    def name(self) -> str:
        return f"arg_missing:{self._arg_name}"

    def match(self, event) -> bool:
        return self._arg_name not in event.tool_args


def _build_matcher(match_spec: dict) -> Optional[HookMatcher]:
    """Build a (possibly compound) matcher from a YAML match spec."""
    matchers: list[HookMatcher] = []
    if "tool_name" in match_spec:
        matchers.append(ToolNameMatcher({match_spec["tool_name"]}))
    if "tool_name_pattern" in match_spec:
        matchers.append(_ToolNamePatternMatcher(match_spec["tool_name_pattern"]))
    if "arg_missing" in match_spec:
        matchers.append(_ArgMissingMatcher(match_spec["arg_missing"]))
    if "arg_pattern" in match_spec:
        for arg_name, pattern in match_spec["arg_pattern"].items():
            matchers.append(ArgPatternMatcher(arg_name, str(pattern)))
    if not matchers:
        return None
    return matchers[0] if len(matchers) == 1 else CompoundMatcher(matchers)


def load_hooks_from_yaml(path: str) -> list[HookRule]:
    """Parse a hooks YAML file and return validated HookRule objects."""
    rules: list[HookRule] = []
    try:
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    except Exception as exc:
        logger.warning("Failed to read hooks YAML %s: %s", path, exc)
        return rules
    if not isinstance(data, dict) or "hooks" not in data:
        logger.warning("Hooks YAML %s missing top-level 'hooks' key", path)
        return rules
    for idx, entry in enumerate(data["hooks"]):
        try:
            if not isinstance(entry, dict):
                raise ValueError("rule must be a mapping")
            name = entry.get("name", f"yaml_rule_{idx}")
            action_str = entry.get("action", "").upper()
            if action_str not in _VALID_ACTIONS:
                raise ValueError(f"unknown action '{entry.get('action')}'")
            match_spec = entry.get("match")
            if not isinstance(match_spec, dict):
                raise ValueError("'match' must be a mapping")
            matcher = _build_matcher(match_spec)
            if matcher is None:
                raise ValueError("match spec produced no matchers")
            rules.append(HookRule(
                matcher=matcher, action=_VALID_ACTIONS[action_str],
                priority=int(entry.get("priority", 50)), name=name,
            ))
        except Exception as exc:
            rule_name = entry.get("name", "?") if isinstance(entry, dict) else "?"
            logger.warning("Skipping invalid hook rule #%d (%s): %s", idx, rule_name, exc)
    logger.info("Loaded %d hook rule(s) from %s", len(rules), path)
    return rules

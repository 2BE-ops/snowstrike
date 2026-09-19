"""Handler for transform flow steps."""

from __future__ import annotations

import copy
import json
import logging
import re
import time
from typing import Any

from flows.schema import StepDefinition, StepResult, StepStatus

logger = logging.getLogger(__name__)


def _resolve_source(source_path: str, context: dict) -> Any:
    """Resolve a dotted path like 'steps.osint_recon.findings' from context."""
    parts = source_path.split(".")
    current = context
    for part in parts:
        if isinstance(current, dict):
            current = current.get(part)
        elif isinstance(current, list) and part.isdigit():
            idx = int(part)
            current = current[idx] if idx < len(current) else None
        else:
            current = getattr(current, part, None)
        if current is None:
            return None
    return current


class TransformStepHandler:
    """Execute data transformations."""

    def execute(
        self,
        step: StepDefinition,
        context: dict,
        workspace: str,
        engagement_id: int = 0,
    ) -> StepResult:
        t0 = time.monotonic()

        # Resolve sources
        resolved_sources = []
        for src in step.sources:
            resolved_sources.append(_resolve_source(src, context))

        try:
            result = self._apply_operation(step.operation, resolved_sources, step.params, context)
        except Exception as exc:
            elapsed = time.monotonic() - t0
            return StepResult(
                step_id=step.id,
                status=StepStatus.FAILED.value,
                success=False,
                duration_seconds=elapsed,
                errors=[f"Transform '{step.operation}' failed: {exc}"],
            )

        elapsed = time.monotonic() - t0
        return StepResult(
            step_id=step.id,
            status=StepStatus.COMPLETED.value,
            success=True,
            output={"output": result},
            duration_seconds=elapsed,
        )

    def _apply_operation(
        self, operation: str, sources: list, params: dict, context: dict
    ) -> Any:
        if operation == "merge_dicts":
            return self._merge_dicts(sources, params)
        if operation == "merge_lists":
            return self._merge_lists(sources, params)
        if operation == "filter":
            return self._filter(sources, params)
        if operation == "extract":
            return self._extract(sources, params)
        if operation == "format_string":
            return self._format_string(params, context)
        if operation == "json_parse":
            return self._json_parse(sources)
        if operation == "regex_extract":
            return self._regex_extract(sources, params)
        raise ValueError(f"Unknown transform operation: {operation}")

    @staticmethod
    def _merge_dicts(sources: list, params: dict) -> dict:
        result = {}
        deep = params.get("strategy", "shallow_merge") == "deep_merge"
        for src in sources:
            if isinstance(src, dict):
                if deep:
                    _deep_merge(result, src)
                else:
                    result.update(src)
        return result

    @staticmethod
    def _merge_lists(sources: list, params: dict) -> list:
        result = []
        for src in sources:
            if isinstance(src, list):
                result.extend(src)
            elif src is not None:
                result.append(src)
        if params.get("deduplicate", False):
            seen = set()
            deduped = []
            for item in result:
                key = str(item)
                if key not in seen:
                    seen.add(key)
                    deduped.append(item)
            result = deduped
        return result

    @staticmethod
    def _filter(sources: list, params: dict) -> list:
        from flows.condition_eval import ConditionEvaluator
        predicate = params.get("predicate", "")
        if not predicate or not sources:
            return sources[0] if sources else []
        data = sources[0] if sources else []
        if not isinstance(data, list):
            return []
        evaluator = ConditionEvaluator()
        return [item for item in data if evaluator.evaluate(predicate, {"item": item})]

    @staticmethod
    def _extract(sources: list, params: dict) -> Any:
        path = params.get("path", "")
        data = sources[0] if sources else None
        if not path or data is None:
            return data
        for part in path.split("."):
            if isinstance(data, dict):
                data = data.get(part)
            elif isinstance(data, list) and part.isdigit():
                idx = int(part)
                data = data[idx] if idx < len(data) else None
            else:
                return None
        return data

    @staticmethod
    def _format_string(params: dict, context: dict) -> str:
        from flows.template_env import render_template
        template = params.get("template", "")
        return render_template(template, context)

    @staticmethod
    def _json_parse(sources: list) -> Any:
        data = sources[0] if sources else ""
        if isinstance(data, str):
            return json.loads(data)
        return data

    @staticmethod
    def _regex_extract(sources: list, params: dict) -> str | list[str]:
        data = str(sources[0]) if sources else ""
        pattern = params.get("pattern", "")
        group = params.get("group", 0)
        match = re.search(pattern, data)
        if match:
            try:
                return match.group(group)
            except IndexError:
                return match.group(0)
        return ""


def _deep_merge(base: dict, override: dict) -> None:
    for k, v in override.items():
        if k in base and isinstance(base[k], dict) and isinstance(v, dict):
            _deep_merge(base[k], v)
        else:
            base[k] = copy.deepcopy(v)

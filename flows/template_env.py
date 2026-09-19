"""Sandboxed Jinja2 template environment for flow variable resolution."""

from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from typing import Any

from jinja2 import StrictUndefined
from jinja2.sandbox import SandboxedEnvironment

_MAX_RENDER_SIZE = 1_048_576  # 1 MB


# ---------------------------------------------------------------------------
# Custom filters
# ---------------------------------------------------------------------------

def _filter_slugify(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", str(value).lower()).strip("-")


def _filter_basename(value: str) -> str:
    return os.path.basename(str(value))


def _filter_dirname(value: str) -> str:
    return os.path.dirname(str(value))


def _filter_tojson(value: Any) -> str:
    return json.dumps(value, default=str)


def _filter_fromjson(value: str) -> Any:
    return json.loads(str(value))


def _filter_dateformat(value: Any, fmt: str = "%Y-%m-%d") -> str:
    if isinstance(value, datetime):
        return value.strftime(fmt)
    if isinstance(value, str):
        try:
            dt = datetime.fromisoformat(value)
            return dt.strftime(fmt)
        except ValueError:
            return value
    return str(value)


def _filter_truncate(value: str, length: int = 500, suffix: str = "...") -> str:
    s = str(value)
    if len(s) <= length:
        return s
    return s[: length - len(suffix)] + suffix


def _filter_split(value: str, sep: str = ",") -> list[str]:
    return str(value).split(sep)


def _filter_join(value: list, sep: str = ", ") -> str:
    return sep.join(str(v) for v in value)


def _filter_length(value: Any) -> int:
    return len(value)


def _filter_first(value: list) -> Any:
    if value:
        return value[0]
    return None


def _filter_last(value: list) -> Any:
    if value:
        return value[-1]
    return None


# ---------------------------------------------------------------------------
# Environment factory
# ---------------------------------------------------------------------------

def create_flow_template_env() -> SandboxedEnvironment:
    """Create a sandboxed Jinja2 environment with flow-specific filters."""
    env = SandboxedEnvironment(
        undefined=StrictUndefined,
        keep_trailing_newline=True,
        autoescape=False,
    )
    env.filters["slugify"] = _filter_slugify
    env.filters["basename"] = _filter_basename
    env.filters["dirname"] = _filter_dirname
    env.filters["tojson"] = _filter_tojson
    env.filters["fromjson"] = _filter_fromjson
    env.filters["dateformat"] = _filter_dateformat
    env.filters["truncate"] = _filter_truncate
    env.filters["split"] = _filter_split
    env.filters["join"] = _filter_join
    env.filters["length"] = _filter_length
    env.filters["first"] = _filter_first
    env.filters["last"] = _filter_last
    return env


# Singleton environment
_env: SandboxedEnvironment | None = None


def _get_env() -> SandboxedEnvironment:
    global _env
    if _env is None:
        _env = create_flow_template_env()
    return _env


def render_template(template_str: str, context: dict) -> str:
    """Render a Jinja2 template string against flow context.

    Raises jinja2.TemplateSyntaxError or jinja2.UndefinedError on failure.
    """
    if not template_str or "{{" not in template_str and "{%" not in template_str:
        return template_str

    env = _get_env()
    tpl = env.from_string(template_str)
    result = tpl.render(**context)

    if len(result) > _MAX_RENDER_SIZE:
        result = result[:_MAX_RENDER_SIZE]
    return result

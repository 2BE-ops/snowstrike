"""Handler for save_artifact flow steps."""

from __future__ import annotations

import logging
import os
import time
from pathlib import Path

from flows.schema import StepDefinition, StepResult, StepStatus

logger = logging.getLogger(__name__)


class ArtifactStepHandler:
    """Write content to files with path traversal protection."""

    def execute(
        self,
        step: StepDefinition,
        context: dict,
        workspace: str,
        engagement_id: int = 0,
    ) -> StepResult:
        from flows.template_env import render_template

        t0 = time.monotonic()

        # Render path and content
        try:
            rendered_path = render_template(step.path, context)
            rendered_content = render_template(step.content, context)
        except Exception as exc:
            elapsed = time.monotonic() - t0
            return StepResult(
                step_id=step.id,
                status=StepStatus.FAILED.value,
                success=False,
                duration_seconds=elapsed,
                errors=[f"Template render failed: {exc}"],
            )

        # Path traversal protection
        real_path = os.path.realpath(rendered_path)
        real_workspace = os.path.realpath(workspace)

        if not real_path.startswith(real_workspace + os.sep) and real_path != real_workspace:
            elapsed = time.monotonic() - t0
            return StepResult(
                step_id=step.id,
                status=StepStatus.FAILED.value,
                success=False,
                duration_seconds=elapsed,
                errors=[
                    f"Path traversal blocked: '{rendered_path}' resolves outside workspace"
                ],
            )

        # Write
        try:
            dest = Path(real_path)
            dest.parent.mkdir(parents=True, exist_ok=True)

            mode_flag = "a" if step.mode == "append" else "w"
            with open(dest, mode_flag) as f:
                f.write(rendered_content)

            size = dest.stat().st_size
        except Exception as exc:
            elapsed = time.monotonic() - t0
            return StepResult(
                step_id=step.id,
                status=StepStatus.FAILED.value,
                success=False,
                duration_seconds=elapsed,
                errors=[f"File write failed: {exc}"],
            )

        elapsed = time.monotonic() - t0
        logger.debug("Saved artifact: %s (%d bytes)", real_path, size)

        return StepResult(
            step_id=step.id,
            status=StepStatus.COMPLETED.value,
            success=True,
            output={"file_path": real_path, "size_bytes": size},
            duration_seconds=elapsed,
        )

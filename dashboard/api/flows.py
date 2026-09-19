"""Flow REST API endpoints for the SnowStrike dashboard."""

from __future__ import annotations

import asyncio
import json
import logging
import time
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, StreamingResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/flows", tags=["flows"])


def _get_engine():
    """Lazy import to avoid circular dependencies."""
    from flows.engine import get_flow_engine
    return get_flow_engine()


# ---------------------------------------------------------------------------
# Flow definitions
# ---------------------------------------------------------------------------

@router.get("")
async def list_flows():
    """List all available flow definitions."""
    try:
        engine = _get_engine()
        flows = engine.list_flows()
        return JSONResponse({"flows": flows})
    except Exception as exc:
        return JSONResponse({"error": str(exc)}, status_code=500)


@router.get("/{name}")
async def get_flow(name: str):
    """Get a single flow definition."""
    try:
        engine = _get_engine()
        flow_def = engine.get_flow(name)
        return JSONResponse({"flow": flow_def.to_dict()})
    except KeyError:
        return JSONResponse({"error": f"Flow '{name}' not found"}, status_code=404)
    except Exception as exc:
        return JSONResponse({"error": str(exc)}, status_code=500)


@router.post("/{name}/validate")
async def validate_flow(name: str):
    """Validate a flow definition."""
    try:
        engine = _get_engine()
        flow_def = engine.get_flow(name)
        from flows.validators import validate_flow as _validate
        errors = _validate(flow_def)
        return JSONResponse({
            "valid": len(errors) == 0,
            "errors": errors,
        })
    except KeyError:
        return JSONResponse({"error": f"Flow '{name}' not found"}, status_code=404)
    except Exception as exc:
        return JSONResponse({"error": str(exc)}, status_code=500)


# ---------------------------------------------------------------------------
# Flow execution
# ---------------------------------------------------------------------------

@router.post("/{name}/run")
async def run_flow(name: str, request: Request):
    """Trigger a flow execution."""
    try:
        body = await request.json()
    except Exception:
        body = {}

    inputs = body.get("inputs", {})
    workspace = body.get("workspace", "")
    engagement_id = body.get("engagement_id", 0)
    async_mode = body.get("async", True)

    try:
        engine = _get_engine()
        if async_mode:
            flow_id = engine.execute_async(
                flow_name=name,
                inputs=inputs,
                workspace=workspace,
                engagement_id=engagement_id,
                trigger_type="api",
                trigger_source="dashboard",
            )
            return JSONResponse({
                "status": "dispatched",
                "flow_id": flow_id,
                "flow_name": name,
            })
        else:
            result = engine.trigger(
                flow_name=name,
                inputs=inputs,
                workspace=workspace,
                engagement_id=engagement_id,
                trigger_type="api",
                trigger_source="dashboard",
            )
            return JSONResponse(result.to_dict())
    except KeyError:
        return JSONResponse({"error": f"Flow '{name}' not found"}, status_code=404)
    except Exception as exc:
        logger.error("Flow run failed: %s", exc)
        return JSONResponse({"error": str(exc)}, status_code=500)


# ---------------------------------------------------------------------------
# Flow runs (status)
# ---------------------------------------------------------------------------

@router.get("/runs/active")
async def list_active_runs():
    """List currently running flows."""
    try:
        engine = _get_engine()
        return JSONResponse({"active": engine.get_active_flows()})
    except Exception as exc:
        return JSONResponse({"error": str(exc)}, status_code=500)


@router.get("/runs/completed")
async def list_completed_runs():
    """List recently completed flows."""
    try:
        engine = _get_engine()
        return JSONResponse({"completed": engine.get_completed_flows(20)})
    except Exception as exc:
        return JSONResponse({"error": str(exc)}, status_code=500)


@router.post("/runs/{flow_id}/cancel")
async def cancel_run(flow_id: str):
    """Cancel a running flow."""
    try:
        engine = _get_engine()
        cancelled = engine.cancel_flow(flow_id)
        return JSONResponse({
            "cancelled": cancelled,
            "flow_id": flow_id,
        })
    except Exception as exc:
        return JSONResponse({"error": str(exc)}, status_code=500)


# ---------------------------------------------------------------------------
# SSE: flow events
# ---------------------------------------------------------------------------

@router.get("/events")
async def flow_events_stream():
    """SSE stream of flow lifecycle events."""
    try:
        from memory.event_bus import get_event_bus, EventType
        event_bus = get_event_bus()
        queue = event_bus.create_async_queue(maxsize=200)
    except ImportError:
        return JSONResponse({"error": "EventBus not available"}, status_code=500)

    flow_event_types = {
        EventType.FLOW_START,
        EventType.FLOW_STEP_START,
        EventType.FLOW_STEP_COMPLETE,
        EventType.FLOW_COMPLETE,
    }

    async def event_generator():
        try:
            while True:
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=30)
                    if event.type in flow_event_types:
                        yield event.to_sse()
                except asyncio.TimeoutError:
                    yield f"event: heartbeat\ndata: {json.dumps({'time': time.time()})}\n\n"
        except asyncio.CancelledError:
            pass
        finally:
            try:
                event_bus.remove_async_queue(queue)
            except Exception:
                pass

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )

#!/usr/bin/env python3
"""
SnowStrike AI v7.0 - Live Engagement Dashboard

Usage:
    python -m dashboard.app
    python -m dashboard.app --engagement /path/to/engagement
    python -m dashboard.app --port 9090
"""

import argparse
import logging
import os
import sys

# Configure logging early
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler()],
)

# Ensure project root is on path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# Load .env EARLY so all modules see the env vars
try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(PROJECT_ROOT, ".env"))
except ImportError:
    pass

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi import Request

from dashboard.api.routes import router as api_router
from dashboard.api.chat import router as chat_router
from dashboard.api.builder import router as builder_router
from dashboard.api.approvals import router as approvals_router
from dashboard.api.flows import router as flows_router
from dashboard.data.db_reader import DBReader
from dashboard.data.file_reader import FileReader

DASHBOARD_DIR = os.path.dirname(os.path.abspath(__file__))

app = FastAPI(title="SnowStrike AI Dashboard", version="7.0.0")

# Mount static files
app.mount(
    "/static",
    StaticFiles(directory=os.path.join(DASHBOARD_DIR, "static")),
    name="static",
)

# Templates
templates = Jinja2Templates(directory=os.path.join(DASHBOARD_DIR, "templates"))

# API routes
app.include_router(api_router)
app.include_router(chat_router)
app.include_router(builder_router)
app.include_router(approvals_router)
app.include_router(flows_router)


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    if request.query_params.get("clear"):
        response = HTMLResponse(status_code=302, headers={"Location": "/"})
        response.delete_cookie("active_engagement")
        return response

    active_eng = request.cookies.get("active_engagement")
    if not active_eng:
        return templates.TemplateResponse(request=request, name="picker.html")
    return templates.TemplateResponse(request=request, name="index.html")


@app.get("/builder", response_class=HTMLResponse)
async def builder(request: Request):
    """Agent Builder — visual graph editor for agent configuration."""
    return templates.TemplateResponse(request=request, name="builder.html")


def setup_app(engagements_dir: str):
    """Configure app state with base engagement directory."""
    app.state.engagements_dir = engagements_dir
    print(f"[*] Dashboard loaded base directory: {engagements_dir}")


def _init_tool_api_keys():
    """Auto-initialize CLI tools that require persistent API key config."""
    import subprocess
    import shutil

    shodan_key = os.environ.get("SHODAN_API_KEY", "")
    if shodan_key and shutil.which("shodan"):
        try:
            subprocess.run(["shodan", "init", shodan_key], capture_output=True, timeout=10)
            print("[+] Shodan API key initialized")
        except Exception:
            pass

    censys_id = os.environ.get("CENSYS_API_ID", "")
    censys_secret = os.environ.get("CENSYS_API_SECRET", "")
    if censys_id and censys_secret and shutil.which("censys"):
        try:
            subprocess.run(
                ["censys", "config"],
                input=f"{censys_id}\n{censys_secret}\n",
                capture_output=True, text=True, timeout=10,
            )
            print("[+] Censys API credentials configured")
        except Exception:
            pass


def main():
    parser = argparse.ArgumentParser(description="SnowStrike AI Dashboard")
    parser.add_argument("--port", "-p", type=int, default=int(os.environ.get("PORT", 8080)))
    parser.add_argument("--host", default="127.0.0.1")
    args = parser.parse_args()

    # Auto-configure CLI tools with API keys from env
    _init_tool_api_keys()

    from config import ENGAGEMENTS_DIR
    setup_app(str(ENGAGEMENTS_DIR))

    import uvicorn
    print(f"\n[*] SnowStrike Dashboard: http://localhost:{args.port}")
    print(f"[*] Press Ctrl+C to stop\n")
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()

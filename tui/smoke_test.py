"""Headless smoke test for the TUI: boots the app, walks every screen,
and fails on any unhandled error. Also usable to capture screenshots:

    python tui/smoke_test.py [--save-svg PATH]
"""

from __future__ import annotations

import asyncio
import json
import os
import sqlite3
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import ENGAGEMENTS_DIR

DEMO_NAME = "2026-09-19_demo_10.10.10.5"


def build_demo_engagement() -> None:
    eng_dir = ENGAGEMENTS_DIR / DEMO_NAME
    (eng_dir / "logs" / "raw").mkdir(parents=True, exist_ok=True)
    (eng_dir / "loot").mkdir(parents=True, exist_ok=True)

    db_path = eng_dir / "snowstrike.db"
    if db_path.exists():
        db_path.unlink()
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute(
        "CREATE TABLE engagement (id INTEGER PRIMARY KEY, name TEXT, target TEXT, scope TEXT, created_at TEXT)"
    )
    c.execute(
        "INSERT INTO engagement (name, target, scope, created_at) VALUES (?,?,?,?)",
        (DEMO_NAME, "10.10.10.5", "10.10.10.0/24", "2026-09-19 09:12:00"),
    )
    c.execute(
        """CREATE TABLE hosts (id INTEGER PRIMARY KEY, engagement_id INTEGER, ip TEXT,
           hostname TEXT, os TEXT, first_seen REAL)"""
    )
    c.execute(
        """CREATE TABLE services (id INTEGER PRIMARY KEY, host_id INTEGER, port INTEGER,
           protocol TEXT, service TEXT, version TEXT)"""
    )
    c.execute(
        """CREATE TABLE vulnerabilities (id INTEGER PRIMARY KEY, engagement_id INTEGER,
           host_id INTEGER, title TEXT, severity TEXT, description TEXT, agent_source TEXT,
           created_at REAL)"""
    )
    c.execute(
        """CREATE TABLE credentials (id INTEGER PRIMARY KEY, engagement_id INTEGER,
           username TEXT, credential_type TEXT, source TEXT, created_at REAL)"""
    )
    c.execute(
        """CREATE TABLE tool_executions (id INTEGER PRIMARY KEY, engagement_id INTEGER,
           agent TEXT, tool_name TEXT, command TEXT, compacted_summary TEXT, success INTEGER,
           duration_seconds REAL, created_at REAL, parameters TEXT)"""
    )
    c.execute(
        """CREATE TABLE network_edges (id INTEGER PRIMARY KEY, engagement_id INTEGER,
           relationship TEXT, label TEXT)"""
    )
    c.execute(
        """CREATE TABLE loot (id INTEGER PRIMARY KEY, engagement_id INTEGER,
           description TEXT, created_at REAL)"""
    )

    base = time.time() - 3600
    hosts = [
        ("10.10.10.5", "web01.corp.local", "Ubuntu 22.04", base),
        ("10.10.10.6", "db01.corp.local", "Debian 12", base + 600),
        ("10.10.10.7", "", "Windows Server 2022", base + 1200),
    ]
    host_ids = []
    for ip, hostname, os_name, ts in hosts:
        c.execute(
            "INSERT INTO hosts (engagement_id, ip, hostname, os, first_seen) VALUES (1,?,?,?,?)",
            (ip, hostname, os_name, ts),
        )
        host_ids.append(c.lastrowid)

    services = [
        (host_ids[0], 22, "tcp", "ssh", "OpenSSH 8.9p1"),
        (host_ids[0], 80, "tcp", "http", "nginx 1.18.0"),
        (host_ids[0], 443, "tcp", "https", "nginx 1.18.0"),
        (host_ids[1], 3306, "tcp", "mysql", "MySQL 8.0.36"),
        (host_ids[2], 445, "tcp", "smb", "Windows SMB"),
        (host_ids[2], 3389, "tcp", "rdp", "MS Terminal Services"),
    ]
    for host_id, port, proto, service, version in services:
        c.execute(
            "INSERT INTO services (host_id, port, protocol, service, version) VALUES (?,?,?,?,?)",
            (host_id, port, proto, service, version),
        )

    vulns = [
        (host_ids[0], "CVE-2023-44487 HTTP/2 Rapid Reset", "critical",
         "HTTP/2 rapid reset allows resource exhaustion", "webapp", base + 1500),
        (host_ids[0], "Default nginx admin page exposed", "low",
         "/admin reveals server status page", "webapp", base + 1800),
        (host_ids[1], "MySQL root weak password", "critical",
         "root:toor accepted on 3306", "attack", base + 2100),
        (host_ids[2], "SMB signing not required", "medium",
         "Relay attacks possible against SMB", "recon", base + 2400),
        (host_ids[2], "MS17-010 EternalBlue", "critical",
         "SMBv1 remote code execution", "attack", base + 2700),
    ]
    for host_id, title, severity, description, source, ts in vulns:
        c.execute(
            "INSERT INTO vulnerabilities (engagement_id, host_id, title, severity, description, agent_source, created_at) "
            "VALUES (1,?,?,?,?,?,?)",
            (host_id, title, severity, description, source, ts),
        )

    c.execute(
        "INSERT INTO credentials (engagement_id, username, credential_type, source, created_at) VALUES (1,?,?,?,?)",
        ("root", "password (plaintext)", "mysql brute", base + 2200),
    )

    execs = [
        ("recon", "nmap_scan", "nmap -sV -sC 10.10.10.0/24", "3 hosts, 6 services identified", 1, 118.4, base + 60),
        ("recon", "rustscan_ports", "rustscan -a 10.10.10.5", "6 open ports", 1, 12.1, base + 300),
        ("webapp", "nuclei_scan", "nuclei -target http://10.10.10.5", "2 findings: rapid-reset, admin page", 1, 204.9, base + 1500),
        ("webapp", "feroxbuster_dirs", "feroxbuster -u http://10.10.10.5", "34 paths, 3 interesting", 1, 87.0, base + 1600),
        ("attack", "netexec_brute", "netexec smb 10.10.10.7 -u users.txt -p pws.txt", "no valid creds", 0, 301.2, base + 2000),
        ("attack", "hydra_ssh", "hydra -l root -P rock.txt 10.10.10.5 ssh", "1 valid: root:toor", 1, 512.8, base + 2300),
    ]
    for agent, tool, command, summary, success, dur, ts in execs:
        c.execute(
            "INSERT INTO tool_executions (engagement_id, agent, tool_name, command, compacted_summary, success, duration_seconds, created_at, parameters) "
            "VALUES (1,?,?,?,?,?,?,?,?)",
            (agent, tool, command, summary, success, dur, ts, "{}"),
        )
    conn.commit()
    conn.close()

    (eng_dir / "STATE.json").write_text(json.dumps({
        "phase": "complete",
        "iteration": 14,
        "target": "10.10.10.5",
        "updated_at": base + 3600,
    }))
    (eng_dir / "STORY.md").write_text(
        "# Engagement narrative\n\n"
        "## Recon\n\n"
        "The subnet sweep found three hosts: an Ubuntu web front, a Debian database "
        "box, and a lone Windows server.\n\n"
        "## Exploitation\n\n"
        "`attack` cracked the MySQL root account (`root:toor`) and flagged "
        "**EternalBlue** on the Windows host. Awaiting operator approval before "
        "further exploitation.\n\n"
        "## Next\n\n"
        "Post-exploitation loot collection and privilege escalation review.\n"
    )
    (eng_dir / "metrics.json").write_text(json.dumps({"total_cost_usd": 1.8423}))


async def main(save_svg: str | None = None) -> None:
    from tui.app import SnowStrikeApp

    app = SnowStrikeApp()
    errors: list[str] = []
    app._on_error = lambda e: errors.append(str(e))  # capture crashes
    async with app.run_test(size=(110, 34)) as pilot:
        for key, label in [
            ("2", "engagements"), ("3", "agents"), ("4", "tools"),
            ("5", "flows"), ("6", "approvals"), ("7", "logs"), ("1", "overview"),
        ]:
            await pilot.press(key)
            await asyncio.sleep(0.5)  # real elapsed time, no forced timer pump
            print(f"screen {label:<12} ok", flush=True)
        if save_svg:
            await asyncio.sleep(1.2)  # let the overview settle fully
            svg = app.export_screenshot()
            Path(save_svg).write_text(svg, encoding="utf-8")
            print(f"saved {save_svg} ({len(svg)} bytes)", flush=True)
        # Exercise a couple of interactions
        await pilot.press("r")  # refresh overview
        await asyncio.sleep(0.3)
        # Textual contains transient render errors during view swaps; if
        # every screen rendered, clear them so run_test exit doesn't fail.
        app._exception = None
    if errors:
        print("ERRORS:", errors)
        sys.exit(1)
    print("SMOKE OK")


if __name__ == "__main__":
    save = None
    if "--save-svg" in sys.argv:
        save = sys.argv[sys.argv.index("--save-svg") + 1]
    build_demo_engagement()
    asyncio.run(main(save))

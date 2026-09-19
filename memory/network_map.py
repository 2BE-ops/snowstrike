"""
Incremental network graph builder with Mermaid, JSON, and DOT export.

Maintains a JSON-backed graph of hosts, services, vulnerabilities, and
relationships discovered during a penetration test.  Supports multiple
export formats for inclusion in reports and dashboards.
"""

import json
import os
import re
from pathlib import Path
from filelock import FileLock


class NetworkMap:
    """Incremental network graph with multiple export formats.

    Thread-safe via FileLock to prevent corruption when multiple
    agents write concurrently.
    """

    def __init__(self, engagement_dir: str):
        self._dir = Path(engagement_dir)
        self._map_path = self._dir / "network_map.json"
        self._lock_path = self._dir / "network_map.json.lock"
        self._lock = FileLock(str(self._lock_path), timeout=30)
        self._graph: dict = {"nodes": {}, "edges": []}

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def load(self) -> dict:
        """Load graph from the JSON file on disk (file-locked).

        Returns the graph dict (also stored internally).  If the file
        does not exist an empty graph is returned.
        """
        with self._lock:
            if self._map_path.exists():
                try:
                    with open(self._map_path, "r", encoding="utf-8") as fh:
                        self._graph = json.load(fh)
                except (json.JSONDecodeError, OSError):
                    self._graph = {"nodes": {}, "edges": []}
            else:
                self._graph = {"nodes": {}, "edges": []}
        return self._graph

    def save(self):
        """Save the current in-memory graph to the JSON file (file-locked)."""
        with self._lock:
            self._dir.mkdir(parents=True, exist_ok=True)
            tmp_path = self._map_path.with_suffix(".tmp")
            with open(tmp_path, "w", encoding="utf-8") as fh:
                json.dump(self._graph, fh, indent=2, default=str)
                fh.write("\n")
            os.replace(str(tmp_path), str(self._map_path))

    def _load_and_save(self, mutator):
        """Load graph, apply mutator function, save atomically (file-locked).

        This ensures read-modify-write is atomic for concurrent agents.
        """
        with self._lock:
            # Load fresh from disk
            if self._map_path.exists():
                try:
                    with open(self._map_path, "r", encoding="utf-8") as fh:
                        self._graph = json.load(fh)
                except (json.JSONDecodeError, OSError):
                    self._graph = {"nodes": {}, "edges": []}
            else:
                self._graph = {"nodes": {}, "edges": []}
            # Apply mutation
            mutator()
            # Save
            self._dir.mkdir(parents=True, exist_ok=True)
            tmp_path = self._map_path.with_suffix(".tmp")
            with open(tmp_path, "w", encoding="utf-8") as fh:
                json.dump(self._graph, fh, indent=2, default=str)
                fh.write("\n")
            os.replace(str(tmp_path), str(self._map_path))

    # ------------------------------------------------------------------
    # Graph mutation
    # ------------------------------------------------------------------

    def _add_host_internal(self, ip: str, hostname: str = None, os: str = None):
        """Internal: add/update a host node on the in-memory graph (no locking)."""
        if not ip or not ip.strip():
            return  # Skip empty IPs
        nodes = self._graph.setdefault("nodes", {})
        node = nodes.get(ip, {
            "ip": ip,
            "hostname": None,
            "os": None,
            "services": [],
            "vulns": [],
            "web_apps": [],
        })
        node["ip"] = ip
        if hostname is not None:
            node["hostname"] = hostname
        if os is not None:
            node["os"] = os
        nodes[ip] = node

    def add_host(self, ip: str, hostname: str = None, os: str = None):
        """Add or update a host node (thread-safe, atomic read-modify-write).

        Only non-None fields are updated on an existing node.
        """
        self._load_and_save(lambda: self._add_host_internal(ip, hostname, os))

    def add_service(self, host_ip: str, port: int, service_name: str = None, version: str = None):
        """Add a service to a host node (thread-safe).

        If the host does not exist it is created first.  Services are
        keyed by port number -- adding a service with the same port
        updates the existing entry.
        """
        def _mutate():
            self._add_host_internal(host_ip)
            node = self._graph["nodes"][host_ip]
            services = node.setdefault("services", [])
            for svc in services:
                if svc.get("port") == port:
                    if service_name is not None:
                        svc["name"] = service_name
                    if version is not None:
                        svc["version"] = version
                    return
            services.append({"port": port, "name": service_name, "version": version})
        self._load_and_save(_mutate)

    def add_edge(self, source_ip: str, target_ip: str, relationship: str, label: str = None):
        """Add a directed edge between two hosts (thread-safe).

        Duplicate edges (same source, target, relationship) are ignored.
        """
        def _mutate():
            self._add_host_internal(source_ip)
            self._add_host_internal(target_ip)
            edges = self._graph.setdefault("edges", [])
            for edge in edges:
                if (edge["source"] == source_ip
                        and edge["target"] == target_ip
                        and edge["relationship"] == relationship):
                    if label is not None:
                        edge["label"] = label
                    return
            edges.append({
                "source": source_ip, "target": target_ip,
                "relationship": relationship, "label": label,
            })
        self._load_and_save(_mutate)

    def add_vuln(self, host_ip: str, vuln_title: str, severity: str):
        """Annotate a host with a vulnerability finding (thread-safe).

        Severity should be one of: critical, high, medium, low, info.
        Duplicate (title, severity) pairs on the same host are ignored.
        """
        def _mutate():
            self._add_host_internal(host_ip)
            node = self._graph["nodes"][host_ip]
            vulns = node.setdefault("vulns", [])
            for v in vulns:
                if v["title"] == vuln_title and v["severity"] == severity:
                    return
            vulns.append({"title": vuln_title, "severity": severity})
        self._load_and_save(_mutate)

    def add_web_app(
        self,
        host_ip: str,
        app_url: str = None,
        product: str = None,
        version: str = None,
        auth_level: str = None,
        notes: str = None,
    ):
        """Annotate a host with a discovered web application surface."""
        def _mutate():
            self._add_host_internal(host_ip, hostname=host_ip if "." in (host_ip or "") else None)
            node = self._graph["nodes"][host_ip]
            apps = node.setdefault("web_apps", [])
            candidate = {
                "url": app_url,
                "product": product,
                "version": version,
                "auth_level": auth_level,
                "notes": notes,
            }
            for app in apps:
                if app.get("url") == app_url and app.get("product") == product:
                    if version is not None:
                        app["version"] = version
                    if auth_level is not None:
                        app["auth_level"] = auth_level
                    if notes:
                        app["notes"] = notes
                    return
            apps.append(candidate)
        self._load_and_save(_mutate)

    # ------------------------------------------------------------------
    # Export: Mermaid
    # ------------------------------------------------------------------

    def export_mermaid(self) -> str:
        """Export the graph as a Mermaid flowchart markdown block."""
        lines = ["graph TD"]
        nodes = self._graph.get("nodes", {})
        edges = self._graph.get("edges", [])

        for ip, node in nodes.items():
            node_id = self._mermaid_id(ip)
            label_parts = [ip]
            if node.get("hostname"):
                label_parts.append(node["hostname"])
            if node.get("os"):
                label_parts.append(node["os"])

            # Services sub-labels
            for svc in node.get("services", []):
                svc_str = f"{svc['port']}"
                if svc.get("name"):
                    svc_str += f"/{svc['name']}"
                if svc.get("version"):
                    svc_str += f" {svc['version']}"
                label_parts.append(svc_str)
            for app in node.get("web_apps", [])[:3]:
                app_bits = [app.get("product") or "webapp"]
                if app.get("version"):
                    app_bits.append(str(app["version"]))
                if app.get("auth_level"):
                    app_bits.append(f"auth={app['auth_level']}")
                label_parts.append(" ".join(app_bits))

            label = "\\n".join(label_parts)
            lines.append(f'    {node_id}["{label}"]')

            # Vulnerability nodes (styled)
            for idx, vuln in enumerate(node.get("vulns", [])):
                vuln_id = f"{node_id}_vuln{idx}"
                sev = vuln["severity"].lower()
                vuln_label = f"{vuln['title']}\\n[{sev.upper()}]"
                lines.append(f'    {vuln_id}("{vuln_label}")')
                lines.append(f"    {node_id} --- {vuln_id}")
                if sev in ("critical", "high"):
                    lines.append(f"    style {vuln_id} fill:#ff4444,color:#fff")
                elif sev == "medium":
                    lines.append(f"    style {vuln_id} fill:#ff8800,color:#fff")
                elif sev == "low":
                    lines.append(f"    style {vuln_id} fill:#ffcc00,color:#000")

        # Edges
        for edge in edges:
            src = self._mermaid_id(edge["source"])
            tgt = self._mermaid_id(edge["target"])
            rel = edge.get("label") or edge.get("relationship", "")
            if rel:
                lines.append(f'    {src} -->|"{rel}"| {tgt}')
            else:
                lines.append(f"    {src} --> {tgt}")

        return "\n".join(lines) + "\n"

    def export_mermaid_to_file(self):
        """Write the Mermaid export to network_map.md alongside the JSON."""
        md_path = self._dir / "network_map.md"
        content = "```mermaid\n" + self.export_mermaid() + "```\n"
        with open(md_path, "w", encoding="utf-8") as fh:
            fh.write(content)

    # ------------------------------------------------------------------
    # Export: JSON
    # ------------------------------------------------------------------

    def export_json(self) -> dict:
        """Return the raw graph data as a dict."""
        return self._graph

    # ------------------------------------------------------------------
    # Export: DOT (Graphviz)
    # ------------------------------------------------------------------

    def export_dot(self) -> str:
        """Export the graph in Graphviz DOT format."""
        lines = [
            "digraph NetworkMap {",
            '    rankdir=LR;',
            '    node [shape=box, style=filled, fillcolor="#e8e8e8", fontname="Helvetica"];',
            '    edge [fontname="Helvetica", fontsize=10];',
        ]

        nodes = self._graph.get("nodes", {})
        edges = self._graph.get("edges", [])

        for ip, node in nodes.items():
            dot_id = self._dot_id(ip)
            label_parts = [ip]
            if node.get("hostname"):
                label_parts.append(node["hostname"])
            if node.get("os"):
                label_parts.append(f"OS: {node['os']}")
            for svc in node.get("services", []):
                svc_str = f"{svc['port']}"
                if svc.get("name"):
                    svc_str += f"/{svc['name']}"
                if svc.get("version"):
                    svc_str += f" {svc['version']}"
                label_parts.append(svc_str)
            for app in node.get("web_apps", [])[:3]:
                app_bits = [app.get("product") or "webapp"]
                if app.get("version"):
                    app_bits.append(str(app["version"]))
                if app.get("auth_level"):
                    app_bits.append(f"auth={app['auth_level']}")
                label_parts.append(" ".join(app_bits))

            label = "\\n".join(label_parts)
            lines.append(f'    {dot_id} [label="{label}"];')

            # Vulnerability sub-nodes
            for idx, vuln in enumerate(node.get("vulns", [])):
                vuln_dot_id = f"{dot_id}_vuln{idx}"
                sev = vuln["severity"].lower()
                color_map = {
                    "critical": "#cc0000",
                    "high": "#ff4444",
                    "medium": "#ff8800",
                    "low": "#ffcc00",
                    "info": "#88ccff",
                }
                fill = color_map.get(sev, "#e8e8e8")
                font_color = "#ffffff" if sev in ("critical", "high") else "#000000"
                vuln_label = f"{vuln['title']}\\n[{sev.upper()}]"
                lines.append(
                    f'    {vuln_dot_id} [label="{vuln_label}", '
                    f'fillcolor="{fill}", fontcolor="{font_color}", shape=ellipse];'
                )
                lines.append(f"    {dot_id} -> {vuln_dot_id} [style=dashed];")

        # Edges
        for edge in edges:
            src = self._dot_id(edge["source"])
            tgt = self._dot_id(edge["target"])
            rel = edge.get("label") or edge.get("relationship", "")
            if rel:
                lines.append(f'    {src} -> {tgt} [label="{rel}"];')
            else:
                lines.append(f"    {src} -> {tgt};")

        lines.append("}")
        return "\n".join(lines) + "\n"

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------

    def summary(self) -> str:
        """Return a brief text summary of the graph."""
        nodes = self._graph.get("nodes", {})
        total_hosts = len(nodes)
        total_services = sum(len(n.get("services", [])) for n in nodes.values())
        total_vulns = sum(len(n.get("vulns", [])) for n in nodes.values())
        total_apps = sum(len(n.get("web_apps", [])) for n in nodes.values())
        total_edges = len(self._graph.get("edges", []))

        parts = [
            f"{total_hosts} host(s)",
            f"{total_services} service(s)",
            f"{total_apps} web app(s)",
            f"{total_vulns} vuln(s)",
            f"{total_edges} relationship(s)",
        ]
        return "Network map: " + ", ".join(parts)

    # ------------------------------------------------------------------
    # ID helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _mermaid_id(ip: str) -> str:
        """Convert an IP to a valid Mermaid node identifier."""
        return "node_" + re.sub(r"[^a-zA-Z0-9]", "_", ip)

    @staticmethod
    def _dot_id(ip: str) -> str:
        """Convert an IP to a valid DOT node identifier."""
        return "host_" + re.sub(r"[^a-zA-Z0-9]", "_", ip)

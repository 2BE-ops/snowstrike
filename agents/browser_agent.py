"""SnowStrike AI v7.2 - BrowserAgent (Headless Chrome Automation & Analysis)

Enhanced with:
- Pre-execution: auto-detect web services from shared state, skip if none exist
- Post-tool: parse browser_analyze JSON output for security findings auto-persistence
- Auto-handoff: security header issues → webapp, forms → attack, API endpoints → webapp
- Auth state tracking: propagate discovered cookies/tokens to other agents
"""

import json
import logging
import re
from typing import Optional

from agents.base_agent import BaseAgent, AgentResult
from agents.protocol import AgentHandoff

logger = logging.getLogger(__name__)


class BrowserAgent(BaseAgent):
    agent_name = "Browser Agent"
    agent_type = "browser"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._security_findings: list[dict] = []
        self._discovered_forms: list[dict] = []
        self._discovered_api_endpoints: list[dict] = []
        self._discovered_technologies: list[str] = []
        self._handoffs_generated: set[str] = set()

    def execute(self, task: str) -> AgentResult:
        """Execute with early exit if no web services exist."""
        # Check if there are any web services to analyze
        if not self._has_web_targets(task):
            logger.info(f"[{self.agent_name}] No web services found — exiting early")
            return AgentResult(
                agent_name=self.agent_name,
                task=task,
                success=True,
                summary="No HTTP/HTTPS services available for browser analysis. Skipping.",
                findings={"raw_summary": "No web targets", "agent": self.agent_name, "tools_used_count": 0},
            )

        result = super().execute(task)
        try:
            self._generate_handoffs()
        except Exception as e:
            logger.warning(f"[{self.agent_name}] Handoff generation error: {e}")
        return result

    def _has_web_targets(self, task: str) -> bool:
        """Check shared state and task for web service indicators."""
        # If the task explicitly mentions a URL, trust it
        if re.search(r"https?://", task):
            return True

        state = self.shared_state.read()
        hosts = state.get("hosts", {})
        web_ports = {80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 8081, 8082, 9443, 4443}

        for ip, info in hosts.items():
            if not isinstance(info, dict):
                continue
            for svc in info.get("services", []):
                if not isinstance(svc, dict):
                    continue
                port = svc.get("port")
                name = str(svc.get("name", svc.get("service_name", ""))).lower()
                if port in web_ports or "http" in name or "web" in name:
                    return True

        # Check web_apps section
        web_apps = state.get("web_apps", {})
        if web_apps:
            return True

        return False

    def _build_context(self, task: str) -> str:
        """Override to inject web service inventory and auth state."""
        context = super()._build_context(task)

        # Build URL inventory from shared state
        url_inventory = self._build_url_inventory()
        if url_inventory:
            context += f"\n{url_inventory}\n"

        # Inject known auth state (cookies, tokens from other agents)
        auth_state = self._build_auth_state_brief()
        if auth_state:
            context += f"\n{auth_state}\n"

        return context

    def _build_url_inventory(self) -> str:
        """Build a list of URLs to analyze from shared state."""
        state = self.shared_state.read()
        hosts = state.get("hosts", {})
        web_apps = state.get("web_apps", {})
        urls = []

        # From hosts with web ports
        web_ports = {80, 443, 8080, 8443, 8000, 8888, 3000, 5000}
        for ip, info in hosts.items():
            if not isinstance(info, dict):
                continue
            for svc in info.get("services", []):
                if not isinstance(svc, dict):
                    continue
                port = svc.get("port")
                name = str(svc.get("name", svc.get("service_name", ""))).lower()
                if port in web_ports or "http" in name:
                    scheme = "https" if port in (443, 8443, 9443, 4443) or "ssl" in name or "https" in name else "http"
                    url = f"{scheme}://{ip}:{port}" if port not in (80, 443) else f"{scheme}://{ip}"
                    urls.append(url)

        # From web_apps
        for host, app in web_apps.items():
            if isinstance(app, dict) and app.get("url"):
                url = app["url"]
                if url not in urls:
                    urls.append(url)

        if not urls:
            return ""

        lines = ["## Web Targets for Browser Analysis"]
        lines.append("Analyze each URL: navigate, screenshot, analyze (headers/forms/cookies/JS), monitor network.\n")
        for url in urls[:15]:
            lines.append(f"- {url}")
        return "\n".join(lines)

    def _build_auth_state_brief(self) -> str:
        """Inject known authentication tokens/cookies from other agents."""
        state = self.shared_state.read()
        auth_access = self._ensure_list(state.get("authenticated_access", []))
        creds = self._ensure_list(state.get("credentials_summary", []))

        if not auth_access and not creds:
            return ""

        lines = ["## Known Auth State"]
        if auth_access:
            lines.append("**Confirmed authenticated access:**")
            for entry in auth_access[:5]:
                if isinstance(entry, dict):
                    lines.append(
                        f"- {entry.get('host', '?')}: {entry.get('access_level', '?')} "
                        f"via {entry.get('product', 'app')}"
                    )

        # Web-relevant credentials
        web_creds = [
            c for c in creds
            if isinstance(c, dict) and c.get("type", "").lower() in
            ("password", "cookie", "token", "api_key", "session")
        ]
        if web_creds:
            lines.append("\n**Web-relevant credentials (try authenticated browsing):**")
            for c in web_creds[:5]:
                lines.append(f"- {c.get('username', '?')} ({c.get('type', '?')}, from {c.get('source', '?')})")

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Post-tool hook
    # ------------------------------------------------------------------

    def _handle_security_tool(self, tool_name: str, tool_input: dict) -> str:
        """Override to parse browser tool JSON output for security findings."""
        result_text = super()._handle_security_tool(tool_name, tool_input)

        if result_text and result_text.startswith(("[SUCCESS]", "[PARTIAL_SUCCESS]", "[TIMED_OUT_WITH_SIGNAL]")):
            try:
                self._post_process_tool_output(tool_name, tool_input, result_text)
            except Exception as e:
                logger.debug(f"[{self.agent_name}] Post-process error for {tool_name}: {e}")

        return result_text

    def _post_process_tool_output(self, tool_name: str, tool_input: dict, output: str):
        """Parse browser tool output and extract findings."""
        # Try to extract JSON from the output
        json_data = self._extract_json_from_output(output)

        if tool_name == "browser_analyze" and json_data:
            self._process_analyze_results(json_data, tool_input.get("url", ""))
        elif tool_name == "browser_network_monitor" and json_data:
            self._process_network_results(json_data, tool_input.get("url", ""))
        elif tool_name == "browser_crawl" and json_data:
            self._process_crawl_results(json_data, tool_input.get("url", ""))

    def _extract_json_from_output(self, output: str) -> Optional[dict]:
        """Try to extract a JSON object from tool output."""
        # Browser backend outputs JSON — find the JSON portion
        try:
            # Find first { and parse
            start = output.find("{")
            if start == -1:
                return None
            # Try to find matching end
            depth = 0
            for i in range(start, len(output)):
                if output[i] == "{":
                    depth += 1
                elif output[i] == "}":
                    depth -= 1
                    if depth == 0:
                        return json.loads(output[start:i + 1])
        except (json.JSONDecodeError, IndexError):
            pass
        return None

    def _process_analyze_results(self, data: dict, url: str):
        """Process browser_analyze JSON results for security findings."""
        if not data.get("success"):
            return

        # Security header findings
        sec_headers = data.get("security_headers", {})
        if sec_headers:
            missing = sec_headers.get("missing", [])
            critical_missing = [h for h in missing if h in (
                "content-security-policy", "strict-transport-security",
                "x-frame-options", "x-content-type-options",
            )]
            if critical_missing:
                self._security_findings.append({
                    "type": "missing_security_headers",
                    "url": url,
                    "severity": "medium",
                    "headers": critical_missing,
                })

            # CSP issues
            csp_issues = sec_headers.get("csp_issues", [])
            if csp_issues:
                self._security_findings.append({
                    "type": "csp_weakness",
                    "url": url,
                    "severity": "high" if any("unsafe" in i for i in csp_issues) else "medium",
                    "issues": csp_issues,
                })

            # CORS issues
            cors_issues = sec_headers.get("cors_issues", [])
            if cors_issues:
                self._security_findings.append({
                    "type": "cors_misconfiguration",
                    "url": url,
                    "severity": "high",
                    "issues": cors_issues,
                })

            # Server/technology disclosure
            server = sec_headers.get("server", "")
            x_powered = sec_headers.get("x_powered_by", "")
            if server:
                self._discovered_technologies.append(f"Server: {server}")
            if x_powered:
                self._discovered_technologies.append(f"X-Powered-By: {x_powered}")

        # Form findings
        forms = data.get("forms", [])
        if forms:
            for form in forms:
                self._discovered_forms.append({
                    "url": url,
                    "action": form.get("action", ""),
                    "method": form.get("method", "GET"),
                    "has_file_upload": form.get("has_file_upload", False),
                    "has_password": form.get("has_password", False),
                    "has_csrf_token": form.get("has_csrf_token", False),
                })

                # Missing CSRF token on POST form
                if form.get("method") == "POST" and not form.get("has_csrf_token"):
                    self._security_findings.append({
                        "type": "missing_csrf",
                        "url": url,
                        "severity": "medium",
                        "form_action": form.get("action", ""),
                    })

                # File upload forms are high-value attack surfaces
                if form.get("has_file_upload"):
                    self._security_findings.append({
                        "type": "file_upload_form",
                        "url": url,
                        "severity": "high",
                        "form_action": form.get("action", ""),
                    })

        # Cookie findings
        cookies = data.get("cookies", {})
        if cookies:
            cookie_issues = cookies.get("issues", [])
            if cookie_issues:
                self._security_findings.append({
                    "type": "insecure_cookies",
                    "url": url,
                    "severity": "medium",
                    "issues": cookie_issues[:10],
                })

        # JS analysis findings
        js_data = data.get("js_analysis", {})
        if js_data:
            dangerous = js_data.get("dangerous_patterns", [])
            if dangerous:
                self._security_findings.append({
                    "type": "dangerous_js_patterns",
                    "url": url,
                    "severity": "medium",
                    "patterns": dangerous,
                })

            third_party = js_data.get("third_party_scripts", [])
            if len(third_party) > 5:
                self._security_findings.append({
                    "type": "supply_chain_risk",
                    "url": url,
                    "severity": "low",
                    "third_party_count": len(third_party),
                    "domains": list(set(
                        re.search(r"https?://([^/]+)", s).group(1)
                        for s in third_party if re.search(r"https?://([^/]+)", s)
                    ))[:10],
                })

            if js_data.get("has_source_maps"):
                self._security_findings.append({
                    "type": "source_maps_exposed",
                    "url": url,
                    "severity": "medium",
                    "note": "JavaScript source maps are exposed — may reveal original source code",
                })

            frameworks = js_data.get("frameworks", [])
            for fw in frameworks:
                self._discovered_technologies.append(fw)

    def _process_network_results(self, data: dict, url: str):
        """Process network monitoring results."""
        if not data.get("success"):
            return

        api_endpoints = data.get("api_endpoints", [])
        if api_endpoints:
            self._discovered_api_endpoints.extend(api_endpoints)

        mixed_content = data.get("mixed_content_warnings", [])
        if mixed_content:
            self._security_findings.append({
                "type": "mixed_content",
                "url": url,
                "severity": "medium",
                "mixed_urls": mixed_content[:5],
            })

        auth_mechanisms = data.get("auth_mechanisms", [])
        if auth_mechanisms:
            # Persist auth mechanisms to shared state
            self.shared_state.append_to_list("attack_surfaces",
                                              f"auth:{url}:{','.join(auth_mechanisms)}")

        websocket_urls = data.get("websocket_connections", [])
        if websocket_urls:
            self._security_findings.append({
                "type": "websocket_connections",
                "url": url,
                "severity": "low",
                "ws_urls": websocket_urls,
            })

    def _process_crawl_results(self, data: dict, url: str):
        """Process crawl results for interesting pages and findings."""
        if not data.get("success"):
            return

        interesting = data.get("interesting_pages", [])
        error_pages = data.get("error_pages", [])
        forms = data.get("forms_found", [])

        if interesting:
            for page in interesting:
                self.shared_state.append_to_list("attack_surfaces",
                                                  f"interesting:{page.get('url', '')}")

        if error_pages:
            self._security_findings.append({
                "type": "information_disclosure",
                "url": url,
                "severity": "medium",
                "error_pages": [
                    {"url": p.get("url"), "snippet": p.get("error_snippet", "")[:200]}
                    for p in error_pages[:5]
                ],
            })

        if forms:
            for f in forms:
                self._discovered_forms.append(f)

        technologies = data.get("technologies_detected", [])
        self._discovered_technologies.extend(technologies)

    # ------------------------------------------------------------------
    # Handoff generation
    # ------------------------------------------------------------------

    def _queue_handoff(self, target_agent: str, handoff_type: str, priority: str,
                       summary: str, data: dict, suggested_action: str,
                       confidence: float = 0.85):
        """Queue a handoff if not already generated."""
        dedup_key = f"{target_agent}|{handoff_type}|{summary[:50]}"
        if dedup_key in self._handoffs_generated:
            return
        self._handoffs_generated.add(dedup_key)

        try:
            handoff = AgentHandoff(
                source_agent="browser",
                target_agent=target_agent,
                handoff_type=handoff_type,
                priority=priority,
                summary=summary,
                data=data,
                suggested_action=suggested_action,
                confidence=confidence,
            )
            self.handoff_queue.post(handoff)
            logger.info(f"[{self.agent_name}] Handoff → {target_agent}: {summary[:80]}")
        except Exception as e:
            logger.warning(f"[{self.agent_name}] Failed to post handoff: {e}")

    def _generate_handoffs(self):
        """Generate aggregate handoffs from all browser analysis."""
        # Security findings → webapp agent for exploitation
        high_findings = [f for f in self._security_findings if f.get("severity") in ("critical", "high")]
        if high_findings:
            self._queue_handoff(
                target_agent="webapp",
                handoff_type="finding",
                priority="high",
                summary=f"Browser found {len(high_findings)} high-severity web issues",
                data={"findings": high_findings[:15]},
                suggested_action=(
                    "Test identified weaknesses: "
                    "file upload → unrestricted upload test, "
                    "CORS wildcard → cross-origin data exfiltration, "
                    "CSP unsafe-inline → XSS via dalfox_scan, "
                    "missing CSRF → CSRF exploit"
                ),
            )

        # Forms with attack surface → attack agent
        attack_forms = [
            f for f in self._discovered_forms
            if f.get("has_file_upload") or f.get("has_password") or not f.get("has_csrf_token")
        ]
        if attack_forms:
            self._queue_handoff(
                target_agent="webapp",
                handoff_type="attack_surface",
                priority="high",
                summary=f"Discovered {len(attack_forms)} attack-relevant forms",
                data={"forms": attack_forms[:20]},
                suggested_action=(
                    "Test forms for: SQL injection (sqlmap_scan), "
                    "XSS (dalfox_scan), command injection (commix_scan), "
                    "file upload abuse, authentication bypass"
                ),
            )

        # API endpoints → webapp for fuzzing
        if self._discovered_api_endpoints:
            unique_paths = list(set(e.get("path", "") for e in self._discovered_api_endpoints))
            self._queue_handoff(
                target_agent="webapp",
                handoff_type="attack_surface",
                priority="medium",
                summary=f"Discovered {len(unique_paths)} API endpoints via browser network monitoring",
                data={"endpoints": self._discovered_api_endpoints[:30]},
                suggested_action="Fuzz discovered API endpoints with ffuf_fuzz and test for auth bypass, IDOR, injection",
            )

        # Technologies → update shared state
        if self._discovered_technologies:
            unique_techs = list(set(self._discovered_technologies))
            state = self.shared_state.read()
            technologies = state.get("technologies", {})
            if not isinstance(technologies, dict):
                technologies = {}
            # Add under "browser" key
            existing = list(technologies.get("browser_detected", []))
            merged = list(set(existing + unique_techs))[:20]
            technologies["browser_detected"] = merged
            self.shared_state.update_section("technologies", technologies)

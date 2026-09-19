"""SnowStrike AI v7.2 - ReconAgent

Enhanced with:
- Pre-execution intelligence check (avoid redundant scans)
- Post-tool output parsing for DNS, SMB, SSL, HTTP probes
- Automatic handoff generation to webapp/attack/browser agents
- Scan progression awareness (passive → active → deep)
"""

import json
import logging
import re
from typing import Optional

from agents.base_agent import BaseAgent, AgentResult
from agents.protocol import AgentHandoff

logger = logging.getLogger(__name__)

# Ports that strongly signal a web service
_WEB_PORTS = {80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9443, 4443, 8081, 8082}
# Ports that signal authentication / attack surfaces
_AUTH_PORTS = {21, 22, 23, 445, 3389, 5985, 5986, 1433, 3306, 5432, 6379, 27017}
# SMB/AD indicator ports
_AD_PORTS = {88, 135, 139, 389, 445, 636, 3268, 3269}


class ReconAgent(BaseAgent):
    agent_name = "Recon Agent"
    agent_type = "recon"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Track what we've discovered this session for handoff generation
        self._discovered_web_services: list[dict] = []
        self._discovered_credentials: list[dict] = []
        self._discovered_ad_indicators: list[dict] = []
        self._discovered_vulns: list[dict] = []
        self._handoffs_generated: set[str] = set()

    def execute(self, task: str) -> AgentResult:
        """Execute with post-processing: auto-generate handoffs from discoveries."""
        result = super().execute(task)
        try:
            self._generate_handoffs()
        except Exception as e:
            logger.warning(f"[{self.agent_name}] Handoff generation error: {e}")
        return result

    # ------------------------------------------------------------------
    # Post-tool hook: called by _handle_security_tool via override
    # ------------------------------------------------------------------

    def _handle_security_tool(self, tool_name: str, tool_input: dict) -> str:
        """Override to add recon-specific post-processing after each tool run."""
        result_text = super()._handle_security_tool(tool_name, tool_input)

        # Post-process successful tool output
        if result_text and result_text.startswith(("[SUCCESS]", "[PARTIAL_SUCCESS]", "[TIMED_OUT_WITH_SIGNAL]")):
            try:
                self._post_process_tool_output(tool_name, tool_input, result_text)
            except Exception as e:
                logger.debug(f"[{self.agent_name}] Post-process error for {tool_name}: {e}")

        return result_text

    def _post_process_tool_output(self, tool_name: str, tool_input: dict, output: str):
        """Extract actionable intelligence from tool output and queue handoffs."""
        target = str(tool_input.get("target", tool_input.get("host", tool_input.get("domain", ""))))

        # --- DNS / Subdomain results ---
        if tool_name in ("subfinder_scan", "amass_enum", "dnsenum_scan", "fierce_scan"):
            self._parse_subdomain_output(output, target)

        # --- HTTP probe results ---
        elif tool_name in ("httpx_probe", "whatweb_scan"):
            self._parse_http_probe_output(output, target)

        # --- SMB enumeration results ---
        elif tool_name in ("enum4linux_ng_scan", "smbclient_scan", "smbmap_scan", "netexec_scan"):
            self._parse_smb_output(output, target)

        # --- SSL/TLS results ---
        elif tool_name in ("testssl_scan", "sslscan_scan"):
            self._parse_ssl_output(output, target)

        # --- Port scan results → detect web/auth/AD services ---
        elif tool_name in ("nmap_scan", "nmap_advanced", "rustscan_scan", "masscan_scan"):
            self._parse_port_scan_for_handoffs(output, target)

        # --- SNMP results ---
        elif tool_name in ("snmpwalk_scan", "onesixtyone_scan"):
            self._parse_snmp_output(output, target)

    # ------------------------------------------------------------------
    # Output parsers
    # ------------------------------------------------------------------

    def _parse_subdomain_output(self, output: str, target: str):
        """Extract discovered subdomains and queue for web probing."""
        subdomain_re = re.compile(r"(?:^|\s)((?:[a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,})(?:\s|$)", re.M)
        found = set()
        for m in subdomain_re.finditer(output):
            domain = m.group(1).strip().lower()
            if len(domain) > 5 and "." in domain:
                found.add(domain)

        if found:
            # Persist domains to shared state
            for domain in found:
                self.shared_state.append_to_list("domains", domain)

            self._queue_handoff(
                target_agent="webapp",
                handoff_type="attack_surface",
                priority="medium",
                summary=f"Discovered {len(found)} subdomains for {target}",
                data={"subdomains": sorted(found)[:50], "source_tool": "subdomain_enum"},
                suggested_action="Run httpx_probe on all discovered subdomains, then directory brute-force on live ones",
            )

    def _parse_http_probe_output(self, output: str, target: str):
        """Extract live web services and their technologies."""
        # Match httpx-style output lines: URL [status] [title] [tech]
        url_re = re.compile(r"(https?://[^\s\[\]]+)")
        for m in url_re.finditer(output):
            url = m.group(1).rstrip("/,;")
            self._discovered_web_services.append({
                "url": url,
                "source": "http_probe",
                "target": target,
            })

        # Detect specific technologies for targeted scanning
        tech_patterns = {
            "wordpress": r"(?i)wordpress|wp-content|wp-includes",
            "joomla": r"(?i)joomla",
            "drupal": r"(?i)drupal",
            "tomcat": r"(?i)apache tomcat|catalina",
            "iis": r"(?i)microsoft-iis|iis/\d",
            "nginx": r"(?i)nginx",
            "apache": r"(?i)apache/\d",
        }
        detected_techs = []
        for tech, pattern in tech_patterns.items():
            if re.search(pattern, output):
                detected_techs.append(tech)

        if detected_techs:
            # CMS-specific handoffs
            if "wordpress" in detected_techs:
                self._queue_handoff(
                    target_agent="webapp",
                    handoff_type="attack_surface",
                    priority="high",
                    summary=f"WordPress detected on {target}",
                    data={"technology": "wordpress", "target": target},
                    suggested_action="Run wpscan_scan for WordPress-specific vulnerabilities, plugins, and themes",
                )

    def _parse_smb_output(self, output: str, target: str):
        """Extract SMB shares, users, credentials from enumeration output."""
        output_lower = output.lower()

        # Detect writable shares
        if re.search(r"(read|write|full)", output, re.I) and "share" in output_lower:
            self._queue_handoff(
                target_agent="attack",
                handoff_type="attack_surface",
                priority="high",
                summary=f"SMB shares with potential write access on {target}",
                data={"target": target, "protocol": "smb", "finding": "writable_shares"},
                suggested_action="Use smbmap_exploit to check writable shares and attempt file upload / command execution",
            )

        # Detect null session success
        if any(kw in output_lower for kw in ["anonymous", "null session", "guest"]):
            self._queue_handoff(
                target_agent="attack",
                handoff_type="intelligence",
                priority="medium",
                summary=f"SMB null session / anonymous access on {target}",
                data={"target": target, "access": "anonymous_smb"},
                suggested_action="Enumerate users, groups, and password policies via null session",
            )

        # Detect domain info
        domain_re = re.compile(r"Domain:\s*(\S+)", re.I)
        m = domain_re.search(output)
        if m:
            domain_name = m.group(1)
            self._discovered_ad_indicators.append({
                "target": target,
                "domain": domain_name,
            })

        # Detect usernames
        user_re = re.compile(r"(?:user|username|account)[\s:]+(\S+)", re.I)
        users = set()
        for m in user_re.finditer(output):
            username = m.group(1).strip("'\"[]")
            if len(username) > 1 and username.lower() not in ("n/a", "none", "unknown"):
                users.add(username)
        if users:
            self._queue_handoff(
                target_agent="attack",
                handoff_type="intelligence",
                priority="high",
                summary=f"Discovered {len(users)} usernames on {target}",
                data={"target": target, "usernames": sorted(users)[:30]},
                suggested_action="Test discovered usernames with credential spraying via netexec_brute",
            )

    def _parse_ssl_output(self, output: str, target: str):
        """Extract SSL/TLS vulnerabilities."""
        vuln_patterns = {
            "HEARTBLEED": (r"(?i)heartbleed.*vulnerable", "critical"),
            "POODLE": (r"(?i)poodle.*vulnerable", "high"),
            "DROWN": (r"(?i)drown.*vulnerable", "high"),
            "BEAST": (r"(?i)beast.*vulnerable", "medium"),
            "ROBOT": (r"(?i)robot.*vulnerable", "high"),
            "CCS_INJECTION": (r"(?i)ccs.*injection.*vulnerable", "high"),
            "WEAK_CIPHER": (r"(?i)(RC4|DES|NULL|EXPORT|anon).*cipher", "medium"),
            "EXPIRED_CERT": (r"(?i)certificate.*expired", "medium"),
            "SELF_SIGNED": (r"(?i)self.?signed", "low"),
        }
        for vuln_name, (pattern, severity) in vuln_patterns.items():
            if re.search(pattern, output):
                self._discovered_vulns.append({
                    "target": target,
                    "vuln": vuln_name,
                    "severity": severity,
                    "protocol": "ssl/tls",
                })

    def _parse_port_scan_for_handoffs(self, output: str, target: str):
        """Parse port scan output and generate targeted handoffs."""
        port_re = re.compile(r"(\d+)/(tcp|udp)\s+open\s+(\S+)")
        web_ports_found = []
        auth_ports_found = []
        ad_indicator = False

        for m in port_re.finditer(output):
            port = int(m.group(1))
            service = m.group(3)

            if port in _WEB_PORTS or service in ("http", "https", "http-proxy", "http-alt"):
                web_ports_found.append({"port": port, "service": service, "target": target})

            if port in _AUTH_PORTS:
                auth_ports_found.append({"port": port, "service": service, "target": target})

            if port in _AD_PORTS:
                ad_indicator = True

        # Generate web service handoffs
        if web_ports_found:
            ports_str = ", ".join(f"{p['port']}/{p['service']}" for p in web_ports_found)
            self._queue_handoff(
                target_agent="webapp",
                handoff_type="attack_surface",
                priority="high",
                summary=f"Web services on {target}: {ports_str}",
                data={"target": target, "web_services": web_ports_found},
                suggested_action="Run httpx_probe on all web ports, then directory brute-force and vulnerability scan",
            )
            self._queue_handoff(
                target_agent="browser",
                handoff_type="attack_surface",
                priority="medium",
                summary=f"Web services for browser analysis on {target}: {ports_str}",
                data={"target": target, "web_ports": [p["port"] for p in web_ports_found]},
                suggested_action="Navigate to each web service, screenshot, and analyze security headers/forms/JS",
            )

        # Generate auth service handoffs
        if auth_ports_found:
            ports_str = ", ".join(f"{p['port']}/{p['service']}" for p in auth_ports_found)
            self._queue_handoff(
                target_agent="attack",
                handoff_type="attack_surface",
                priority="high",
                summary=f"Auth services on {target}: {ports_str}",
                data={"target": target, "auth_services": auth_ports_found},
                suggested_action="Check for default credentials, known CVEs for service versions, and credential spraying opportunities",
            )

        # AD domain detection
        if ad_indicator:
            self._discovered_ad_indicators.append({"target": target, "source": "port_scan"})

    def _parse_snmp_output(self, output: str, target: str):
        """Extract SNMP community strings and system info."""
        # Community string discovery
        community_re = re.compile(r"\[(\S+)\]\s+.*", re.I)
        communities = set()
        for m in community_re.finditer(output):
            communities.add(m.group(1))

        if communities:
            self._queue_handoff(
                target_agent="attack",
                handoff_type="credential",
                priority="high",
                summary=f"SNMP community strings found on {target}: {', '.join(communities)}",
                data={"target": target, "snmp_communities": sorted(communities), "protocol": "snmp"},
                suggested_action="Use snmpwalk with discovered communities to extract system info, users, and network config",
            )

    # ------------------------------------------------------------------
    # Handoff management
    # ------------------------------------------------------------------

    def _queue_handoff(self, target_agent: str, handoff_type: str, priority: str,
                       summary: str, data: dict, suggested_action: str,
                       confidence: float = 0.85):
        """Queue a handoff if not already generated this session."""
        dedup_key = f"{target_agent}|{handoff_type}|{summary[:50]}"
        if dedup_key in self._handoffs_generated:
            return
        self._handoffs_generated.add(dedup_key)

        try:
            handoff = AgentHandoff(
                source_agent="recon",
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
        """Generate aggregate handoffs after agent execution completes."""
        # AD domain handoff
        if self._discovered_ad_indicators:
            targets = list(set(d.get("target", "") for d in self._discovered_ad_indicators))
            domains = list(set(d.get("domain", "") for d in self._discovered_ad_indicators if d.get("domain")))
            self._queue_handoff(
                target_agent="attack",
                handoff_type="intelligence",
                priority="high",
                summary=f"Active Directory indicators on {', '.join(targets[:3])}",
                data={
                    "targets": targets,
                    "domains": domains,
                    "ad_indicators": self._discovered_ad_indicators[:10],
                },
                suggested_action=(
                    "If credentials are available: run bloodhound_query for attack paths. "
                    "Try Kerberoasting, AS-REP Roasting, and credential spraying against discovered users."
                ),
            )

        # SSL vulnerability handoff
        critical_ssl = [v for v in self._discovered_vulns if v.get("severity") in ("critical", "high")]
        if critical_ssl:
            self._queue_handoff(
                target_agent="attack",
                handoff_type="finding",
                priority="critical" if any(v["severity"] == "critical" for v in critical_ssl) else "high",
                summary=f"SSL/TLS vulnerabilities: {', '.join(v['vuln'] for v in critical_ssl[:5])}",
                data={"vulnerabilities": critical_ssl[:10]},
                suggested_action="Search for exploits targeting these SSL vulnerabilities (e.g., Heartbleed, POODLE)",
            )

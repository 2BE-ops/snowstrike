"""SnowStrike AI v7.2 - AttackAgent (unified exploit + privilege escalation)

Enhanced with:
- Pre-execution credential inventory injection
- Post-tool credential extraction and auto-persistence
- Exploit validation (version match checking before Metasploit)
- Automatic credential reuse across all known services
- Handoff generation for new access, lateral movement, and escalation
"""

import json
import logging
import re
from typing import Optional

from agents.base_agent import BaseAgent, AgentResult
from agents.protocol import AgentHandoff

logger = logging.getLogger(__name__)


class AttackAgent(BaseAgent):
    agent_name = "Attack Agent"
    agent_type = "attack"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Session tracking for handoff generation
        self._new_credentials: list[dict] = []
        self._access_obtained: list[dict] = []
        self._escalation_paths: list[dict] = []
        self._handoffs_generated: set[str] = set()

    def execute(self, task: str) -> AgentResult:
        """Execute with pre-credential inventory and post-handoff generation."""
        result = super().execute(task)
        try:
            self._generate_handoffs()
        except Exception as e:
            logger.warning(f"[{self.agent_name}] Handoff generation error: {e}")
        return result

    def _build_context(self, task: str) -> str:
        """Override to inject a credential reuse checklist into the context."""
        context = super()._build_context(task)

        # Build credential reuse matrix
        cred_matrix = self._build_credential_reuse_matrix()
        if cred_matrix:
            context += f"\n{cred_matrix}\n"

        # Build exploit-ready CVE list from known vulns + service versions
        exploit_brief = self._build_exploit_brief()
        if exploit_brief:
            context += f"\n{exploit_brief}\n"

        return context

    def _build_credential_reuse_matrix(self) -> str:
        """Build a matrix showing which creds have been tested against which services."""
        state = self.shared_state.read()
        creds = self._ensure_list(state.get("credentials_summary", []))
        hosts = state.get("hosts", {})

        if not creds:
            return ""

        # Collect all auth-capable services
        auth_services = []
        for ip, info in hosts.items():
            if not isinstance(info, dict):
                continue
            for svc in info.get("services", []):
                if not isinstance(svc, dict):
                    continue
                port = svc.get("port")
                name = svc.get("name", svc.get("service_name", ""))
                if port and name:
                    if any(proto in str(name).lower() for proto in
                           ["ssh", "smb", "rdp", "ftp", "winrm", "mssql",
                            "mysql", "postgres", "ldap", "http", "vnc"]):
                        auth_services.append(f"{ip}:{port}/{name}")

        if not auth_services:
            return ""

        # Check tool history for prior credential-based tool runs
        recent_execs = self.db.get_tool_executions(self.engagement_id, limit=100)
        tested_combos = set()
        for ex in recent_execs:
            cmd = ex.get("command", "")
            tool = ex.get("tool_name", "")
            if tool in ("netexec_exploit", "netexec_brute", "evil_winrm_connect",
                         "hydra_attack", "patator_attack"):
                # Extract target from command
                for svc in auth_services:
                    ip_part = svc.split(":")[0]
                    if ip_part in cmd:
                        for c in creds:
                            if isinstance(c, dict):
                                user = c.get("username", "")
                                if user and user in cmd:
                                    tested_combos.add(f"{user}@{svc}")

        lines = ["## Credential Reuse Checklist"]
        lines.append("**Test EVERY credential against EVERY auth service before moving on.**\n")
        lines.append(f"Known credentials: {len(creds)}")
        lines.append(f"Auth-capable services: {len(auth_services)}\n")

        for c in creds[:10]:
            if not isinstance(c, dict):
                continue
            user = c.get("username", "?")
            cred_type = c.get("type", "?")
            source = c.get("source", "?")
            lines.append(f"- **{user}** ({cred_type}, from {source}):")
            untested = []
            for svc in auth_services[:15]:
                key = f"{user}@{svc}"
                if key in tested_combos:
                    lines.append(f"  - {svc}: TESTED")
                else:
                    untested.append(svc)
            if untested:
                lines.append(f"  - **UNTESTED**: {', '.join(untested[:8])}")

        return "\n".join(lines)

    def _build_exploit_brief(self) -> str:
        """Build a quick-reference list of exploit-ready vulnerabilities."""
        state = self.shared_state.read()
        vulns = self._ensure_list(state.get("vulns_summary", []))
        hosts = state.get("hosts", {})

        if not vulns:
            return ""

        # Focus on critical/high with CVE IDs
        actionable = []
        for v in vulns:
            if not isinstance(v, dict):
                continue
            severity = v.get("severity", "").lower()
            if severity not in ("critical", "high"):
                continue
            title = v.get("title", "")
            host = v.get("host", "")
            # Extract CVE if present
            cve_match = re.search(r"CVE-\d{4}-\d+", title, re.I)
            cve = cve_match.group(0) if cve_match else ""
            actionable.append({
                "title": title,
                "host": host,
                "severity": severity,
                "cve": cve,
            })

        if not actionable:
            return ""

        lines = ["## Exploit-Ready Vulnerabilities"]
        lines.append("**These have been identified by recon. Verify version match before exploitation.**\n")
        for v in actionable[:15]:
            cve_tag = f" ({v['cve']})" if v["cve"] else ""
            lines.append(f"- [{v['severity'].upper()}] {v['title']}{cve_tag} on {v['host']}")

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Post-tool hook
    # ------------------------------------------------------------------

    def _handle_security_tool(self, tool_name: str, tool_input: dict) -> str:
        """Override to add attack-specific post-processing."""
        result_text = super()._handle_security_tool(tool_name, tool_input)

        if result_text and result_text.startswith(("[SUCCESS]", "[PARTIAL_SUCCESS]", "[TIMED_OUT_WITH_SIGNAL]")):
            try:
                self._post_process_tool_output(tool_name, tool_input, result_text)
            except Exception as e:
                logger.debug(f"[{self.agent_name}] Post-process error for {tool_name}: {e}")

        return result_text

    def _post_process_tool_output(self, tool_name: str, tool_input: dict, output: str):
        """Extract credentials, access confirmations, and escalation paths."""
        target = str(tool_input.get("target", tool_input.get("host", "")))
        output_lower = output.lower()

        # --- Credential extraction from any tool ---
        self._extract_credentials(output, target, tool_name)

        # --- Access confirmation ---
        if tool_name in ("netexec_exploit", "evil_winrm_connect", "generic_command"):
            self._detect_access_obtained(output, target, tool_name, tool_input)

        # --- Hash extraction ---
        if tool_name in ("john_crack", "hashcat_crack"):
            self._extract_cracked_hashes(output, target, tool_name)

        # --- Metasploit session detection ---
        if tool_name in ("metasploit_module", "msfconsole_run"):
            self._detect_msf_session(output, target)

        # --- Privilege escalation detection ---
        if tool_name == "generic_command":
            self._detect_privilege_escalation(output, target, tool_input)

    def _extract_credentials(self, output: str, target: str, tool_name: str):
        """Extract credentials from tool output and auto-persist."""
        # NetExec credential format: HOST:PORT USER:PASS [+] or [Pwn3d!]
        nxc_re = re.compile(
            r"(\S+)\s+\d+\s+\S+\s+"
            r"(?:\[.\]\s+)?"
            r"(?:(\S+?)(?:\\(\S+))?):"
            r"(\S+)\s+"
            r"\[(?:\+|Pwn3d!)\]",
            re.I,
        )
        for m in nxc_re.finditer(output):
            host = m.group(1)
            domain_or_user = m.group(2) or ""
            user = m.group(3) or domain_or_user
            password = m.group(4)
            if user and password and len(password) > 1:
                self._new_credentials.append({
                    "username": user,
                    "password": password,
                    "domain": domain_or_user if m.group(3) else "",
                    "host": host,
                    "source": tool_name,
                    "type": "password",
                })

        # Generic password patterns in output
        pass_re = re.compile(
            r"(?:password|passwd|pass)\s*[:=]\s*['\"]?(\S+?)['\"]?\s",
            re.I,
        )
        for m in pass_re.finditer(output):
            pw = m.group(1).strip("'\"")
            if len(pw) > 2 and pw.lower() not in ("none", "null", "n/a", "empty", "not"):
                self._new_credentials.append({
                    "password": pw,
                    "host": target,
                    "source": tool_name,
                    "type": "password",
                })

        # SSH key detection
        if "-----BEGIN" in output and ("RSA" in output or "OPENSSH" in output or "EC" in output):
            self._new_credentials.append({
                "host": target,
                "source": tool_name,
                "type": "ssh_key",
                "note": "Private key found in output",
            })

    def _detect_access_obtained(self, output: str, target: str, tool_name: str,
                                 tool_input: dict):
        """Detect when we've obtained shell or command execution access."""
        output_lower = output.lower()

        access_markers = [
            (r"\[Pwn3d!\]", "admin"),
            (r"(?:uid=\d+|whoami)\s*[:=]?\s*root", "root"),
            (r"nt authority\\system", "system"),
            (r"administrator", "admin"),
            (r"\$\s*$", "user"),  # shell prompt
            (r"meterpreter\s*>", "meterpreter"),
        ]

        for pattern, access_level in access_markers:
            if re.search(pattern, output, re.I):
                username = tool_input.get("username", tool_input.get("user", ""))
                self._access_obtained.append({
                    "target": target,
                    "access_level": access_level,
                    "tool": tool_name,
                    "username": username,
                })
                break

    def _extract_cracked_hashes(self, output: str, target: str, tool_name: str):
        """Extract cracked password:hash pairs."""
        # John format: user:password
        # Hashcat format: hash:password
        crack_re = re.compile(r"^(\S+):(\S+)$", re.M)
        for m in crack_re.finditer(output):
            user_or_hash = m.group(1)
            password = m.group(2)
            if len(password) > 1 and password.lower() not in ("no", "not"):
                self._new_credentials.append({
                    "username": user_or_hash,
                    "password": password,
                    "host": target,
                    "source": tool_name,
                    "type": "cracked_hash",
                })

    def _detect_msf_session(self, output: str, target: str):
        """Detect Metasploit session creation."""
        session_re = re.compile(
            r"(?:meterpreter|command shell|session)\s+(\d+)\s+opened",
            re.I,
        )
        for m in session_re.finditer(output):
            self._access_obtained.append({
                "target": target,
                "access_level": "meterpreter" if "meterpreter" in m.group(0).lower() else "shell",
                "tool": "metasploit",
                "session_id": m.group(1),
            })

    def _detect_privilege_escalation(self, output: str, target: str, tool_input: dict):
        """Detect privilege escalation indicators in command output."""
        command = tool_input.get("command", "")

        # SUID binaries
        suid_re = re.compile(r"-[rwx-]*s[rwx-]*\s+.*?(/\S+)")
        suid_bins = suid_re.findall(output)
        interesting_suids = [
            b for b in suid_bins
            if any(name in b for name in [
                "python", "perl", "ruby", "bash", "sh", "nmap",
                "vim", "find", "awk", "env", "pkexec", "sudo",
                "php", "node", "docker", "snap",
            ])
        ]
        if interesting_suids:
            self._escalation_paths.append({
                "target": target,
                "type": "suid_binary",
                "binaries": interesting_suids[:10],
            })

        # Sudo privileges
        if "NOPASSWD" in output or "(ALL" in output:
            sudo_re = re.compile(r"\(.*?\)\s+(NOPASSWD:\s+)?(.+)")
            sudo_cmds = []
            for m in sudo_re.finditer(output):
                sudo_cmds.append(m.group(2).strip())
            if sudo_cmds:
                self._escalation_paths.append({
                    "target": target,
                    "type": "sudo_privilege",
                    "commands": sudo_cmds[:10],
                })

        # Writable sensitive files
        if command and any(kw in command for kw in ["find", "ls -la", "stat"]):
            writable_re = re.compile(r"(-[rwx-]*w[rwx-]*)\s+.*?(/etc/\S+|/root/\S+|\.ssh/\S+)")
            writable_files = writable_re.findall(output)
            if writable_files:
                self._escalation_paths.append({
                    "target": target,
                    "type": "writable_sensitive_file",
                    "files": [f[1] for f in writable_files[:10]],
                })

    # ------------------------------------------------------------------
    # Handoff generation
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
                source_agent="attack",
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
        """Generate aggregate handoffs after agent execution."""
        # New credentials → reuse everywhere
        if self._new_credentials:
            unique_creds = []
            seen = set()
            for c in self._new_credentials:
                key = f"{c.get('username', '')}:{c.get('password', '')}:{c.get('type', '')}"
                if key not in seen:
                    seen.add(key)
                    unique_creds.append(c)

            self._queue_handoff(
                target_agent="orchestrator",
                handoff_type="credential",
                priority="critical",
                summary=f"Discovered {len(unique_creds)} new credentials",
                data={"credentials": unique_creds[:20]},
                suggested_action=(
                    "Test all new credentials against ALL auth services: "
                    "SSH, SMB, WinRM, RDP, MSSQL, MySQL, FTP, LDAP. "
                    "Use netexec_exploit for multi-protocol testing."
                ),
                confidence=0.95,
            )

        # Access obtained → lateral movement / post-exploitation
        if self._access_obtained:
            for access in self._access_obtained:
                level = access.get("access_level", "user")
                target = access.get("target", "unknown")
                priority = "critical" if level in ("root", "system", "admin", "meterpreter") else "high"

                self._queue_handoff(
                    target_agent="orchestrator",
                    handoff_type="access_obtained",
                    priority=priority,
                    summary=f"{level} access obtained on {target}",
                    data=access,
                    suggested_action=(
                        f"{'Post-exploitation: dump credentials, search for flags/sensitive data. ' if level in ('root', 'system', 'admin') else ''}"
                        f"Run internal recon from {target}. Test credential reuse for lateral movement."
                    ),
                    confidence=0.95,
                )

        # Escalation paths → orchestrator for next steps
        if self._escalation_paths:
            self._queue_handoff(
                target_agent="orchestrator",
                handoff_type="escalation_path",
                priority="high",
                summary=f"Found {len(self._escalation_paths)} privilege escalation paths",
                data={"paths": self._escalation_paths[:10]},
                suggested_action=(
                    "Attempt privilege escalation using the discovered paths. "
                    "Prioritize: sudo misconfiguration > SUID abuse > writable files > kernel exploits."
                ),
            )

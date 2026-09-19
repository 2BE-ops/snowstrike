"""
Output compaction system for penetration testing tool output.

Converts raw, often verbose tool output into compact structured summaries
suitable for inclusion in an LLM's context window.  Each supported tool
has a dedicated compactor that uses regex parsing to extract the most
important information.  Unknown tools fall back to a generic compactor.
"""

import re


class OutputCompactor:
    """Compact raw tool output into structured summaries for agent context."""

    # Map tool names (lowercase) to compactor methods
    _TOOL_MAP = {
        "nmap": "_compact_nmap",
        "gobuster": "_compact_gobuster",
        "ffuf": "_compact_ffuf",
        "nuclei": "_compact_nuclei",
        "sqlmap": "_compact_sqlmap",
        "httpx": "_compact_httpx",
        "amass": "_compact_subdomain_enum",
        "subfinder": "_compact_subdomain_enum",
        "nikto": "_compact_nikto",
        "hydra": "_compact_credential_tools",
        "john": "_compact_credential_tools",
        "hashcat": "_compact_credential_tools",
        # AD / Windows tools
        "crackmapexec": "_compact_crackmapexec",
        "nxc": "_compact_crackmapexec",
        "netexec": "_compact_crackmapexec",
        "enum4linux": "_compact_enum4linux",
        "enum4linux-ng": "_compact_enum4linux",
        "smbclient": "_compact_smb_tools",
        "smbmap": "_compact_smb_tools",
        "rpcclient": "_compact_smb_tools",
        "ldapsearch": "_compact_ldap",
        "getuserspns": "_compact_impacket",
        "getnpusers": "_compact_impacket",
        "secretsdump": "_compact_impacket",
        "mssqlclient": "_compact_impacket",
        "psexec": "_compact_impacket",
        "wmiexec": "_compact_impacket",
        "smbexec": "_compact_impacket",
        "evil-winrm": "_compact_shell_session",
        "kerbrute": "_compact_kerbrute",
        "bloodhound-python": "_compact_bloodhound",
        "bloodhound": "_compact_bloodhound",
    }

    def compact(self, tool_name: str, raw_output: str, max_lines: int = 100) -> str:
        """Route to a tool-specific compactor or fall back to generic.

        Parameters
        ----------
        tool_name : str
            Name of the tool that produced the output (case-insensitive).
        raw_output : str
            The raw stdout/stderr from the tool.
        max_lines : int
            Maximum output lines for the generic compactor.

        Returns
        -------
        str
            Compact, structured summary of the tool output.
        """
        if not raw_output or not raw_output.strip():
            return f"[{tool_name}] No output."

        method_name = self._TOOL_MAP.get(tool_name.lower())
        if method_name:
            method = getattr(self, method_name)
            try:
                result = method(raw_output)
                if result and result.strip():
                    return result
            except Exception:
                pass  # Fall through to generic on parse failure

        return self._generic_compact(raw_output, max_lines)

    # ------------------------------------------------------------------
    # Nmap
    # ------------------------------------------------------------------

    def _compact_nmap(self, raw: str) -> str:
        """Extract open ports, services, OS detection, and NSE highlights."""
        lines = raw.splitlines()
        results = []
        current_host = None
        host_ports = []
        os_info = None
        nse_highlights = []

        for line in lines:
            # Host header: "Nmap scan report for hostname (ip)" or "Nmap scan report for ip"
            host_match = re.match(
                r"Nmap scan report for (?:(\S+)\s+\()?(\d+\.\d+\.\d+\.\d+)\)?", line
            )
            if host_match:
                # Flush previous host
                if current_host and host_ports:
                    results.append(self._format_nmap_host(current_host, host_ports, os_info, nse_highlights))
                hostname = host_match.group(1)
                ip = host_match.group(2)
                current_host = f"{hostname} ({ip})" if hostname else ip
                host_ports = []
                os_info = None
                nse_highlights = []
                continue

            # Port line: "80/tcp   open  http    Apache httpd 2.4.49"
            port_match = re.match(
                r"\s*(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)", line
            )
            if port_match:
                port = port_match.group(1)
                proto = port_match.group(2)
                service = port_match.group(3)
                version = port_match.group(4).strip()
                entry = f"{port}/{proto} {service}"
                if version:
                    entry += f" {version}"
                host_ports.append(entry)
                continue

            # OS detection
            os_match = re.match(r"OS details?:\s*(.+)", line, re.IGNORECASE)
            if os_match:
                os_info = os_match.group(1).strip()
                continue

            # Aggressive OS guess
            os_guess = re.match(r"Aggressive OS guesses?:\s*(.+)", line, re.IGNORECASE)
            if os_guess and not os_info:
                os_info = os_guess.group(1).strip().split(",")[0]
                continue

            # NSE script output (lines starting with "|")
            if line.startswith("|") and not line.startswith("|_"):
                script_line = line.lstrip("| ").strip()
                if script_line and len(script_line) > 5:
                    nse_highlights.append(script_line)
            elif line.startswith("|_"):
                script_line = line.lstrip("|_ ").strip()
                if script_line and len(script_line) > 5:
                    nse_highlights.append(script_line)

        # Flush last host
        if current_host and host_ports:
            results.append(self._format_nmap_host(current_host, host_ports, os_info, nse_highlights))

        if not results:
            return self._generic_compact(raw)

        return "[nmap]\n" + "\n".join(results)

    @staticmethod
    def _format_nmap_host(host: str, ports: list, os_info: str, nse: list) -> str:
        parts = [f"  {host}: {', '.join(ports)}"]
        if os_info:
            parts.append(f"    OS: {os_info}")
        # Keep only the most interesting NSE output (limit to 5 lines)
        if nse:
            for item in nse[:5]:
                parts.append(f"    NSE: {item}")
        return "\n".join(parts)

    # ------------------------------------------------------------------
    # Gobuster
    # ------------------------------------------------------------------

    def _compact_gobuster(self, raw: str) -> str:
        """Extract discovered paths with status codes."""
        findings = []
        for line in raw.splitlines():
            # Pattern: "/path (Status: 200) [Size: 1234]" or "/path [Status=200]"
            match = re.search(
                r"(/\S*)\s+.*(?:\(Status:\s*(\d+)\)|\[Status=(\d+)\])", line
            )
            if match:
                path = match.group(1)
                status = match.group(2) or match.group(3)
                findings.append(f"{path} ({status})")
                continue

            # Alternative: lines starting with a discovered path
            alt_match = re.match(r"(/\S+)\s+\(Status:\s*(\d+)\)", line)
            if alt_match:
                findings.append(f"{alt_match.group(1)} ({alt_match.group(2)})")

        if not findings:
            return self._generic_compact(raw)

        return f"[gobuster] {len(findings)} paths found:\n  " + "\n  ".join(findings)

    # ------------------------------------------------------------------
    # ffuf
    # ------------------------------------------------------------------

    def _compact_ffuf(self, raw: str) -> str:
        """Extract discovered endpoints with status and size."""
        findings = []
        for line in raw.splitlines():
            # ffuf output: "FUZZ: /path [Status: 200, Size: 1234, Words: 56]"
            match = re.search(
                r"(\S+)\s+\[Status:\s*(\d+),\s*Size:\s*(\d+)", line
            )
            if match:
                path = match.group(1)
                status = match.group(2)
                size = match.group(3)
                findings.append(f"{path} (status={status}, size={size})")
                continue

            # JSON output mode
            json_match = re.search(
                r'"url"\s*:\s*"([^"]+)".*"status"\s*:\s*(\d+)', line
            )
            if json_match:
                findings.append(f"{json_match.group(1)} ({json_match.group(2)})")

        if not findings:
            return self._generic_compact(raw)

        return f"[ffuf] {len(findings)} endpoints found:\n  " + "\n  ".join(findings)

    # ------------------------------------------------------------------
    # Nuclei
    # ------------------------------------------------------------------

    def _compact_nuclei(self, raw: str) -> str:
        """Extract vulnerability findings with severity and template ID."""
        findings = []
        for line in raw.splitlines():
            # Pattern: "[severity] [template-id] [protocol] finding-detail url"
            match = re.match(
                r"\[(\w+)\]\s+\[([^\]]+)\]\s+\[?([^\]]*)\]?\s*(.*)", line
            )
            if match:
                severity = match.group(1)
                template_id = match.group(2)
                detail = match.group(4).strip()
                findings.append(f"[{severity.upper()}] {template_id}: {detail}")
                continue

            # Alternative: lines with severity tags like [critical], [high], etc.
            alt_match = re.search(
                r"\[(critical|high|medium|low|info)\].*?(\S+://\S+)", line, re.IGNORECASE
            )
            if alt_match:
                findings.append(f"[{alt_match.group(1).upper()}] {alt_match.group(2)}")

        if not findings:
            return self._generic_compact(raw)

        # Sort by severity (safe regex extraction)
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        def _get_severity_rank(finding):
            m = re.match(r"\[(\w+)\]", finding)
            return severity_order.get(m.group(1) if m else "", 5)
        findings.sort(key=_get_severity_rank)

        return f"[nuclei] {len(findings)} findings:\n  " + "\n  ".join(findings)

    # ------------------------------------------------------------------
    # SQLMap
    # ------------------------------------------------------------------

    def _compact_sqlmap(self, raw: str) -> str:
        """Extract injectable parameters, DBMS type, and extracted data."""
        sections = []

        # DBMS identification
        dbms_match = re.search(r"back-end DBMS:\s*(.+)", raw, re.IGNORECASE)
        if dbms_match:
            sections.append(f"DBMS: {dbms_match.group(1).strip()}")

        # Injectable parameters
        injectable = []
        for match in re.finditer(
            r"Parameter:\s*(\S+)\s*\(([^)]+)\)", raw
        ):
            injectable.append(f"{match.group(1)} ({match.group(2)})")
        if injectable:
            sections.append(f"Injectable params: {', '.join(injectable)}")

        # Injection types
        types = set()
        for match in re.finditer(r"Type:\s*(.+)", raw):
            types.add(match.group(1).strip())
        if types:
            sections.append(f"Injection types: {', '.join(sorted(types))}")

        # Extracted databases
        dbs = []
        for match in re.finditer(r"\[\*\]\s+(\S+)", raw):
            db = match.group(1)
            if db and not db.startswith("-") and not db.startswith("("):
                dbs.append(db)
        if dbs:
            # Deduplicate while preserving order
            seen = set()
            unique_dbs = []
            for db in dbs:
                if db not in seen:
                    seen.add(db)
                    unique_dbs.append(db)
            sections.append(f"Databases: {', '.join(unique_dbs[:20])}")

        # Extracted tables (limit)
        tables = re.findall(r"\|\s+(\w+)\s+\|", raw)
        if tables:
            unique_tables = list(dict.fromkeys(tables))[:20]
            sections.append(f"Tables: {', '.join(unique_tables)}")

        if not sections:
            return self._generic_compact(raw)

        return "[sqlmap]\n  " + "\n  ".join(sections)

    # ------------------------------------------------------------------
    # httpx
    # ------------------------------------------------------------------

    def _compact_httpx(self, raw: str) -> str:
        """Extract live hosts with status code, title, and technologies."""
        findings = []
        for line in raw.splitlines():
            line = line.strip()
            if not line or line.startswith("["):
                continue

            # httpx output: "https://host [200] [title] [tech1,tech2]"
            match = re.match(
                r"(\S+)\s+\[(\d+)\](?:\s+\[([^\]]*)\])?(?:\s+\[([^\]]*)\])?", line
            )
            if match:
                url = match.group(1)
                status = match.group(2)
                title = match.group(3) or ""
                tech = match.group(4) or ""
                entry = f"{url} [{status}]"
                if title:
                    entry += f" \"{title}\""
                if tech:
                    entry += f" ({tech})"
                findings.append(entry)
                continue

            # Plain URL lines (from some httpx modes)
            if re.match(r"https?://", line):
                findings.append(line)

        if not findings:
            return self._generic_compact(raw)

        return f"[httpx] {len(findings)} live hosts:\n  " + "\n  ".join(findings)

    # ------------------------------------------------------------------
    # Subdomain enumeration (amass / subfinder)
    # ------------------------------------------------------------------

    def _compact_subdomain_enum(self, raw: str) -> str:
        """Extract a deduplicated subdomain list."""
        subdomains = set()
        for line in raw.splitlines():
            line = line.strip()
            if not line or line.startswith("[") or line.startswith("#"):
                continue
            # Match domain-like strings
            match = re.match(r"([a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)+)", line)
            if match:
                subdomains.add(match.group(1).lower())

        if not subdomains:
            return self._generic_compact(raw)

        sorted_subs = sorted(subdomains)
        return (
            f"[subdomains] {len(sorted_subs)} found:\n  "
            + "\n  ".join(sorted_subs)
        )

    # ------------------------------------------------------------------
    # Nikto
    # ------------------------------------------------------------------

    def _compact_nikto(self, raw: str) -> str:
        """Extract vulnerability findings and interesting headers."""
        findings = []
        headers = []

        for line in raw.splitlines():
            line = line.strip()

            # Nikto findings: lines starting with "+ "
            if line.startswith("+ "):
                content = line[2:].strip()
                # Skip noise lines
                if any(skip in content.lower() for skip in [
                    "target ip:", "target hostname:", "target port:",
                    "start time:", "end time:", "host(s) tested",
                    "server:", "retrieved x-powered-by",
                ]):
                    # But capture server/header info
                    if "server:" in content.lower():
                        headers.append(content)
                    elif "x-powered-by" in content.lower():
                        headers.append(content)
                    continue
                if content:
                    findings.append(content)
                continue

            # OSVDB or CVE references
            if "OSVDB" in line or "CVE-" in line:
                findings.append(line.lstrip("+ ").strip())

        sections = []
        if headers:
            sections.append("Headers: " + "; ".join(headers[:5]))
        if findings:
            sections.append(f"{len(findings)} findings:")
            for f in findings:
                sections.append(f"  - {f}")

        if not sections:
            return self._generic_compact(raw)

        return "[nikto]\n  " + "\n  ".join(sections)

    # ------------------------------------------------------------------
    # Credential tools (hydra / john / hashcat)
    # ------------------------------------------------------------------

    def _compact_credential_tools(self, raw: str) -> str:
        """Extract cracked credentials from hydra, john, or hashcat output."""
        creds = []

        for line in raw.splitlines():
            # Hydra: "[22][ssh] host: 10.0.0.1   login: admin   password: secret"
            hydra_match = re.search(
                r"\[\d+\]\[(\w+)\]\s+host:\s*(\S+)\s+login:\s*(\S+)\s+password:\s*(\S+)",
                line, re.IGNORECASE,
            )
            if hydra_match:
                service = hydra_match.group(1)
                host = hydra_match.group(2)
                user = hydra_match.group(3)
                creds.append(f"{user}@{host} via {service}")
                continue

            # John: "password  (username)"
            john_match = re.match(r"(\S+)\s+\((\S+)\)", line.strip())
            if john_match and not line.strip().startswith("#"):
                creds.append(f"{john_match.group(2)}:{john_match.group(1)}")
                continue

            # Hashcat: "hash:password" (simplified)
            if ":" in line and not line.startswith("#") and not line.startswith("["):
                parts = line.strip().split(":")
                if len(parts) == 2 and len(parts[1]) < 100:
                    # Heuristic: if the first part looks like a hash
                    if len(parts[0]) >= 16 and re.match(r"^[a-fA-F0-9$./]+$", parts[0]):
                        creds.append(f"cracked: {parts[0][:16]}...:{parts[1]}")

        if not creds:
            # Check for summary lines
            summary_match = re.search(
                r"(\d+)\s+(?:valid|successful)\s+password", raw, re.IGNORECASE
            )
            if summary_match:
                return f"[credentials] {summary_match.group(1)} password(s) found (see raw output for details)"
            return self._generic_compact(raw)

        return f"[credentials] {len(creds)} cracked:\n  " + "\n  ".join(creds)

    # ------------------------------------------------------------------
    # AD / Windows tool compactors
    # ------------------------------------------------------------------

    def _compact_crackmapexec(self, raw: str) -> str:
        """Extract key findings from CrackMapExec / NetExec output."""
        results = {"pwned": [], "access": [], "shares": [], "users": [], "other": []}

        for line in raw.splitlines():
            line_stripped = line.strip()
            if not line_stripped:
                continue
            # Pwned / admin access
            if "(Pwn3d!)" in line or "Pwn3d" in line:
                results["pwned"].append(line_stripped)
            elif "[+]" in line:
                if "share" in line.lower() or "READ" in line or "WRITE" in line:
                    results["shares"].append(line_stripped)
                else:
                    results["access"].append(line_stripped)
            elif "[-]" in line and ("STATUS_LOGON_FAILURE" in line or "STATUS_ACCESS_DENIED" in line):
                continue  # Skip failed auth noise
            elif re.search(r"(domain|user|group|computer|member)", line, re.IGNORECASE) and "[*]" in line:
                results["users"].append(line_stripped)
            elif "[*]" not in line or any(kw in line.lower() for kw in ["smb", "mssql", "winrm", "ldap"]):
                if len(line_stripped) > 5:
                    results["other"].append(line_stripped)

        parts = []
        if results["pwned"]:
            parts.append(f"[CRITICAL] ADMIN ACCESS:\n  " + "\n  ".join(results["pwned"][:10]))
        if results["access"]:
            parts.append(f"[+] Successful:\n  " + "\n  ".join(results["access"][:15]))
        if results["shares"]:
            parts.append(f"[shares] {len(results['shares'])} accessible:\n  " + "\n  ".join(results["shares"][:20]))
        if results["users"]:
            parts.append(f"[users/groups]:\n  " + "\n  ".join(results["users"][:20]))

        if not parts:
            return self._generic_compact(raw, max_lines=60)
        return "[crackmapexec]\n" + "\n".join(parts)

    def _compact_enum4linux(self, raw: str) -> str:
        """Extract key info from enum4linux(-ng) output."""
        sections = {"users": [], "shares": [], "groups": [], "policy": [], "os_info": []}

        current_section = None
        for line in raw.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("="):
                continue

            lower = stripped.lower()
            if "user:" in lower or "username:" in lower or re.match(r".*\buser\b.*\brid\b", lower):
                sections["users"].append(stripped)
            elif "share" in lower and ("disk" in lower or "ipc" in lower or "mapping:" in lower):
                sections["shares"].append(stripped)
            elif "group:" in lower or "group name:" in lower:
                sections["groups"].append(stripped)
            elif any(kw in lower for kw in ["os:", "os version", "server type", "domain:", "workgroup:"]):
                sections["os_info"].append(stripped)
            elif "password" in lower and "policy" in lower:
                sections["policy"].append(stripped)

        parts = []
        if sections["os_info"]:
            parts.append("OS/Domain: " + " | ".join(sections["os_info"][:5]))
        if sections["users"]:
            parts.append(f"Users ({len(sections['users'])}):\n  " + "\n  ".join(sections["users"][:30]))
        if sections["shares"]:
            parts.append(f"Shares:\n  " + "\n  ".join(sections["shares"][:15]))
        if sections["groups"]:
            parts.append(f"Groups ({len(sections['groups'])}):\n  " + "\n  ".join(sections["groups"][:15]))
        if sections["policy"]:
            parts.append("Password Policy: " + " | ".join(sections["policy"][:5]))

        if not parts:
            return self._generic_compact(raw, max_lines=60)
        return "[enum4linux]\n" + "\n".join(parts)

    def _compact_smb_tools(self, raw: str) -> str:
        """Extract key info from smbclient, smbmap, rpcclient output."""
        shares = []
        info = []
        users = []

        for line in raw.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            lower = stripped.lower()
            if any(kw in lower for kw in ["disk", "ipc$", "admin$", "c$", "read", "write", "no access"]):
                shares.append(stripped)
            elif re.search(r"user:|username:|account name:", lower):
                users.append(stripped)
            elif stripped and not stripped.startswith("smb:") and len(stripped) > 3:
                info.append(stripped)

        parts = []
        if shares:
            parts.append(f"Shares ({len(shares)}):\n  " + "\n  ".join(shares[:20]))
        if users:
            parts.append(f"Users:\n  " + "\n  ".join(users[:20]))
        if info and not shares and not users:
            parts.append("\n".join(info[:40]))

        if not parts:
            return self._generic_compact(raw, max_lines=50)
        return "[smb]\n" + "\n".join(parts)

    def _compact_ldap(self, raw: str) -> str:
        """Extract key objects from ldapsearch output."""
        objects = []
        current_dn = None
        current_attrs = {}

        for line in raw.splitlines():
            if line.startswith("dn: "):
                if current_dn:
                    objects.append({"dn": current_dn, **current_attrs})
                current_dn = line[4:]
                current_attrs = {}
            elif ": " in line and current_dn:
                key, _, val = line.partition(": ")
                if key.lower() in ("samaccountname", "cn", "memberof", "serviceprincipalname",
                                    "useraccountcontrol", "description", "operatingsystem",
                                    "dnshostname", "objectclass"):
                    current_attrs[key] = val

        if current_dn:
            objects.append({"dn": current_dn, **current_attrs})

        if not objects:
            return self._generic_compact(raw, max_lines=60)

        # Summarize by type
        users = [o for o in objects if "sAMAccountName" in o or "samaccountname" in o]
        spns = [o for o in objects if "servicePrincipalName" in o or "serviceprincipalname" in o]

        parts = [f"[ldap] {len(objects)} objects found"]
        if users:
            names = [o.get("sAMAccountName", o.get("samaccountname", o.get("cn", "?"))) for o in users[:30]]
            parts.append(f"Users ({len(users)}): {', '.join(names)}")
        if spns:
            parts.append(f"SPN accounts ({len(spns)}): {', '.join(o.get('dn','?')[:60] for o in spns[:10])}")

        return "\n".join(parts)

    def _compact_impacket(self, raw: str) -> str:
        """Extract key findings from Impacket tools (GetUserSPNs, GetNPUsers, secretsdump, mssqlclient)."""
        hashes = []
        creds = []
        info = []
        shell_output = []

        for line in raw.splitlines():
            stripped = line.strip()
            if not stripped:
                continue

            # Kerberos hashes ($krb5tgs$ or $krb5asrep$)
            if "$krb5tgs$" in stripped or "$krb5asrep$" in stripped:
                # Truncate the hash for readability but keep the username
                parts = stripped.split("$")
                if len(parts) >= 4:
                    hashes.append(stripped[:120] + "..." if len(stripped) > 120 else stripped)
                continue

            # NTLM hashes (user:rid:lmhash:nthash:::)
            if re.match(r"\S+:\d+:[a-fA-F0-9]{32}:[a-fA-F0-9]{32}:::", stripped):
                hashes.append(stripped)
                continue

            # SAM hashes
            if re.match(r"\S+:[a-fA-F0-9]{32}:[a-fA-F0-9]{32}", stripped) and ":" in stripped:
                hashes.append(stripped)
                continue

            # Credential discoveries
            if any(kw in stripped.lower() for kw in ["password:", "plaintext:", "cleartext", "login succeeded"]):
                creds.append(stripped)
                continue

            # MSSQL specific
            if any(kw in stripped.lower() for kw in ["xp_cmdshell", "sql>", "enabled", "impersonat"]):
                shell_output.append(stripped)
                continue

            # Key info lines
            if stripped.startswith("[*]") or stripped.startswith("[+]") or stripped.startswith("[-]"):
                info.append(stripped)

        parts = []
        if hashes:
            parts.append(f"[HASHES] {len(hashes)} found:\n  " + "\n  ".join(hashes[:20]))
        if creds:
            parts.append(f"[CREDENTIALS]:\n  " + "\n  ".join(creds[:10]))
        if shell_output:
            parts.append(f"[SHELL/SQL]:\n  " + "\n  ".join(shell_output[:20]))
        if info:
            parts.append(f"[info]:\n  " + "\n  ".join(info[:15]))

        if not parts:
            return self._generic_compact(raw, max_lines=60)
        return "[impacket]\n" + "\n".join(parts)

    def _compact_shell_session(self, raw: str) -> str:
        """Extract key output from evil-winrm or other shell sessions."""
        commands = []
        current_cmd = None
        current_output = []

        for line in raw.splitlines():
            # Evil-WinRM prompt
            if re.match(r"\*Evil-WinRM\*\s+PS\s+", line) or line.strip().startswith("PS "):
                if current_cmd:
                    commands.append({"cmd": current_cmd, "output": "\n".join(current_output[-10:])})
                current_cmd = line.strip()
                current_output = []
            elif current_cmd:
                current_output.append(line.rstrip())

        if current_cmd:
            commands.append({"cmd": current_cmd, "output": "\n".join(current_output[-10:])})

        if not commands:
            return self._generic_compact(raw, max_lines=60)

        parts = [f"[shell] {len(commands)} commands executed"]
        for cmd in commands[:15]:
            parts.append(f"$ {cmd['cmd']}")
            if cmd["output"].strip():
                parts.append(f"  {cmd['output'][:300]}")

        return "\n".join(parts)

    def _compact_kerbrute(self, raw: str) -> str:
        """Extract valid users/passwords from kerbrute output."""
        valid_users = []
        valid_creds = []

        for line in raw.splitlines():
            stripped = line.strip()
            if "VALID USERNAME:" in stripped:
                user_match = re.search(r"VALID USERNAME:\s+(\S+)", stripped)
                if user_match:
                    valid_users.append(user_match.group(1))
            elif "VALID LOGIN:" in stripped or "VALID PASSWORD:" in stripped:
                valid_creds.append(stripped)
            elif "[+]" in stripped:
                valid_users.append(stripped)

        parts = []
        if valid_creds:
            parts.append(f"[VALID CREDENTIALS]:\n  " + "\n  ".join(valid_creds[:20]))
        if valid_users:
            parts.append(f"[valid users] {len(valid_users)}:\n  " + "\n  ".join(valid_users[:30]))

        if not parts:
            return self._generic_compact(raw, max_lines=50)
        return "[kerbrute]\n" + "\n".join(parts)

    def _compact_bloodhound(self, raw: str) -> str:
        """Summarize BloodHound collection output."""
        collected = []
        counts = {}

        for line in raw.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            # Count collected objects
            count_match = re.search(r"(\d+)\s+(users?|groups?|computers?|sessions?|gpos?|ous?|acls?|trusts?|containers?)", stripped, re.IGNORECASE)
            if count_match:
                obj_type = count_match.group(2).lower()
                counts[obj_type] = int(count_match.group(1))
            elif any(kw in stripped.lower() for kw in ["done", "finished", "output", "json", "zip"]):
                collected.append(stripped)
            elif stripped.startswith("[") or "INFO" in stripped:
                collected.append(stripped)

        parts = [f"[bloodhound] Collection complete"]
        if counts:
            parts.append("Objects: " + ", ".join(f"{v} {k}" for k, v in counts.items()))
        if collected:
            parts.append("\n".join(collected[-10:]))

        return "\n".join(parts)

    # ------------------------------------------------------------------
    # Generic fallback
    # ------------------------------------------------------------------

    def _generic_compact(self, raw: str, max_lines: int = 100) -> str:
        """Strip blank/noise lines, return up to max_lines meaningful lines."""
        noise_patterns = [
            r"^\s*$",                          # blank
            r"^={3,}",                         # separator lines
            r"^-{3,}",                         # separator lines
            r"^\s*#",                           # comments
            r"^\[[\d:]+\]\s*$",                # bare timestamps
            r"^Starting\s",                     # tool startup banners
            r"^Copyright\s",                    # copyright notices
            r"^Disclaimer",                     # disclaimers
            r"^\s*v\d+\.\d+",                  # version strings
        ]
        noise_re = re.compile("|".join(noise_patterns), re.IGNORECASE)

        meaningful = []
        for line in raw.splitlines():
            if not noise_re.match(line):
                stripped = line.rstrip()
                if stripped:
                    meaningful.append(stripped)

        if not meaningful:
            return "[no meaningful output]"

        if len(meaningful) > max_lines:
            truncated = meaningful[:max_lines]
            truncated.append(f"... ({len(meaningful) - max_lines} more lines truncated)")
            return "\n".join(truncated)

        return "\n".join(meaningful)

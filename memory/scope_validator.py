"""
Target-fidelity validator for shared state and handoff queue writes.

Prevents out-of-scope entities (third-party domains, exploit PoC filenames,
documentation sites, CDN hosts) from polluting shared state. Every value
persisted to domains, attack_surfaces, vulns_summary host fields, hosts,
and handoff queue data is checked against the engagement scope before write.
"""

import ipaddress
import logging
import re
from typing import Optional

logger = logging.getLogger(__name__)

# Well-known third-party / documentation / CDN hosts that are never in scope
# unless explicitly listed.  Matched as suffix (e.g. "fonts.gstatic.com").
_KNOWN_OOB_SUFFIXES = frozenset({
    "github.com",
    "raw.githubusercontent.com",
    "githubusercontent.com",
    "gitlab.com",
    "bitbucket.org",
    "gstatic.com",
    "fonts.gstatic.com",
    "googleapis.com",
    "google.com",
    "w3.org",
    "www.w3.org",
    "cloudflare.com",
    "cdnjs.cloudflare.com",
    "jsdelivr.net",
    "unpkg.com",
    "bootstrapcdn.com",
    "jquery.com",
    "nmap.org",
    "exploit-db.com",
    "cvedetails.com",
    "nvd.nist.gov",
    "cve.mitre.org",
    "wikipedia.org",
    "stackoverflow.com",
    "readthedocs.io",
    "pypi.org",
    "npmjs.com",
    "rubygems.org",
    "maven.org",
    "crates.io",
})

# Patterns that look like exploit artifacts, not real targets
_ARTIFACT_PATTERNS = [
    re.compile(r"^\d+\.py$"),                       # e.g. "52347.py"
    re.compile(r"^CVE-\d{4}-\d+\.py$", re.I),      # e.g. "CVE-2023-1234.py"
    re.compile(r"^exploit.*\.(py|rb|sh|pl|c)$", re.I),
    re.compile(r"^(urllib|transport|paramiko|requests|socket)\b"),
    re.compile(r"\.(py|rb|sh|pl|c|js|txt|xml|html|json|csv|md)$", re.I),
    re.compile(r"^(users|passwords|usernames|wordlist|rockyou)\.txt$", re.I),
]


class ScopeValidator:
    """Validates whether a host/domain/entity is within engagement scope.

    Initialized with the engagement target and explicit scope list.
    Provides fast in-scope checks used by SharedState and HandoffQueue.
    """

    def __init__(self, target: str, scope: list[str], out_of_scope: list[str] | None = None):
        self._target = (target or "").strip()
        self._scope_raw = list(scope or [])
        self._out_of_scope_raw = list(out_of_scope or [])

        # Build normalized lookup sets
        self._scope_ips: set[str] = set()
        self._scope_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self._scope_domains: set[str] = set()
        self._scope_domain_suffixes: list[str] = []  # For wildcard entries like *.example.com

        # Out-of-scope exclusions (checked first — take precedence)
        self._oos_ips: set[str] = set()
        self._oos_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self._oos_domains: set[str] = set()
        self._oos_domain_suffixes: list[str] = []

        for entry in [self._target] + self._scope_raw:
            self._parse_scope_entry(entry, is_exclusion=False)

        for entry in self._out_of_scope_raw:
            self._parse_scope_entry(entry, is_exclusion=True)

    def _parse_scope_entry(self, entry: str, is_exclusion: bool) -> None:
        """Parse a scope/out-of-scope entry into the appropriate lookup set."""
        entry = entry.strip().lower()
        if not entry:
            return
        # Handle wildcard domains like *.example.com
        if entry.startswith("*."):
            suffix = entry[2:]  # Remove "*."
            if is_exclusion:
                self._oos_domain_suffixes.append(suffix)
            else:
                self._scope_domain_suffixes.append(suffix)
            return
        # Strip protocol/port for domain extraction
        cleaned = re.sub(r"^https?://", "", entry)
        cleaned = re.sub(r"[:/].*$", "", cleaned)
        try:
            # Try as IP or network
            net = ipaddress.ip_network(cleaned, strict=False)
            if net.prefixlen != net.max_prefixlen and str(net.network_address) != cleaned:
                logger.warning(
                    "Scope entry %r has host bits set — interpreted as %s", entry, net
                )
            if is_exclusion:
                if net.prefixlen == net.max_prefixlen:
                    self._oos_ips.add(str(net.network_address))
                else:
                    self._oos_networks.append(net)
            else:
                if net.prefixlen == net.max_prefixlen:
                    self._scope_ips.add(str(net.network_address))
                else:
                    self._scope_networks.append(net)
        except ValueError:
            # It's a domain/hostname
            if is_exclusion:
                self._oos_domains.add(cleaned)
            else:
                self._scope_domains.add(cleaned)

    def _is_out_of_scope_explicit(self, cleaned_host: str) -> bool:
        """Check if a host is explicitly excluded via out_of_scope list."""
        # Check explicit out-of-scope IPs
        try:
            addr = ipaddress.ip_address(cleaned_host)
            if str(addr) in self._oos_ips:
                return True
            for net in self._oos_networks:
                if addr in net:
                    return True
        except ValueError:
            pass

        # Check explicit out-of-scope domains
        if cleaned_host in self._oos_domains:
            return True
        for suffix in self._oos_domain_suffixes:
            if cleaned_host == suffix or cleaned_host.endswith("." + suffix):
                return True
        for oos_domain in self._oos_domains:
            if cleaned_host.endswith("." + oos_domain):
                return True

        return False

    def is_in_scope(self, value: str) -> bool:
        """Check if a host/domain/IP string is within engagement scope.

        Returns True if the value is plausibly in scope, False if it's
        clearly out of scope (third-party, artifact, excluded, etc.).

        Evaluation order:
        1. Reject artifacts (filenames, exploit scripts)
        2. Reject explicit out_of_scope entries (takes precedence over in-scope)
        3. Reject known OOB suffixes (github.com, etc.)
        4. Accept if matches in-scope IPs/networks/domains
        5. For private IPs: allow if same /24 as a scope IP (pivot range)
        6. Reject unknown domains when scope is IP-only
        7. Empty scope = open scope
        """
        if not value or not isinstance(value, str):
            return False

        cleaned = value.strip().lower()
        if not cleaned:
            return False

        # Strip protocol/port
        cleaned_host = re.sub(r"^https?://", "", cleaned)
        cleaned_host = re.sub(r"[:/].*$", "", cleaned_host)

        if not cleaned_host:
            return False

        # 1. Check for exploit artifact patterns
        if self._is_artifact(cleaned_host):
            logger.debug("Scope reject (artifact): %s", value)
            return False

        # 2. Check explicit out_of_scope entries (takes precedence over in-scope)
        if self._is_out_of_scope_explicit(cleaned_host):
            logger.debug("Scope reject (explicit out_of_scope): %s", value)
            return False

        # 3. Check known OOB suffixes
        for suffix in _KNOWN_OOB_SUFFIXES:
            if cleaned_host == suffix or cleaned_host.endswith("." + suffix):
                # Allow if explicitly in scope
                if cleaned_host in self._scope_domains:
                    return True
                logger.debug("Scope reject (known OOB): %s", value)
                return False

        # 4. Check if it's an IP
        try:
            addr = ipaddress.ip_address(cleaned_host)
            if str(addr) in self._scope_ips:
                return True
            for net in self._scope_networks:
                if addr in net:
                    return True
            # Unknown IP — allow only if no scope IPs are defined (open scope)
            if not self._scope_ips and not self._scope_networks:
                return True
            # 5. Private IP pivot: allow if same /24 as a scope IP (not /16)
            if addr.is_private:
                for scope_ip_str in self._scope_ips:
                    try:
                        scope_addr = ipaddress.ip_address(scope_ip_str)
                        if scope_addr.is_private:
                            scope_net = ipaddress.ip_network(f"{scope_addr}/24", strict=False)
                            if addr in scope_net:
                                return True
                    except ValueError:
                        continue
            logger.debug("Scope reject (IP not in scope): %s", value)
            return False
        except ValueError:
            pass

        # Domain check — accept if it matches or is a subdomain of a scope domain
        for scope_domain in self._scope_domains:
            if cleaned_host == scope_domain or cleaned_host.endswith("." + scope_domain):
                return True

        # Check wildcard scope domain suffixes (e.g., *.example.com)
        for suffix in self._scope_domain_suffixes:
            if cleaned_host == suffix or cleaned_host.endswith("." + suffix):
                return True

        # 6. IP-only scope: reject unknown domains (don't be permissive)
        if self._scope_ips and not self._scope_domains and not self._scope_domain_suffixes:
            logger.debug("Scope reject (unknown domain with IP-only scope): %s", value)
            return False

        # If no scope constraints match, reject
        if self._scope_domains or self._scope_domain_suffixes:
            logger.debug("Scope reject (domain not in scope): %s", value)
            return False

        # Empty scope = open scope
        return True

    @staticmethod
    def _is_artifact(value: str) -> bool:
        """Check if a value looks like an exploit artifact rather than a target."""
        for pattern in _ARTIFACT_PATTERNS:
            if pattern.search(value):
                return True
        return False

    def validate_host_ip(self, ip: str) -> bool:
        """Validate an IP before adding to hosts dict."""
        if not ip or not isinstance(ip, str):
            return False
        ip = ip.strip()
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return False
        return self.is_in_scope(ip)

    def validate_domain_entry(self, entry) -> bool:
        """Validate a domain entry before adding to domains list."""
        if isinstance(entry, dict):
            primary = entry.get("primary_domain", "")
            if primary and not self.is_in_scope(primary):
                return False
            subs = entry.get("subdomains", [])
            if isinstance(subs, list):
                entry["subdomains"] = [s for s in subs if self.is_in_scope(s)]
            return True
        if isinstance(entry, str):
            return self.is_in_scope(entry)
        return False

    def validate_vuln_entry(self, entry: dict) -> bool:
        """Validate a vuln_summary entry's host field."""
        if not isinstance(entry, dict):
            return False
        host = entry.get("host", "")
        if host and not self.is_in_scope(host):
            return False
        return True

    def validate_attack_surface(self, entry) -> bool:
        """Validate an attack_surfaces entry."""
        if isinstance(entry, str):
            # Format: "webapp:80" or "ssh:22" or "http://host:port"
            host_part = re.sub(r"^https?://", "", entry)
            host_part = re.sub(r"[:/].*$", "", host_part)
            if host_part and not self.is_in_scope(host_part):
                return False
        elif isinstance(entry, dict):
            host = entry.get("host", "") or entry.get("target", "")
            if host and not self.is_in_scope(host):
                return False
        return True

    def validate_handoff_data(self, data: dict) -> bool:
        """Validate handoff data for target fidelity."""
        if not isinstance(data, dict):
            return True
        host = data.get("host") or data.get("target") or data.get("ip") or ""
        if host and not self.is_in_scope(host):
            return False
        url = data.get("url", "")
        if url:
            url_host = re.sub(r"^https?://", "", str(url))
            url_host = re.sub(r"[:/].*$", "", url_host)
            if url_host and not self.is_in_scope(url_host):
                return False
        return True

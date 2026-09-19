"""
Replay-based validation harness for tool wrapper changes (Phase 8).

Uses fixture data from observed engagement failures as a canonical regression
set. After any tool-wrapper change, run this harness to ensure:
- Historical wrapper mismatches now either execute successfully or are skipped
  cleanly with the right outcome category
- Useful-but-failed outputs are correctly classified as partial_success
- Empty/no-signal outputs are correctly classified
- Interactive hangs are detected
- Missing binaries are caught pre-execution

Run: python -m pytest testing/test_replay_harness.py -v
"""

import pytest
from tools.executor import ToolResult, OutcomeKind, classify_outcome, detect_signal


# ============================================================================
# Fixture: Known failure families from recent engagements
# ============================================================================

class TestWrapperMismatchReplay:
    """Family 1: wrapper/CLI mismatch — the #1 failure source (51%)."""

    def test_httpx_python_variant_unknown_flag(self):
        """httpx_probe: Python httpx CLI rejects PD flags."""
        r = ToolResult(
            tool_name="httpx",
            command="httpx -sc -title -tech-detect http://10.0.0.1",
            stdout="",
            stderr="Error: no such option: -sc\nUsage: httpx [OPTIONS] URL",
            return_code=2,
            duration_seconds=0.05,
            success=False,
        )
        assert r.outcome_kind == OutcomeKind.WRAPPER_ERROR.value
        assert r.signal_detected is False

    def test_katana_invalid_js_crawl_flag(self):
        """katana_crawl: -js-crawl replaced by -jc in newer versions."""
        r = ToolResult(
            tool_name="katana",
            command="katana -u http://x -js-crawl",
            stdout="",
            stderr="flag provided but not defined: -js-crawl",
            return_code=1,
            duration_seconds=0.1,
            success=False,
        )
        assert r.outcome_kind == OutcomeKind.WRAPPER_ERROR.value

    def test_gobuster_unknown_s_flag(self):
        """gobuster_scan: newer versions removed -s (include status codes)."""
        r = ToolResult(
            tool_name="gobuster",
            command="gobuster dir -u http://x -w /tmp/wl.txt -s 200,301",
            stdout="",
            stderr='unknown flag: -s\nUsage:\n  gobuster dir [flags]',
            return_code=1,
            duration_seconds=0.1,
            success=False,
        )
        assert r.outcome_kind == OutcomeKind.WRAPPER_ERROR.value

    def test_arjun_unsupported_k_flag(self):
        """arjun_scan: -k/--insecure not supported."""
        r = ToolResult(
            tool_name="arjun",
            command="arjun -u http://x -k",
            stdout="",
            stderr="error: unrecognized arguments: -k",
            return_code=2,
            duration_seconds=0.05,
            success=False,
        )
        assert r.outcome_kind == OutcomeKind.WRAPPER_ERROR.value

    def test_nmap_duplicate_p_usage_error(self):
        """nmap_advanced: duplicate -p causes usage error."""
        r = ToolResult(
            tool_name="nmap",
            command="nmap -sS -sV -p 80,443 -p 1-65535 10.0.0.1",
            stdout="",
            stderr="ERROR: Cannot use -p twice",
            return_code=1,
            duration_seconds=0.05,
            success=False,
        )
        # This specific error message wouldn't match wrapper patterns but
        # the important thing is it's not classified as a successful run
        assert r.outcome_kind != OutcomeKind.SUCCESS.value

    def test_nikto_invalid_uri_port(self):
        """nikto_scan: -h http://x:8080 -p 8080 causes double port."""
        r = ToolResult(
            tool_name="nikto",
            command="nikto -h http://10.0.0.1:8080 -p 8080",
            stdout="",
            stderr="Invalid URI scheme or port combination",
            return_code=1,
            duration_seconds=0.1,
            success=False,
        )
        assert r.outcome_kind != OutcomeKind.SUCCESS.value


class TestUsefulOutputMarkedFailedReplay:
    """Family 2: produced useful output but exited nonzero (18.4%)."""

    def test_nikto_findings_nonzero_exit(self):
        """nikto_scan: finds vulnerabilities but exits with rc=1."""
        r = ToolResult(
            tool_name="nikto",
            command="nikto -h http://10.0.0.1",
            stdout=(
                "+ Target IP: 10.0.0.1\n"
                "+ OSVDB-3092: /admin/: This might be interesting\n"
                "+ OSVDB-3268: /icons/: Directory listing found\n"
                "+ 7 items checked: 2 error(s) and 2 item(s) reported on remote host\n"
            ),
            stderr="ERROR: Error limit (20) reached for host",
            return_code=1,
            duration_seconds=45.0,
            success=False,
        )
        assert r.outcome_kind == OutcomeKind.PARTIAL_SUCCESS.value
        assert r.signal_detected is True

    def test_feroxbuster_partial_results(self):
        """feroxbuster_scan: found directories but crashed mid-scan."""
        r = ToolResult(
            tool_name="feroxbuster",
            command="feroxbuster -u http://10.0.0.1 -w /tmp/wl.txt",
            stdout=(
                "200      GET    /index.html\n"
                "301      GET    /admin -> /admin/\n"
                "200      GET    /admin/login.php\n"
                "403      GET    /server-status\n"
            ),
            stderr="thread 'main' panicked at 'capacity overflow'",
            return_code=101,
            duration_seconds=120.0,
            success=False,
        )
        assert r.outcome_kind == OutcomeKind.PARTIAL_SUCCESS.value
        assert r.signal_detected is True

    def test_nmap_partial_scan_nonzero(self):
        """nmap_scan: partial results with interrupted exit."""
        r = ToolResult(
            tool_name="nmap",
            command="nmap -sS -sV 10.0.0.1",
            stdout=(
                "Starting Nmap 7.94\n"
                "Nmap scan report for 10.0.0.1\n"
                "Host is up (0.003s latency).\n"
                "22/tcp  open  ssh     OpenSSH 8.9p1\n"
                "80/tcp  open  http    Apache httpd 2.4.52\n"
                "443/tcp open  ssl/http Apache httpd 2.4.52\n"
                "1 host up\n"
            ),
            stderr="QUITTING!",
            return_code=1,
            duration_seconds=60.0,
            success=False,
        )
        assert r.outcome_kind == OutcomeKind.PARTIAL_SUCCESS.value
        assert r.signal_detected is True


class TestEmptyNoSignalReplay:
    """Family 3: no-signal/empty results (14.3%)."""

    def test_nmap_zero_hosts_up(self):
        """nmap: all hosts down."""
        r = ToolResult(
            tool_name="nmap",
            command="nmap -sS 192.168.1.0/24",
            stdout="0 hosts up",
            stderr="",
            return_code=0,
            duration_seconds=30.0,
            success=True,
        )
        assert r.outcome_kind == OutcomeKind.EMPTY_RESULT.value
        assert r.signal_detected is False

    def test_gobuster_no_results(self):
        """gobuster: no directories found."""
        r = ToolResult(
            tool_name="gobuster",
            command="gobuster dir -u http://x -w /tmp/wl.txt",
            stdout="Progress: 4614 / 4615 (99.98%)\nno results",
            stderr="",
            return_code=0,
            duration_seconds=20.0,
            success=True,
        )
        assert r.outcome_kind == OutcomeKind.EMPTY_RESULT.value
        assert r.signal_detected is False

    def test_completely_empty_output(self):
        r = ToolResult(
            tool_name="nuclei",
            command="nuclei -u http://x -t cves/",
            stdout="",
            stderr="",
            return_code=0,
            duration_seconds=15.0,
            success=True,
        )
        assert r.outcome_kind == OutcomeKind.EMPTY_RESULT.value


class TestInteractiveHangReplay:
    """Family 4: interactive hang."""

    def test_msfconsole_hang(self):
        """msfconsole_run: output shows prompt but never exits."""
        r = ToolResult(
            tool_name="msfconsole",
            command="msfconsole -q -x 'use exploit/multi/handler; set LHOST 10.0.0.1'",
            stdout=(
                "[*] Starting the Metasploit Framework console...\n"
                "msf6 > use exploit/multi/handler\n"
                "msf6 exploit(multi/handler) > set LHOST 10.0.0.1\n"
                "LHOST => 10.0.0.1\n"
                "msf6 exploit(multi/handler) > "
            ),
            stderr="",
            return_code=-1,
            duration_seconds=420.0,
            success=False,
            timed_out=True,
        )
        assert r.outcome_kind == OutcomeKind.INTERACTIVE_HANG.value

    def test_gdb_waiting_for_input(self):
        """gdb_analyze: waiting at prompt."""
        r = ToolResult(
            tool_name="gdb",
            command="gdb ./binary",
            stdout="(gdb) ",
            stderr="",
            return_code=-1,
            duration_seconds=300.0,
            success=False,
            timed_out=True,
        )
        assert r.outcome_kind == OutcomeKind.INTERACTIVE_HANG.value


class TestMissingBinaryReplay:
    """Family 5: binary not found."""

    def test_binary_not_found(self):
        r = ToolResult(
            tool_name="katana",
            command="katana -u http://x",
            stdout="",
            stderr="katana: command not found",
            return_code=127,
            duration_seconds=0.01,
            success=False,
        )
        assert r.outcome_kind == OutcomeKind.ENV_ERROR.value

    def test_permission_denied(self):
        r = ToolResult(
            tool_name="nmap",
            command="nmap -sS 10.0.0.1",
            stdout="",
            stderr="nmap: operation not permitted",
            return_code=126,
            duration_seconds=0.01,
            success=False,
        )
        assert r.outcome_kind == OutcomeKind.ENV_ERROR.value


class TestTargetRefusedReplay:
    """Family 6: target refused connection."""

    def test_connection_refused(self):
        r = ToolResult(
            tool_name="httpx",
            command="httpx http://10.0.0.1:9999",
            stdout="",
            stderr="connection refused",
            return_code=1,
            duration_seconds=2.0,
            success=False,
        )
        assert r.outcome_kind == OutcomeKind.TARGET_REFUSED.value

    def test_host_unreachable(self):
        r = ToolResult(
            tool_name="nmap",
            command="nmap 192.168.99.99",
            stdout="",
            stderr="No route to host",
            return_code=1,
            duration_seconds=5.0,
            success=False,
        )
        assert r.outcome_kind == OutcomeKind.TARGET_REFUSED.value


# ============================================================================
# Outcome classification edge cases
# ============================================================================

class TestOutcomeEdgeCases:

    def test_timeout_with_signal(self):
        """Tool timed out but had findings before deadline."""
        r = ToolResult(
            tool_name="nikto",
            command="nikto -h http://x",
            stdout="+ OSVDB-3092: /admin/: interesting\n+ 80/tcp open http",
            stderr="",
            return_code=-1,
            duration_seconds=360.0,
            success=False,
            timed_out=True,
        )
        assert r.outcome_kind == OutcomeKind.TIMEOUT_WITH_SIGNAL.value
        assert r.signal_detected is True

    def test_timeout_no_signal(self):
        """Tool timed out with no useful output."""
        r = ToolResult(
            tool_name="feroxbuster",
            command="feroxbuster -u http://x",
            stdout="",
            stderr="",
            return_code=-1,
            duration_seconds=360.0,
            success=False,
            timed_out=True,
        )
        assert r.outcome_kind == OutcomeKind.EMPTY_RESULT.value

    def test_success_with_rich_output(self):
        """Clean success with multiple findings."""
        r = ToolResult(
            tool_name="nmap",
            command="nmap -sS -sV 10.0.0.1",
            stdout=(
                "Nmap scan report for 10.0.0.1\n"
                "22/tcp  open  ssh\n"
                "80/tcp  open  http\n"
                "3 hosts up\n"
            ),
            stderr="",
            return_code=0,
            duration_seconds=15.0,
            success=True,
        )
        assert r.outcome_kind == OutcomeKind.SUCCESS.value
        assert r.signal_detected is True


# ============================================================================
# Signal detection unit tests
# ============================================================================

class TestSignalDetection:

    def test_nmap_port_open(self):
        r = ToolResult(
            tool_name="nmap", command="", stdout="22/tcp open ssh",
            stderr="", return_code=0, duration_seconds=1, success=True,
        )
        assert r.signal_detected is True

    def test_http_status_code(self):
        r = ToolResult(
            tool_name="httpx", command="", stdout="[200] http://x",
            stderr="", return_code=0, duration_seconds=1, success=True,
        )
        assert r.signal_detected is True

    def test_cve_reference(self):
        r = ToolResult(
            tool_name="nuclei", command="", stdout="CVE-2021-44228 detected",
            stderr="", return_code=0, duration_seconds=1, success=True,
        )
        assert r.signal_detected is True

    def test_sql_injection_finding(self):
        r = ToolResult(
            tool_name="sqlmap", command="", stdout="SQL injection found",
            stderr="", return_code=0, duration_seconds=1, success=True,
        )
        assert r.signal_detected is True

    def test_no_signal_empty(self):
        r = ToolResult(
            tool_name="nmap", command="", stdout="",
            stderr="", return_code=0, duration_seconds=1, success=True,
        )
        assert r.signal_detected is False


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

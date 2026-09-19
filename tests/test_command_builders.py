"""
Command-builder unit tests for Phase 1 wrapper stabilization.

Each test covers:
1. Normal invocation with typical parameters
2. At least one "known bad" regression case per tool (from observed engagement failures)
3. Edge cases around flag deduplication and URL parsing

Run: python -m pytest testing/test_command_builders.py -v
"""

import pytest
from tools.definitions import build_command, _split_extra


# ============================================================================
# httpx_probe
# ============================================================================

class TestBuildHttpx:
    """httpx_probe: wrong binary variant was the #1 failure."""

    def test_basic_target(self):
        args = build_command("httpx_probe", {"target": "http://10.0.0.1"})
        assert args is not None
        assert "http://10.0.0.1" in args

    def test_projectdiscovery_flags_present_by_default(self):
        """When no compat profile, assume PD and emit all flags."""
        args = build_command("httpx_probe", {"target": "http://10.0.0.1"})
        assert "-sc" in args
        assert "-title" in args
        assert "-tech-detect" in args
        assert "-follow-redirects" in args

    def test_python_variant_strips_pd_flags(self):
        """Regression: Python httpx CLI doesn't support PD flags."""
        profile = {
            "capabilities": {
                "-sc": False, "-title": False, "-tech-detect": False,
                "-follow-redirects": False, "-threads": False,
            }
        }
        args = build_command("httpx_probe", {
            "target": "http://10.0.0.1",
            "_compat_profile": profile,
        })
        assert "-sc" not in args
        assert "-title" not in args
        assert "-tech-detect" not in args
        assert "-follow-redirects" not in args
        assert "http://10.0.0.1" in args

    def test_targets_file(self):
        args = build_command("httpx_probe", {
            "target": "http://10.0.0.1",
            "targets_file": "/tmp/urls.txt",
        })
        assert "-l" in args
        assert "/tmp/urls.txt" in args

    def test_threads(self):
        args = build_command("httpx_probe", {
            "target": "http://10.0.0.1",
            "threads": 50,
        })
        assert "-threads" in args
        assert "50" in args


# ============================================================================
# katana_crawl
# ============================================================================

class TestBuildKatana:
    """katana_crawl: invalid flags and invalid flag values."""

    def test_basic(self):
        args = build_command("katana_crawl", {"url": "http://10.0.0.1"})
        assert args is not None
        assert "-u" in args
        assert "http://10.0.0.1" in args

    def test_js_crawl_default_flag(self):
        args = build_command("katana_crawl", {"url": "http://x", "js_crawl": True})
        # Default (no profile): uses -js-crawl
        assert "-js-crawl" in args

    def test_js_crawl_jc_replacement(self):
        """Regression: newer katana uses -jc instead of -js-crawl."""
        profile = {"capabilities": {"js_crawl_flag": "-jc", "-headless": True}}
        args = build_command("katana_crawl", {
            "url": "http://x",
            "js_crawl": True,
            "_compat_profile": profile,
        })
        assert "-jc" in args
        assert "-js-crawl" not in args

    def test_scope_flag_fallback(self):
        """Regression: -cs may be -crawl-scope in some versions."""
        profile = {"capabilities": {"scope_flag": "-crawl-scope", "-H": True}}
        args = build_command("katana_crawl", {
            "url": "http://x",
            "scope": "example.com",
            "_compat_profile": profile,
        })
        assert "-crawl-scope" in args
        assert "-cs" not in args

    def test_json_output_flag(self):
        profile = {"capabilities": {"json_flag": "-json"}}
        args = build_command("katana_crawl", {
            "url": "http://x",
            "output_format": "json",
            "_compat_profile": profile,
        })
        assert "-json" in args
        assert "-jsonl" not in args

    def test_headless_unsupported(self):
        """When headless is not supported, don't emit it."""
        profile = {"capabilities": {"-headless": False}}
        args = build_command("katana_crawl", {
            "url": "http://x",
            "headless": True,
            "_compat_profile": profile,
        })
        assert "-headless" not in args

    def test_depth(self):
        args = build_command("katana_crawl", {"url": "http://x", "depth": 3})
        assert "-d" in args
        assert "3" in args

    def test_rejects_non_finite_depth(self):
        with pytest.raises(ValueError, match="Non-finite numeric parameter"):
            build_command("katana_crawl", {"url": "http://x", "depth": float("inf")})


class TestBrowserBuilders:
    """Browser tools should build backend invocation commands."""

    def test_browser_builder_returns_backend_command(self):
        args = build_command("browser_navigate", {"url": "http://example.com"})
        assert args[:4] == ["python3", "-m", "tools.browser_backend", "navigate"]
        assert len(args) == 5
        assert '"url": "http://example.com"' in args[4]


# ============================================================================
# nikto_scan
# ============================================================================

class TestBuildNikto:
    """nikto_scan: invalid URI/port combination logic."""

    def test_basic_target(self):
        args = build_command("nikto_scan", {"target": "http://10.0.0.1"})
        assert "-h" in args
        assert "http://10.0.0.1" in args

    def test_separate_port(self):
        """Port should be added when target has no embedded port."""
        args = build_command("nikto_scan", {"target": "http://10.0.0.1", "port": 8080})
        assert "-p" in args
        assert "8080" in args

    def test_regression_url_with_port_no_duplicate(self):
        """Regression: when target is http://10.0.0.1:8080, don't add -p again."""
        args = build_command("nikto_scan", {
            "target": "http://10.0.0.1:8080",
            "port": 8080,
        })
        # -p should NOT appear because the URL already contains the port
        assert "-p" not in args

    def test_bare_host_port_no_duplicate(self):
        """Regression: target='10.0.0.1:8080' also embeds port."""
        args = build_command("nikto_scan", {
            "target": "10.0.0.1:8080",
            "port": 8080,
        })
        assert "-p" not in args

    def test_https_auto_ssl(self):
        """https targets should auto-enable -ssl."""
        args = build_command("nikto_scan", {"target": "https://10.0.0.1"})
        assert "-ssl" in args

    def test_explicit_ssl(self):
        args = build_command("nikto_scan", {"target": "http://10.0.0.1", "ssl": True})
        assert "-ssl" in args

    def test_tuning(self):
        args = build_command("nikto_scan", {"target": "http://x", "tuning": "1234"})
        assert "-Tuning" in args
        assert "1234" in args

    def test_maxtime(self):
        args = build_command("nikto_scan", {"target": "http://x", "maxtime": 300})
        assert "-maxtime" in args
        assert "300" in args


# ============================================================================
# gobuster_scan
# ============================================================================

class TestBuildGobuster:
    """gobuster_scan: conflicting defaults around status-code handling."""

    def test_basic(self):
        args = build_command("gobuster_scan", {
            "target": "http://10.0.0.1",
            "wordlist": "/usr/share/wordlists/dirb/common.txt",
        })
        assert "dir" in args
        assert "-u" in args
        assert "-w" in args

    def test_status_codes_include_mode(self):
        """Default (include mode): emit -s."""
        args = build_command("gobuster_scan", {
            "target": "http://x",
            "wordlist": "/tmp/wl.txt",
            "status_codes": "200,301,302",
        })
        assert "-s" in args
        assert "200,301,302" in args

    def test_regression_exclude_only_mode(self):
        """Regression: newer gobuster removed -s. When probe says exclude_only,
        don't emit -s to avoid unknown-flag error."""
        profile = {"capabilities": {"status_code_mode": "exclude_only"}}
        args = build_command("gobuster_scan", {
            "target": "http://x",
            "wordlist": "/tmp/wl.txt",
            "status_codes": "200,301",
            "_compat_profile": profile,
        })
        assert "-s" not in args

    def test_extra_args_dedup(self):
        """Extra args that duplicate explicit flags should be stripped."""
        args = build_command("gobuster_scan", {
            "target": "http://x",
            "wordlist": "/tmp/wl.txt",
            "threads": 20,
            "extra_args": "-t 50",
        })
        # -t should appear only once (from threads=20), not also from extra_args
        assert args.count("-t") == 1

    def test_extensions(self):
        args = build_command("gobuster_scan", {
            "target": "http://x",
            "wordlist": "/tmp/wl.txt",
            "extensions": "php,html",
        })
        assert "-x" in args
        assert "php,html" in args


# ============================================================================
# arjun_scan
# ============================================================================

class TestBuildArjun:
    """arjun_scan: unsupported -k flag."""

    def test_basic(self):
        args = build_command("arjun_scan", {"url": "http://10.0.0.1"})
        assert "-u" in args

    def test_regression_k_flag_stripped(self):
        """Regression: arjun doesn't support -k/--insecure."""
        args = build_command("arjun_scan", {
            "url": "http://x",
            "extra_args": "-k",
        })
        assert "-k" not in args

    def test_regression_insecure_flag_stripped(self):
        args = build_command("arjun_scan", {
            "url": "http://x",
            "extra_args": "--insecure",
        })
        assert "--insecure" not in args

    def test_method(self):
        args = build_command("arjun_scan", {"url": "http://x", "method": "POST"})
        assert "-m" in args
        assert "POST" in args

    def test_threads(self):
        args = build_command("arjun_scan", {"url": "http://x", "threads": 10})
        assert "-t" in args
        assert "10" in args


# ============================================================================
# nmap_advanced
# ============================================================================

class TestBuildNmapAdvanced:
    """nmap_advanced: duplicate -p construction."""

    def test_basic(self):
        args = build_command("nmap_advanced", {
            "target": "10.0.0.1",
            "ports": "1-1000",
        })
        assert "-p" in args
        assert "1-1000" in args
        assert "10.0.0.1" in args

    def test_regression_duplicate_p(self):
        """Regression: when ports is set and extra_args also has -p, only one -p should appear."""
        args = build_command("nmap_advanced", {
            "target": "10.0.0.1",
            "ports": "80,443",
            "extra_args": "-p 1-65535",
        })
        count = args.count("-p")
        assert count == 1, f"Expected 1 -p flag, got {count}: {args}"
        # The explicit ports param should win
        assert "80,443" in args

    def test_no_duplicate_p_without_explicit_ports(self):
        """When ports is not set, -p from extra_args should be kept."""
        args = build_command("nmap_advanced", {
            "target": "10.0.0.1",
            "extra_args": "-p 1-65535",
        })
        assert "-p" in args
        assert "1-65535" in args

    def test_scripts(self):
        args = build_command("nmap_advanced", {
            "target": "10.0.0.1",
            "script_categories": ["vuln", "safe"],
        })
        assert "--script" in args
        assert "vuln,safe" in args

    def test_decoys(self):
        args = build_command("nmap_advanced", {
            "target": "10.0.0.1",
            "decoys": "RND:5",
        })
        assert "-D" in args
        assert "RND:5" in args

    def test_rate_limiting(self):
        args = build_command("nmap_advanced", {
            "target": "10.0.0.1",
            "min_rate": 100,
            "max_rate": 500,
        })
        assert "--min-rate" in args
        assert "100" in args
        assert "--max-rate" in args
        assert "500" in args


# ============================================================================
# nmap_scan (basic builder - ensure no regressions)
# ============================================================================

class TestBuildNmapScan:
    def test_basic(self):
        args = build_command("nmap_scan", {"target": "10.0.0.1"})
        assert "10.0.0.1" in args
        assert "-sS" in args  # default scan type

    def test_udp_scan(self):
        args = build_command("nmap_scan", {"target": "10.0.0.1", "scan_type": "udp"})
        assert "-sU" in args

    def test_ports(self):
        args = build_command("nmap_scan", {"target": "10.0.0.1", "ports": "80,443"})
        assert "-p" in args
        assert "80,443" in args

    def test_timing(self):
        args = build_command("nmap_scan", {"target": "10.0.0.1", "timing": 3})
        assert "-T3" in args


# ============================================================================
# Compatibility probe unit tests
# ============================================================================

class TestCompatibilityProbe:
    """Test the probe infrastructure (not actual binary availability)."""

    def test_probe_init(self):
        from tools.compatibility import CompatibilityProbe
        probe = CompatibilityProbe()
        assert probe.is_compatible("unknown_tool") is True  # not probed = assumed OK

    def test_profile_to_dict(self):
        from tools.compatibility import ToolProfile
        p = ToolProfile(
            tool_name="test_tool",
            binary_name="test",
            available=True,
            compatible=False,
            reason="test_reason",
        )
        d = p.to_dict()
        assert d["compatible"] is False
        assert d["reason"] == "test_reason"

    def test_skip_reason_for_missing_binary(self):
        from tools.compatibility import CompatibilityProbe, ToolProfile
        probe = CompatibilityProbe()
        probe._profiles["fake_tool"] = ToolProfile(
            tool_name="fake_tool",
            binary_name="nonexistent",
            available=False,
            compatible=False,
            reason="binary_missing",
        )
        assert probe.get_skip_reason("fake_tool") is not None
        assert "binary_missing" in probe.get_skip_reason("fake_tool")

    def test_compatible_tool_no_skip(self):
        from tools.compatibility import CompatibilityProbe, ToolProfile
        probe = CompatibilityProbe()
        probe._profiles["good_tool"] = ToolProfile(
            tool_name="good_tool",
            binary_name="good",
            available=True,
            compatible=True,
        )
        assert probe.get_skip_reason("good_tool") is None
        assert probe.is_compatible("good_tool") is True

    def test_shared_state_export(self):
        from tools.compatibility import CompatibilityProbe, ToolProfile
        probe = CompatibilityProbe()
        probe._profiles["tool_a"] = ToolProfile(
            tool_name="tool_a", binary_name="a",
            available=True, compatible=True, version="1.0",
        )
        export = probe.to_shared_state_format()
        assert "tools" in export
        assert "tool_a" in export["tools"]
        assert export["tools"]["tool_a"]["version"] == "1.0"


# ============================================================================
# Extra helpers
# ============================================================================

class TestSplitExtra:
    def test_empty(self):
        assert _split_extra({}) == []

    def test_simple(self):
        assert _split_extra({"extra_args": "-v --timeout 30"}) == ["-v", "--timeout", "30"]

    def test_quoted(self):
        result = _split_extra({"extra_args": '--header "Authorization: Bearer token"'})
        assert "--header" in result
        assert "Authorization: Bearer token" in result


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

"""
Command builders and tool-definition accessors.

Tool schemas (name, description, input_schema) are now loaded exclusively
from the YAML catalog via ToolRegistry in registry_loader.py.

Main exports:
  - COMMAND_BUILDERS: Dict mapping tool name -> function(params) -> list[str].
  - get_tool_definitions_for_agent(): Returns Anthropic-compatible schemas.
  - build_command(): Builds subprocess arg lists for tool execution.
"""

import json
import logging
import math
import re
import shlex
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)


# =============================================================================
# COMMAND BUILDERS - Functions that translate JSON params to subprocess arg lists
# =============================================================================

# Flags that must never appear in extra_args (dangerous for any tool)
_DENIED_EXTRA_FLAGS = frozenset({
    "--exec", "--os-cmd", "--os-shell", "--eval-code",
    "--file-write", "--file-dest", "--file-read",
    "--priv-esc", "--batch-os", "--shell",
})


def _split_extra(params: dict) -> list[str]:
    """Split extra_args string into list, preserving quoted substrings.

    Strips dangerous flags that could enable arbitrary file writes,
    code execution, or privilege escalation.
    """
    extra = params.get("extra_args", "")
    if not extra:
        return []
    try:
        parts = shlex.split(extra)
    except ValueError:
        # Fallback if quotes are unbalanced
        parts = extra.split()
    # Strip denied flags
    filtered = []
    skip_next = False
    for i, part in enumerate(parts):
        if skip_next:
            skip_next = False
            continue
        flag = part.split("=")[0] if "=" in part else part
        if flag.lower() in _DENIED_EXTRA_FLAGS:
            logger.warning("Stripped denied extra_args flag: %s", part)
            # If the flag takes a value as the next arg, skip it too
            if "=" not in part and i + 1 < len(parts) and not parts[i + 1].startswith("-"):
                skip_next = True
            continue
        filtered.append(part)
    return filtered


def _build_nmap_scan(params: dict) -> list[str]:
    """Build nmap command from params."""
    args = []
    scan_map = {
        "syn": "-sS", "connect": "-sT", "udp": "-sU", "ack": "-sA",
        "fin": "-sF", "xmas": "-sX", "null": "-sN", "ping": "-sn",
    }
    scan_type = params.get("scan_type", "syn")
    args.append(scan_map.get(scan_type, "-sS"))

    if params.get("version_detection", True):
        args.append("-sV")
    if params.get("os_detection"):
        args.append("-O")
    if params.get("ports"):
        args.extend(["-p", params["ports"]])
    if params.get("scripts"):
        args.extend(["--script", params["scripts"]])

    timing = params.get("timing", 4)
    args.append(f"-T{timing}")

    output_map = {"xml": "-oX -", "greppable": "-oG -"}
    fmt = params.get("output_format", "normal")
    if fmt in output_map:
        args.extend(output_map[fmt].split())

    args.extend(_split_extra(params))
    args.append(params["target"])
    return args


def _build_nmap_advanced(params: dict) -> list[str]:
    """Build advanced nmap command from params.

    Fixes: prevents duplicate -p when extra_args also contains a -p flag.
    The explicit 'ports' parameter takes precedence over -p in extra_args.
    """
    args = ["-sS", "-sV"]
    has_explicit_ports = bool(params.get("ports"))
    if has_explicit_ports:
        args.extend(["-p", params["ports"]])
    if params.get("script_categories"):
        args.extend(["--script", ",".join(params["script_categories"])])
    if params.get("script_args"):
        args.extend(["--script-args", params["script_args"]])
    if params.get("decoys"):
        args.extend(["-D", params["decoys"]])
    if params.get("fragment"):
        args.append("-f")
    if params.get("source_port"):
        args.extend(["--source-port", str(params["source_port"])])
    if params.get("min_rate"):
        args.extend(["--min-rate", str(params["min_rate"])])
    if params.get("max_rate"):
        args.extend(["--max-rate", str(params["max_rate"])])

    # Strip duplicate -p from extra_args when ports was already set explicitly
    extra = _split_extra(params)
    if has_explicit_ports:
        cleaned = []
        skip_next = False
        for i, tok in enumerate(extra):
            if skip_next:
                skip_next = False
                continue
            if tok == "-p":
                # Skip -p and its value
                if i + 1 < len(extra) and not extra[i + 1].startswith("-"):
                    skip_next = True
                continue
            cleaned.append(tok)
        extra = cleaned
    args.extend(extra)
    args.append(params["target"])
    return args


def _build_rustscan(params: dict) -> list[str]:
    args = ["-a", params["target"]]
    if params.get("ports"):
        args.extend(["-r", params["ports"]])
    if params.get("batch_size"):
        args.extend(["-b", str(params["batch_size"])])
    if params.get("timeout"):
        args.extend(["-t", str(params["timeout"])])
    if params.get("ulimit"):
        args.extend(["--ulimit", str(params["ulimit"])])
    if params.get("nmap_args"):
        args.extend(["--", *params["nmap_args"].split()])
    args.extend(_split_extra(params))
    return args

def _build_amass(params: dict) -> list[str]:
    mode = params.get("mode", "passive")
    args = ["enum"]
    if mode == "passive":
        args.append("-passive")
    args.extend(["-d", params["domain"]])
    if params.get("brute_force"):
        args.append("-brute")
    if params.get("wordlist"):
        args.extend(["-w", params["wordlist"]])
    if params.get("timeout_minutes"):
        args.extend(["-timeout", str(params["timeout_minutes"])])
    args.extend(_split_extra(params))
    return args

def _build_httpx(params: dict) -> list[str]:
    """Build httpx command.

    Compatibility-aware: reads _compat_profile from params (injected by the
    pre-execution gate) to adapt flags for the installed binary variant.
    When no profile is present, assumes ProjectDiscovery httpx.
    """
    caps = (params.get("_compat_profile") or {}).get("capabilities", {})
    args = []
    if params.get("targets_file"):
        args.extend(["-l", params["targets_file"]])
    else:
        args.append(params["target"])

    # Only emit PD-specific flags when the binary supports them
    if params.get("status_code", True) and caps.get("-sc", True):
        args.append("-sc")
    if params.get("title", True) and caps.get("-title", True):
        args.append("-title")
    if params.get("tech_detect", True) and caps.get("-tech-detect", True):
        args.append("-tech-detect")
    if params.get("follow_redirects", True) and caps.get("-follow-redirects", True):
        args.append("-follow-redirects")
    if params.get("threads") and caps.get("-threads", True):
        args.extend(["-threads", str(params["threads"])])
    args.extend(_split_extra(params))
    return args


def _build_whatweb(params: dict) -> list[str]:
    args = []
    if params.get("aggression"):
        level = int(params["aggression"])
        # WhatWeb rejects level 2 ("must be 1,3, or 4"), coerce to 3.
        if level == 2:
            level = 3
        if level not in (1, 3, 4):
            level = 1
        args.extend(["-a", str(level)])
    if params.get("verbose"):
        args.append("-v")
    args.extend(_split_extra(params))
    args.append(params["target"])
    return args


def _build_gobuster(params: dict) -> list[str]:
    """Build gobuster command.

    Compatibility-aware: newer gobuster versions removed -s (include status
    codes) and default to showing all codes.  When status_codes is provided,
    we emit -b (exclude blacklist) if the probe says the binary only supports
    exclude mode, or -s if include mode is available.  Extra args that
    duplicate already-emitted flags are stripped to prevent conflicts.
    """
    caps = (params.get("_compat_profile") or {}).get("capabilities", {})
    mode = params.get("mode", "dir")
    args = [mode, "-u", params["target"], "-w", params["wordlist"]]
    if params.get("extensions"):
        args.extend(["-x", params["extensions"]])
    if params.get("threads"):
        args.extend(["-t", str(params["threads"])])
    if params.get("status_codes"):
        sc_mode = caps.get("status_code_mode", "include")
        if sc_mode == "exclude_only":
            # Cannot include: skip -s to avoid unknown-flag error.
            # If user passed codes to include, we can't honour that on
            # this binary — let gobuster show all and rely on post-filter.
            pass
        else:
            args.extend(["-s", params["status_codes"]])
    if params.get("exclude_length"):
        args.extend(["--exclude-length", params["exclude_length"]])

    # Deduplicate extra_args against already-emitted flags
    extra = _split_extra(params)
    emitted = {a for a in args if a.startswith("-")}
    deduped = []
    skip_next = False
    for i, tok in enumerate(extra):
        if skip_next:
            skip_next = False
            continue
        # Skip flags already emitted (e.g. duplicate -t, -x)
        if tok in emitted and tok in ("-t", "-x", "-s", "-b", "-u", "-w"):
            # Also skip the value that follows the flag
            if i + 1 < len(extra) and not extra[i + 1].startswith("-"):
                skip_next = True
            continue
        deduped.append(tok)
    args.extend(deduped)
    return args


def _build_feroxbuster(params: dict) -> list[str]:
    args = ["-u", params["target"]]
    if params.get("wordlist"):
        args.extend(["-w", params["wordlist"]])
    if params.get("extensions"):
        args.extend(["-x", params["extensions"]])
    if params.get("threads"):
        args.extend(["-t", str(params["threads"])])
    if params.get("depth"):
        args.extend(["-d", str(params["depth"])])
    if params.get("status_codes"):
        args.extend(["-s", params["status_codes"]])
    if params.get("filter_status"):
        args.extend(["-C", params["filter_status"]])
    if params.get("filter_size"):
        args.extend(["-S", params["filter_size"]])
    if params.get("headers"):
        for k, v in params["headers"].items():
            args.extend(["-H", f"{k}: {v}"])
    if params.get("insecure"):
        args.append("-k")
    # Deduplicate flags that can't appear twice (e.g. --insecure/-k)
    extra = _split_extra(params)
    seen_singles = {a for a in args if a.startswith("-") and ":" not in a}
    deduped_extra = []
    for token in extra:
        if token in ("-k", "--insecure") and ("-k" in seen_singles or "--insecure" in seen_singles):
            continue
        deduped_extra.append(token)
    args.extend(deduped_extra)
    return args


def _build_ffuf(params: dict) -> list[str]:
    args = ["-u", params["url"], "-w", params["wordlist"]]
    if params.get("method"):
        args.extend(["-X", params["method"]])
    if params.get("headers"):
        for k, v in params["headers"].items():
            args.extend(["-H", f"{k}: {v}"])
    if params.get("data"):
        args.extend(["-d", params["data"]])
    if params.get("filter_code"):
        args.extend(["-fc", params["filter_code"]])
    if params.get("filter_size"):
        args.extend(["-fs", params["filter_size"]])
    if params.get("filter_words"):
        args.extend(["-fw", params["filter_words"]])
    if params.get("match_code"):
        args.extend(["-mc", params["match_code"]])
    if params.get("threads"):
        args.extend(["-t", str(params["threads"])])
    if params.get("rate"):
        args.extend(["-rate", str(params["rate"])])
    if params.get("recursion"):
        args.append("-recursion")
    if params.get("recursion_depth"):
        args.extend(["-recursion-depth", str(params["recursion_depth"])])
    args.extend(_split_extra(params))
    return args


def _build_nikto(params: dict) -> list[str]:
    """Build nikto command.

    Fixes the invalid URI/port combination: when the target already contains
    a port (e.g. http://host:8080 or host:8080), nikto -h already picks it
    up.  Adding -p on top creates an invalid target and double-port errors.
    Also auto-detects HTTPS targets and adds -ssl when appropriate.
    """
    target = params["target"]
    explicit_port = params.get("port")

    # Parse port from target URL to avoid duplicate -p
    target_has_port = False
    target_is_https = False
    if "://" in target:
        from urllib.parse import urlparse
        parsed = urlparse(target)
        if parsed.port:
            target_has_port = True
        target_is_https = parsed.scheme == "https"
    elif ":" in target:
        # bare host:port
        parts = target.rsplit(":", 1)
        if parts[-1].isdigit():
            target_has_port = True

    args = ["-h", target]

    # Only add -p when the target doesn't already embed a port
    if explicit_port and not target_has_port:
        args.extend(["-p", str(explicit_port)])

    # Auto-enable SSL for https targets
    if params.get("ssl") or target_is_https:
        args.append("-ssl")

    if params.get("tuning"):
        args.extend(["-Tuning", params["tuning"]])
    if params.get("plugins"):
        args.extend(["-Plugins", params["plugins"]])
    if params.get("maxtime"):
        args.extend(["-maxtime", str(params["maxtime"])])
    args.extend(_split_extra(params))
    return args


def _build_nuclei(params: dict) -> list[str]:
    args = []
    if params.get("targets_file"):
        args.extend(["-l", params["targets_file"]])
    else:
        args.extend(["-u", params["target"]])
    if params.get("templates"):
        args.extend(["-t", params["templates"]])
    if params.get("tags"):
        args.extend(["-tags", params["tags"]])
    if params.get("severity"):
        args.extend(["-severity", params["severity"]])
    if params.get("rate_limit"):
        args.extend(["-rl", str(params["rate_limit"])])
    if params.get("concurrency"):
        args.extend(["-c", str(params["concurrency"])])
    if params.get("header"):
        args.extend(["-H", params["header"]])
    args.extend(_split_extra(params))
    return args

def _build_msfconsole(params: dict) -> list[str]:
    """Build msfconsole command.

    Phase 6: Forces non-interactive mode by always appending 'exit' to -x
    commands so msfconsole doesn't hang waiting for interactive input.
    """
    args = []
    if params.get("quiet", True):
        args.append("-q")
    if params.get("resource_file"):
        rf = params["resource_file"]
        if ".." in rf or rf.startswith("/") and not rf.startswith("/app/engagements"):
            raise ValueError(f"resource_file path not allowed: {rf!r}")
        args.extend(["-r", rf])
    elif params.get("command"):
        cmd = params["command"].rstrip().rstrip(";")
        # Ensure the command chain ends with 'exit' to prevent hanging
        if not cmd.lower().endswith("exit"):
            cmd = cmd + "; exit"
        args.extend(["-x", cmd])
    else:
        # No command or resource file — force immediate exit
        args.extend(["-x", "exit"])
    args.extend(_split_extra(params))
    return args


def _build_msfvenom(params: dict) -> list[str]:
    args = ["-p", params["payload"]]
    if params.get("lhost"):
        args.append(f"LHOST={params['lhost']}")
    if params.get("lport"):
        args.append(f"LPORT={params['lport']}")
    if params.get("format"):
        args.extend(["-f", params["format"]])
    if params.get("encoder"):
        args.extend(["-e", params["encoder"]])
    if params.get("iterations"):
        args.extend(["-i", str(params["iterations"])])
    if params.get("platform"):
        args.extend(["--platform", params["platform"]])
    if params.get("arch"):
        args.extend(["-a", params["arch"]])
    if params.get("output_file"):
        args.extend(["-o", params["output_file"]])
    if params.get("bad_chars"):
        args.extend(["-b", params["bad_chars"]])
    args.extend(_split_extra(params))
    return args


_MSF_MODULE_RE = re.compile(r"^(exploit|auxiliary|post|payload|encoder|nop)/[\w/]+$")
_MSF_OPTION_UNSAFE = re.compile(r"[;\n\r`$|&]")


def _build_metasploit_module(params: dict) -> list[str]:
    """Build msfconsole -x command for a module with options.

    Validates module names and sanitizes option values to prevent
    command injection via semicolons or shell metacharacters.
    """
    module = params["module"]
    if not _MSF_MODULE_RE.match(module):
        raise ValueError(f"Invalid Metasploit module name: {module!r}")

    lines = [f"use {module}"]
    for k, v in (params.get("options") or {}).items():
        k_safe = re.sub(r"[^A-Za-z0-9_]", "", str(k))
        v_safe = _MSF_OPTION_UNSAFE.sub("", str(v))
        lines.append(f"set {k_safe} {v_safe}")
    if params.get("payload"):
        payload = params["payload"]
        if not re.match(r"^[\w/]+$", payload):
            raise ValueError(f"Invalid payload name: {payload!r}")
        lines.append(f"set PAYLOAD {payload}")
    for k, v in (params.get("payload_options") or {}).items():
        k_safe = re.sub(r"[^A-Za-z0-9_]", "", str(k))
        v_safe = _MSF_OPTION_UNSAFE.sub("", str(v))
        lines.append(f"set {k_safe} {v_safe}")
    if params.get("action"):
        action = re.sub(r"[^A-Za-z0-9_\- ]", "", str(params["action"]))
        lines.append(f"set ACTION {action}")
    lines.append("run")
    lines.append("exit")
    cmd_str = "; ".join(lines)
    args = ["-q", "-x", cmd_str]
    args.extend(_split_extra(params))
    return args


def _build_hydra(params: dict) -> list[str]:
    args = []
    if params.get("username"):
        args.extend(["-l", params["username"]])
    if params.get("username_list"):
        args.extend(["-L", params["username_list"]])
    if params.get("password"):
        args.extend(["-p", params["password"]])
    if params.get("password_list"):
        args.extend(["-P", params["password_list"]])
    if params.get("port"):
        args.extend(["-s", str(params["port"])])
    if params.get("threads"):
        args.extend(["-t", str(params["threads"])])
    args.extend(_split_extra(params))
    target = params["target"]
    service = params["service"]
    if params.get("http_form") and "http" in service:
        args.extend([target, service, params["http_form"]])
    else:
        args.extend([target, service])
    return args

def _build_generic_command(params: dict) -> list[str]:
    """Build args for generic shell command execution."""
    shell = params.get("shell", "bash")
    return ["-c", params["command"]]

def _build_strings(params: dict) -> list[str]:
    args = []
    if params.get("min_length"):
        args.extend(["-n", str(params["min_length"])])
    if params.get("encoding"):
        args.extend(["-e", params["encoding"]])
    if params.get("offset"):
        args.append("-t")
        args.append("x")
    args.extend(_split_extra(params))
    args.append(params["file"])
    return args


def _build_radare2(params: dict) -> list[str]:
    args = ["-q"]
    if params.get("write_mode"):
        args.append("-w")
    for cmd in params.get("commands", []):
        args.extend(["-c", cmd])
    args.extend(_split_extra(params))
    args.append(params["file"])
    return args


def _build_gdb(params: dict) -> list[str]:
    args = ["--batch"]
    for cmd in params.get("commands", []):
        args.extend(["-ex", cmd])
    if params.get("args"):
        args.extend(["--args", params["file"]] + params["args"].split())
    else:
        args.append(params["file"])
    if params.get("pid"):
        args.extend(["-p", str(params["pid"])])
    args.extend(_split_extra(params))
    return args

def _build_objdump(params: dict) -> list[str]:
    args = []
    if params.get("intel_syntax", True):
        args.extend(["-M", "intel"])
    if params.get("disassemble_all"):
        args.append("-D")
    elif params.get("disassemble", True):
        args.append("-d")
    if params.get("headers"):
        args.append("-h")
    if params.get("symbols"):
        args.append("-t")
    if params.get("reloc"):
        args.append("-r")
    if params.get("section"):
        args.extend(["-j", params["section"]])
    args.extend(_split_extra(params))
    args.append(params["file"])
    return args


def _build_readelf(params: dict) -> list[str]:
    args = []
    if params.get("all"):
        args.append("-a")
    else:
        if params.get("headers"):
            args.append("-h")
        if params.get("sections"):
            args.append("-S")
        if params.get("symbols"):
            args.append("-s")
        if params.get("dynamic"):
            args.append("-d")
        if params.get("relocs"):
            args.append("-r")
        if params.get("notes"):
            args.append("-n")
        # If nothing was specified, default to showing the header
        if len(args) == 0:
            args.append("-h")
    args.extend(_split_extra(params))
    args.append(params["file"])
    return args


def _build_sherlock(params: dict) -> list[str]:
    import re
    username = params.get("username", "")

    # Reject IP addresses, domains, and URLs as usernames
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', username):
        raise ValueError(f"Sherlock searches social media usernames, not IP addresses. '{username}' is an IP address.")
    if re.match(r'^[\d.]+$', username):
        raise ValueError(f"Sherlock searches social media usernames, not numeric strings. '{username}' looks like an IP without dots.")
    if '.' in username and not re.match(r'^[a-zA-Z][a-zA-Z0-9._-]*$', username):
        raise ValueError(f"'{username}' looks like a domain/hostname, not a social media username.")
    if username.startswith(('http://', 'https://')):
        raise ValueError(f"Sherlock searches social media usernames, not URLs.")

    args = []
    if params.get("print_found", True):
        args.append("--print-found")
    if params.get("timeout"):
        args.extend(["--timeout", str(params["timeout"])])
    if params.get("output_file"):
        args.extend(["-o", params["output_file"]])
    if params.get("sites"):
        for site in params["sites"]:
            args.extend(["--site", site])
    args.extend(_split_extra(params))
    args.append(username)
    return args


def _build_shodan(params: dict) -> list[str]:
    if params.get("host"):
        return ["host", params["host"]] + _split_extra(params)
    args = ["search"]
    if params.get("count"):
        args = ["count"]
    if params.get("facets"):
        args.extend(["--facets", params["facets"]])
    if params.get("limit"):
        args.extend(["--limit", str(params["limit"])])
    args.extend(_split_extra(params))
    if params.get("query"):
        args.append(params["query"])
    return args

def _build_recon_ng(params: dict) -> list[str]:
    args = []
    if params.get("workspace"):
        args.extend(["-w", params["workspace"]])
    if params.get("module"):
        args.extend(["-m", params["module"]])
    if params.get("commands"):
        for cmd in params["commands"]:
            args.extend(["-c", cmd])
    args.extend(_split_extra(params))
    return args


def _build_censys(params: dict) -> list[str]:
    index = params.get("index", "hosts")
    args = ["search", params["query"]]
    if index != "hosts":
        args = ["search", "--index-type", index, params["query"]]
    if params.get("fields"):
        args.extend(["--fields", ",".join(params["fields"])])
    if params.get("max_records"):
        args.extend(["--max-records", str(params["max_records"])])
    args.extend(_split_extra(params))
    return args

def _build_bloodhound_query(params: dict) -> list[str]:
    """Build command for BloodHound query via cypher-shell or custom script.

    For predefined queries, this builds a cypher-shell command against the
    Neo4j database where BloodHound data has been imported.
    """
    neo4j_uri = params.get("neo4j_uri", "bolt://localhost:7687")
    neo4j_user = params.get("neo4j_user", "neo4j")
    neo4j_password = params.get("neo4j_password", "neo4j")

    query_type = params["query_type"]

    cypher_queries = {
        "find_da_paths": (
            "MATCH p=shortestPath((u:User)-[*1..]->(g:Group)) "
            "WHERE g.name =~ '(?i).*DOMAIN ADMINS.*' "
            "AND u.name =~ '(?i).*{start_node}.*' "
            "RETURN p LIMIT 20"
        ),
        "kerberoastable": (
            "MATCH (u:User) WHERE u.hasspn=true "
            "RETURN u.name AS name, u.serviceprincipalnames AS spns, "
            "u.admincount AS admin_count, u.enabled AS enabled"
        ),
        "asreproastable": (
            "MATCH (u:User) WHERE u.dontreqpreauth=true "
            "RETURN u.name AS name, u.enabled AS enabled, u.lastlogon AS last_logon"
        ),
        "unconstrained_delegation": (
            "MATCH (c:Computer) WHERE c.unconstraineddelegation=true "
            "RETURN c.name AS computer, c.operatingsystem AS os"
        ),
        "high_value_targets": (
            "MATCH (n) WHERE n.highvalue=true "
            "RETURN labels(n) AS type, n.name AS name"
        ),
        "owned_to_da": (
            "MATCH p=shortestPath((o)-[*1..]->(g:Group)) "
            "WHERE o.owned=true AND g.name =~ '(?i).*DOMAIN ADMINS.*' "
            "RETURN p LIMIT 20"
        ),
        "domain_trusts": (
            "MATCH (d1:Domain)-[r:TrustedBy]->(d2:Domain) "
            "RETURN d1.name AS source, d2.name AS target, r.trusttype AS type, "
            "r.transitive AS transitive, r.sidfiltering AS sid_filtering"
        ),
    }

    if query_type == "custom":
        # Sanitize custom queries: reject obvious injection patterns
        raw_query = params.get("custom_query", "RETURN 1")
        if re.search(r"(?i)\b(CALL|LOAD|CREATE|DELETE|DETACH|MERGE|SET|REMOVE)\b", raw_query):
            raise ValueError("Custom Cypher queries must not contain mutating operations")
        cypher = raw_query
    else:
        cypher = cypher_queries.get(query_type, "RETURN 1")

    if query_type == "find_da_paths" and params.get("start_node"):
        # Sanitize start_node to prevent Cypher injection
        start_node = re.sub(r"[^a-zA-Z0-9_. @\-]", "", params["start_node"])
        cypher = cypher.replace("{start_node}", start_node)
    elif query_type == "find_da_paths":
        cypher = cypher.replace("{start_node}", ".*")

    args = [
        "-a", neo4j_uri,
        "-u", neo4j_user,
        "-p", neo4j_password,
        "--format", "plain",
        cypher,
    ]
    return args


# ---- Browser tools: all python3-based, return None ----

def _build_browser_navigate(params: dict) -> list[str]:
    p = {k: v for k, v in params.items() if not k.startswith("_")}
    return ["python3", "-m", "tools.browser_backend", "navigate", json.dumps(p)]


def _build_browser_screenshot(params: dict) -> list[str]:
    p = {k: v for k, v in params.items() if not k.startswith("_")}
    return ["python3", "-m", "tools.browser_backend", "screenshot", json.dumps(p)]


def _build_browser_analyze(params: dict) -> list[str]:
    p = {k: v for k, v in params.items() if not k.startswith("_")}
    return ["python3", "-m", "tools.browser_backend", "analyze", json.dumps(p)]


def _build_browser_network_monitor(params: dict) -> list[str]:
    p = {k: v for k, v in params.items() if not k.startswith("_")}
    return ["python3", "-m", "tools.browser_backend", "network_monitor", json.dumps(p)]


def _build_browser_crawl(params: dict) -> list[str]:
    p = {k: v for k, v in params.items() if not k.startswith("_")}
    return ["python3", "-m", "tools.browser_backend", "crawl", json.dumps(p)]


# ---- Credential tools ----

def _build_patator(params: dict) -> list[str]:
    args = [params["module"]]
    args.append(f"host={params['target']}")
    if params.get("port"):
        args.append(f"port={params['port']}")
    if params.get("username"):
        args.append(f"user={params['username']}")
    if params.get("password_file"):
        args.append(f"password=FILE0")
        args.append(f"0={params['password_file']}")
    args.extend(_split_extra(params))
    return args

def _build_crackstation_lookup(params: dict) -> None:
    return None


# ---- Attack: smbmap_exploit & netexec_exploit ----

# ---- Binary: new tools ----

# _build_ghidra removed — replaced by ghidra-mcp HTTP transport


def _build_angr_analyze(params: dict) -> None:
    return None


def _build_libc_database_lookup(params: dict) -> None:
    return None

def _build_pwntools_run(params: dict) -> None:
    return None

def _build_falco(params: dict) -> list[str]:
    args = []
    if params.get("rules_file"):
        args.extend(["-r", params["rules_file"]])
    if params.get("duration"):
        args.extend(["-M", str(params["duration"])])
    fmt = params.get("output_format", "json")
    if fmt == "json":
        args.append("--json-output")
    args.extend(_split_extra(params))
    return args

def _build_gcloud_cli(params: dict) -> list[str]:
    args = [params["service"]]
    args.extend(params["command"].split())
    args.extend(_split_extra(params))
    return args


# --- Forensics builders ---

def _build_photorec(params: dict) -> list[str]:
    args = ["/d", params.get("output_dir", "/tmp/photorec_out")]
    if params.get("file_types"):
        args.extend(["/fileopt", params["file_types"]])
    args.extend(_split_extra(params))
    args.append(params["device"])
    return args


def _build_testdisk(params: dict) -> list[str]:
    args = []
    if params.get("log_file"):
        args.extend(["/log", params["log_file"]])
    else:
        args.append("/log")
    args.extend(_split_extra(params))
    args.append(params["device"])
    return args


def _build_bulk_extractor(params: dict) -> list[str]:
    args = ["-o", params["output_dir"]]
    if params.get("scanners"):
        for scanner in params["scanners"].split(","):
            args.extend(["-e", scanner.strip()])
    args.extend(_split_extra(params))
    args.append(params["image_file"])
    return args


def _build_steghide(params: dict) -> list[str]:
    args = ["extract", "-sf", params["stego_file"]]
    if params.get("passphrase") is not None:
        args.extend(["-p", params["passphrase"]])
    if params.get("extract_file"):
        args.extend(["-xf", params["extract_file"]])
    else:
        args.append("-f")
    args.extend(_split_extra(params))
    return args


def _build_stegsolve(params: dict) -> list[str]:
    args = ["-jar", "StegSolve.jar", params["image_file"]]
    args.extend(_split_extra(params))
    return args

def _build_sleuthkit(params: dict) -> list[str]:
    """Build Sleuth Kit command. The binary is determined by the command param."""
    args = []
    if params.get("offset"):
        args.extend(["-o", str(params["offset"])])
    if params["command"] == "icat" and params.get("inode"):
        args.extend(_split_extra(params))
        args.append(params["image_file"])
        args.append(str(params["inode"]))
    else:
        args.extend(_split_extra(params))
        args.append(params["image_file"])
    return args


def _build_cyberchef_process(params: dict) -> list[str]:
    """Python3-based tool - handled elsewhere."""
    return None


def _build_rsatool_analyze(params: dict) -> list[str]:
    """Python3-based tool - handled elsewhere."""
    return None


def _build_factordb_lookup(params: dict) -> list[str]:
    """Python3-based tool - handled elsewhere."""
    return None


# --- OSINT builders (new) ---

# =============================================================================
# NEW RECON TOOL BUILDERS
# =============================================================================

def _build_autorecon(params: dict) -> list[str]:
    args = [params["target"]]
    if params.get("profile") and params["profile"] != "default":
        args.extend(["--profile", params["profile"]])
    if params.get("output_dir"):
        args.extend(["-o", params["output_dir"]])
    if params.get("ports"):
        args.extend(["-p", params["ports"]])
    args.extend(_split_extra(params))
    return args

def _build_arp_scan(params: dict) -> list[str]:
    args = []
    if params.get("interface"):
        args.extend(["-I", params["interface"]])
    target = params["target"]
    if target == "--localnet":
        args.append("--localnet")
    else:
        args.append(target)
    args.extend(_split_extra(params))
    return args

def _build_smbclient(params: dict) -> list[str]:
    target = params["target"]
    share = params.get("share", "")
    if share:
        args = [f"//{target}/{share}"]
    else:
        args = ["-L", target]
    if params.get("username"):
        args.extend(["-U", params["username"]])
    if params.get("password"):
        args.extend(["--password", params["password"]])
    if params.get("command"):
        args.extend(["-c", params["command"]])
    args.extend(_split_extra(params))
    return args

# =============================================================================
# NEW WEBAPP TOOL BUILDERS
# =============================================================================

def _build_katana(params: dict) -> list[str]:
    """Build katana command.

    Compatibility-aware: adapts flags based on _compat_profile from the
    probe (e.g. -js-crawl vs -jc, -cs vs -crawl-scope, -jsonl vs -json).
    """
    caps = (params.get("_compat_profile") or {}).get("capabilities", {})
    args = ["-u", params["url"]]
    if params.get("depth"):
        args.extend(["-d", str(params["depth"])])
    if params.get("headless") and caps.get("-headless", True):
        args.append("-headless")
    if params.get("js_crawl"):
        # Use the probed flag name, falling back to -js-crawl
        js_flag = caps.get("js_crawl_flag", "-js-crawl")
        if js_flag:
            args.append(js_flag)
    if params.get("scope"):
        scope_flag = caps.get("scope_flag", "-cs")
        if scope_flag:
            args.extend([scope_flag, params["scope"]])
    if params.get("headers"):
        if caps.get("-H", True):
            for k, v in params["headers"].items():
                args.extend(["-H", f"{k}: {v}"])
    fmt = params.get("output_format", "")
    if fmt == "json":
        json_flag = caps.get("json_flag", "-jsonl")
        if json_flag:
            args.append(json_flag)
    elif fmt == "csv" and caps.get("-f", True):
        args.extend(["-f", "url,method,body,status_code,content_type"])
    args.extend(_split_extra(params))
    return args

def _build_arjun(params: dict) -> list[str]:
    """Build arjun command — strips -k/--insecure from extra_args."""
    args = []
    if params.get("url"):
        args.extend(["-u", params["url"]])
    if params.get("method"):
        args.extend(["-m", params["method"]])
    if params.get("headers"):
        args.extend(["--headers", params["headers"]])
    if params.get("wordlist"):
        args.extend(["-w", params["wordlist"]])
    if params.get("threads"):
        args.extend(["-t", str(params["threads"])])
    extra = _split_extra(params)
    extra = [a for a in extra if a not in ("-k", "--insecure")]
    args.extend(extra)
    return args


def _build_aquatone(params: dict) -> list[str]:
    # gowitness replaces unmaintained aquatone for visual recon / screenshotting.
    # Usage: gowitness scan single --url <url> --screenshot-path <dir>
    args = ["scan", "single"]
    if params.get("url"):
        args.extend(["--url", params["url"]])
    if params.get("output_dir"):
        args.extend(["--screenshot-path", params["output_dir"]])
    if params.get("threads"):
        args.extend(["--threads", str(params["threads"])])
    args.extend(_split_extra(params))
    return args


# =============================================================================
# NEW INJECT TOOL BUILDERS
# =============================================================================

def _build_jwt_tool(params: dict) -> list[str]:
    args = [params["token"]]
    mode = params.get("mode", "scan")
    if mode == "scan":
        args.append("-M")
        args.append("at")
    elif mode == "exploit":
        exploit = params.get("exploit_type", "none")
        if exploit == "alg":
            args.extend(["-X", "a"])
        elif exploit == "kid":
            args.extend(["-X", "k"])
        elif exploit == "jku":
            args.extend(["-X", "s"])
        elif exploit == "x5u":
            args.extend(["-X", "s"])
        elif exploit == "jwk":
            args.extend(["-X", "i"])
    if params.get("secret"):
        args.extend(["-C", "-d", params["secret"]])
    args.extend(_split_extra(params))
    return args

def _build_zap_scan(params: dict) -> list[str]:
    scan_type = params.get("scan_type", "quick")
    if scan_type == "quick":
        args = ["quick-scan", params["target"]]
    elif scan_type == "full":
        args = ["active-scan", params["target"]]
    elif scan_type == "ajax":
        args = ["ajax-spider", params["target"]]
    else:
        args = ["quick-scan", params["target"]]
    args.extend(_split_extra(params))
    return args

# =============================================================================
# COMMAND_BUILDERS registry: tool_name -> builder function
# =============================================================================

COMMAND_BUILDERS: dict[str, Callable[[dict], list[str]]] = {
    # Recon
    "nmap_scan": _build_nmap_scan,
    "nmap_advanced": _build_nmap_advanced,
    "rustscan_scan": _build_rustscan,
    "amass_enum": _build_amass,
    "httpx_probe": _build_httpx,
    "whatweb_scan": _build_whatweb,
    # Recon (new)
    "autorecon_scan": _build_autorecon,
    "arp_scan": _build_arp_scan,
    "smbclient_scan": _build_smbclient,
    # Webapp
    "gobuster_scan": _build_gobuster,
    "feroxbuster_scan": _build_feroxbuster,
    "ffuf_scan": _build_ffuf,
    "nikto_scan": _build_nikto,
    "nuclei_scan": _build_nuclei,
    # Webapp (new)
    "katana_crawl": _build_katana,
    "arjun_scan": _build_arjun,
    "aquatone_screenshot": _build_aquatone,
    # Inject
    "jwt_tool_scan": _build_jwt_tool,
    "zap_scan": _build_zap_scan,
    # Attack (combines exploit and privesc)
    "msfconsole_run": _build_msfconsole,
    "msfvenom_generate": _build_msfvenom,
    "metasploit_module": _build_metasploit_module,
    "hydra_attack": _build_hydra,
    "generic_command": _build_generic_command,
    # Cloud
    # Binary/RE
    "strings_extract": _build_strings,
    "radare2_analyze": _build_radare2,
    "gdb_analyze": _build_gdb,
    "gdb_peda": _build_gdb,
    "objdump_disasm": _build_objdump,
    "readelf_analyze": _build_readelf,
    # OSINT
    "sherlock_search": _build_sherlock,
    "shodan_search": _build_shodan,
    "recon_ng_run": _build_recon_ng,
    "censys_search": _build_censys,
    # BloodHound
    "bloodhound_query": _build_bloodhound_query,
    # Browser (python3-based, builders return None)
    "browser_navigate": _build_browser_navigate,
    "browser_screenshot": _build_browser_screenshot,
    "browser_analyze": _build_browser_analyze,
    "browser_network_monitor": _build_browser_network_monitor,
    "browser_crawl": _build_browser_crawl,
    # Credential
    "patator_attack": _build_patator,
    "crackstation_lookup": _build_crackstation_lookup,
    # Attack (new)
    # Binary (new)
    # ghidra_analyze removed — replaced by ghidra-mcp HTTP transport
    "angr_analyze": _build_angr_analyze,
    "libc_database_lookup": _build_libc_database_lookup,
    "pwntools_run": _build_pwntools_run,
    # Cloud (new)
    "falco_monitor": _build_falco,
    "gcloud_cli_exec": _build_gcloud_cli,
    # Forensics
    "photorec_recover": _build_photorec,
    "testdisk_recover": _build_testdisk,
    "bulk_extractor_run": _build_bulk_extractor,
    "steghide_extract": _build_steghide,
    "stegsolve_analyze": _build_stegsolve,
    "sleuthkit_analyze": _build_sleuthkit,
    "cyberchef_process": _build_cyberchef_process,
    "rsatool_analyze": _build_rsatool_analyze,
    "factordb_lookup": _build_factordb_lookup,
    # OSINT (new)
}


# =============================================================================
# Helper functions
# =============================================================================

def get_tool_definitions_for_agent(agent_name: str, agent_config: dict = None) -> list[dict]:
    """Get tool definitions for a specific agent, including shared tools.

    All schemas come from the YAML catalog via ToolRegistry.

    Args:
        agent_name: Agent type key (e.g., "recon").
        agent_config: Optional YAML agent config dict (from AgentRegistry).
            If provided, uses the config's tool list to select schemas.
    """
    from tools.registry_loader import get_registry

    registry = get_registry()

    if agent_config:
        tool_names = agent_config.get("spec", {}).get("tools", [])
    else:
        tool_names = registry.get_tools_for_agent(agent_name)

    return registry.get_definitions_for_agent(agent_name, tool_names)


def get_all_tool_definitions() -> list[dict]:
    """Get all tool definitions across all agents (with shared tools once)."""
    from tools.registry_loader import get_registry
    return get_registry().get_all_definitions()


def _sanitize_builder_params(value: Any, path: str = "params") -> Any:
    """Normalize builder params and reject non-finite numeric values early."""
    if isinstance(value, bool) or value is None or isinstance(value, str):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError(f"Non-finite numeric parameter at {path}: {value!r}")
        return int(value) if value.is_integer() else value
    if isinstance(value, int):
        return value
    if isinstance(value, dict):
        return {
            key: _sanitize_builder_params(val, f"{path}.{key}")
            for key, val in value.items()
        }
    if isinstance(value, list):
        return [
            _sanitize_builder_params(item, f"{path}[{idx}]")
            for idx, item in enumerate(value)
        ]
    if isinstance(value, tuple):
        return tuple(
            _sanitize_builder_params(item, f"{path}[{idx}]")
            for idx, item in enumerate(value)
        )
    return value


# ---------------------------------------------------------------------------
# Data-driven (YAML flag_map) builder
# ---------------------------------------------------------------------------


def _get_flag_map(tool_name: str) -> list[dict] | None:
    """Get the flag_map for a tool from the YAML catalog via ToolRegistry."""
    from tools.registry_loader import get_registry
    return get_registry().get_flag_map(tool_name)


def _build_from_flag_map(params: dict, flag_map: list[dict]) -> list[str]:
    """Generic command builder driven by a YAML flag_map.

    flag_map entry format:
        param:     parameter name in params dict (or null for constant flags)
        flag:      CLI flag string, or null for positional arg
        transform: "str" (default), "bool" (flag-only), "int"
        join:      if true, emit as --flag=value instead of --flag value
        const:     constant value to always emit (no param lookup)
        position:  "head" for positionals before flags (default: "tail")
    """
    args = []
    head_positionals = []
    tail_positionals = []

    for entry in flag_map:
        param_name = entry.get("param", "")
        flag = entry.get("flag")
        transform = entry.get("transform", "str")
        join_flag = entry.get("join", False) or (flag and flag.endswith("="))
        position = entry.get("position", "tail")

        # Constant flag (always emitted, no param lookup)
        const = entry.get("const")
        if const is not None:
            args.append(str(const))
            continue

        value = params.get(param_name)
        if value is None:
            continue

        # Bool transform: emit flag only if true, skip if false
        if transform == "bool":
            if value:
                if flag:
                    args.append(flag.rstrip("="))
            continue

        # Skip empty strings
        if isinstance(value, str) and not value.strip():
            continue

        str_value = str(value)

        if flag is None:
            # Positional argument
            if position == "head":
                head_positionals.append(str_value)
            else:
                tail_positionals.append(str_value)
        elif join_flag:
            # --flag=value style (flag already ends with = or join was explicit)
            base = flag if flag.endswith("=") else flag + "="
            args.append(f"{base}{str_value}")
        else:
            # --flag value style
            args.extend([flag, str_value])

    # extra_args always processed via _split_extra
    extra = _split_extra(params)

    # Assemble: head positionals, flags, extra_args, tail positionals
    return head_positionals + args + extra + tail_positionals


def build_command(tool_name: str, params: dict) -> Optional[list[str]]:
    """
    Build a subprocess argument list for a tool.

    Checks COMMAND_BUILDERS first (hand-coded complex builders), then
    falls back to YAML flag_map (data-driven generic builder).
    """
    sanitized = _sanitize_builder_params(params or {})

    # 1. Hand-coded builder (complex tools)
    builder = COMMAND_BUILDERS.get(tool_name)
    if builder is not None:
        built = builder(sanitized)
        if built is None:
            raise ValueError(f"{tool_name} is not executable in the current runtime")
        return built

    # 2. Data-driven builder (YAML flag_map)
    flag_map = _get_flag_map(tool_name)
    if flag_map is not None:
        return _build_from_flag_map(sanitized, flag_map)

    return None

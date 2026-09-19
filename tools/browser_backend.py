"""
SnowStrike AI v7.2 - Browser Automation Backend

Playwright-based headless Chrome automation for BrowserAgent tools.
Each tool function returns JSON to stdout for the agent's consumption.

Usage (via subprocess from command builders):
    python3 -m tools.browser_backend <action> <json_params>

Actions: navigate, screenshot, analyze, network_monitor, crawl
"""

import json
import os
import sys
import time
import logging
import traceback
from pathlib import Path
from urllib.parse import urlparse, urljoin

logger = logging.getLogger(__name__)


def _launch_browser(headless: bool = True, user_agent: str = ""):
    """Launch a Playwright Chromium browser with pentest-safe defaults."""
    from playwright.sync_api import sync_playwright

    pw = sync_playwright().start()
    launch_args = [
        "--no-sandbox",
        "--disable-gpu",
        "--disable-dev-shm-usage",
        "--ignore-certificate-errors",
        "--disable-web-security",
        "--allow-running-insecure-content",
    ]
    browser = pw.chromium.launch(
        headless=headless,
        args=launch_args,
    )
    context_opts = {
        "ignore_https_errors": True,
        "java_script_enabled": True,
    }
    if user_agent:
        context_opts["user_agent"] = user_agent
    context = browser.new_context(**context_opts)
    context.set_default_timeout(30000)
    page = context.new_page()
    return pw, browser, context, page


def _safe_close(pw, browser):
    """Gracefully close browser and playwright."""
    try:
        browser.close()
    except Exception:
        pass
    try:
        pw.stop()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# navigate
# ---------------------------------------------------------------------------

def action_navigate(params: dict) -> dict:
    """Navigate to URL, return page content, final URL, status, and metadata."""
    url = params["url"]
    wait_for = params.get("wait_for", "")
    timeout_s = params.get("timeout", 30)
    user_agent = params.get("user_agent", "")

    pw, browser, context, page = _launch_browser(user_agent=user_agent)
    try:
        page.set_default_timeout(timeout_s * 1000)

        response = page.goto(url, wait_until="networkidle", timeout=timeout_s * 1000)

        if wait_for:
            if wait_for.endswith("s") and wait_for[:-1].isdigit():
                time.sleep(int(wait_for[:-1]))
            else:
                page.wait_for_selector(wait_for, timeout=10000)

        status_code = response.status if response else 0
        final_url = page.url
        title = page.title()
        content = page.content()

        # Extract visible text (truncated for context)
        try:
            visible_text = page.evaluate("() => document.body?.innerText || ''")
            visible_text = visible_text[:5000] if visible_text else ""
        except Exception:
            visible_text = ""

        # Detect redirects
        redirected = final_url != url

        # Count resources
        frames = len(page.frames)

        return {
            "success": True,
            "url": url,
            "final_url": final_url,
            "redirected": redirected,
            "status_code": status_code,
            "title": title,
            "frames": frames,
            "content_length": len(content),
            "visible_text": visible_text,
            "html_snippet": content[:3000],
        }
    except Exception as e:
        return {"success": False, "url": url, "error": str(e)}
    finally:
        _safe_close(pw, browser)


# ---------------------------------------------------------------------------
# screenshot
# ---------------------------------------------------------------------------

def action_screenshot(params: dict) -> dict:
    """Capture a screenshot of the target URL."""
    url = params["url"]
    full_page = params.get("full_page", False)
    viewport_w = params.get("viewport_width", 1280)
    viewport_h = params.get("viewport_height", 720)
    output_path = params.get("output_path", "")

    pw, browser, context, page = _launch_browser()
    try:
        page.set_viewport_size({"width": viewport_w, "height": viewport_h})
        response = page.goto(url, wait_until="networkidle", timeout=30000)

        if not output_path:
            output_path = f"/tmp/snowstrike_screenshot_{int(time.time())}.png"

        # Validate output path: reject path traversal and restrict to safe directories
        if ".." in output_path or "\x00" in output_path:
            raise ValueError(f"Invalid screenshot output path: {output_path!r}")
        allowed_prefixes = ("/tmp/", "/app/engagements/", "/home/")
        real_path = os.path.realpath(output_path)
        if not any(real_path.startswith(p) for p in allowed_prefixes):
            raise ValueError(f"Screenshot output path not in allowed directories: {output_path!r}")

        page.screenshot(path=output_path, full_page=full_page)

        status_code = response.status if response else 0
        title = page.title()

        return {
            "success": True,
            "url": url,
            "screenshot_path": output_path,
            "status_code": status_code,
            "title": title,
            "viewport": f"{viewport_w}x{viewport_h}",
            "full_page": full_page,
        }
    except Exception as e:
        return {"success": False, "url": url, "error": str(e)}
    finally:
        _safe_close(pw, browser)


# ---------------------------------------------------------------------------
# analyze
# ---------------------------------------------------------------------------

def action_analyze(params: dict) -> dict:
    """Analyze a page for security headers, forms, cookies, JS analysis."""
    url = params["url"]
    checks = params.get("checks", ["forms", "js_analysis", "security_headers", "cookies"])

    pw, browser, context, page = _launch_browser()
    try:
        response = page.goto(url, wait_until="networkidle", timeout=30000)
        result = {
            "success": True,
            "url": url,
            "final_url": page.url,
            "status_code": response.status if response else 0,
            "title": page.title(),
        }

        # --- Security Headers ---
        if "security_headers" in checks and response:
            headers = response.headers
            security_headers = {}
            header_checks = [
                "content-security-policy", "x-frame-options",
                "x-content-type-options", "strict-transport-security",
                "x-xss-protection", "referrer-policy",
                "permissions-policy", "access-control-allow-origin",
                "x-permitted-cross-domain-policies", "cross-origin-opener-policy",
                "cross-origin-resource-policy", "cross-origin-embedder-policy",
            ]
            missing_headers = []
            for h in header_checks:
                val = headers.get(h)
                if val:
                    security_headers[h] = val
                else:
                    missing_headers.append(h)

            # Analyze CSP
            csp = headers.get("content-security-policy", "")
            csp_issues = []
            if csp:
                if "unsafe-inline" in csp:
                    csp_issues.append("unsafe-inline allows inline scripts (XSS risk)")
                if "unsafe-eval" in csp:
                    csp_issues.append("unsafe-eval allows eval() (XSS risk)")
                if "'none'" not in csp and "script-src" not in csp:
                    csp_issues.append("No explicit script-src directive")
                if "*" in csp.split():
                    csp_issues.append("Wildcard (*) in CSP allows any source")

            # Analyze HSTS
            hsts = headers.get("strict-transport-security", "")
            hsts_issues = []
            if hsts:
                if "includeSubDomains" not in hsts:
                    hsts_issues.append("Missing includeSubDomains")
                import re
                max_age_match = re.search(r"max-age=(\d+)", hsts)
                if max_age_match and int(max_age_match.group(1)) < 31536000:
                    hsts_issues.append(f"max-age={max_age_match.group(1)} is below recommended 31536000")
            elif response and url.startswith("https"):
                hsts_issues.append("HSTS not set on HTTPS endpoint")

            # Analyze CORS
            cors = headers.get("access-control-allow-origin", "")
            cors_issues = []
            if cors == "*":
                cors_issues.append("Wildcard CORS (Access-Control-Allow-Origin: *)")

            result["security_headers"] = {
                "present": security_headers,
                "missing": missing_headers,
                "csp_issues": csp_issues,
                "hsts_issues": hsts_issues,
                "cors_issues": cors_issues,
                "server": headers.get("server", ""),
                "x_powered_by": headers.get("x-powered-by", ""),
            }

        # --- Forms ---
        if "forms" in checks:
            forms_data = page.evaluate("""() => {
                return Array.from(document.querySelectorAll('form')).map(form => {
                    const inputs = Array.from(form.querySelectorAll('input, textarea, select')).map(el => ({
                        name: el.name || el.id || '',
                        type: el.type || el.tagName.toLowerCase(),
                        value: el.type === 'hidden' ? el.value : '',
                        required: el.required,
                        placeholder: el.placeholder || '',
                    }));
                    return {
                        action: form.action || '',
                        method: (form.method || 'GET').toUpperCase(),
                        id: form.id || '',
                        enctype: form.enctype || '',
                        inputs: inputs,
                        has_csrf_token: inputs.some(i =>
                            /csrf|token|_token|authenticity/i.test(i.name)),
                        has_file_upload: inputs.some(i => i.type === 'file'),
                        has_password: inputs.some(i => i.type === 'password'),
                    };
                });
            }""")
            result["forms"] = forms_data

        # --- Cookies ---
        if "cookies" in checks:
            cookies = context.cookies()
            cookie_issues = []
            cookie_data = []
            for c in cookies:
                issues = []
                if not c.get("httpOnly"):
                    issues.append("missing HttpOnly")
                if not c.get("secure"):
                    issues.append("missing Secure")
                same_site = c.get("sameSite", "None")
                if same_site == "None":
                    issues.append("SameSite=None")
                cookie_data.append({
                    "name": c.get("name", ""),
                    "domain": c.get("domain", ""),
                    "path": c.get("path", ""),
                    "httpOnly": c.get("httpOnly", False),
                    "secure": c.get("secure", False),
                    "sameSite": same_site,
                    "issues": issues,
                })
                if issues:
                    cookie_issues.extend(
                        f"Cookie '{c.get('name')}': {i}" for i in issues
                    )
            result["cookies"] = {"cookies": cookie_data, "issues": cookie_issues}

        # --- JS Analysis ---
        if "js_analysis" in checks:
            js_data = page.evaluate("""() => {
                const scripts = Array.from(document.querySelectorAll('script'));
                const inline_scripts = scripts.filter(s => !s.src).length;
                const external_scripts = scripts.filter(s => s.src).map(s => s.src);

                // Detect common frameworks
                const frameworks = [];
                if (window.React || document.querySelector('[data-reactroot]')) frameworks.push('React');
                if (window.Vue || document.querySelector('[data-v-]')) frameworks.push('Vue.js');
                if (window.angular || document.querySelector('[ng-app]')) frameworks.push('Angular');
                if (window.jQuery || window.$) frameworks.push('jQuery');
                if (window.next) frameworks.push('Next.js');
                if (window.__NUXT__) frameworks.push('Nuxt.js');

                // Detect dangerous patterns in inline scripts
                const dangerous_patterns = [];
                scripts.filter(s => !s.src).forEach(s => {
                    const text = s.textContent || '';
                    if (/eval\s*\(/.test(text)) dangerous_patterns.push('eval() usage');
                    if (/document\.write/.test(text)) dangerous_patterns.push('document.write()');
                    if (/innerHTML\s*=/.test(text)) dangerous_patterns.push('innerHTML assignment');
                    if (/localStorage|sessionStorage/.test(text)) dangerous_patterns.push('Web Storage usage');
                    if (/postMessage/.test(text)) dangerous_patterns.push('postMessage usage');
                });

                // Check for source maps
                const has_source_maps = external_scripts.some(s =>
                    s.includes('.map') || s.includes('sourceMappingURL'));

                // Third-party script origins
                const current_origin = window.location.origin;
                const third_party = external_scripts.filter(s => {
                    try { return new URL(s).origin !== current_origin; }
                    catch { return false; }
                });

                return {
                    inline_count: inline_scripts,
                    external_scripts: external_scripts.slice(0, 30),
                    frameworks: frameworks,
                    dangerous_patterns: [...new Set(dangerous_patterns)],
                    has_source_maps: has_source_maps,
                    third_party_scripts: third_party.slice(0, 20),
                    total_scripts: scripts.length,
                };
            }""")
            result["js_analysis"] = js_data

        return result
    except Exception as e:
        return {"success": False, "url": url, "error": str(e)}
    finally:
        _safe_close(pw, browser)


# ---------------------------------------------------------------------------
# network_monitor
# ---------------------------------------------------------------------------

def action_network_monitor(params: dict) -> dict:
    """Monitor network requests made by a page."""
    url = params["url"]
    duration = params.get("duration", 10)
    filter_type = params.get("filter_type", "all")

    pw, browser, context, page = _launch_browser()
    try:
        requests_log = []
        api_endpoints = []
        auth_headers_seen = []
        websocket_urls = []

        def on_request(request):
            req_type = request.resource_type
            if filter_type != "all" and req_type != filter_type:
                return

            entry = {
                "method": request.method,
                "url": request.url[:500],
                "resource_type": req_type,
                "headers": {},
            }

            # Capture auth-related headers
            headers = request.headers
            for h in ["authorization", "cookie", "x-api-key", "x-auth-token",
                       "x-csrf-token", "x-xsrf-token"]:
                if h in headers:
                    val = headers[h]
                    # Redact values but show type
                    if h == "authorization":
                        parts = val.split(" ", 1)
                        entry["headers"][h] = f"{parts[0]} [REDACTED]" if len(parts) > 1 else "[REDACTED]"
                        auth_headers_seen.append(parts[0] if len(parts) > 1 else "unknown")
                    elif h == "cookie":
                        cookie_names = [c.split("=")[0].strip() for c in val.split(";")]
                        entry["headers"]["cookie_names"] = cookie_names[:20]
                    else:
                        entry["headers"][h] = "[PRESENT]"

            # Detect API endpoints
            parsed = urlparse(request.url)
            if any(p in parsed.path.lower() for p in ["/api/", "/v1/", "/v2/", "/v3/",
                                                        "/graphql", "/rest/", "/json",
                                                        "/ws/", "/ajax/"]):
                api_endpoints.append({
                    "method": request.method,
                    "path": parsed.path,
                    "query": parsed.query[:200] if parsed.query else "",
                })

            # Detect sensitive data in URL params
            if parsed.query:
                sensitive_params = []
                for param in parsed.query.split("&"):
                    name = param.split("=")[0].lower()
                    if any(s in name for s in ["token", "key", "secret", "password",
                                                 "auth", "session", "jwt", "api_key"]):
                        sensitive_params.append(name)
                if sensitive_params:
                    entry["sensitive_url_params"] = sensitive_params

            requests_log.append(entry)

        def on_websocket(ws):
            websocket_urls.append(ws.url)

        page.on("request", on_request)
        page.on("websocket", on_websocket)

        page.goto(url, wait_until="networkidle", timeout=30000)

        # Wait for additional requests during the monitoring window
        time.sleep(min(duration, 30))

        # Detect mixed content
        mixed_content = []
        if url.startswith("https://"):
            for req in requests_log:
                if req["url"].startswith("http://") and not req["url"].startswith("http://localhost"):
                    mixed_content.append(req["url"][:200])

        # Identify third-party domains
        base_domain = urlparse(url).netloc
        third_party_domains = set()
        for req in requests_log:
            req_domain = urlparse(req["url"]).netloc
            if req_domain and req_domain != base_domain:
                third_party_domains.add(req_domain)

        return {
            "success": True,
            "url": url,
            "monitoring_duration_s": duration,
            "total_requests": len(requests_log),
            "requests": requests_log[:100],
            "api_endpoints": api_endpoints[:30],
            "auth_mechanisms": list(set(auth_headers_seen)),
            "websocket_connections": websocket_urls,
            "mixed_content_warnings": mixed_content[:10],
            "third_party_domains": sorted(third_party_domains)[:20],
        }
    except Exception as e:
        return {"success": False, "url": url, "error": str(e)}
    finally:
        _safe_close(pw, browser)


# ---------------------------------------------------------------------------
# crawl
# ---------------------------------------------------------------------------

def action_crawl(params: dict) -> dict:
    """JS-aware multi-page crawl."""
    start_url = params["url"]
    max_pages = min(params.get("max_pages", 50), 100)
    max_depth = min(params.get("depth", 3), 5)
    same_origin = params.get("same_origin", True)

    pw, browser, context, page = _launch_browser()
    try:
        base_parsed = urlparse(start_url)
        base_origin = f"{base_parsed.scheme}://{base_parsed.netloc}"

        visited = set()
        queue = [(start_url, 0)]
        pages_data = []
        all_forms = []
        all_endpoints = []
        technologies = set()
        errors = []

        while queue and len(visited) < max_pages:
            current_url, depth = queue.pop(0)

            # Normalize URL
            current_url = current_url.split("#")[0].rstrip("/")
            if current_url in visited:
                continue

            # Scope check
            if same_origin:
                parsed = urlparse(current_url)
                if f"{parsed.scheme}://{parsed.netloc}" != base_origin:
                    continue

            visited.add(current_url)

            try:
                response = page.goto(current_url, wait_until="networkidle", timeout=15000)
                time.sleep(1)  # Rate limiting

                status = response.status if response else 0
                title = page.title()
                content_type = (response.headers.get("content-type", "")
                                if response else "")

                page_info = {
                    "url": current_url,
                    "status": status,
                    "title": title,
                    "depth": depth,
                }

                # Extract links for further crawling
                if depth < max_depth:
                    links = page.evaluate("""() => {
                        return Array.from(document.querySelectorAll('a[href]'))
                            .map(a => a.href)
                            .filter(h => h.startsWith('http'));
                    }""")
                    for link in links:
                        normalized = link.split("#")[0].rstrip("/")
                        if normalized not in visited:
                            queue.append((normalized, depth + 1))

                # Extract forms
                forms = page.evaluate("""() => {
                    return Array.from(document.querySelectorAll('form')).map(f => ({
                        action: f.action,
                        method: f.method.toUpperCase(),
                        inputs: Array.from(f.querySelectorAll('input')).map(i => ({
                            name: i.name, type: i.type
                        })),
                    }));
                }""")
                if forms:
                    for f in forms:
                        f["found_on"] = current_url
                    all_forms.extend(forms)

                # Detect technology hints
                server = (response.headers.get("server", "") if response else "")
                x_powered = (response.headers.get("x-powered-by", "") if response else "")
                if server:
                    technologies.add(f"Server: {server}")
                if x_powered:
                    technologies.add(f"X-Powered-By: {x_powered}")

                # Detect interesting pages
                page_lower = current_url.lower()
                interesting_markers = [
                    "admin", "login", "dashboard", "upload", "config",
                    "api", "debug", "test", "backup", "panel", "console",
                    "phpmyadmin", "wp-admin", "manage",
                ]
                if any(m in page_lower for m in interesting_markers):
                    page_info["interesting"] = True

                # Check for error pages with stack traces
                if status >= 400:
                    body_text = page.evaluate("() => document.body?.innerText || ''")
                    if body_text and any(kw in body_text.lower() for kw in
                                          ["traceback", "stack trace", "exception",
                                           "debug", "error in", "at line"]):
                        page_info["has_stack_trace"] = True
                        page_info["error_snippet"] = body_text[:500]

                pages_data.append(page_info)

            except Exception as e:
                errors.append({"url": current_url, "error": str(e)[:200]})

        return {
            "success": True,
            "start_url": start_url,
            "pages_crawled": len(visited),
            "pages": pages_data,
            "forms_found": all_forms[:50],
            "technologies_detected": sorted(technologies),
            "interesting_pages": [p for p in pages_data if p.get("interesting")],
            "error_pages": [p for p in pages_data if p.get("has_stack_trace")],
            "crawl_errors": errors[:20],
            "urls_discovered": len(visited),
        }
    except Exception as e:
        return {"success": False, "start_url": start_url, "error": str(e)}
    finally:
        _safe_close(pw, browser)


# ---------------------------------------------------------------------------
# CLI dispatcher
# ---------------------------------------------------------------------------

ACTIONS = {
    "navigate": action_navigate,
    "screenshot": action_screenshot,
    "analyze": action_analyze,
    "network_monitor": action_network_monitor,
    "crawl": action_crawl,
}


def main():
    if len(sys.argv) < 3:
        print(json.dumps({"error": "Usage: python3 -m tools.browser_backend <action> <json_params>"}))
        sys.exit(1)

    action = sys.argv[1]
    try:
        params = json.loads(sys.argv[2])
    except json.JSONDecodeError as e:
        print(json.dumps({"error": f"Invalid JSON params: {e}"}))
        sys.exit(1)

    handler = ACTIONS.get(action)
    if not handler:
        print(json.dumps({"error": f"Unknown action: {action}. Valid: {list(ACTIONS.keys())}"}))
        sys.exit(1)

    try:
        result = handler(params)
        print(json.dumps(result, default=str, indent=2))
    except Exception as e:
        print(json.dumps({
            "error": f"Unhandled error in {action}: {e}",
            "traceback": traceback.format_exc(),
        }))
        sys.exit(1)


if __name__ == "__main__":
    main()

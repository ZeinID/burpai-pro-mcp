"""BurpAI Pro MCP Server — Professional Burp Suite Integration.

Exposes 40+ security testing tools via the Model Context Protocol (MCP).
Tools are organized into categories: Proxy, Scanner, Intruder, Recon, Auth,
Payload Generation, HTTP Requests, Reporting, and Encoding/Utility.
"""
import sys
from typing import Optional
from mcp.server.fastmcp import FastMCP
from config import MCP_SERVER_NAME, MCP_HOST, MCP_PORT

# Import tool modules
import tools.proxy_tools as proxy
import tools.scanner_tools as scanner
import tools.payload_tools as payload
import tools.request_tools as req
import tools.recon_tools as recon
import tools.report_tools as report
import tools.encoding_tools as encoding
import tools.intruder_tools as intruder
import tools.auth_tools as auth

# Initialize FastMCP Server
mcp = FastMCP(MCP_SERVER_NAME)

# ══════════════════════════════════════════════════════════════════
# Connection & Status
# ══════════════════════════════════════════════════════════════════

@mcp.tool()
async def check_burp_connection() -> str:
    """[BURP] Verify Burp Suite API connection. Returns connection status, API URL, and diagnostics."""
    result = await scanner.check_connection()
    return str(result)

# ══════════════════════════════════════════════════════════════════
# Proxy & Traffic Analysis Tools
# ══════════════════════════════════════════════════════════════════

@mcp.tool()
async def get_proxy_history(limit: int = 10) -> str:
    """[BURP] Retrieve the latest N requests from Burp's proxy history."""
    history = await proxy.get_proxy_history(limit)
    if not history:
        return "No proxy history available. Ensure Burp Suite is running with burp-rest-api extension."
    return str(history)

@mcp.tool()
def analyze_request(request_data: str) -> str:
    """[ANALYSIS] Analyze a raw HTTP request. Extracts method, path, headers, params, cookies, and security observations."""
    return str(proxy.analyze_request(request_data))

@mcp.tool()
def analyze_response(response_data: str) -> str:
    """[ANALYSIS] Analyze a raw HTTP response. Extracts status, headers, body preview, and security observations."""
    return str(proxy.analyze_response(response_data))

# ══════════════════════════════════════════════════════════════════
# Vulnerability Scanning Tools
# ══════════════════════════════════════════════════════════════════

@mcp.tool()
async def scan_url(url: str, config_name: str = "") -> str:
    """[BURP] Start an active scan on a URL. Optionally specify a Burp scan config name."""
    return await scanner.scan_url(url, config_name or None)

@mcp.tool()
async def scan_urls(urls: list[str], config_name: str = "") -> str:
    """[BURP] Scan multiple URLs in a single task. Accepts a list of URLs."""
    return await scanner.scan_urls(urls, config_name or None)

@mcp.tool()
async def get_scan_progress(task_id: str) -> str:
    """[BURP] Get scan progress: status, percentage, requests made/queued, issues found so far."""
    result = await scanner.get_scan_progress(task_id)
    return str(result)

@mcp.tool()
async def cancel_scan(task_id: str) -> str:
    """[BURP] Cancel a running scan task."""
    return await scanner.cancel_scan(task_id)

@mcp.tool()
async def get_scan_issues() -> str:
    """[BURP] Retrieve all vulnerability issues found by the Burp scanner."""
    issues = await scanner.get_scan_issues()
    return str(issues) if issues else "No scan issues found. Run a scan first."

@mcp.tool()
async def get_issue_definitions(search: str = "") -> str:
    """[BURP] Query Burp knowledge base for issue definitions. Optional keyword filter."""
    defs = await scanner.get_issue_definitions(search)
    return str(defs) if defs else "No matching issue definitions found."

@mcp.tool()
def detect_vulnerabilities(request_body: str, response_body: str) -> str:
    """[ANALYSIS] Detect vulnerabilities (SQLi, XSS, NoSQL, info disclosure, etc.) in a request/response pair."""
    vulns = scanner.detect_vulnerabilities(request_body, response_body)
    return str(vulns) if vulns else "No vulnerabilities detected."

@mcp.tool()
def check_security_headers(headers: dict) -> str:
    """[ANALYSIS] Analyze HTTP response headers for security issues. Returns score (0-100) and grade (A-F)."""
    return str(scanner.check_security_headers(headers))

# ══════════════════════════════════════════════════════════════════
# Intruder / Fuzzing Tools
# ══════════════════════════════════════════════════════════════════

@mcp.tool()
async def fuzz_parameter(
    url: str,
    param: str,
    payloads: list[str],
    method: str = "GET",
    delay: float = 0.1,
) -> str:
    """[INTRUDER] Inject payloads into a parameter and detect anomalies (Sniper mode). Returns status codes, lengths, timing, and anomaly flags."""
    result = await intruder.fuzz_parameter(url, param, payloads, method, delay=delay)
    return str(result)

@mcp.tool()
async def fuzz_endpoint(
    base_url: str,
    wordlist: list[str],
    extensions: Optional[list[str]] = None,
) -> str:
    """[INTRUDER] Discover hidden paths/files by fuzzing URL paths with a wordlist. Optionally append file extensions."""
    result = await intruder.fuzz_endpoint(base_url, wordlist, extensions)
    return str(result)

@mcp.tool()
async def parameter_mining(url: str, method: str = "GET") -> str:
    """[INTRUDER] Discover hidden parameters by fuzzing common param names. Detects accepted params via response changes."""
    result = await intruder.parameter_mining(url, method)
    return str(result)

# ══════════════════════════════════════════════════════════════════
# Auth / CORS / IDOR / Access Control Tools
# ══════════════════════════════════════════════════════════════════

@mcp.tool()
async def test_cors(url: str) -> str:
    """[AUTH] Test CORS misconfiguration. Checks origin reflection, null origin, wildcard, and credentials flag."""
    result = await auth.test_cors(url)
    return str(result)

@mcp.tool()
async def test_idor(url_template: str, param: str, id_list: list[str]) -> str:
    """[AUTH] Test IDOR by iterating IDs. Replace {ID} in url_template. Returns accessible resources."""
    result = await auth.test_idor(url_template, param, id_list)
    return str(result)

@mcp.tool()
async def test_auth_bypass(url: str) -> str:
    """[AUTH] Test auth bypass via HTTP verb tampering, path manipulation, and header overrides (X-Forwarded-For, X-Original-URL, etc.)."""
    result = await auth.test_auth_bypass(url)
    return str(result)

@mcp.tool()
async def test_rate_limiting(url: str, count: int = 30) -> str:
    """[AUTH] Test if rate limiting is enforced. Sends N rapid requests and checks for 429 or throttling."""
    result = await auth.test_rate_limiting(url, count)
    return str(result)

# ══════════════════════════════════════════════════════════════════
# Payload Generation Tools
# ══════════════════════════════════════════════════════════════════

@mcp.tool()
def generate_sqli_payloads(limit: int = 10) -> list[str]:
    """[PAYLOAD] SQL injection payloads (error-based, union, blind, stacked, bypass)."""
    return payload.generate_sqli_payloads(limit)

@mcp.tool()
def generate_xss_payloads(limit: int = 10) -> list[str]:
    """[PAYLOAD] XSS payloads (reflected, stored, DOM, event handlers, polyglot)."""
    return payload.generate_xss_payloads(limit)

@mcp.tool()
def generate_ssrf_payloads(limit: int = 10) -> list[str]:
    """[PAYLOAD] SSRF payloads (localhost, cloud metadata, internal services, gopher)."""
    return payload.generate_ssrf_payloads(limit)

@mcp.tool()
def generate_path_traversal_payloads(limit: int = 10) -> list[str]:
    """[PAYLOAD] Path Traversal / LFI payloads (Linux, Windows, encoding bypass, PHP wrappers)."""
    return payload.generate_path_traversal_payloads(limit)

@mcp.tool()
def generate_cmdi_payloads(limit: int = 10) -> list[str]:
    """[PAYLOAD] OS Command Injection payloads."""
    return payload.generate_cmdi_payloads(limit)

@mcp.tool()
def generate_ssti_payloads(limit: int = 10) -> list[str]:
    """[PAYLOAD] Server-Side Template Injection (SSTI) payloads (Jinja2, Twig, Freemarker, etc.)."""
    return payload.generate_ssti_payloads(limit)

@mcp.tool()
def generate_xxe_payloads(limit: int = 10) -> list[str]:
    """[PAYLOAD] XML External Entity (XXE) payloads (file read, SSRF, OOB)."""
    return payload.generate_xxe_payloads(limit)

@mcp.tool()
def generate_nosqli_payloads(limit: int = 10) -> list[str]:
    """[PAYLOAD] NoSQL injection payloads (MongoDB operators, JSON injection, $where)."""
    return payload.generate_nosqli_payloads(limit)

@mcp.tool()
def generate_open_redirect_payloads(limit: int = 10) -> list[str]:
    """[PAYLOAD] Open Redirect payloads (protocol-relative, encoded, subdomain tricks)."""
    return payload.generate_open_redirect_payloads(limit)

@mcp.tool()
def generate_header_injection_payloads(limit: int = 10) -> list[str]:
    """[PAYLOAD] CRLF / Header Injection payloads."""
    return payload.generate_header_injection_payloads(limit)

@mcp.tool()
def generate_waf_bypass_payloads(limit: int = 10) -> list[str]:
    """[PAYLOAD] WAF bypass payloads (encoding, case alternation, comments, concatenation)."""
    return payload.generate_waf_bypass_payloads(limit)

@mcp.tool()
def generate_fuzzing_wordlist(attack_type: str, limit: int = 20) -> list[str]:
    """[PAYLOAD] Generate a fuzzing wordlist by type: sqli, xss, ssrf, path_traversal, cmdi, ssti, xxe, nosqli, open_redirect, cors, crlf, waf_bypass, auth_bypass."""
    return payload.generate_fuzzing_wordlist(attack_type, limit)

# ══════════════════════════════════════════════════════════════════
# HTTP Request Tools
# ══════════════════════════════════════════════════════════════════

@mcp.tool()
async def send_http_request(
    url: str,
    method: str = "GET",
    body: str = "",
    follow_redirects: bool = True,
    proxy_through_burp: bool = False,
) -> str:
    """[REQUEST] Send HTTP request with full control. Supports custom method, body, redirect handling, and optional Burp proxy routing."""
    res = await req.send_http_request(url, method, body=body, follow_redirects=follow_redirects, proxy_through_burp=proxy_through_burp)
    return str(res)

@mcp.tool()
async def send_through_burp(request_data: str, host: str, port: int, use_https: bool) -> str:
    """[BURP] Send a raw HTTP request through Burp Repeater API."""
    res = await req.send_through_burp(request_data, host, port, use_https)
    return str(res)

@mcp.tool()
def compare_responses(response1: str, response2: str) -> str:
    """[ANALYSIS] Differential analysis between two responses. Compares length, lines, keywords, and calculates similarity."""
    return str(req.compare_responses(response1, response2))

# ══════════════════════════════════════════════════════════════════
# Reconnaissance Tools
# ══════════════════════════════════════════════════════════════════

@mcp.tool()
async def get_sitemap(url_prefix: str = "") -> str:
    """[BURP] Retrieve the sitemap from Burp Suite for a given URL prefix."""
    sitemap = await recon.get_sitemap(url_prefix)
    return str(sitemap) if sitemap else "No sitemap data available."

@mcp.tool()
def enumerate_endpoints(sitemap_data: list[dict]) -> list[str]:
    """[ANALYSIS] Extract unique endpoints from sitemap data."""
    return recon.enumerate_endpoints(sitemap_data)

@mcp.tool()
def analyze_attack_surface(endpoints: list[str]) -> str:
    """[ANALYSIS] Comprehensive attack surface analysis. Categorizes endpoints: auth, API, admin, upload, GraphQL, debug, etc."""
    return str(recon.analyze_attack_surface(endpoints))

@mcp.tool()
def discover_technologies(headers: dict, body: str = "") -> str:
    """[RECON] Fingerprint technology stack from response headers/body. Detects server, framework, CMS, CDN, WAF."""
    return str(recon.discover_technologies(headers, body))

@mcp.tool()
def extract_urls_and_params(html_body: str, base_url: str = "") -> str:
    """[RECON] Parse HTML to extract links, forms (with params), JavaScript files, and API endpoints."""
    return str(recon.extract_urls_and_params(html_body, base_url))

@mcp.tool()
async def check_robots_sitemap(base_url: str) -> str:
    """[RECON] Fetch and parse robots.txt and sitemap.xml. Returns disallowed paths and sitemap URLs."""
    result = await recon.check_robots_sitemap(base_url)
    return str(result)

# ══════════════════════════════════════════════════════════════════
# Reporting Tools
# ══════════════════════════════════════════════════════════════════

@mcp.tool()
def generate_finding_report(vuln_data: dict) -> str:
    """[REPORT] Generate a structured Markdown report for a single vulnerability finding."""
    return report.generate_finding_report(vuln_data)

@mcp.tool()
def export_findings(findings: list[dict], project_name: str) -> str:
    """[REPORT] Export all findings into an executive summary (JSON)."""
    return report.export_findings(findings, project_name)

# ══════════════════════════════════════════════════════════════════
# Encoding & Decoding Tools
# ══════════════════════════════════════════════════════════════════

@mcp.tool()
def encode_decode(text: str, format: str, operation: str = "encode") -> str:
    """[UTIL] Encode/decode text. Formats: base64, url, double_url, html, hex, unicode."""
    return encoding.encode_decode(text, format, operation)

@mcp.tool()
def hash_text(text: str, algorithm: str = "sha256") -> str:
    """[UTIL] Hash text. Algorithms: md5, sha1, sha256, sha512."""
    return encoding.hash_text(text, algorithm)

@mcp.tool()
def analyze_jwt(token: str) -> str:
    """[UTIL] Decode and analyze JWT. Checks for none alg, missing expiry, admin claims, kid injection, jku SSRF."""
    return str(encoding.analyze_jwt(token))

@mcp.tool()
def generate_jwt_none_bypass(token: str) -> str:
    """[UTIL] Generate a JWT with 'none' algorithm (alg:none attack). Removes signature from existing token."""
    return encoding.generate_jwt_none_bypass(token)

# ══════════════════════════════════════════════════════════════════
# Server Entry Point
# ══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Run BurpAI Pro MCP Server")
    parser.add_argument("--transport", choices=["stdio", "streamable-http"], default="stdio", help="Transport protocol")
    args = parser.parse_args()

    print(f"Starting {MCP_SERVER_NAME} with {args.transport} transport...", file=sys.stderr)
    try:
        mcp.run(transport=args.transport)
    except Exception as e:
        import traceback
        import os
        log_path = os.path.join(os.path.dirname(__file__), "crash.log")
        with open(log_path, "w") as f:
            f.write("CRASH DETECTED:\n")
            traceback.print_exc(file=f)
        print(f"CRASH: {e}", file=sys.stderr)

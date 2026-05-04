import sys
from mcp.server.fastmcp import FastMCP
from config import MCP_SERVER_NAME, MCP_HOST, MCP_PORT

# Import tools
import tools.proxy_tools as proxy
import tools.scanner_tools as scanner
import tools.payload_tools as payload
import tools.request_tools as req
import tools.recon_tools as recon
import tools.report_tools as report
import tools.encoding_tools as encoding

# Initialize FastMCP Server
mcp = FastMCP(MCP_SERVER_NAME)

# ══════════════════════════════════════════════════════════════════
# Proxy & Traffic Analysis Tools
# ══════════════════════════════════════════════════════════════════

@mcp.tool()
async def get_proxy_history(limit: int = 10) -> str:
    """[BURP] Retrieve the latest N requests from Burp's proxy history. Requires burp-rest-api extension."""
    history = await proxy.get_proxy_history(limit)
    if not history:
        return "No proxy history available. Make sure Burp Suite is running with the 'burp-rest-api' extension installed."
    return str(history)

@mcp.tool()
def analyze_request(request_data: str) -> str:
    """[ANALISIS] Analyze a raw HTTP request string. Extracts method, path, headers, parameters, cookies, and security observations."""
    result = proxy.analyze_request(request_data)
    return str(result)

@mcp.tool()
def analyze_response(response_data: str) -> str:
    """[ANALISIS] Analyze a raw HTTP response string. Extracts status, headers, body preview, and security observations."""
    result = proxy.analyze_response(response_data)
    return str(result)

# ══════════════════════════════════════════════════════════════════
# Vulnerability Scanning Tools
# ══════════════════════════════════════════════════════════════════

@mcp.tool()
async def scan_url(url: str) -> str:
    """[BURP] Trigger an active scan on the given URL in Burp Suite."""
    return await scanner.scan_url(url)

@mcp.tool()
async def get_scan_issues() -> str:
    """[BURP] Retrieve all vulnerability issues found by the Burp scanner."""
    issues = await scanner.get_scan_issues()
    if not issues:
        return "No scan issues found. Run a scan first with scan_url()."
    return str(issues)

@mcp.tool()
def detect_vulnerabilities(request_body: str, response_body: str) -> str:
    """[ANALISIS] Standalone vulnerability detection on a request/response pair. Checks for SQLi, info disclosure, etc."""
    vulns = scanner.detect_vulnerabilities(request_body, response_body)
    return str(vulns) if vulns else "No vulnerabilities detected."

@mcp.tool()
def check_security_headers(headers: dict) -> str:
    """[ANALISIS] Analyze HTTP response headers for missing/misconfigured security headers and cookie flags."""
    issues = scanner.check_security_headers(headers)
    return str(issues)

# ══════════════════════════════════════════════════════════════════
# Payload Generation Tools
# ══════════════════════════════════════════════════════════════════

@mcp.tool()
def generate_sqli_payloads(limit: int = 10) -> list[str]:
    """[PAYLOAD] Generate SQL injection payloads (error-based, union, boolean-blind, time-blind, bypass)."""
    return payload.generate_sqli_payloads(limit)

@mcp.tool()
def generate_xss_payloads(limit: int = 10) -> list[str]:
    """[PAYLOAD] Generate XSS payloads (reflected, stored, DOM-based, event handlers, polyglot)."""
    return payload.generate_xss_payloads(limit)

@mcp.tool()
def generate_ssrf_payloads(limit: int = 10) -> list[str]:
    """[PAYLOAD] Generate SSRF payloads (localhost variants, cloud metadata, internal services)."""
    return payload.generate_ssrf_payloads(limit)

@mcp.tool()
def generate_path_traversal_payloads(limit: int = 10) -> list[str]:
    """[PAYLOAD] Generate Path Traversal / LFI payloads (Linux, Windows, encoding bypass)."""
    return payload.generate_path_traversal_payloads(limit)

@mcp.tool()
def generate_cmdi_payloads(limit: int = 10) -> list[str]:
    """[PAYLOAD] Generate OS Command Injection payloads."""
    return payload.generate_cmdi_payloads(limit)

@mcp.tool()
def generate_ssti_payloads(limit: int = 10) -> list[str]:
    """[PAYLOAD] Generate Server-Side Template Injection (SSTI) payloads."""
    return payload.generate_ssti_payloads(limit)

@mcp.tool()
def generate_fuzzing_wordlist(attack_type: str, limit: int = 20) -> list[str]:
    """[PAYLOAD] Generate a custom fuzzing wordlist. Supported types: sqli, xss, ssrf, path_traversal, cmdi, ssti."""
    return payload.generate_fuzzing_wordlist(attack_type, limit)

# ══════════════════════════════════════════════════════════════════
# HTTP Request Tools
# ══════════════════════════════════════════════════════════════════

@mcp.tool()
async def send_http_request(url: str, method: str = "GET", body: str = "") -> str:
    """[REQUEST] Send a custom HTTP request directly (standalone, without Burp proxy)."""
    res = await req.send_http_request(url, method, None, body)
    return str(res)

@mcp.tool()
async def send_through_burp(request_data: str, host: str, port: int, use_https: bool) -> str:
    """[BURP] Send a raw HTTP request through Burp Repeater API."""
    res = await req.send_through_burp(request_data, host, port, use_https)
    return str(res)

@mcp.tool()
def compare_responses(response1: str, response2: str) -> str:
    """[ANALISIS] Differential analysis between two HTTP response bodies. Useful for detecting blind injection."""
    result = req.compare_responses(response1, response2)
    return str(result)

# ══════════════════════════════════════════════════════════════════
# Reconnaissance Tools
# ══════════════════════════════════════════════════════════════════

@mcp.tool()
async def get_sitemap(url_prefix: str = "") -> str:
    """[BURP] Retrieve the sitemap for a given URL prefix from Burp Suite."""
    sitemap = await recon.get_sitemap(url_prefix)
    if not sitemap:
        return "No sitemap data available."
    return str(sitemap)

@mcp.tool()
def enumerate_endpoints(sitemap_data: list[dict]) -> list[str]:
    """[ANALISIS] Extract unique endpoints from sitemap data."""
    return recon.enumerate_endpoints(sitemap_data)

@mcp.tool()
def analyze_attack_surface(endpoints: list[str]) -> str:
    """[ANALISIS] Analyze attack surface from a list of endpoints. Identifies auth, API, and admin endpoints."""
    result = recon.analyze_attack_surface(endpoints)
    return str(result)

# ══════════════════════════════════════════════════════════════════
# Reporting Tools
# ══════════════════════════════════════════════════════════════════

@mcp.tool()
def generate_finding_report(vuln_data: dict) -> str:
    """[LAPORAN] Generate a structured Markdown report for a single vulnerability finding."""
    return report.generate_finding_report(vuln_data)

@mcp.tool()
def export_findings(findings: list[dict], project_name: str) -> str:
    """[LAPORAN] Export all findings into an executive summary (JSON)."""
    return report.export_findings(findings, project_name)

# ══════════════════════════════════════════════════════════════════
# Encoding & Decoding Tools
# ══════════════════════════════════════════════════════════════════

@mcp.tool()
def encode_decode(text: str, format: str, operation: str = "encode") -> str:
    """[UTIL] Encode or decode text. Formats: base64, url, html. Operations: encode, decode."""
    return encoding.encode_decode(text, format, operation)

@mcp.tool()
def hash_text(text: str, algorithm: str = "sha256") -> str:
    """[UTIL] Hash text. Algorithms: md5, sha1, sha256, sha512."""
    return encoding.hash_text(text, algorithm)

@mcp.tool()
def analyze_jwt(token: str) -> str:
    """[UTIL] Decode and analyze a JWT token (header, payload, algorithm) without signature verification."""
    result = encoding.analyze_jwt(token)
    return str(result)


# ══════════════════════════════════════════════════════════════════
# Server Entry Point
# ══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Run BurpAI Pro MCP Server")
    parser.add_argument("--transport", choices=["stdio", "streamable-http"], default="stdio", help="Transport protocol to use")
    args = parser.parse_args()

    print(f"Starting {MCP_SERVER_NAME} with {args.transport} transport...", file=sys.stderr)
    mcp.run(transport=args.transport)

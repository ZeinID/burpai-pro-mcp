"""Enhanced vulnerability detection engine with pattern matching for multiple vuln classes."""
import re
from typing import Dict, Any, List, Optional
from models.vulnerability import VulnType, SeverityLevel


class VulnDetector:
    """Detects common vulnerabilities based on response patterns."""

    SQL_ERRORS = [
        re.compile(r"SQL syntax.*?MySQL", re.I),
        re.compile(r"Warning.*?mysqli?", re.I),
        re.compile(r"PostgreSQL.*?ERROR", re.I),
        re.compile(r"Warning.*?pg_query", re.I),
        re.compile(r"Microsoft OLE DB Provider for SQL Server", re.I),
        re.compile(r"SQLServer JDBC Driver", re.I),
        re.compile(r"SQLite/JDBCDriver", re.I),
        re.compile(r"System\.Data\.SQLite\.SQLiteException", re.I),
        re.compile(r"ORA-[0-9]{4,5}", re.I),
        re.compile(r"com\.mysql\.jdbc", re.I),
        re.compile(r"SQLSTATE\[", re.I),
        re.compile(r"Syntax error.*?in query expression", re.I),
        re.compile(r"Unclosed quotation mark", re.I),
        re.compile(r"quoted string not properly terminated", re.I),
        re.compile(r"pg_connect\(\)", re.I),
        re.compile(r"mysql_fetch", re.I),
    ]

    NOSQL_ERRORS = [
        re.compile(r"MongoError", re.I),
        re.compile(r"MongoDB.*?Error", re.I),
        re.compile(r"\$where.*?function", re.I),
        re.compile(r"CouchDB", re.I),
        re.compile(r"RethinkDB", re.I),
    ]

    STACK_TRACE_PATTERNS = [
        re.compile(r"Stack trace:", re.I),
        re.compile(r"java\.lang\.\w+Exception", re.I),
        re.compile(r"Traceback \(most recent call last\)", re.I),
        re.compile(r"at [\w\.]+\([\w\.]+:\d+\)", re.I),  # Java stack frame
        re.compile(r"Microsoft\.AspNetCore", re.I),
        re.compile(r"System\.NullReferenceException", re.I),
        re.compile(r"Fatal error.*?on line \d+", re.I),  # PHP
        re.compile(r"Parse error.*?syntax error", re.I),  # PHP
        re.compile(r"node_modules/", re.I),  # Node.js
    ]

    INFO_LEAK_PATTERNS = [
        (re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"), "Email address"),
        (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "Internal IP address"),
        (re.compile(r"/(?:home|var|usr|opt|etc|tmp)/[\w/]+"), "Internal file path (Unix)"),
        (re.compile(r"[A-Z]:\\(?:Users|Windows|Program Files)\\[\w\\]+", re.I), "Internal file path (Windows)"),
        (re.compile(r"(?:password|passwd|pwd|secret|api_key|apikey|token)\s*[:=]\s*\S+", re.I), "Credential/secret in response"),
        (re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"), "Private key exposed"),
        (re.compile(r"AWS[_A-Z]*=[\w/+=]+", re.I), "AWS credential"),
    ]

    DIRECTORY_LISTING_PATTERNS = [
        re.compile(r"Index of /", re.I),
        re.compile(r"<title>Directory listing", re.I),
        re.compile(r"Parent Directory</a>", re.I),
        re.compile(r"Directory Listing For /", re.I),
    ]

    def __init__(self):
        pass

    def detect_sqli(self, response_body: str) -> bool:
        if not response_body:
            return False
        return any(p.search(response_body) for p in self.SQL_ERRORS)

    def detect_nosqli(self, response_body: str) -> bool:
        if not response_body:
            return False
        return any(p.search(response_body) for p in self.NOSQL_ERRORS)

    def detect_xss_reflection(self, request_body: str, response_body: str) -> List[str]:
        """Check if input from request appears unescaped in response."""
        if not request_body or not response_body:
            return []
        reflected = []
        test_markers = [
            "<script>", "onerror=", "javascript:", "onload=",
            "<img", "<svg", "alert(", "confirm(", "prompt(",
        ]
        for marker in test_markers:
            if marker in request_body and marker in response_body:
                reflected.append(marker)
        return reflected

    def detect_information_disclosure(self, response_body: str) -> List[Dict[str, Any]]:
        findings = []
        if not response_body:
            return findings

        # Stack traces
        for pattern in self.STACK_TRACE_PATTERNS:
            if pattern.search(response_body):
                findings.append({
                    "type": "INFO_DISCLOSURE",
                    "detail": "Stack trace / error detail in response",
                    "severity": "LOW",
                    "evidence": pattern.pattern,
                })
                break

        # Info leaks
        for pattern, desc in self.INFO_LEAK_PATTERNS:
            matches = pattern.findall(response_body[:5000])  # limit scan scope
            if matches:
                findings.append({
                    "type": "INFO_DISCLOSURE",
                    "detail": desc,
                    "severity": "LOW" if "Email" in desc else "MEDIUM",
                    "evidence": str(matches[:3]),
                })

        # Directory listing
        for pattern in self.DIRECTORY_LISTING_PATTERNS:
            if pattern.search(response_body):
                findings.append({
                    "type": "INFO_DISCLOSURE",
                    "detail": "Directory listing enabled",
                    "severity": "MEDIUM",
                    "evidence": pattern.pattern,
                })
                break

        return findings

    def detect_open_redirect(self, headers: Dict[str, str], status_code: int) -> Optional[Dict[str, str]]:
        """Check for open redirect via Location header."""
        if status_code in (301, 302, 303, 307, 308):
            location = headers.get("Location", headers.get("location", ""))
            if location:
                # External redirect indicators
                if location.startswith("//") or location.startswith("http"):
                    from urllib.parse import urlparse
                    parsed = urlparse(location)
                    if parsed.netloc and parsed.netloc not in ("", "localhost", "127.0.0.1"):
                        return {
                            "type": "OPEN_REDIRECT",
                            "detail": f"Redirect to external host: {parsed.netloc}",
                            "location": location,
                            "severity": "MEDIUM",
                        }
        return None

    def detect_version_disclosure(self, headers: Dict[str, str]) -> List[Dict[str, str]]:
        """Check for technology version leaks in headers."""
        findings = []
        version_headers = {
            "Server": "Server technology",
            "X-Powered-By": "Backend framework",
            "X-AspNet-Version": "ASP.NET version",
            "X-AspNetMvc-Version": "ASP.NET MVC version",
            "X-Generator": "CMS/Generator",
        }
        for header, desc in version_headers.items():
            val = headers.get(header, "")
            if val:
                findings.append({
                    "type": "INFO_DISCLOSURE",
                    "detail": f"{desc} disclosed: {val}",
                    "header": header,
                    "value": val,
                    "severity": "INFORMATIONAL",
                })
        return findings

    def analyze_traffic(self, request: Dict[str, Any], response: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Comprehensive analysis of a request/response pair."""
        vulnerabilities = []
        req_body = request.get("body", "")
        resp_body = response.get("body", "")
        resp_headers = response.get("headers", {})
        status_code = response.get("status_code", 0)

        # SQL Injection
        if self.detect_sqli(resp_body):
            vulnerabilities.append({
                "type": "SQL_INJECTION",
                "title": "SQL Error Message Detected",
                "severity": "HIGH",
                "description": "Database error message in response indicates potential SQL injection.",
                "evidence": "SQL error pattern matched in response body.",
            })

        # NoSQL Injection
        if self.detect_nosqli(resp_body):
            vulnerabilities.append({
                "type": "NOSQL_INJECTION",
                "title": "NoSQL Error Message Detected",
                "severity": "HIGH",
                "description": "NoSQL database error in response indicates potential injection.",
                "evidence": "NoSQL error pattern matched in response body.",
            })

        # XSS Reflection
        reflected = self.detect_xss_reflection(req_body, resp_body)
        if reflected:
            vulnerabilities.append({
                "type": "XSS",
                "title": "Reflected XSS Input Detected",
                "severity": "HIGH",
                "description": "Input containing XSS markers was reflected unescaped in the response.",
                "evidence": f"Reflected markers: {reflected}",
            })

        # Information Disclosure
        info_findings = self.detect_information_disclosure(resp_body)
        vulnerabilities.extend(info_findings)

        # Open Redirect
        redirect = self.detect_open_redirect(resp_headers, status_code)
        if redirect:
            vulnerabilities.append(redirect)

        # Version Disclosure
        version_leaks = self.detect_version_disclosure(resp_headers)
        vulnerabilities.extend(version_leaks)

        return vulnerabilities

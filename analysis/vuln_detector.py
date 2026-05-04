import re
from typing import Dict, Any, List
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
        re.compile(r"ORA-[0-9][0-9][0-9][0-9]", re.I)
    ]
    
    # Very basic XSS reflection check (for illustrative purposes)
    XSS_PAYLOADS_TO_CHECK = ["<script>alert(1)</script>", "javascript:alert(1)"]
    
    def __init__(self):
        pass

    def detect_sqli(self, response_body: str) -> bool:
        """Check for SQL error messages in the response body."""
        if not response_body:
            return False
        for pattern in self.SQL_ERRORS:
            if pattern.search(response_body):
                return True
        return False
        
    def detect_information_disclosure(self, response_body: str) -> List[Dict[str, str]]:
        """Check for leaked information like stack traces or emails."""
        findings = []
        if not response_body:
            return findings
            
        # Basic stack trace detection
        if "Stack trace:" in response_body or "java.lang.Exception" in response_body or "Traceback (most recent call last)" in response_body:
            findings.append({
                "type": VulnType.INFO_DISCLOSURE,
                "evidence": "Stack trace found in response.",
                "severity": SeverityLevel.LOW
            })
            
        return findings

    def analyze_traffic(self, request: Dict[str, Any], response: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze a request/response pair for vulnerabilities."""
        vulnerabilities = []
        
        body = response.get("body", "")
        
        # Check SQLi
        if self.detect_sqli(body):
            vulnerabilities.append({
                "type": VulnType.SQL_INJECTION,
                "title": "SQL Error Message Detected",
                "severity": SeverityLevel.HIGH,
                "description": "The application responded with a database error message, indicating potential SQL injection.",
                "evidence": "SQL error matched in response body."
            })
            
        # Check Info Disclosure
        info_findings = self.detect_information_disclosure(body)
        vulnerabilities.extend(info_findings)
        
        return vulnerabilities

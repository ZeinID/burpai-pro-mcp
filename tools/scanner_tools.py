from typing import List, Dict, Any
from burp_client import BurpClient
from analysis.vuln_detector import VulnDetector
from analysis.header_analyzer import HeaderAnalyzer

async def scan_url(url: str) -> str:
    """Trigger an active scan on the given URL in Burp Suite."""
    client = BurpClient()
    task_id = await client.start_scan([url])
    return f"Started scan with task ID: {task_id}" if task_id else "Failed to start scan."

async def get_scan_issues() -> List[Dict[str, Any]]:
    """Retrieve all vulnerability issues from the scanner."""
    client = BurpClient()
    return await client.get_scan_issues()

def detect_vulnerabilities(request_body: str, response_body: str) -> List[Dict[str, Any]]:
    """Standalone vulnerability detection on a request/response pair."""
    detector = VulnDetector()
    return detector.analyze_traffic({"body": request_body}, {"body": response_body})

def check_security_headers(headers: Dict[str, str]) -> Dict[str, Any]:
    """Analyze HTTP response headers for security issues."""
    analyzer = HeaderAnalyzer()
    return analyzer.analyze_response_headers(headers)

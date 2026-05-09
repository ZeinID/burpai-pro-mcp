"""Enhanced scanner tools with full scan lifecycle control."""
from typing import List, Dict, Any, Optional
from burp_client import BurpClient
from analysis.vuln_detector import VulnDetector
from analysis.header_analyzer import HeaderAnalyzer


async def scan_url(url: str, config_name: Optional[str] = None) -> str:
    """Trigger an active scan on a URL in Burp Suite.
    
    Args:
        url: Target URL to scan.
        config_name: Optional Burp scan config name (e.g., "Audit checks - all except time-based detection methods").
    """
    client = BurpClient.get_instance()
    task_id = await client.start_scan([url], named_config=config_name)
    return f"Scan started — task_id: {task_id}" if task_id else "Failed to start scan. Check Burp connection."


async def scan_urls(urls: List[str], config_name: Optional[str] = None) -> str:
    """Scan multiple URLs in a single Burp scan task."""
    client = BurpClient.get_instance()
    task_id = await client.start_scan(urls, named_config=config_name)
    return f"Scan started for {len(urls)} URLs — task_id: {task_id}" if task_id else "Failed to start scan."


async def get_scan_progress(task_id: str) -> Dict[str, Any]:
    """Get detailed scan progress including percentage, status, and issues found so far."""
    client = BurpClient.get_instance()
    status = await client.get_scan_status(task_id)
    if not status or (isinstance(status, dict) and "error" in status):
        return {"error": f"Could not retrieve scan status for task {task_id}"}

    result = {
        "task_id": task_id,
        "scan_status": status.get("scan_status", "unknown"),
    }

    # Extract scan metrics
    scan_metrics = status.get("scan_metrics", {})
    if scan_metrics:
        result["metrics"] = {
            "crawl_requests_made": scan_metrics.get("crawl_requests_made", 0),
            "crawl_requests_queued": scan_metrics.get("crawl_requests_queued", 0),
            "audit_requests_made": scan_metrics.get("audit_requests_made", 0),
            "audit_requests_queued": scan_metrics.get("audit_requests_queued", 0),
            "crawl_unique_locations": scan_metrics.get("crawl_unique_locations_visited", 0),
        }
        # Calculate progress percentage
        audit_made = scan_metrics.get("audit_requests_made", 0)
        audit_queued = scan_metrics.get("audit_requests_queued", 0)
        total_audit = audit_made + audit_queued
        if total_audit > 0:
            result["audit_progress_pct"] = round((audit_made / total_audit) * 100, 1)

    # Extract issues summary
    issues = status.get("issue_events", [])
    if issues:
        severity_counts = {}
        for issue in issues:
            sev = issue.get("issue", {}).get("severity", "unknown")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        result["issues_found"] = len(issues)
        result["severity_breakdown"] = severity_counts

    return result


async def cancel_scan(task_id: str) -> str:
    """Cancel a running scan task."""
    client = BurpClient.get_instance()
    res = await client.cancel_scan(task_id)
    if isinstance(res, dict) and "error" in res:
        return f"Failed to cancel scan: {res['error']}"
    return f"Scan {task_id} cancelled successfully."


async def get_scan_issues() -> List[Dict[str, Any]]:
    """Retrieve all vulnerability issues from the Burp scanner."""
    client = BurpClient.get_instance()
    return await client.get_scan_issues()


async def get_issue_definitions(search: str = "") -> List[Dict[str, Any]]:
    """Query Burp knowledge base for issue type definitions.
    
    Args:
        search: Optional keyword to filter issue definitions (e.g., "SQL injection").
    """
    client = BurpClient.get_instance()
    definitions = await client.get_issue_definitions()
    if search:
        search_lower = search.lower()
        definitions = [d for d in definitions if search_lower in str(d).lower()]
    return definitions[:50]  # Limit output size


async def check_connection() -> Dict[str, Any]:
    """Verify Burp Suite API connection status."""
    client = BurpClient.get_instance()
    return await client.check_connection()


def detect_vulnerabilities(request_body: str, response_body: str) -> List[Dict[str, Any]]:
    """Standalone vulnerability detection on a request/response pair."""
    detector = VulnDetector()
    return detector.analyze_traffic({"body": request_body}, {"body": response_body})


def check_security_headers(headers: Dict[str, str]) -> Dict[str, Any]:
    """Analyze HTTP response headers for security issues. Returns score and grade."""
    analyzer = HeaderAnalyzer()
    return analyzer.analyze_response_headers(headers)

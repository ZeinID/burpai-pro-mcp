import httpx
from typing import Dict, Any, Optional
from burp_client import BurpClient

async def send_http_request(url: str, method: str = "GET", headers: Optional[Dict[str, str]] = None, body: str = "") -> Dict[str, Any]:
    """Send a custom HTTP request directly (bypassing Burp if standalone, or could be routed through proxy)."""
    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            res = await client.request(method, url, headers=headers, content=body)
            return {
                "status_code": res.status_code,
                "headers": dict(res.headers),
                "body": res.text
            }
        except Exception as e:
            return {"error": str(e)}

async def send_through_burp(request_data: str, host: str, port: int, use_https: bool) -> Dict[str, Any]:
    """Send an HTTP request through Burp Repeater API."""
    client = BurpClient.get_instance()
    res = await client.send_request(request_data, host, port, use_https)
    return res if res else {"error": "Failed to send request through Burp."}

def compare_responses(resp1_body: str, resp2_body: str) -> Dict[str, Any]:
    """Differential analysis between two HTTP responses for anomaly detection."""
    len1 = len(resp1_body)
    len2 = len(resp2_body)
    diff_length = abs(len1 - len2)
    
    # Line-by-line comparison for summary
    lines1 = resp1_body.splitlines()
    lines2 = resp2_body.splitlines()
    differing_lines = 0
    for l1, l2 in zip(lines1, lines2):
        if l1 != l2:
            differing_lines += 1
    differing_lines += abs(len(lines1) - len(lines2))
    
    return {
        "response1_length": len1,
        "response2_length": len2,
        "length_difference": diff_length,
        "is_different": resp1_body != resp2_body,
        "differing_lines": differing_lines,
        "total_lines_resp1": len(lines1),
        "total_lines_resp2": len(lines2),
    }

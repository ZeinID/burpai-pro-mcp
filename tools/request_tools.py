"""Enhanced HTTP request tools with proxy support, custom headers, and smarter comparison."""
import httpx
import time
from typing import Dict, Any, Optional
from burp_client import BurpClient


async def send_http_request(
    url: str,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    body: str = "",
    follow_redirects: bool = True,
    proxy_through_burp: bool = False,
    timeout: float = 15.0,
) -> Dict[str, Any]:
    """Send a custom HTTP request with full control over headers, redirects, and proxy.
    
    Args:
        url: Target URL
        method: HTTP method (GET, POST, PUT, DELETE, etc.)
        headers: Custom headers dict
        body: Request body
        follow_redirects: Whether to follow 3xx redirects
        proxy_through_burp: If True, routes through Burp proxy (127.0.0.1:8080)
        timeout: Request timeout in seconds
    """
    mounts = None
    if proxy_through_burp:
        mounts = {
            "http://": httpx.AsyncHTTPTransport(proxy="http://127.0.0.1:8080"),
            "https://": httpx.AsyncHTTPTransport(proxy="http://127.0.0.1:8080"),
        }

    start = time.time()
    async with httpx.AsyncClient(
        timeout=timeout,
        verify=False,
        follow_redirects=follow_redirects,
        mounts=mounts,
    ) as client:
        try:
            res = await client.request(method, url, headers=headers or {}, content=body)
            elapsed = round(time.time() - start, 3)
            return {
                "status_code": res.status_code,
                "headers": dict(res.headers),
                "body": res.text[:10000],  # Limit body size
                "body_length": len(res.text),
                "time_seconds": elapsed,
                "final_url": str(res.url),
                "redirect_count": len(res.history) if hasattr(res, 'history') else 0,
            }
        except Exception as e:
            return {"error": str(e)}


async def send_through_burp(
    request_data: str,
    host: str,
    port: int,
    use_https: bool,
) -> Dict[str, Any]:
    """Send a raw HTTP request through Burp Repeater API."""
    client = BurpClient.get_instance()
    res = await client.send_request(request_data, host, port, use_https)
    return res if res else {"error": "Failed to send request through Burp."}


def compare_responses(
    resp1_body: str,
    resp2_body: str,
    resp1_headers: Optional[Dict[str, str]] = None,
    resp2_headers: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """Advanced differential analysis between two HTTP responses.
    
    Compares body content, length, headers, and keyword presence.
    """
    len1 = len(resp1_body)
    len2 = len(resp2_body)

    # Line-by-line diff
    lines1 = resp1_body.splitlines()
    lines2 = resp2_body.splitlines()
    differing_lines = sum(1 for l1, l2 in zip(lines1, lines2) if l1 != l2)
    differing_lines += abs(len(lines1) - len(lines2))

    # Keyword presence diff
    keywords = ["error", "success", "invalid", "denied", "authorized", "true", "false", "token", "redirect"]
    keyword_diff = {}
    for kw in keywords:
        in_r1 = kw.lower() in resp1_body.lower()
        in_r2 = kw.lower() in resp2_body.lower()
        if in_r1 != in_r2:
            keyword_diff[kw] = {"in_response1": in_r1, "in_response2": in_r2}

    # Header diff
    header_diff = {}
    if resp1_headers and resp2_headers:
        all_keys = set(list(resp1_headers.keys()) + list(resp2_headers.keys()))
        for key in all_keys:
            v1 = resp1_headers.get(key, "(missing)")
            v2 = resp2_headers.get(key, "(missing)")
            if v1 != v2:
                header_diff[key] = {"response1": v1, "response2": v2}

    return {
        "response1_length": len1,
        "response2_length": len2,
        "length_difference": abs(len1 - len2),
        "is_different": resp1_body != resp2_body,
        "differing_lines": differing_lines,
        "total_lines_resp1": len(lines1),
        "total_lines_resp2": len(lines2),
        "keyword_differences": keyword_diff,
        "header_differences": header_diff,
        "similarity_pct": round((1 - differing_lines / max(len(lines1), len(lines2), 1)) * 100, 1),
    }

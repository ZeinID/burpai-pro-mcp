"""Auth, CORS, IDOR, and access control testing tools."""
import httpx
import asyncio
import time
from typing import List, Dict, Any, Optional


async def test_cors(url: str, origins: Optional[List[str]] = None) -> Dict[str, Any]:
    """Test CORS misconfiguration with various Origin headers.
    
    Checks if the server reflects arbitrary origins, supports null origin,
    or has overly permissive Access-Control-Allow-Origin.
    """
    test_origins = origins or [
        "https://evil.com",
        "null",
        "https://attacker.example.com",
        "http://localhost",
        "https://trusted.com.evil.com",
    ]
    results = []
    async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
        # Baseline without Origin
        try:
            baseline = await client.get(url)
            baseline_acao = baseline.headers.get("access-control-allow-origin", "")
        except Exception as e:
            return {"error": f"Baseline request failed: {e}"}

        for origin in test_origins:
            try:
                resp = await client.get(url, headers={"Origin": origin})
                acao = resp.headers.get("access-control-allow-origin", "")
                acac = resp.headers.get("access-control-allow-credentials", "")
                vulnerable = False
                risk = "none"
                if acao == origin:
                    vulnerable = True
                    risk = "critical" if acac.lower() == "true" else "high"
                elif acao == "*":
                    vulnerable = True
                    risk = "medium"
                elif acao == "null" and origin == "null":
                    vulnerable = True
                    risk = "high"

                results.append({
                    "origin": origin,
                    "acao": acao,
                    "acac": acac,
                    "vulnerable": vulnerable,
                    "risk": risk,
                })
            except Exception as e:
                results.append({"origin": origin, "error": str(e)})

    vulns = [r for r in results if r.get("vulnerable")]
    return {
        "url": url,
        "baseline_acao": baseline_acao,
        "tests_run": len(results),
        "vulnerabilities_found": len(vulns),
        "results": results,
    }


async def test_idor(
    url_template: str,
    param: str,
    id_list: List[str],
    headers: Optional[Dict[str, str]] = None,
    delay: float = 0.1,
) -> Dict[str, Any]:
    """Test for Insecure Direct Object References (IDOR).
    
    Iterates through a list of IDs replacing {ID} in url_template.
    Detects when responses differ (indicating access to other users' data).
    """
    results = []
    baseline_len = None

    async with httpx.AsyncClient(timeout=10.0, verify=False, follow_redirects=False) as client:
        for id_val in id_list:
            target_url = url_template.replace("{ID}", str(id_val))
            try:
                resp = await client.get(target_url, headers=headers or {})
                resp_len = len(resp.text)
                if baseline_len is None:
                    baseline_len = resp_len

                accessible = resp.status_code == 200
                results.append({
                    "id": id_val,
                    "url": target_url,
                    "status_code": resp.status_code,
                    "response_length": resp_len,
                    "accessible": accessible,
                    "length_diff": resp_len - baseline_len,
                })
            except Exception as e:
                results.append({"id": id_val, "error": str(e)})
            if delay > 0:
                await asyncio.sleep(delay)

    accessible = [r for r in results if r.get("accessible")]
    return {
        "url_template": url_template,
        "ids_tested": len(id_list),
        "accessible_count": len(accessible),
        "potential_idor": len(accessible) > 1,
        "results": results,
    }


async def test_auth_bypass(
    url: str,
    headers: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """Test authentication bypass via HTTP verb tampering and path manipulation.
    
    Tries multiple HTTP methods and path variations to bypass access controls.
    """
    methods = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD", "TRACE"]
    path_bypasses = [
        "",        # original
        "/",       # trailing slash
        "/..",     # path traversal
        "/./",     # current dir
        "%2e/",    # encoded dot
        ";/",      # semicolon
        "..;/",    # tomcat bypass
    ]
    override_headers = [
        {"X-HTTP-Method-Override": "GET"},
        {"X-Method-Override": "GET"},
        {"X-Original-URL": url},
        {"X-Rewrite-URL": url},
        {"X-Forwarded-For": "127.0.0.1"},
        {"X-Real-IP": "127.0.0.1"},
        {"X-Custom-IP-Authorization": "127.0.0.1"},
    ]

    results = []
    async with httpx.AsyncClient(timeout=10.0, verify=False, follow_redirects=False) as client:
        # Test HTTP methods
        for method in methods:
            try:
                resp = await client.request(method, url, headers=headers or {})
                if resp.status_code not in (405, 501):
                    results.append({
                        "test": f"HTTP method: {method}",
                        "status_code": resp.status_code,
                        "response_length": len(resp.text),
                        "interesting": resp.status_code in (200, 301, 302),
                    })
            except Exception:
                pass

        # Test path bypasses
        for suffix in path_bypasses:
            target = url.rstrip("/") + suffix
            try:
                resp = await client.get(target, headers=headers or {})
                if resp.status_code == 200:
                    results.append({
                        "test": f"Path bypass: {suffix or '(original)'}",
                        "url": target,
                        "status_code": resp.status_code,
                        "response_length": len(resp.text),
                        "interesting": True,
                    })
            except Exception:
                pass

        # Test header overrides
        for override in override_headers:
            try:
                merged = {**(headers or {}), **override}
                resp = await client.get(url, headers=merged)
                header_name = list(override.keys())[0]
                if resp.status_code == 200:
                    results.append({
                        "test": f"Header override: {header_name}",
                        "status_code": resp.status_code,
                        "response_length": len(resp.text),
                        "interesting": True,
                    })
            except Exception:
                pass

    interesting = [r for r in results if r.get("interesting")]
    return {
        "url": url,
        "tests_run": len(results),
        "interesting_findings": len(interesting),
        "results": results,
    }


async def test_rate_limiting(
    url: str,
    count: int = 30,
    method: str = "GET",
    body: Optional[str] = None,
    headers: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """Test if rate limiting is enforced on an endpoint.
    
    Sends N rapid requests and checks for 429 responses or other throttling indicators.
    """
    results = []
    status_codes: Dict[int, int] = {}
    start_total = time.time()

    async with httpx.AsyncClient(timeout=10.0, verify=False, follow_redirects=False) as client:
        for i in range(count):
            try:
                start = time.time()
                if method.upper() == "GET":
                    resp = await client.get(url, headers=headers or {})
                else:
                    resp = await client.request(method.upper(), url, headers=headers or {}, content=body or "")
                elapsed = round(time.time() - start, 3)

                code = resp.status_code
                status_codes[code] = status_codes.get(code, 0) + 1
                results.append({
                    "request_num": i + 1,
                    "status_code": code,
                    "time_seconds": elapsed,
                })

                # Stop if we get rate limited
                if code == 429:
                    retry_after = resp.headers.get("retry-after", "unknown")
                    results.append({"rate_limited_at": i + 1, "retry_after": retry_after})
                    break
            except Exception as e:
                results.append({"request_num": i + 1, "error": str(e)})

    total_time = round(time.time() - start_total, 2)
    has_rate_limit = 429 in status_codes
    return {
        "url": url,
        "requests_sent": len(results),
        "total_time_seconds": total_time,
        "rate_limiting_detected": has_rate_limit,
        "status_code_distribution": status_codes,
        "results": results[-10:],  # last 10 only
    }

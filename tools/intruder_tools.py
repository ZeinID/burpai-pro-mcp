"""Intruder-style attack tools: fuzzing, brute-force, parameter mining."""
import httpx
import asyncio
import time
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse


async def fuzz_parameter(
    url: str,
    param: str,
    payloads: List[str],
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    body_template: Optional[str] = None,
    delay: float = 0.1,
) -> Dict[str, Any]:
    """Inject payloads into a single parameter and analyze responses (Sniper mode).
    
    For GET: replaces/appends query param. For POST: replaces {FUZZ} in body_template.
    Returns results with status codes, lengths, timing, and anomaly detection.
    """
    results = []
    baseline_status = None
    baseline_length = None

    async with httpx.AsyncClient(timeout=15.0, verify=False, follow_redirects=False) as client:
        for i, payload in enumerate(payloads):
            start = time.time()
            try:
                if method.upper() == "GET":
                    parsed = urlparse(url)
                    qs = parse_qs(parsed.query, keep_blank_values=True)
                    qs[param] = [payload]
                    new_query = urlencode(qs, doseq=True)
                    target_url = urlunparse(parsed._replace(query=new_query))
                    resp = await client.get(target_url, headers=headers or {})
                else:
                    body = ""
                    if body_template:
                        body = body_template.replace("{FUZZ}", payload)
                    else:
                        body = urlencode({param: payload})
                    h = headers or {}
                    if "Content-Type" not in h:
                        h["Content-Type"] = "application/x-www-form-urlencoded"
                    resp = await client.request(method.upper(), url, headers=h, content=body)

                elapsed = round(time.time() - start, 3)
                resp_len = len(resp.text)

                if i == 0:
                    baseline_status = resp.status_code
                    baseline_length = resp_len

                anomaly = False
                anomaly_reasons = []
                if baseline_status and resp.status_code != baseline_status:
                    anomaly = True
                    anomaly_reasons.append(f"status changed: {baseline_status}->{resp.status_code}")
                if baseline_length and abs(resp_len - baseline_length) > 50:
                    anomaly = True
                    anomaly_reasons.append(f"length diff: {abs(resp_len - baseline_length)}")
                if elapsed > 3.0:
                    anomaly = True
                    anomaly_reasons.append(f"slow response: {elapsed}s")

                results.append({
                    "index": i,
                    "payload": payload,
                    "status_code": resp.status_code,
                    "response_length": resp_len,
                    "time_seconds": elapsed,
                    "anomaly": anomaly,
                    "anomaly_reasons": anomaly_reasons,
                })
            except Exception as e:
                results.append({"index": i, "payload": payload, "error": str(e)})

            if delay > 0:
                await asyncio.sleep(delay)

    anomalies = [r for r in results if r.get("anomaly")]
    return {
        "total_requests": len(results),
        "anomalies_found": len(anomalies),
        "anomalies": anomalies,
        "results": results,
    }


async def fuzz_endpoint(
    base_url: str,
    wordlist: List[str],
    extensions: Optional[List[str]] = None,
    delay: float = 0.05,
) -> Dict[str, Any]:
    """Discover hidden paths/files by fuzzing URL paths.
    
    Appends each word from wordlist to base_url and checks status codes.
    Optionally appends file extensions (.php, .bak, .old, etc.)
    """
    base_url = base_url.rstrip("/")
    targets = []
    for word in wordlist:
        targets.append(f"{base_url}/{word}")
        if extensions:
            for ext in extensions:
                targets.append(f"{base_url}/{word}{ext}")

    found = []
    async with httpx.AsyncClient(timeout=10.0, verify=False, follow_redirects=False) as client:
        for target in targets:
            try:
                resp = await client.get(target)
                if resp.status_code not in (404, 502, 503):
                    found.append({
                        "url": target,
                        "status_code": resp.status_code,
                        "response_length": len(resp.text),
                        "content_type": resp.headers.get("content-type", "unknown"),
                    })
            except Exception:
                pass
            if delay > 0:
                await asyncio.sleep(delay)

    return {
        "base_url": base_url,
        "paths_tested": len(targets),
        "found": len(found),
        "results": found,
    }


async def parameter_mining(
    url: str,
    method: str = "GET",
    custom_params: Optional[List[str]] = None,
    delay: float = 0.05,
) -> Dict[str, Any]:
    """Discover hidden parameters by fuzzing common param names.
    
    Sends requests with common parameter names and detects when
    the response changes (indicating the param is accepted).
    """
    common_params = custom_params or [
        "id", "user", "username", "email", "password", "token", "key", "api_key",
        "secret", "admin", "debug", "test", "page", "limit", "offset", "sort",
        "order", "filter", "search", "q", "query", "callback", "redirect",
        "url", "next", "return", "ref", "source", "type", "action", "cmd",
        "exec", "command", "file", "path", "dir", "folder", "include",
        "template", "view", "role", "group", "permission", "lang", "locale",
        "format", "output", "version", "v", "config", "setting",
    ]

    # Get baseline response
    async with httpx.AsyncClient(timeout=10.0, verify=False, follow_redirects=False) as client:
        try:
            baseline = await client.request(method.upper(), url)
            baseline_len = len(baseline.text)
            baseline_status = baseline.status_code
        except Exception as e:
            return {"error": f"Baseline request failed: {e}"}

        discovered = []
        for param in common_params:
            try:
                if method.upper() == "GET":
                    parsed = urlparse(url)
                    qs = parse_qs(parsed.query, keep_blank_values=True)
                    qs[param] = ["1"]
                    new_query = urlencode(qs, doseq=True)
                    target = urlunparse(parsed._replace(query=new_query))
                    resp = await client.get(target)
                else:
                    resp = await client.post(url, data={param: "1"})

                resp_len = len(resp.text)
                if resp.status_code != baseline_status or abs(resp_len - baseline_len) > 20:
                    discovered.append({
                        "parameter": param,
                        "status_code": resp.status_code,
                        "response_length": resp_len,
                        "baseline_diff": resp_len - baseline_len,
                    })
            except Exception:
                pass
            if delay > 0:
                await asyncio.sleep(delay)

    return {
        "url": url,
        "params_tested": len(common_params),
        "discovered": len(discovered),
        "results": discovered,
    }



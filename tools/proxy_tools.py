from typing import List, Dict, Any
from urllib.parse import urlparse, parse_qs
from burp_client import BurpClient

async def get_proxy_history(limit: int = 10) -> List[Dict[str, Any]]:
    """Retrieve the latest N requests from Burp's proxy history."""
    client = BurpClient.get_instance()
    history = await client.get_proxy_history()
    return history[-limit:] if history else []

def analyze_request(request_data: str) -> Dict[str, Any]:
    """Analyze a raw HTTP request and extract its components (method, path, headers, body, params)."""
    lines = request_data.strip().split("\n")
    if not lines:
        return {"error": "Empty request data"}
    
    # Parse request line: GET /path?param=value HTTP/1.1
    first_line = lines[0].strip()
    parts = first_line.split(" ")
    method = parts[0] if len(parts) >= 1 else "UNKNOWN"
    raw_path = parts[1] if len(parts) >= 2 else "/"
    http_version = parts[2] if len(parts) >= 3 else "HTTP/1.1"
    
    # Extract query parameters from path
    query_params = {}
    if "?" in raw_path:
        path, query_string = raw_path.split("?", 1)
        query_params = parse_qs(query_string)
        # Flatten single-value params
        query_params = {k: v[0] if len(v) == 1 else v for k, v in query_params.items()}
    else:
        path = raw_path
    
    # Parse headers
    headers = {}
    body_start = -1
    for i, line in enumerate(lines[1:], 1):
        stripped = line.strip()
        if stripped == "":
            body_start = i + 1
            break
        if ": " in stripped:
            key, value = stripped.split(": ", 1)
            headers[key.strip()] = value.strip()
    
    # Extract body
    body = "\n".join(lines[body_start:]).strip() if body_start > 0 and body_start < len(lines) else ""
    
    # Extract cookies from Cookie header
    cookies = {}
    cookie_header = headers.get("Cookie", "")
    if cookie_header:
        for pair in cookie_header.split(";"):
            pair = pair.strip()
            if "=" in pair:
                ck, cv = pair.split("=", 1)
                cookies[ck.strip()] = cv.strip()
    
    # Detect content type
    content_type = headers.get("Content-Type", "none")
    
    # Extract Host
    host = headers.get("Host", "unknown")
    
    return {
        "method": method,
        "path": path,
        "full_url": f"https://{host}{raw_path}" if host != "unknown" else raw_path,
        "http_version": http_version,
        "headers": headers,
        "header_count": len(headers),
        "query_parameters": query_params,
        "cookies": cookies,
        "body": body,
        "has_body": bool(body),
        "content_type": content_type,
        "host": host,
        # Security observations
        "observations": _analyze_request_security(method, headers, query_params, body, cookies)
    }

def _analyze_request_security(method: str, headers: Dict, params: Dict, body: str, cookies: Dict) -> List[str]:
    """Generate security observations from request components."""
    observations = []
    
    # Check for interesting parameters
    sensitive_param_names = ["password", "passwd", "pass", "token", "api_key", "apikey", "secret", "ssn", "credit"]
    all_param_keys = [k.lower() for k in params.keys()]
    for name in sensitive_param_names:
        if any(name in k for k in all_param_keys):
            observations.append(f"⚠️ Sensitive parameter detected in query string: matches '{name}'")
    
    # Check auth headers
    if "Authorization" in headers:
        auth_val = headers["Authorization"]
        if auth_val.startswith("Basic"):
            observations.append("⚠️ Basic Authentication detected — credentials are Base64 encoded (easily decodable)")
        elif auth_val.startswith("Bearer"):
            observations.append("🔑 Bearer token detected — check JWT validity and expiration")
    
    # Check for lack of CSRF protection on state-changing methods
    if method in ("POST", "PUT", "PATCH", "DELETE"):
        has_csrf = any(k.lower() in ("x-csrf-token", "x-xsrf-token", "csrf-token") for k in headers.keys())
        if not has_csrf:
            observations.append(f"⚠️ {method} request without CSRF token header")

    # Check for cookies without SameSite
    if cookies:
        observations.append(f"🍪 {len(cookies)} cookie(s) sent with request")
    
    if not observations:
        observations.append("✅ No obvious security concerns in request structure")
    
    return observations


def analyze_response(response_data: str) -> Dict[str, Any]:
    """Analyze a raw HTTP response and extract its components."""
    lines = response_data.strip().split("\n")
    if not lines:
        return {"error": "Empty response data"}
    
    # Parse status line: HTTP/1.1 200 OK
    first_line = lines[0].strip()
    parts = first_line.split(" ", 2)
    http_version = parts[0] if len(parts) >= 1 else "HTTP/1.1"
    status_code = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else 0
    status_text = parts[2] if len(parts) >= 3 else ""
    
    # Parse headers
    headers = {}
    body_start = -1
    for i, line in enumerate(lines[1:], 1):
        stripped = line.strip()
        if stripped == "":
            body_start = i + 1
            break
        if ": " in stripped:
            key, value = stripped.split(": ", 1)
            headers[key.strip()] = value.strip()
    
    body = "\n".join(lines[body_start:]).strip() if body_start > 0 and body_start < len(lines) else ""
    
    # Content type analysis
    content_type = headers.get("Content-Type", "unknown")
    content_length = headers.get("Content-Length", str(len(body)))
    
    return {
        "http_version": http_version,
        "status_code": status_code,
        "status_text": status_text,
        "headers": headers,
        "header_count": len(headers),
        "body_length": len(body),
        "content_type": content_type,
        "body_preview": body[:500] + "..." if len(body) > 500 else body,
        # Security observations
        "observations": _analyze_response_security(status_code, headers, body)
    }

def _analyze_response_security(status_code: int, headers: Dict, body: str) -> List[str]:
    """Generate security observations from response components."""
    from analysis.header_analyzer import HeaderAnalyzer
    
    observations = []
    
    # Status code analysis
    if status_code == 200:
        observations.append("✅ 200 OK — Request succeeded")
    elif status_code == 301 or status_code == 302:
        location = headers.get("Location", "unknown")
        observations.append(f"🔀 Redirect to: {location}")
    elif status_code == 401:
        observations.append("🔒 401 Unauthorized — Authentication required")
    elif status_code == 403:
        observations.append("🚫 403 Forbidden — Access denied (potential authorization bypass target)")
    elif status_code == 500:
        observations.append("💥 500 Internal Server Error — May leak error details")
    
    # Security header check
    analyzer = HeaderAnalyzer()
    header_result = analyzer.analyze_response_headers(headers)
    if header_result["missing"]:
        missing_names = [h["header"] for h in header_result["missing"]]
        observations.append(f"⚠️ Missing security headers: {', '.join(missing_names)}")
    
    # Information disclosure in body
    if body:
        if "stack trace" in body.lower() or "traceback" in body.lower():
            observations.append("🚨 Stack trace detected in response body!")
        if "sql" in body.lower() and ("error" in body.lower() or "syntax" in body.lower()):
            observations.append("🚨 Possible SQL error message in response!")
        server = headers.get("Server", "")
        if server:
            observations.append(f"ℹ️ Server header reveals: {server}")
        x_powered = headers.get("X-Powered-By", "")
        if x_powered:
            observations.append(f"ℹ️ X-Powered-By reveals: {x_powered}")
    
    return observations

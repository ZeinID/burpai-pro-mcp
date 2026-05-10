"""Enhanced reconnaissance tools with tech fingerprinting, URL extraction, and robots.txt parsing."""
import re
import httpx
from typing import List, Dict, Any
from urllib.parse import urljoin
from burp_client import BurpClient


async def get_sitemap(url_prefix: str = "") -> List[Dict[str, Any]]:
    """Retrieve the sitemap for a given URL prefix from Burp Suite."""
    client = BurpClient.get_instance()
    return await client.get_sitemap(url_prefix)


def enumerate_endpoints(sitemap_data: List[Dict[str, Any]]) -> List[str]:
    """Extract unique endpoints from sitemap data."""
    endpoints = set()
    for item in sitemap_data:
        url = item.get("url", item.get("request", {}).get("url", ""))
        if url:
            endpoints.add(url)
    return sorted(endpoints)


def analyze_attack_surface(endpoints: List[str]) -> Dict[str, Any]:
    """Comprehensive attack surface analysis from a list of endpoints."""
    categories = {
        "auth_endpoints": [],
        "api_endpoints": [],
        "admin_endpoints": [],
        "file_upload_endpoints": [],
        "graphql_endpoints": [],
        "websocket_endpoints": [],
        "password_reset_endpoints": [],
        "api_docs_endpoints": [],
        "debug_endpoints": [],
        "static_assets": [],
    }

    patterns = {
        "auth_endpoints": ["login", "signin", "auth", "oauth", "sso", "saml", "logout", "register", "signup"],
        "api_endpoints": ["/api/", "/api/v", "/rest/", "/graphql", "/v1/", "/v2/", "/v3/"],
        "admin_endpoints": ["admin", "dashboard", "manage", "panel", "console", "backoffice"],
        "file_upload_endpoints": ["upload", "import", "attachment", "file", "media"],
        "graphql_endpoints": ["graphql", "graphiql", "playground"],
        "websocket_endpoints": ["ws://", "wss://", "socket", "websocket"],
        "password_reset_endpoints": ["reset", "forgot", "recover", "password"],
        "api_docs_endpoints": ["swagger", "openapi", "docs", "api-docs", "redoc"],
        "debug_endpoints": ["debug", "test", "actuator", "health", "status", "info", "metrics", "trace"],
    }

    static_extensions = [".js", ".css", ".png", ".jpg", ".gif", ".svg", ".ico", ".woff", ".ttf"]

    for ep in endpoints:
        ep_lower = ep.lower()
        categorized = False
        for category, keywords in patterns.items():
            if any(kw in ep_lower for kw in keywords):
                categories[category].append(ep)
                categorized = True
                break
        if not categorized and any(ep_lower.endswith(ext) for ext in static_extensions):
            categories["static_assets"].append(ep)

    # Summary
    non_empty = {k: v for k, v in categories.items() if v}
    return {
        "total_endpoints": len(endpoints),
        "categorized": non_empty,
        "high_value_targets": (
            categories["auth_endpoints"]
            + categories["api_endpoints"]
            + categories["admin_endpoints"]
            + categories["file_upload_endpoints"]
            + categories["graphql_endpoints"]
        ),
        "high_value_count": sum(
            len(categories[k]) for k in ["auth_endpoints", "api_endpoints", "admin_endpoints", "file_upload_endpoints", "graphql_endpoints"]
        ),
    }


def discover_technologies(headers: Dict[str, str], body: str = "") -> Dict[str, Any]:
    """Fingerprint technology stack from HTTP response headers and body content."""
    detected = {}

    # Header-based detection
    header_map = {
        "Server": "server",
        "X-Powered-By": "framework",
        "X-AspNet-Version": "aspnet_version",
        "X-AspNetMvc-Version": "aspnet_mvc_version",
        "X-Generator": "generator",
        "X-Drupal-Cache": "cms",
        "X-Varnish": "cache_proxy",
        "X-Cache": "cdn_cache",
        "CF-RAY": "cdn",
    }
    for header, key in header_map.items():
        val = headers.get(header, "")
        if val:
            detected[key] = val

    # CDN detection
    if "CF-RAY" in headers:
        detected["cdn"] = "Cloudflare"
    elif "x-amz-cf-id" in {k.lower() for k in headers}:
        detected["cdn"] = "AWS CloudFront"
    elif "x-akamai" in str(headers).lower():
        detected["cdn"] = "Akamai"

    # Body-based detection
    if body:
        body_lower = body[:10000].lower()
        body_techs = [
            (r"wp-content|wordpress", "CMS", "WordPress"),
            (r"drupal|sites/default", "CMS", "Drupal"),
            (r"joomla", "CMS", "Joomla"),
            (r"react", "js_framework", "React"),
            (r"angular", "js_framework", "Angular"),
            (r"vue\.js|vuejs", "js_framework", "Vue.js"),
            (r"next\.js|__next", "js_framework", "Next.js"),
            (r"laravel", "framework", "Laravel"),
            (r"django", "framework", "Django"),
            (r"express", "framework", "Express.js"),
            (r"spring", "framework", "Spring"),
        ]
        for pattern, key, name in body_techs:
            if re.search(pattern, body_lower):
                detected[key] = name

    # WAF detection
    waf_indicators = {
        "cloudflare": "Cloudflare WAF",
        "akamai": "Akamai WAF",
        "sucuri": "Sucuri WAF",
        "incapsula": "Incapsula/Imperva",
        "mod_security": "ModSecurity",
        "barracuda": "Barracuda WAF",
        "f5 big-ip": "F5 BIG-IP",
    }
    server_header = headers.get("Server", "").lower()
    for indicator, waf_name in waf_indicators.items():
        if indicator in server_header or indicator in str(headers).lower():
            detected["waf"] = waf_name
            break

    return detected


def extract_urls_and_params(html_body: str, base_url: str = "") -> Dict[str, Any]:
    """Parse HTML body to extract links, forms, and JavaScript file references."""
    links = set()
    forms = []
    js_files = set()

    # Extract href links
    href_pattern = re.compile(r'href=["\']([^"\']+)["\']', re.I)
    for match in href_pattern.findall(html_body[:50000]):
        url = urljoin(base_url, match) if base_url else match
        links.add(url)

    # Extract src attributes (JS, images)
    src_pattern = re.compile(r'src=["\']([^"\']+)["\']', re.I)
    for match in src_pattern.findall(html_body[:50000]):
        url = urljoin(base_url, match) if base_url else match
        if match.endswith(".js"):
            js_files.add(url)
        links.add(url)

    # Extract action from forms
    form_pattern = re.compile(r'<form[^>]*action=["\']([^"\']*)["\'][^>]*>(.*?)</form>', re.I | re.S)
    input_pattern = re.compile(r'<input[^>]*name=["\']([^"\']+)["\'][^>]*>', re.I)
    for form_match in form_pattern.findall(html_body[:50000]):
        action = form_match[0]
        form_body = form_match[1]
        params = input_pattern.findall(form_body)
        method_match = re.search(r'method=["\']([^"\']+)["\']', form_body, re.I)
        forms.append({
            "action": urljoin(base_url, action) if base_url else action,
            "method": method_match.group(1).upper() if method_match else "GET",
            "parameters": params,
        })

    # Extract API endpoints from JS
    api_pattern = re.compile(r'["\'](/api/[^"\']+)["\']', re.I)
    api_endpoints = set(api_pattern.findall(html_body[:50000]))

    return {
        "links": sorted(links)[:100],
        "forms": forms,
        "js_files": sorted(js_files),
        "api_endpoints": sorted(api_endpoints),
        "total_links": len(links),
    }


async def check_robots_sitemap(base_url: str) -> Dict[str, Any]:
    """Fetch and parse robots.txt and sitemap.xml for reconnaissance."""
    base_url = base_url.rstrip("/")
    result = {"robots_txt": None, "sitemap_xml": None, "disallowed_paths": [], "sitemaps": []}

    async with httpx.AsyncClient(timeout=10.0, verify=False, follow_redirects=True) as client:
        # robots.txt
        try:
            resp = await client.get(f"{base_url}/robots.txt")
            if resp.status_code == 200 and "text" in resp.headers.get("content-type", ""):
                result["robots_txt"] = resp.text[:5000]
                for line in resp.text.splitlines():
                    line = line.strip()
                    if line.lower().startswith("disallow:"):
                        path = line.split(":", 1)[1].strip()
                        if path:
                            result["disallowed_paths"].append(path)
                    elif line.lower().startswith("sitemap:"):
                        result["sitemaps"].append(line.split(":", 1)[1].strip())
        except Exception:
            pass

        # sitemap.xml
        try:
            resp = await client.get(f"{base_url}/sitemap.xml")
            if resp.status_code == 200:
                # Extract URLs from sitemap
                loc_pattern = re.compile(r"<loc>(.*?)</loc>", re.I)
                urls = loc_pattern.findall(resp.text[:50000])
                result["sitemap_xml"] = {
                    "url_count": len(urls),
                    "urls": urls[:50],
                }
        except Exception:
            pass

    return result

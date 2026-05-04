from typing import List, Dict, Any
from burp_client import BurpClient

async def get_sitemap(url_prefix: str = "") -> List[Dict[str, Any]]:
    """Retrieve the sitemap for a given URL prefix."""
    client = BurpClient()
    return await client.get_sitemap(url_prefix)

def enumerate_endpoints(sitemap_data: List[Dict[str, Any]]) -> List[str]:
    """Extract unique endpoints from sitemap data."""
    endpoints = set()
    for item in sitemap_data:
        # Depending on Burp API structure, extract URL
        # Assumes structure might have a 'requestResponse' -> 'url' or similar
        url = item.get("url", item.get("request", {}).get("url", ""))
        if url:
            endpoints.add(url)
    return list(endpoints)

def analyze_attack_surface(endpoints: List[str]) -> Dict[str, Any]:
    """Basic attack surface analysis based on endpoints."""
    # Placeholder logic
    auth_endpoints = [ep for ep in endpoints if "login" in ep.lower() or "auth" in ep.lower()]
    api_endpoints = [ep for ep in endpoints if "api" in ep.lower()]
    
    return {
        "total_endpoints": len(endpoints),
        "potential_auth_endpoints": auth_endpoints,
        "potential_api_endpoints": api_endpoints
    }

import httpx
from typing import Dict, Any, List, Optional
import logging
from config import BURP_API_URL, BURP_API_KEY

logger = logging.getLogger("burpai.client")

class BurpClient:
    """Async HTTP client to interact with Burp Suite REST API."""
    
    _instance: Optional["BurpClient"] = None
    
    def __init__(self, api_url: str = BURP_API_URL, api_key: str = BURP_API_KEY):
        self.base_url = api_url.rstrip('/')
        self.api_key = api_key
        self.headers = {}
    
    @classmethod
    def get_instance(cls) -> "BurpClient":
        """Singleton pattern — reuse a single BurpClient across tools."""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance
            
    async def _request(self, method: str, endpoint: str, timeout: float = 10.0, **kwargs) -> Optional[Dict[str, Any]]:
        """Internal method to make HTTP requests to the Burp API."""
        # Burp Suite Pro REST API format: http://host:port/{api_key}/v0.1/{endpoint}
        api_path = f"/{self.api_key}/v0.1" if self.api_key else "/v0.1"
        clean_endpoint = endpoint.lstrip('/')
        url = f"{self.base_url}{api_path}/{clean_endpoint}"
        
        async with httpx.AsyncClient(timeout=timeout) as client:
            try:
                response = await client.request(method, url, headers=self.headers, **kwargs)
                response.raise_for_status()
                return response.json() if response.text else {}
            except httpx.HTTPStatusError as e:
                logger.error(f"HTTP error occurred: {e.response.status_code} - {e.response.text}")
                return None
            except httpx.RequestError as e:
                logger.error(f"An error occurred while requesting {e.request.url!r}: {e}")
                return None
            except Exception as e:
                logger.error(f"Unexpected error: {e}")
                return None

    async def check_connection(self) -> bool:
        """Check if the Burp REST API is reachable."""
        try:
            async with httpx.AsyncClient(timeout=3.0) as client:
                api_path = f"/{self.api_key}/v0.1" if self.api_key else "/v0.1"
                res = await client.get(f"{self.base_url}{api_path}/knowledge_base/issue_definitions")
                return res.status_code < 500
        except Exception:
            return False

    # ── Burp Suite Pro Native REST API (v0.1) ──────────────────────
    
    async def get_issue_definitions(self) -> List[Dict[str, Any]]:
        """Fetch all known issue type definitions from Burp knowledge base."""
        res = await self._request("GET", "knowledge_base/issue_definitions")
        return res if isinstance(res, list) else []

    async def start_scan(self, urls: List[str]) -> Optional[str]:
        """
        Start an active scan on the given URLs.
        Burp Pro API: POST /{key}/v0.1/scan
        """
        # Burp expects a specific scan configuration
        scan_config = {
            "urls": urls,
        }
        res = await self._request("POST", "scan", json=scan_config)
        # Burp returns task_id in the Location header or response body
        return str(res) if res else None

    async def get_scan_status(self, task_id: str) -> Optional[Dict[str, Any]]:
        """
        Get the status of a running scan.
        Burp Pro API: GET /{key}/v0.1/scan/{task_id}
        """
        return await self._request("GET", f"scan/{task_id}")

    # ── Extension-based endpoints (requires burp-rest-api extension) ──
    
    async def get_proxy_history(self) -> List[Dict[str, Any]]:
        """
        Fetch proxy history from Burp.
        Requires: burp-rest-api extension or similar.
        Falls back gracefully if not available.
        """
        res = await self._request("GET", "proxy/history")
        if res is None:
            logger.warning("Proxy history endpoint not available. Install 'burp-rest-api' extension for this feature.")
            return []
        return res.get("messages", []) if isinstance(res, dict) else []

    async def get_sitemap(self, url_prefix: str = "") -> List[Dict[str, Any]]:
        """
        Fetch the sitemap.
        Requires: burp-rest-api extension or similar.
        """
        params = {"urlPrefix": url_prefix} if url_prefix else {}
        res = await self._request("GET", "target/sitemap", params=params)
        if res is None:
            logger.warning("Sitemap endpoint not available. Install 'burp-rest-api' extension for this feature.")
            return []
        return res.get("messages", []) if isinstance(res, dict) else []

    async def get_scan_issues(self) -> List[Dict[str, Any]]:
        """
        Fetch all scan issues.
        Requires: burp-rest-api extension or similar.
        """
        res = await self._request("GET", "scanner/issues")
        if res is None:
            logger.warning("Scanner issues endpoint not available.")
            return []
        return res.get("issues", []) if isinstance(res, dict) else []

    async def send_request(self, request_data: str, host: str, port: int, use_https: bool) -> Optional[Dict[str, Any]]:
        """
        Send a raw HTTP request through Burp (Repeater equivalent).
        Requires: burp-rest-api extension or similar.
        """
        payload = {
            "host": host,
            "port": port,
            "useHttps": use_https,
            "request": request_data
        }
        return await self._request("POST", "repeater/send", json=payload)

import httpx
import asyncio
from typing import Dict, Any, List, Optional
import logging
from config import BURP_API_URL, BURP_API_KEY

logger = logging.getLogger("burpai.client")


class BurpClient:
    """Async HTTP client for Burp Suite Professional REST API.
    Uses singleton pattern to reuse connections across all tools.
    """
    _instance: Optional["BurpClient"] = None

    def __init__(self, api_url: str = BURP_API_URL, api_key: str = BURP_API_KEY):
        self.base_url = api_url.rstrip('/')
        self.api_key = api_key
        self.headers = {}
        self._max_retries = 3
        self._base_delay = 0.5

    @classmethod
    def get_instance(cls) -> "BurpClient":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def _build_url(self, endpoint: str) -> str:
        api_path = f"/{self.api_key}/v0.1" if self.api_key else "/v0.1"
        return f"{self.base_url}{api_path}/{endpoint.lstrip('/')}"

    async def _request(self, method: str, endpoint: str, timeout: float = 15.0, retries: int = None, **kwargs) -> Optional[Any]:
        url = self._build_url(endpoint)
        max_retries = retries if retries is not None else self._max_retries
        last_error = None
        for attempt in range(max_retries):
            async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
                try:
                    response = await client.request(method, url, headers=self.headers, **kwargs)
                    response.raise_for_status()
                    if response.status_code == 201 and "location" in response.headers:
                        return {"task_id": response.headers["location"]}
                    if response.status_code == 204:
                        return {"status": "success"}
                    return response.json() if response.text.strip() else {}
                except httpx.HTTPStatusError as e:
                    last_error = f"HTTP {e.response.status_code}: {e.response.text[:200]}"
                    logger.error(f"HTTP error (attempt {attempt+1}): {last_error}")
                    if e.response.status_code < 500:
                        return {"error": last_error}
                except httpx.ConnectError as e:
                    last_error = f"Connection failed: {e}"
                    logger.error(f"Connect error (attempt {attempt+1}): {last_error}")
                except httpx.RequestError as e:
                    last_error = f"Request error: {e}"
                    logger.error(f"Request error (attempt {attempt+1}): {last_error}")
                except Exception as e:
                    last_error = f"Unexpected: {e}"
                    logger.error(f"Unexpected error (attempt {attempt+1}): {last_error}")
            if attempt < max_retries - 1:
                await asyncio.sleep(self._base_delay * (2 ** attempt))
        return {"error": f"All {max_retries} attempts failed. Last: {last_error}"}

    async def check_connection(self) -> Dict[str, Any]:
        try:
            async with httpx.AsyncClient(timeout=5.0, verify=False) as client:
                url = self._build_url("knowledge_base/issue_definitions")
                res = await client.get(url)
                if res.status_code < 500:
                    return {"connected": True, "status_code": res.status_code, "api_url": self.base_url}
                return {"connected": False, "error": f"Server returned {res.status_code}"}
        except Exception as e:
            return {"connected": False, "error": str(e)}

    # ── Burp Suite Pro Native REST API ─────────────────────────
    async def get_issue_definitions(self) -> List[Dict[str, Any]]:
        res = await self._request("GET", "knowledge_base/issue_definitions")
        return res if isinstance(res, list) else []

    async def start_scan(self, urls: List[str], named_config: Optional[str] = None) -> Optional[str]:
        scan_config: Dict[str, Any] = {"urls": urls}
        if named_config:
            scan_config["scan_configurations"] = [{"name": named_config, "type": "NamedConfiguration"}]
        res = await self._request("POST", "scan", json=scan_config, timeout=30.0)
        if isinstance(res, dict) and "task_id" in res:
            return res["task_id"]
        return str(res) if res else None

    async def get_scan_status(self, task_id: str) -> Optional[Dict[str, Any]]:
        return await self._request("GET", f"scan/{task_id}", timeout=30.0)

    async def cancel_scan(self, task_id: str) -> Dict[str, Any]:
        res = await self._request("DELETE", f"scan/{task_id}")
        return res if res else {"error": "Failed to cancel scan"}

    # ── Scope Management ───────────────────────────────────────
    async def include_in_scope(self, url: str) -> Dict[str, Any]:
        res = await self._request("PUT", f"target/scope?url={url}")
        return res if res else {"status": "scope updated"}

    async def exclude_from_scope(self, url: str) -> Dict[str, Any]:
        res = await self._request("DELETE", f"target/scope?url={url}")
        return res if res else {"status": "scope updated"}

    # ── Extension-based endpoints ──────────────────────────────
    async def get_proxy_history(self) -> List[Dict[str, Any]]:
        res = await self._request("GET", "proxy/history", timeout=30.0)
        if res is None or (isinstance(res, dict) and "error" in res):
            return []
        return res.get("messages", []) if isinstance(res, dict) else []

    async def get_sitemap(self, url_prefix: str = "") -> List[Dict[str, Any]]:
        params = {"urlPrefix": url_prefix} if url_prefix else {}
        res = await self._request("GET", "target/sitemap", params=params, timeout=30.0)
        if res is None or (isinstance(res, dict) and "error" in res):
            return []
        return res.get("messages", []) if isinstance(res, dict) else []

    async def get_scan_issues(self) -> List[Dict[str, Any]]:
        res = await self._request("GET", "scanner/issues", timeout=30.0)
        if res is None or (isinstance(res, dict) and "error" in res):
            return []
        return res.get("issues", []) if isinstance(res, dict) else []

    async def send_request(self, request_data: str, host: str, port: int, use_https: bool) -> Optional[Dict[str, Any]]:
        payload = {"host": host, "port": port, "useHttps": use_https, "request": request_data}
        return await self._request("POST", "repeater/send", json=payload, timeout=30.0)


import httpx
import asyncio

async def scan_paths():
    base = "https://www.syfe.com"
    paths = [
        "/admin", "/api", "/v1", "/v2", "/test", "/dev", 
        "/staging", "/.env", "/config.php", "/wp-admin", 
        "/login", "/auth", "/v3", "/api/v1", "/api/v2"
    ]
    print(f"Scanning common paths on {base}...\n")
    
    async with httpx.AsyncClient(follow_redirects=False, timeout=5) as client:
        for p in paths:
            url = base + p
            try:
                res = await client.get(url)
                if res.status_code != 404:
                    print(f"[{res.status_code}] {url} -> {res.headers.get('Location', '')}")
            except:
                pass

if __name__ == "__main__":
    asyncio.run(scan_paths())

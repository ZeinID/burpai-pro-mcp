
import httpx
import asyncio

async def recon_syfe():
    target = "syfe.com"
    subdomains = ["api", "auth", "app", "developers", "support", "blog", "static"]
    print(f"Reconnaissance on {target}...\n")
    
    async with httpx.AsyncClient(follow_redirects=True, timeout=5) as client:
        for sub in subdomains:
            url = f"https://{sub}.{target}"
            try:
                res = await client.get(url)
                print(f"[{res.status_code}] {url} (Server: {res.headers.get('Server', 'unknown')})")
            except:
                pass

if __name__ == "__main__":
    asyncio.run(recon_syfe())

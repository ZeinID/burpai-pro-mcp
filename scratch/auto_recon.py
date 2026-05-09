
import httpx
import asyncio

async def recon_all():
    targets = ["oppomobile.com", "coloros.com", "oplus.com"]
    prefixes = ["api", "dev", "staging", "id", "auth", "developers", "admin", "v", "m"]
    
    found = []
    print(f"Starting auto-recon on {targets}...")
    
    async with httpx.AsyncClient(timeout=5.0) as client:
        for domain in targets:
            for pre in prefixes:
                url = f"https://{pre}.{domain}"
                try:
                    res = await client.get(url)
                    print(f"[FOUND] {url} (Status: {res.status_code})")
                    found.append(url)
                except:
                    pass
    return found

if __name__ == "__main__":
    asyncio.run(recon_all())

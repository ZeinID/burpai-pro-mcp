
import httpx
import asyncio

async def probe_verify():
    base = "https://www.syfe.com"
    email = "qwe123@wearehackerone.com"
    endpoints = [
        "/api/v1/auth/verify-email",
        "/api/v1/auth/confirm",
        "/api/v1/auth/otp/verify",
        "/api/v1/auth/status",
        "/api/auth/verify",
        "/api/user/status"
    ]
    print(f"Probing verification endpoints for {email}...\n")
    
    async with httpx.AsyncClient(follow_redirects=True, timeout=10) as client:
        for ep in endpoints:
            url = base + ep
            try:
                # Test with GET
                res = await client.get(url, params={"email": email})
                print(f"[GET] {url} -> {res.status_code}")
                
                # Test with POST
                res = await client.post(url, json={"email": email, "code": "123456"})
                print(f"[POST] {url} -> {res.status_code}")
            except:
                pass

if __name__ == "__main__":
    asyncio.run(probe_verify())


import httpx
import asyncio

async def probe_upload():
    url = "https://developers.oppomobile.com/api/utility/upload"
    print(f"Probing upload endpoint: {url}")
    
    async with httpx.AsyncClient(follow_redirects=True, timeout=10) as client:
        # Test 1: Simple GET
        res = await client.get(url)
        print(f"[GET] Status: {res.status_code}")
        
        # Test 2: POST with empty data
        res = await client.post(url)
        print(f"[POST Empty] Status: {res.status_code}")
        
        # Test 3: POST with a dummy file
        files = {'file': ('test.txt', 'hello world', 'text/plain')}
        res = await client.post(url, files=files)
        print(f"[POST File] Status: {res.status_code}")
        if res.status_code == 200:
            print(f"Response (length {len(res.text)}):")
            print(res.text.encode('ascii', 'ignore').decode('ascii')[:500])

if __name__ == "__main__":
    asyncio.run(probe_upload())

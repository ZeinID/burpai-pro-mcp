
import httpx
import asyncio
import re

async def analyze_scripts():
    base = "https://www.syfe.com"
    print(f"Analyzing scripts from {base}/create-account...")
    
    async with httpx.AsyncClient(follow_redirects=True, timeout=10) as client:
        r = await client.get(f"{base}/create-account")
        scripts = re.findall(r'src=["\'](.*?\.(?:js|json))["\']', r.text)
        
        print(f"Found {len(scripts)} scripts.")
        for s in scripts:
            full_url = s if s.startswith('http') else base + (s if s.startswith('/') else '/' + s)
            print(f"\n--- Analyzing: {full_url} ---")
            try:
                js_res = await client.get(full_url)
                if js_res.status_code == 200:
                    # Look for verification related keywords
                    keywords = ['verify', 'otp', 'code', 'auth', 'signup', 'confirm']
                    for kw in keywords:
                        matches = re.findall(r'[^;]*?' + kw + r'[^;]*?', js_res.text, re.I)
                        if matches:
                            print(f"  [!] Found '{kw}' matches (showing first 3):")
                            for m in matches[:3]:
                                print(f"      {m.strip()[:100]}...")
            except Exception as e:
                print(f"  Error: {e}")

if __name__ == "__main__":
    asyncio.run(analyze_scripts())

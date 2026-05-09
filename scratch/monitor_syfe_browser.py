
import asyncio
import sys
import os
import time

# Add parent directory to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from burp_client import BurpClient

async def monitor_syfe():
    client = BurpClient()
    target_domain = "syfe.com"
    print(f"=== SYFE LIVE MONITORING (Burp Browser) ===")
    print(f"Status: Menunggu trafik dari browser Anda ke domain {target_domain}...")
    
    last_count = 0
    try:
        while True:
            # Periksa riwayat proxy
            history = await client.get_proxy_history()
            current_count = len(history)
            
            if current_count > last_count:
                new_items = history[last_count:]
                for item in new_items:
                    url = item.get('url', '')
                    if target_domain in url:
                        print(f"\n[!] TERDETEKSI REQUEST KE SYFE: [{item.get('method')}] {url}")
                        # Jika ini request verifikasi atau login, tandai untuk analisis mendalam
                        if any(k in url.lower() for k in ['verify', 'login', 'auth', 'account']):
                            print(f"    [>>>] Menganalisis parameter untuk potensi Bypass/Injection...")
                
                last_count = current_count
            
            await asyncio.sleep(2)
    except Exception as e:
        # Jika extension belum ada, berikan instruksi lagi
        if "404" in str(e) or "not available" in str(e).lower():
            print("\n[!] ERROR: Ekstensi 'Burp REST API' belum aktif.")
            print("Silakan instal dari BApp Store agar saya bisa membaca trafik browser Anda secara otomatis.")
        else:
            print(f"\nError: {e}")

if __name__ == "__main__":
    asyncio.run(monitor_syfe())

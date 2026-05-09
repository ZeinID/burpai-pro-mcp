
import asyncio
import sys
import os
import time

# Add parent directory to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from burp_client import BurpClient

async def monitor():
    client = BurpClient()
    print("=== MU-MU TO BURP MONITOR ===")
    print("Status: Mencari trafik dari emulator...")
    
    last_count = 0
    try:
        while True:
            history = await client.get_proxy_history()
            current_count = len(history)
            
            if current_count > last_count:
                new_items = current_count - last_count
                print(f"\n[!] TERDETEKSI: {new_items} request baru masuk!")
                # Tampilkan 3 request terakhir
                for item in history[-3:]:
                    print(f"    -> [{item.get('method')}] {item.get('url')}")
                last_count = current_count
            
            await asyncio.sleep(3)
    except KeyboardInterrupt:
        print("\nMonitoring dihentikan.")
    except Exception as e:
        print(f"\nError: {e}")

if __name__ == "__main__":
    asyncio.run(monitor())

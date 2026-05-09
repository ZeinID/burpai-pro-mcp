
import asyncio
import sys
import os

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from burp_client import BurpClient

async def check_targets():
    client = BurpClient()
    targets = [
        "com.coloros.video",
        "com.oplus.games",
        "com.katanlabs.bubblepop",
        "com.katanlabs.matchballgame",
        "com.katanlabs.worm.ioeatemall",
        "developers.oppomobile.com"
    ]
    
    print(f"Checking Burp history for targets: {targets}")
    
    # Try sitemap first as it's more structured
    for target in targets:
        print(f"\n--- Checking Sitemap for: {target} ---")
        sitemap = await client.get_sitemap(url_prefix=target if "." in target else "")
        if sitemap:
            print(f"Found {len(sitemap)} entries in sitemap for {target}")
            # Show first few
            for entry in sitemap[:3]:
                print(f"  URL: {entry.get('url')}")
        else:
            print(f"No sitemap entries for {target}")

    # Try proxy history
    print("\n--- Checking Proxy History ---")
    history = await client.get_proxy_history()
    if history:
        print(f"Total history entries: {len(history)}")
        matches = []
        for msg in history:
            url = msg.get("url", "")
            if any(t in url for t in targets):
                matches.append(msg)
        
        print(f"Found {len(matches)} matching requests in history.")
        for msg in matches[:5]:
            print(f"  [{msg.get('method')}] {msg.get('url')}")
    else:
        print("No proxy history found (or extension not installed).")

if __name__ == "__main__":
    asyncio.run(check_targets())

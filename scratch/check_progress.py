import asyncio
import sys
import os

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from burp_client import BurpClient
import json

async def check_progress():
    client = BurpClient()
    status = await client.get_scan_status('3')
    metrics = status.get('scan_metrics', {})
    progress = metrics.get('crawl_and_audit_progress', 0)
    print(f"Scan progress: {progress}%")
    
    issues = status.get('issue_events', [])
    if issues:
        print(f"Found {len(issues)} issues.")
        # Only print unique captions
        captions = set([i.get('caption') for i in issues])
        for c in captions:
            print(f"- {c}")

if __name__ == "__main__":
    asyncio.run(check_progress())

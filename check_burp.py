
import asyncio
from burp_client import BurpClient

async def main():
    client = BurpClient.get_instance()
    print(f"Checking connection to Burp Suite at {client.base_url}...")
    result = await client.check_connection()
    if result.get("connected"):
        print("SUCCESS: Connected to Burp Suite Professional REST API!")
        print(f"Status Code: {result.get('status_code')}")
    else:
        print("FAILED: Could not connect to Burp Suite.")
        print(f"Error: {result.get('error')}")
        print("\nPastikan:")
        print("1. Burp Suite Professional sedang berjalan.")
        print("2. REST API diaktifkan (User options > Miscellaneous > REST API).")
        print(f"3. API Key di .env sudah benar (saat ini: {client.api_key[:5]}...)")
        print("4. Port 1337 (default) terbuka.")

if __name__ == "__main__":
    asyncio.run(main())

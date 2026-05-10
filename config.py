"""
Configuration for BurpAI Pro MCP Server.
Load sensitive values from environment variables or a .env file.
"""
import os
from pathlib import Path

# Load .env file if it exists
_env_path = Path(__file__).parent / ".env"
if _env_path.exists():
    with open(_env_path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, _, value = line.partition("=")
                os.environ.setdefault(key.strip(), value.strip())

# Burp Suite REST API Configuration
BURP_API_HOST = os.getenv("BURP_API_HOST", "127.0.0.1")
BURP_API_PORT = int(os.getenv("BURP_API_PORT", "1337"))
BURP_API_URL = f"http://{BURP_API_HOST}:{BURP_API_PORT}"
BURP_API_KEY = os.getenv("BURP_API_KEY", "")  # Set via .env or env var, JANGAN hardcode!

# MCP Server Configuration
MCP_SERVER_NAME = "BurpAI Pro"

# Reporting
REPORT_OUTPUT_DIR = os.getenv("REPORT_OUTPUT_DIR", "./reports")

# Ensure report directory exists
os.makedirs(REPORT_OUTPUT_DIR, exist_ok=True)

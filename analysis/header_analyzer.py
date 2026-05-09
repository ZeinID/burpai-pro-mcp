"""Enhanced HTTP security header analyzer with modern header checks and CSP analysis."""
from typing import Dict, List, Any


class HeaderAnalyzer:
    """Analyzes HTTP headers for security misconfigurations."""

    SECURITY_HEADERS = {
        "Strict-Transport-Security": "Ensures communication is sent over HTTPS.",
        "Content-Security-Policy": "Prevents XSS and content injection attacks.",
        "X-Frame-Options": "Prevents Clickjacking by controlling framing.",
        "X-Content-Type-Options": "Prevents MIME-sniffing.",
        "Referrer-Policy": "Controls referrer information in requests.",
        "Permissions-Policy": "Controls browser features (camera, mic, geolocation, etc.).",
        "Cross-Origin-Embedder-Policy": "Controls cross-origin resource embedding (COEP).",
        "Cross-Origin-Opener-Policy": "Isolates browsing context (COOP).",
        "Cross-Origin-Resource-Policy": "Controls cross-origin resource sharing (CORP).",
    }

    CSP_DANGEROUS_DIRECTIVES = [
        "unsafe-inline", "unsafe-eval", "data:", "blob:",
        "*",  # wildcard source
    ]

    def __init__(self):
        pass

    def analyze_response_headers(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Check for missing or misconfigured security headers."""
        lower_headers = {k.lower(): v for k, v in headers.items()}

        missing = []
        present = []
        misconfigured = []

        for header, description in self.SECURITY_HEADERS.items():
            h_lower = header.lower()
            if h_lower in lower_headers:
                present.append(header)
                val = lower_headers[h_lower]

                # Specific validation
                if h_lower == "x-frame-options" and val.upper() not in ("DENY", "SAMEORIGIN"):
                    misconfigured.append({"header": header, "value": val, "issue": "Should be DENY or SAMEORIGIN"})
                elif h_lower == "x-content-type-options" and val.lower() != "nosniff":
                    misconfigured.append({"header": header, "value": val, "issue": "Should be nosniff"})
                elif h_lower == "strict-transport-security":
                    self._check_hsts(val, misconfigured)
                elif h_lower == "content-security-policy":
                    self._check_csp(val, misconfigured)
                elif h_lower == "cross-origin-opener-policy" and val.lower() not in ("same-origin", "same-origin-allow-popups"):
                    misconfigured.append({"header": header, "value": val, "issue": "Weak COOP policy"})
            else:
                missing.append({"header": header, "description": description})

        # Cookie security checks
        self._check_cookies(lower_headers, misconfigured)

        # Cache-Control check for sensitive pages
        cache_control = lower_headers.get("cache-control", "")
        if not cache_control or ("no-store" not in cache_control.lower() and "private" not in cache_control.lower()):
            misconfigured.append({
                "header": "Cache-Control",
                "value": cache_control or "(not set)",
                "issue": "Sensitive responses should use 'no-store' or 'private'",
            })

        score = self._calculate_score(present, missing, misconfigured)

        return {
            "present": present,
            "missing": missing,
            "misconfigured": misconfigured,
            "security_score": score,
            "grade": self._score_to_grade(score),
        }

    def _check_hsts(self, value: str, misconfigured: List):
        """Validate HSTS header configuration."""
        lower_val = value.lower()
        # Check max-age
        if "max-age=" in lower_val:
            try:
                max_age_str = lower_val.split("max-age=")[1].split(";")[0].strip()
                max_age = int(max_age_str)
                if max_age < 31536000:  # Less than 1 year
                    misconfigured.append({
                        "header": "Strict-Transport-Security",
                        "value": value,
                        "issue": f"max-age={max_age} is too low. Recommend at least 31536000 (1 year).",
                    })
            except (ValueError, IndexError):
                pass
        if "includesubdomains" not in lower_val:
            misconfigured.append({
                "header": "Strict-Transport-Security",
                "value": value,
                "issue": "Missing 'includeSubDomains' directive.",
            })

    def _check_csp(self, value: str, misconfigured: List):
        """Analyze CSP directives for dangerous settings."""
        lower_val = value.lower()
        for dangerous in self.CSP_DANGEROUS_DIRECTIVES:
            if dangerous in lower_val:
                misconfigured.append({
                    "header": "Content-Security-Policy",
                    "value": value[:200],
                    "issue": f"Dangerous directive found: '{dangerous}'",
                })
        if "default-src" not in lower_val and "script-src" not in lower_val:
            misconfigured.append({
                "header": "Content-Security-Policy",
                "value": value[:200],
                "issue": "Missing 'default-src' or 'script-src' directive.",
            })

    def _check_cookies(self, lower_headers: Dict, misconfigured: List):
        """Check Set-Cookie headers for security flags."""
        set_cookie = lower_headers.get("set-cookie", "")
        if not set_cookie:
            return
        # Handle multiple Set-Cookie (simplified)
        cookies = set_cookie.split("\n") if "\n" in set_cookie else [set_cookie]
        for cookie in cookies:
            c_lower = cookie.lower()
            name = cookie.split("=")[0].strip() if "=" in cookie else "unknown"
            if "secure" not in c_lower:
                misconfigured.append({"header": "Set-Cookie", "cookie": name, "issue": "Missing 'Secure' flag"})
            if "httponly" not in c_lower:
                misconfigured.append({"header": "Set-Cookie", "cookie": name, "issue": "Missing 'HttpOnly' flag"})
            if "samesite" not in c_lower:
                misconfigured.append({"header": "Set-Cookie", "cookie": name, "issue": "Missing 'SameSite' attribute"})

    def _calculate_score(self, present: List, missing: List, misconfigured: List) -> int:
        """Calculate a security score (0-100) based on header configuration."""
        total = len(self.SECURITY_HEADERS)
        if total == 0:
            return 0
        base_score = (len(present) / total) * 100
        penalty = min(len(misconfigured) * 5, 40)  # Max 40 point penalty
        return max(0, int(base_score - penalty))

    def _score_to_grade(self, score: int) -> str:
        if score >= 90: return "A"
        if score >= 80: return "B"
        if score >= 60: return "C"
        if score >= 40: return "D"
        return "F"

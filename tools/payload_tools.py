"""Payload generation tools for all attack types."""
from typing import List
from analysis.payload_db import PayloadDB


def generate_sqli_payloads(limit: int = 10) -> List[str]:
    """Generate SQL injection payloads."""
    return PayloadDB.get_sqli_payloads(limit)

def generate_xss_payloads(limit: int = 10) -> List[str]:
    """Generate XSS payloads."""
    return PayloadDB.get_xss_payloads(limit)

def generate_ssrf_payloads(limit: int = 10) -> List[str]:
    """Generate SSRF payloads."""
    return PayloadDB.get_ssrf_payloads(limit)

def generate_path_traversal_payloads(limit: int = 10) -> List[str]:
    """Generate Path Traversal payloads."""
    return PayloadDB.get_path_traversal_payloads(limit)

def generate_cmdi_payloads(limit: int = 10) -> List[str]:
    """Generate OS Command Injection payloads."""
    return PayloadDB.get_cmdi_payloads(limit)

def generate_ssti_payloads(limit: int = 10) -> List[str]:
    """Generate Server-Side Template Injection (SSTI) payloads."""
    return PayloadDB.get_ssti_payloads(limit)

def generate_xxe_payloads(limit: int = 10) -> List[str]:
    """Generate XML External Entity (XXE) payloads."""
    return PayloadDB.get_xxe_payloads(limit)

def generate_nosqli_payloads(limit: int = 10) -> List[str]:
    """Generate NoSQL injection payloads."""
    return PayloadDB.get_nosqli_payloads(limit)

def generate_open_redirect_payloads(limit: int = 10) -> List[str]:
    """Generate Open Redirect payloads."""
    return PayloadDB.get_open_redirect_payloads(limit)

def generate_cors_payloads(limit: int = 10) -> List[str]:
    """Generate CORS bypass Origin headers."""
    return PayloadDB.get_cors_origins(limit)

def generate_header_injection_payloads(limit: int = 10) -> List[str]:
    """Generate CRLF / Header Injection payloads."""
    return PayloadDB.get_header_injection_payloads(limit)

def generate_waf_bypass_payloads(limit: int = 10) -> List[str]:
    """Generate WAF bypass payloads."""
    return PayloadDB.get_waf_bypass_payloads(limit)

def generate_auth_bypass_payloads(limit: int = 10) -> List[str]:
    """Generate authentication bypass payloads."""
    return PayloadDB.get_auth_bypass_payloads(limit)

def generate_fuzzing_wordlist(attack_type: str, limit: int = 20) -> List[str]:
    """Generate a custom fuzzing wordlist by attack type."""
    attack_type = attack_type.lower().replace(" ", "_").replace("-", "_")
    mapping = {
        'sqli': generate_sqli_payloads,
        'sql_injection': generate_sqli_payloads,
        'xss': generate_xss_payloads,
        'cross_site_scripting': generate_xss_payloads,
        'ssrf': generate_ssrf_payloads,
        'path_traversal': generate_path_traversal_payloads,
        'lfi': generate_path_traversal_payloads,
        'cmdi': generate_cmdi_payloads,
        'command_injection': generate_cmdi_payloads,
        'os_injection': generate_cmdi_payloads,
        'ssti': generate_ssti_payloads,
        'template_injection': generate_ssti_payloads,
        'xxe': generate_xxe_payloads,
        'nosqli': generate_nosqli_payloads,
        'nosql_injection': generate_nosqli_payloads,
        'open_redirect': generate_open_redirect_payloads,
        'redirect': generate_open_redirect_payloads,
        'cors': generate_cors_payloads,
        'header_injection': generate_header_injection_payloads,
        'crlf': generate_header_injection_payloads,
        'waf_bypass': generate_waf_bypass_payloads,
        'waf': generate_waf_bypass_payloads,
        'auth_bypass': generate_auth_bypass_payloads,
    }
    func = mapping.get(attack_type)
    if func:
        return func(limit)
    return [f"No wordlist for: {attack_type}. Supported: {', '.join(sorted(set(mapping.keys())))}"]

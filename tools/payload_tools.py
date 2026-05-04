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

def generate_fuzzing_wordlist(attack_type: str, limit: int = 20) -> List[str]:
    """Generate a custom wordlist based on the attack type (sqli, xss, ssrf, path_traversal, cmdi, ssti)."""
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
    }
    func = mapping.get(attack_type)
    if func:
        return func(limit)
    return [f"No wordlist available for attack type: {attack_type}. Supported: {', '.join(mapping.keys())}"]

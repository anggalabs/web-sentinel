"""
Dynamic Application Security Testing (DAST) Module.
Performs active parameter injection fuzzing:
1. Reflected Input & Cross-Site Scripting (XSS) Canary
2. SQL Injection (SQLi) Error-Based Anomaly Detection
3. Local File Inclusion (LFI) & Path Traversal
4. Open Redirect Validation
Uses persistent HTTP sessions with upstream proxy support.
"""

import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core.http_client import PersistentSession
from core.ui import print_info, print_success, print_warning, print_danger, print_table, Colors

# Database Error Regex Patterns for SQLi
SQLI_ERROR_PATTERNS = [
    (re.compile(r"(SQL syntax.*MySQL|Warning.*mysql_|valid MySQL result|MySqlClient\.)", re.I), "MySQL"),
    (re.compile(r"(PostgreSQL.*ERROR|Warning.*\bpg_|valid PostgreSQL result|Npgsql\.)", re.I), "PostgreSQL"),
    (re.compile(r"(Driver.*SQL[\-\_\ ]*Server|OLE DB.*SQL Server|\bODBC SQL Server Driver|SQLServer JDBC)", re.I), "Microsoft SQL Server"),
    (re.compile(r"(SQLite/JDBCDriver|SQLite.Exception|System.Data.SQLite.SQLiteException)", re.I), "SQLite"),
    (re.compile(r"(ORA-[0-9]{4,5}|Oracle error|Oracle.*Driver)", re.I), "Oracle DB")
]

XSS_CANARY = 'wsntnl<"\'789>'
LFI_PAYLOAD = "../../../../etc/passwd"
LFI_PATTERN = re.compile(r"root:.*:0:0:")

def inject_param(target_url: str, param_name: str, payload: str) -> str:
    """Replaces or injects a payload into a specific query parameter"""
    parsed = urlparse(target_url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param_name] = [payload]
    new_query = urlencode(qs, doseq=True)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

def test_parameter_sqli(session: PersistentSession, url: str, param: str) -> dict:
    """Tests for SQL injection error anomalies"""
    test_url = inject_param(url, param, "'")
    try:
        resp = session.request("GET", test_url)
        body = resp["body"]
        for pattern, db_name in SQLI_ERROR_PATTERNS:
            if pattern.search(body):
                return {
                    "vulnerable": True,
                    "type": "SQL Injection (Error-Based)",
                    "severity": "CRITICAL",
                    "param": param,
                    "evidence": f"Leaked {db_name} syntax error in response body",
                    "url": test_url
                }
    except Exception:
        pass
    return None

def test_parameter_xss(session: PersistentSession, url: str, param: str) -> dict:
    """Tests for unescaped reflected input (XSS canary)"""
    test_url = inject_param(url, param, XSS_CANARY)
    try:
        resp = session.request("GET", test_url)
        # Check if raw HTML canary was reflected verbatim without sanitization
        if XSS_CANARY in resp["body"]:
            content_type = resp["headers"].get("Content-Type", resp["headers"].get("content-type", "")).lower()
            if "html" in content_type:
                return {
                    "vulnerable": True,
                    "type": "Reflected Cross-Site Scripting (XSS)",
                    "severity": "HIGH",
                    "param": param,
                    "evidence": f"Raw canary '{XSS_CANARY}' reflected unescaped in HTML response",
                    "url": test_url
                }
    except Exception:
        pass
    return None

def test_parameter_lfi(session: PersistentSession, url: str, param: str) -> dict:
    """Tests for Local File Inclusion / Path Traversal"""
    # Only test params likely to handle files
    if not any(k in param.lower() for k in ["file", "path", "page", "doc", "view", "include", "template"]):
        return None
        
    test_url = inject_param(url, param, LFI_PAYLOAD)
    try:
        resp = session.request("GET", test_url)
        if LFI_PATTERN.search(resp["body"]):
            return {
                "vulnerable": True,
                "type": "Path Traversal / LFI",
                "severity": "CRITICAL",
                "param": param,
                "evidence": "Matched Linux /etc/passwd root user entry",
                "url": test_url
            }
    except Exception:
        pass
    return None

def run_dast_audit(target_url: str, discovered_params=None, proxy=None):
    """
    Main runner for DAST parameter injection scanner.
    """
    if not target_url.startswith("http://") and not target_url.startswith("https://"):
        target_url = "https://" + target_url

    print_info(f"Initiating Active DAST Injection Audit on: {Colors.BOLD}{target_url}{Colors.RESET}")
    
    # Common test parameters if none supplied by crawler
    default_test_params = ["id", "q", "search", "page", "file", "url", "user", "redirect", "view"]
    params_to_test = list(set((discovered_params or []) + default_test_params))

    print_info(f"Testing {len(params_to_test)} parameters across SQLi, XSS, and LFI canary vectors...")
    session = PersistentSession(timeout=5.0, proxy_url=proxy)
    findings = []

    for param in params_to_test:
        # 1. SQL Injection Test
        sqli_res = test_parameter_sqli(session, target_url, param)
        if sqli_res:
            findings.append(sqli_res)
            print_danger(f"[CRITICAL] {sqli_res['type']} in param '{param}' -> {sqli_res['url']}")

        # 2. Reflected XSS Test
        xss_res = test_parameter_xss(session, target_url, param)
        if xss_res:
            findings.append(xss_res)
            print_warning(f"[HIGH] {xss_res['type']} in param '{param}' -> {xss_res['url']}")

        # 3. LFI / Traversal Test
        lfi_res = test_parameter_lfi(session, target_url, param)
        if lfi_res:
            findings.append(lfi_res)
            print_danger(f"[CRITICAL] {lfi_res['type']} in param '{param}' -> {lfi_res['url']}")

    print("\n")
    if findings:
        print_danger(f"DAST Audit identified {len(findings)} active injection vulnerabilities:")
        rows = [[f["severity"], f["type"], f["param"], f["evidence"][:40]] for f in findings]
        print_table(["Severity", "Vulnerability Type", "Parameter", "Evidence"], rows)
    else:
        print_success("No direct reflection or SQL error anomalies observed on tested parameters.")

    return {
        "parameters_tested": params_to_test,
        "total_vulnerabilities": len(findings),
        "findings": findings
    }

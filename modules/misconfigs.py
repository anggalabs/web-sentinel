"""
Common Web Misconfigurations Module (CORS, Clickjacking, Insecure Transport).
"""

import ssl
import urllib.request
from core.ui import print_info, print_success, print_warning, print_danger, print_table, Colors
from core.config import DEFAULT_USER_AGENT, DEFAULT_TIMEOUT

def test_cors(url: str, ctx: ssl.SSLContext) -> dict:
    """Test for permissive or origin-reflecting CORS headers"""
    test_origin = "https://evil-attacker.com"
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": DEFAULT_USER_AGENT,
            "Origin": test_origin
        }
    )
    try:
        with urllib.request.urlopen(req, timeout=DEFAULT_TIMEOUT, context=ctx) as resp:
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "")
            
            if acao == test_origin and acac.lower() == "true":
                return {
                    "vulnerable": True,
                    "severity": "HIGH",
                    "detail": f"Arbitrary Origin reflection ({test_origin}) with credentials enabled!"
                }
            elif acao == "*":
                return {
                    "vulnerable": False,
                    "severity": "INFO",
                    "detail": "Public wildcard (*) allowed (Standard for public APIs without credentials)."
                }
            elif acao == test_origin:
                return {
                    "vulnerable": True,
                    "severity": "MEDIUM",
                    "detail": f"Origin reflected without explicit credentials flag."
                }
    except Exception as e:
        return {"vulnerable": False, "severity": "ERROR", "detail": str(e)}
        
    return {"vulnerable": False, "severity": "SECURE", "detail": "Origin not reflected or CORS disabled."}

def test_clickjacking(url: str, ctx: ssl.SSLContext) -> dict:
    """Test if page can be framed (Clickjacking)"""
    req = urllib.request.Request(url, headers={"User-Agent": DEFAULT_USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=DEFAULT_TIMEOUT, context=ctx) as resp:
            xfo = resp.headers.get("X-Frame-Options", "").upper()
            csp = resp.headers.get("Content-Security-Policy", "").lower()
            
            has_csp_frame = "frame-ancestors" in csp
            has_xfo = xfo in ["DENY", "SAMEORIGIN"]
            
            if not has_xfo and not has_csp_frame:
                return {
                    "vulnerable": True,
                    "severity": "MEDIUM",
                    "detail": "Missing X-Frame-Options and CSP frame-ancestors. Site may be frameable."
                }
            else:
                protection = f"XFO: {xfo}" if has_xfo else "CSP frame-ancestors"
                return {
                    "vulnerable": False,
                    "severity": "SECURE",
                    "detail": f"Protected via {protection}."
                }
    except Exception as e:
        return {"vulnerable": False, "severity": "ERROR", "detail": str(e)}

def run_misconfig_auditor(url: str):
    """
    Main runner for Web Misconfiguration Checks.
    """
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    print_info(f"Auditing common misconfigurations for: {Colors.BOLD}{url}{Colors.RESET}")
    
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    print_info("Testing CORS (Cross-Origin Resource Sharing)...")
    cors_res = test_cors(url, ctx)
    
    print_info("Testing Clickjacking frame protection...")
    click_res = test_clickjacking(url, ctx)

    results_table = [
        ["CORS Reflection", cors_res["severity"], cors_res["detail"]],
        ["Clickjacking Check", click_res["severity"], click_res["detail"]]
    ]
    
    print("\n")
    print_table(["Test Name", "Verdict", "Observation"], results_table)
    
    return {
        "cors": cors_res,
        "clickjacking": click_res
    }

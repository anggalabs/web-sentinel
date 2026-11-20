"""
Security Headers & Technology Stack Fingerprinting Module.
"""

import ssl
import urllib.request
from core.ui import print_info, print_success, print_warning, print_danger, print_table, Colors
from core.config import DEFAULT_USER_AGENT, DEFAULT_TIMEOUT

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "desc": "Forces HTTPS connections (HSTS)",
        "recommendation": "max-age=31536000; includeSubDomains; preload"
    },
    "Content-Security-Policy": {
        "desc": "Mitigates XSS and data injection",
        "recommendation": "Define trusted script sources"
    },
    "X-Frame-Options": {
        "desc": "Mitigates Clickjacking attacks",
        "recommendation": "DENY or SAMEORIGIN"
    },
    "X-Content-Type-Options": {
        "desc": "Prevents MIME-type sniffing",
        "recommendation": "nosniff"
    },
    "Referrer-Policy": {
        "desc": "Controls referrer information leakage",
        "recommendation": "strict-origin-when-cross-origin"
    },
    "Permissions-Policy": {
        "desc": "Controls browser features (camera, mic, etc.)",
        "recommendation": "Restrict unused sensors and APIs"
    }
}

TECH_SIGNATURES = {
    "Cloudflare": ["cf-ray", "cloudflare"],
    "Nginx": ["nginx"],
    "Apache": ["apache"],
    "LiteSpeed": ["litespeed"],
    "IIS / ASP.NET": ["iis", "asp.net", "x-aspnet-version"],
    "PHP": ["php", "x-powered-by: php"],
    "WordPress": ["wp-content", "wp-includes", "wordpress"],
    "Laravel": ["laravel_session", "x-powered-by: laravel"],
    "Django": ["csrftoken", "django"],
    "Node.js / Express": ["x-powered-by: express"],
    "Next.js": ["__next", "_next/static"]
}

def analyze_headers_and_tech(url: str):
    """
    Fetches headers and page content to analyze missing security headers
    and identify tech stack components.
    """
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    print_info(f"Auditing Security Headers & Tech for: {Colors.BOLD}{url}{Colors.RESET}")
    
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    
    req = urllib.request.Request(
        url,
        headers={"User-Agent": DEFAULT_USER_AGENT}
    )
    
    try:
        with urllib.request.urlopen(req, timeout=DEFAULT_TIMEOUT, context=ctx) as response:
            headers = dict(response.info())
            body = response.read(65536).decode('utf-8', errors='ignore')
    except Exception as e:
        print_danger(f"Failed to connect to {url}: {e}")
        return {"error": str(e)}

    # 1. Audit Security Headers
    header_rows = []
    missing_count = 0
    headers_lower = {k.lower(): v for k, v in headers.items()}
    
    for sec_header, meta in SECURITY_HEADERS.items():
        val = headers_lower.get(sec_header.lower())
        if val:
            status = f"{Colors.GREEN}PASS{Colors.RESET}"
            val_display = (val[:30] + "...") if len(val) > 30 else val
        else:
            status = f"{Colors.RED}MISSING{Colors.RESET}"
            val_display = meta["recommendation"]
            missing_count += 1
        header_rows.append([sec_header, status, val_display])

    print("\n")
    print_table(["Security Header", "Status", "Value / Recommendation"], header_rows)

    # 2. Technology Stack Fingerprint
    detected_tech = []
    combined_raw = (str(headers) + "\n" + body).lower()
    
    for tech_name, signatures in TECH_SIGNATURES.items():
        for sig in signatures:
            if sig.lower() in combined_raw:
                detected_tech.append(tech_name)
                break
                
    server_header = headers.get("Server", headers.get("server", "Not Disclosed"))
    powered_by = headers.get("X-Powered-By", headers.get("x-powered-by", "Not Disclosed"))
    
    print("\n")
    print_info(f"Server Banner : {Colors.CYAN}{server_header}{Colors.RESET}")
    print_info(f"X-Powered-By  : {Colors.CYAN}{powered_by}{Colors.RESET}")
    if detected_tech:
        print_success(f"Detected Tech : {Colors.GREEN}{', '.join(detected_tech)}{Colors.RESET}")
    else:
        print_info("No specific frameworks detected in signatures.")

    return {
        "server": server_header,
        "x_powered_by": powered_by,
        "missing_headers_count": missing_count,
        "detected_technologies": detected_tech,
        "headers_audit": {row[0]: row[1] for row in header_rows}
    }

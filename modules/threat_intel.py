"""
Threat Intelligence & Known CVE Hunter Module.
Integrates Shodan InternetDB (Zero-Auth) & OSV.dev Database to detect open attack surfaces and known CVEs.
"""

import socket
import json
import urllib.request
from core.ui import print_info, print_success, print_warning, print_danger, print_table, Colors
from core.config import DEFAULT_USER_AGENT, DEFAULT_TIMEOUT

def query_shodan_internetdb(ip: str) -> dict:
    """
    Queries Shodan InternetDB API for open ports, hostnames, tags, and known CVEs.
    No API key required.
    """
    url = f"https://internetdb.shodan.io/{ip}"
    req = urllib.request.Request(
        url,
        headers={"User-Agent": DEFAULT_USER_AGENT, "Accept": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=DEFAULT_TIMEOUT) as resp:
            if resp.status == 200:
                return json.loads(resp.read().decode('utf-8'))
    except Exception:
        pass
    return None

def query_osv_cve(package_name: str, version: str, ecosystem: str = "PyPI") -> list:
    """
    Queries Open Source Vulnerabilities (OSV.dev) database for known CVEs.
    """
    url = "https://api.osv.dev/v1/query"
    payload = json.dumps({
        "package": {"name": package_name, "ecosystem": ecosystem},
        "version": version
    }).encode("utf-8")
    
    req = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json", "User-Agent": DEFAULT_USER_AGENT}
    )
    
    cves = []
    try:
        with urllib.request.urlopen(req, timeout=DEFAULT_TIMEOUT) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            for vuln in data.get("vulns", [])[:10]: # Top 10 vulnerabilities
                vuln_id = vuln.get("id", "Unknown")
                summary = vuln.get("summary", "No description provided")
                cves.append({"id": vuln_id, "summary": summary})
    except Exception:
        pass
    return cves

def run_threat_intel_hunter(target_host: str, detected_versions=None):
    """
    Main runner for Threat Intelligence and CVE hunting.
    """
    print_info(f"Gathering Threat Intelligence for: {Colors.BOLD}{target_host}{Colors.RESET}")
    
    try:
        target_ip = socket.gethostbyname(target_host)
        print_success(f"Resolved IP Address: {Colors.CYAN}{target_ip}{Colors.RESET}")
    except socket.gaierror as e:
        print_danger(f"Failed to resolve {target_host}: {e}")
        return {"error": str(e)}

    # 1. Shodan InternetDB Lookup
    print_info("Querying Shodan InternetDB (Global attack surface cache)...")
    shodan_data = query_shodan_internetdb(target_ip)
    
    cve_findings = []
    shodan_ports = []
    cpes = []
    
    if shodan_data:
        shodan_ports = shodan_data.get("ports", [])
        cpes = shodan_data.get("cpes", [])
        vulns = shodan_data.get("vulns", [])
        
        print_success(f"Shodan Discovered Ports: {Colors.GREEN}{', '.join(map(str, shodan_ports)) or 'None'}{Colors.RESET}")
        if cpes:
            print_info(f"Identified Software CPEs: {Colors.CYAN}{', '.join(cpes)}{Colors.RESET}")
            
        if vulns:
            print_danger(f"Shodan Flagged {len(vulns)} Known Vulnerabilities / CVEs:")
            for v in vulns[:10]:
                print_danger(f" - {v}")
                cve_findings.append({"source": "Shodan InternetDB", "cve": v, "detail": "Observed on target IP"})
        else:
            print_success("No historical CVEs flagged on Shodan for this IP.")
    else:
        print_info("No existing records found in Shodan InternetDB cache for this IP.")

    # 2. OSV.dev CVE Lookup for Detected Tech
    if detected_versions and isinstance(detected_versions, dict):
        print_info("Cross-referencing detected software versions with OSV.dev database...")
        for pkg, ver in detected_versions.items():
            found_cves = query_osv_cve(pkg, ver)
            if found_cves:
                print_danger(f"Found {len(found_cves)} CVEs for {pkg} v{ver}:")
                for c in found_cves[:5]:
                    print_warning(f"   [{c['id']}] {c['summary']}")
                    cve_findings.append({"source": f"{pkg} v{ver}", "cve": c["id"], "detail": c["summary"]})

    # Display Summary Table
    if cve_findings:
        rows = [[f["source"], f["cve"], (f["detail"][:50] + "...") if len(f["detail"]) > 50 else f["detail"]] for f in cve_findings]
        print("\n")
        print_table(["Source", "CVE / Advisory", "Summary"], rows)

    return {
        "ip": target_ip,
        "shodan_ports": shodan_ports,
        "cpes": cpes,
        "cve_count": len(cve_findings),
        "cve_list": [f"{f['source']}: {f['cve']} - {f['detail']}" for f in cve_findings]
    }

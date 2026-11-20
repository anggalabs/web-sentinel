"""
Subdomain Enumeration Module (Passive via crt.sh + Active DNS resolution).
"""

import socket
import ssl
import json
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.ui import print_info, print_success, print_warning, print_table, Colors
from core.config import BUILTIN_SUBDOMAINS, DEFAULT_TIMEOUT

def fetch_crtsh_subdomains(domain: str) -> set:
    """Fetch subdomains from Certificate Transparency logs via crt.sh"""
    subdomains = set()
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "WebSentinel/1.0", "Accept": "application/json"}
    )
    
    # Ignore SSL validation errors if local cert store is outdated
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
            if resp.status == 200:
                data = json.loads(resp.read().decode('utf-8', errors='ignore'))
                for entry in data:
                    name_value = entry.get("name_value", "")
                    for sub in name_value.split("\n"):
                        sub = sub.strip().lower()
                        if sub.endswith(domain) and not "*" in sub:
                            subdomains.add(sub)
    except Exception as e:
        print_warning(f"Passive lookup via crt.sh failed or timed out: {e}")
        
    return subdomains

def resolve_subdomain(subdomain: str):
    """Test if a subdomain resolves to an IP address"""
    try:
        ip = socket.gethostbyname(subdomain)
        return (subdomain, ip)
    except (socket.gaierror, socket.timeout):
        return None

def run_subdomain_scanner(domain: str, wordlist=None, threads=15):
    """
    Main runner for subdomain enumeration.
    Combines passive CT logs and active wordlist brute-force.
    """
    print_info(f"Starting Subdomain Discovery for: {Colors.BOLD}{domain}{Colors.RESET}")
    
    # 1. Passive Reconnaissance
    print_info("Querying Certificate Transparency logs (crt.sh)...")
    found_passive = fetch_crtsh_subdomains(domain)
    if found_passive:
        print_success(f"Discovered {len(found_passive)} subdomains from CT logs.")
    else:
        print_info("No subdomains found in CT logs or query skipped.")

    # 2. Active Brute-Force Candidate List
    candidate_list = list(found_passive)
    brute_list = wordlist if wordlist else BUILTIN_SUBDOMAINS
    for sub in brute_list:
        fqdn = f"{sub}.{domain}".lower()
        if fqdn not in candidate_list:
            candidate_list.append(fqdn)
            
    print_info(f"Resolving {len(candidate_list)} potential subdomains with {threads} threads...")
    
    active_results = []
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(resolve_subdomain, sub): sub for sub in candidate_list}
        for future in as_completed(futures):
            res = future.result()
            if res:
                active_results.append(res)
                
    active_results.sort(key=lambda x: x[0])
    
    # Display table
    table_rows = [[sub, ip] for sub, ip in active_results]
    print_success(f"Found {len(active_results)} active subdomains:")
    print_table(["Subdomain", "Resolved IP"], table_rows)
    
    return {
        "total_active": len(active_results),
        "subdomains": [f"{sub} ({ip})" for sub, ip in active_results]
    }

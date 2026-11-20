#!/usr/bin/env python3
"""
Web-Sentinel: Industry-Grade Web Reconnaissance & Vulnerability Audit Toolkit.
Main entry point offering an interactive CLI menu or command-line flags.
Supports Custom Wordlists, Upstream Proxy (Burp/ZAP), Web Spidering, and Active DAST Injection.
"""

import sys
import os
import argparse
from urllib.parse import urlparse

# Add current folder to sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.ui import banner, print_header, print_info, print_success, print_warning, print_danger, Colors
from core.reporter import Reporter
from modules.subdomains import run_subdomain_scanner
from modules.ports import run_port_scanner
from modules.headers_tech import analyze_headers_and_tech
from modules.fuzzer import run_directory_fuzzer
from modules.misconfigs import run_misconfig_auditor
from modules.templates_scanner import run_template_scanner
from modules.threat_intel import run_threat_intel_hunter
from modules.crawler import run_web_crawler
from modules.dast_scanner import run_dast_audit

def clean_target(target_input: str):
    """Extract domain and full URL safely"""
    target_input = target_input.strip()
    if not target_input.startswith("http://") and not target_input.startswith("https://"):
        url = "https://" + target_input
    else:
        url = target_input
        
    parsed = urlparse(url)
    domain = parsed.hostname or parsed.path.split("/")[0]
    return domain, url

def interactive_menu(proxy=None, wordlist=None):
    banner()
    
    target_raw = input(f"{Colors.BOLD}Masukkan Target Domain/URL (contoh: example.com): {Colors.RESET}").strip()
    if not target_raw:
        print_danger("Target tidak boleh kosong. Keluar.")
        sys.exit(1)
        
    domain, url = clean_target(target_raw)
    reporter = Reporter(target=domain)
    detected_tech = []
    discovered_params = []
    
    while True:
        print(f"\n{Colors.CYAN}{'━' * 68}{Colors.RESET}")
        proxy_info = f" | Proxy: {Colors.YELLOW}{proxy}{Colors.RESET}" if proxy else ""
        wl_info = f" | Wordlist: {Colors.YELLOW}{wordlist}{Colors.RESET}" if wordlist else ""
        print(f"Target: {Colors.GREEN}{Colors.BOLD}{domain}{Colors.RESET} ({url}){proxy_info}{wl_info}")
        print(f"{Colors.CYAN}{'━' * 68}{Colors.RESET}")
        print(f" {Colors.BOLD}[1]{Colors.RESET} Subdomain Enumeration (Passive CT Logs + DNS Resolution)")
        print(f" {Colors.BOLD}[2]{Colors.RESET} Open Ports & Service Scanner (Top Web & Infra Ports)")
        print(f" {Colors.BOLD}[3]{Colors.RESET} Security Headers & Tech Stack Fingerprinting")
        print(f" {Colors.BOLD}[4]{Colors.RESET} Web Spider & Crawler (Extract HTML/JS Links, Forms, APIs)")
        print(f" {Colors.BOLD}[5]{Colors.RESET} Sensitive Files & Directory Fuzzer (Keep-Alive Accelerated)")
        print(f" {Colors.BOLD}[6]{Colors.RESET} Web Misconfiguration Audit (CORS, Clickjacking)")
        print(f" {Colors.BOLD}[7]{Colors.RESET} {Colors.RED}{Colors.BOLD}Critical & High Vulnerability Scanner (Template Rules){Colors.RESET}")
        print(f" {Colors.BOLD}[8]{Colors.RESET} {Colors.MAGENTA}Threat Intelligence & CVE Hunter (Shodan + OSV.dev){Colors.RESET}")
        print(f" {Colors.BOLD}[9]{Colors.RESET} {Colors.RED}Active DAST Injection Audit (XSS Canary, SQLi, LFI){Colors.RESET}")
        print(f" {Colors.BOLD}[10]{Colors.RESET} {Colors.YELLOW}Full Automated Pipeline (Jalankan Semua Modul 1-9){Colors.RESET}")
        print(f" {Colors.BOLD}[11]{Colors.RESET} Konfigurasi Upstream Proxy (Burp Suite / OWASP ZAP)")
        print(f" {Colors.BOLD}[12]{Colors.RESET} Simpan Laporan Hasil Scan (Markdown & JSON)")
        print(f" {Colors.BOLD}[0]{Colors.RESET} Keluar")
        print(f"{Colors.CYAN}{'━' * 68}{Colors.RESET}")
        
        choice = input(f"{Colors.BOLD}Pilih opsi [0-12]: {Colors.RESET}").strip()
        
        if choice == "1":
            print_header("MODUL 1: SUBDOMAIN ENUMERATION")
            res = run_subdomain_scanner(domain)
            reporter.add_result("Subdomain Enumeration", res)
            
        elif choice == "2":
            print_header("MODUL 2: PORT & SERVICE SCANNER")
            res = run_port_scanner(domain)
            reporter.add_result("Port Scanner", res)
            
        elif choice == "3":
            print_header("MODUL 3: SECURITY HEADERS & TECH STACK")
            res = analyze_headers_and_tech(url)
            if "detected_technologies" in res:
                detected_tech = res["detected_technologies"]
            reporter.add_result("Security Headers & Tech", res)

        elif choice == "4":
            print_header("MODUL 4: WEB SPIDER & CRAWLER")
            c_res = run_web_crawler(url, proxy=proxy)
            discovered_params = c_res.get("parameters", [])
            reporter.add_result("Web Crawler", c_res)
            
        elif choice == "5":
            print_header("MODUL 5: SENSITIVE FILES & DIRECTORY FUZZER")
            res = run_directory_fuzzer(url, custom_wordlist_path=wordlist, detected_tech=detected_tech, proxy=proxy)
            reporter.add_result("Directory Fuzzer", res)
            
        elif choice == "6":
            print_header("MODUL 6: WEB MISCONFIGURATION AUDIT")
            res = run_misconfig_auditor(url)
            reporter.add_result("Misconfiguration Audit", res)
            
        elif choice == "7":
            print_header("MODUL 7: TEMPLATE VULNERABILITY AUDIT (CRITICAL/HIGH)")
            res = run_template_scanner(url)
            reporter.add_result("Template Vulnerability Audit", res)
            
        elif choice == "8":
            print_header("MODUL 8: THREAT INTELLIGENCE & CVE HUNTER")
            res = run_threat_intel_hunter(domain)
            reporter.add_result("Threat Intelligence & CVE Hunter", res)

        elif choice == "9":
            print_header("MODUL 9: ACTIVE DAST INJECTION AUDIT")
            res = run_dast_audit(url, discovered_params=discovered_params, proxy=proxy)
            reporter.add_result("DAST Injection Audit", res)
            
        elif choice == "10":
            print_header("MENJALANKAN FULL AUTOMATED PIPELINE (1-9)")
            reporter.add_result("Subdomain Enumeration", run_subdomain_scanner(domain))
            reporter.add_result("Port Scanner", run_port_scanner(domain))
            h_res = analyze_headers_and_tech(url)
            reporter.add_result("Security Headers & Tech", h_res)
            dt = h_res.get("detected_technologies", [])
            
            c_res = run_web_crawler(url, proxy=proxy)
            reporter.add_result("Web Crawler", c_res)
            d_params = c_res.get("parameters", [])
            
            reporter.add_result("Directory Fuzzer", run_directory_fuzzer(url, custom_wordlist_path=wordlist, detected_tech=dt, proxy=proxy))
            reporter.add_result("Misconfiguration Audit", run_misconfig_auditor(url))
            reporter.add_result("Template Vulnerability Audit", run_template_scanner(url))
            reporter.add_result("Threat Intelligence & CVE Hunter", run_threat_intel_hunter(domain))
            reporter.add_result("DAST Injection Audit", run_dast_audit(url, discovered_params=d_params, proxy=proxy))
            
            md_path = reporter.save_markdown()
            json_path = reporter.save_json()
            print_success(f"Full automated pipeline selesai! Laporan tersimpan di:\n   - {md_path}\n   - {json_path}")

        elif choice == "11":
            p_in = input(f"Masukkan URL Proxy (contoh: http://127.0.0.1:8080, kosongkan untuk nonaktifkan): ").strip()
            proxy = p_in if p_in else None
            print_success(f"Proxy disetel ke: {proxy or 'Dinonaktifkan (Direct)'}")
            
        elif choice == "12":
            md_path = reporter.save_markdown()
            json_path = reporter.save_json()
            print_success(f"Laporan berhasil diekspor ke:\n   - {md_path}\n   - {json_path}")
            
        elif choice == "0":
            print_info("Terima kasih telah menggunakan Web-Sentinel. Happy Hacking!")
            break
        else:
            print_warning("Pilihan tidak valid, silakan masukkan angka 0-12.")

def main():
    parser = argparse.ArgumentParser(description="Web-Sentinel: Industry-Grade Web Recon & Vulnerability Toolkit")
    parser.add_argument("-t", "--target", help="Target domain atau URL (contoh: example.com)")
    parser.add_argument("--all", action="store_true", help="Jalankan seluruh modul secara otomatis (Pipeline Mode)")
    parser.add_argument("-m", "--modules", help="Pilih modul spesifik (contoh: 1,2 atau 4,9)")
    parser.add_argument("-w", "--wordlist", help="Path ke custom wordlist untuk directory fuzzing")
    parser.add_argument("-p", "--proxy", help="Upstream HTTP Proxy URL (contoh: http://127.0.0.1:8080)")
    args = parser.parse_args()
    
    if not args.target:
        interactive_menu(proxy=args.proxy, wordlist=args.wordlist)
    else:
        banner()
        domain, url = clean_target(args.target)
        reporter = Reporter(target=domain)
        
        selected = args.modules.split(",") if args.modules else []
        detected_tech = []
        discovered_params = []
        
        if args.all or "1" in selected:
            reporter.add_result("Subdomain Enumeration", run_subdomain_scanner(domain))
        if args.all or "2" in selected:
            reporter.add_result("Port Scanner", run_port_scanner(domain))
        if args.all or "3" in selected:
            h_res = analyze_headers_and_tech(url)
            detected_tech = h_res.get("detected_technologies", [])
            reporter.add_result("Security Headers & Tech", h_res)
        if args.all or "4" in selected:
            c_res = run_web_crawler(url, proxy=args.proxy)
            discovered_params = c_res.get("parameters", [])
            reporter.add_result("Web Crawler", c_res)
        if args.all or "5" in selected:
            reporter.add_result("Directory Fuzzer", run_directory_fuzzer(url, custom_wordlist_path=args.wordlist, detected_tech=detected_tech, proxy=args.proxy))
        if args.all or "6" in selected:
            reporter.add_result("Misconfiguration Audit", run_misconfig_auditor(url))
        if args.all or "7" in selected:
            reporter.add_result("Template Vulnerability Audit", run_template_scanner(url))
        if args.all or "8" in selected:
            reporter.add_result("Threat Intelligence & CVE Hunter", run_threat_intel_hunter(domain))
        if args.all or "9" in selected:
            reporter.add_result("DAST Injection Audit", run_dast_audit(url, discovered_params=discovered_params, proxy=args.proxy))
            
        md_file = reporter.save_markdown()
        json_file = reporter.save_json()
        print_success(f"Audit selesai. Laporan tersimpan di: {md_file} & {json_file}")

if __name__ == "__main__":
    main()

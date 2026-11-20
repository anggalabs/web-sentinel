#!/usr/bin/env python3
"""
Web-Sentinel: All-in-One Web Reconnaissance & Vulnerability Audit Toolkit.
Main entry point offering an interactive CLI menu or command-line flags.
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

def interactive_menu():
    banner()
    
    target_raw = input(f"{Colors.BOLD}Masukkan Target Domain/URL (contoh: example.com): {Colors.RESET}").strip()
    if not target_raw:
        print_danger("Target tidak boleh kosong. Keluar.")
        sys.exit(1)
        
    domain, url = clean_target(target_raw)
    reporter = Reporter(target=domain)
    detected_tech = []
    
    while True:
        print(f"\n{Colors.CYAN}{'━' * 62}{Colors.RESET}")
        print(f"Target Aktif: {Colors.GREEN}{Colors.BOLD}{domain}{Colors.RESET} ({url})")
        print(f"{Colors.CYAN}{'━' * 62}{Colors.RESET}")
        print(f" {Colors.BOLD}[1]{Colors.RESET} Subdomain Enumeration (Passive CT Logs + DNS Resolution)")
        print(f" {Colors.BOLD}[2]{Colors.RESET} Open Ports & Service Scanner (Top Web & Infra Ports)")
        print(f" {Colors.BOLD}[3]{Colors.RESET} Security Headers & Tech Stack Fingerprinting")
        print(f" {Colors.BOLD}[4]{Colors.RESET} Sensitive Files & Directory Fuzzer (Keep-Alive Accelerated)")
        print(f" {Colors.BOLD}[5]{Colors.RESET} Web Misconfiguration Audit (CORS, Clickjacking)")
        print(f" {Colors.BOLD}[6]{Colors.RESET} {Colors.RED}{Colors.BOLD}Critical & High Vulnerability Scanner (Template Rules){Colors.RESET}")
        print(f" {Colors.BOLD}[7]{Colors.RESET} {Colors.YELLOW}Full Automated Audit (Jalankan Semua Opsi Sekaligus){Colors.RESET}")
        print(f" {Colors.BOLD}[8]{Colors.RESET} Simpan Laporan Hasil Scan (Markdown & JSON)")
        print(f" {Colors.BOLD}[0]{Colors.RESET} Keluar")
        print(f"{Colors.CYAN}{'━' * 62}{Colors.RESET}")
        
        choice = input(f"{Colors.BOLD}Pilih opsi [0-8]: {Colors.RESET}").strip()
        
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
            print_header("MODUL 4: SENSITIVE FILES & DIRECTORY FUZZER")
            res = run_directory_fuzzer(url, detected_tech=detected_tech)
            reporter.add_result("Directory Fuzzer", res)
            
        elif choice == "5":
            print_header("MODUL 5: WEB MISCONFIGURATION AUDIT")
            res = run_misconfig_auditor(url)
            reporter.add_result("Misconfiguration Audit", res)
            
        elif choice == "6":
            print_header("MODUL 6: TEMPLATE VULNERABILITY AUDIT (CRITICAL/HIGH)")
            res = run_template_scanner(url)
            reporter.add_result("Template Vulnerability Audit", res)
            
        elif choice == "7":
            print_header("MENJALANKAN FULL AUTOMATED AUDIT")
            reporter.add_result("Subdomain Enumeration", run_subdomain_scanner(domain))
            reporter.add_result("Port Scanner", run_port_scanner(domain))
            h_res = analyze_headers_and_tech(url)
            reporter.add_result("Security Headers & Tech", h_res)
            dt = h_res.get("detected_technologies", [])
            reporter.add_result("Directory Fuzzer", run_directory_fuzzer(url, detected_tech=dt))
            reporter.add_result("Misconfiguration Audit", run_misconfig_auditor(url))
            reporter.add_result("Template Vulnerability Audit", run_template_scanner(url))
            
            md_path = reporter.save_markdown()
            json_path = reporter.save_json()
            print_success(f"Full audit selesai! Laporan tersimpan di:\n   - {md_path}\n   - {json_path}")
            
        elif choice == "8":
            md_path = reporter.save_markdown()
            json_path = reporter.save_json()
            print_success(f"Laporan berhasil diekspor ke:\n   - {md_path}\n   - {json_path}")
            
        elif choice == "0":
            print_info("Terima kasih telah menggunakan Web-Sentinel. Sampai jumpa!")
            break
        else:
            print_warning("Pilihan tidak valid, silakan masukkan angka 0-8.")

def main():
    parser = argparse.ArgumentParser(description="Web-Sentinel: All-in-One Web Recon & Vulnerability Toolkit")
    parser.add_argument("-t", "--target", help="Target domain atau URL (contoh: example.com)")
    parser.add_argument("--all", action="store_true", help="Jalankan semua modul pemindaian secara otomatis")
    parser.add_argument("-m", "--modules", help="Pilih modul spesifik (contoh: 1,2 atau 3,6)")
    args = parser.parse_args()
    
    if not args.target:
        interactive_menu()
    else:
        banner()
        domain, url = clean_target(args.target)
        reporter = Reporter(target=domain)
        
        selected = args.modules.split(",") if args.modules else []
        detected_tech = []
        
        if args.all or "1" in selected:
            reporter.add_result("Subdomain Enumeration", run_subdomain_scanner(domain))
        if args.all or "2" in selected:
            reporter.add_result("Port Scanner", run_port_scanner(domain))
        if args.all or "3" in selected:
            h_res = analyze_headers_and_tech(url)
            detected_tech = h_res.get("detected_technologies", [])
            reporter.add_result("Security Headers & Tech", h_res)
        if args.all or "4" in selected:
            reporter.add_result("Directory Fuzzer", run_directory_fuzzer(url, detected_tech=detected_tech))
        if args.all or "5" in selected:
            reporter.add_result("Misconfiguration Audit", run_misconfig_auditor(url))
        if args.all or "6" in selected:
            reporter.add_result("Template Vulnerability Audit", run_template_scanner(url))
            
        md_file = reporter.save_markdown()
        json_file = reporter.save_json()
        print_success(f"Audit selesai. Laporan tersimpan di: {md_file} & {json_file}")

if __name__ == "__main__":
    main()

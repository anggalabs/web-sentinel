"""
Template-Based Vulnerability Scanner Engine.
Loads detection templates (JSON/YAML) and executes them using persistent HTTP sessions.
"""

import os
import json
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.http_client import PersistentSession
from core.ui import print_info, print_success, print_warning, print_danger, print_table, Colors

def load_templates(templates_dir=None):
    """Load all detection template definitions from templates folder"""
    if not templates_dir:
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        templates_dir = os.path.join(base_dir, "templates")
        
    templates = []
    if not os.path.exists(templates_dir):
        return templates
        
    for fname in os.listdir(templates_dir):
        if fname.endswith(".json"):
            path = os.path.join(templates_dir, fname)
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    templates.append(data)
            except Exception:
                pass
    return templates

def evaluate_template(session: PersistentSession, base_url: str, template: dict):
    """
    Executes request defined in template and evaluates matchers.
    Returns finding dict if vulnerable, None otherwise.
    """
    req_meta = template.get("request", {})
    method = req_meta.get("method", "GET")
    path = req_meta.get("path", "/")
    target_url = urljoin(base_url, path)
    
    try:
        resp = session.request(method, target_url, headers=req_meta.get("headers"))
    except Exception:
        return None

    # Evaluate matchers
    matchers = template.get("matchers", [])
    all_matched = True
    
    for matcher in matchers:
        mtype = matcher.get("type")
        if mtype == "status":
            allowed_statuses = matcher.get("values", [200])
            if resp["status"] not in allowed_statuses:
                all_matched = False
                break
        elif mtype == "word":
            cond = matcher.get("condition", "or")
            words = matcher.get("words", [])
            body = resp["body"]
            
            if cond == "or":
                if not any(w in body for w in words):
                    all_matched = False
                    break
            elif cond == "and":
                if not all(w in body for w in words):
                    all_matched = False
                    break

    if all_matched:
        return {
            "id": template.get("id"),
            "name": template.get("name"),
            "severity": template.get("severity", "MEDIUM"),
            "category": template.get("category", "General"),
            "path": path,
            "url": target_url,
            "description": template.get("description", "")
        }
    return None

def run_template_scanner(base_url: str, threads=15):
    """
    Main runner for Template Vulnerability Scanner.
    """
    if not base_url.startswith("http://") and not base_url.startswith("https://"):
        base_url = "https://" + base_url
    if not base_url.endswith("/"):
        base_url += "/"

    templates = load_templates()
    print_info(f"Loaded {len(templates)} security templates.")
    print_info(f"Executing Template Vulnerability Audit on: {Colors.BOLD}{base_url}{Colors.RESET}")
    
    session = PersistentSession(timeout=5.0)
    findings = []
    
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(evaluate_template, session, base_url, tmpl): tmpl
            for tmpl in templates
        }
        for future in as_completed(futures):
            res = future.result()
            if res:
                findings.append(res)
                sev = res["severity"]
                if sev == "CRITICAL":
                    print_danger(f"[{sev}] {res['name']} -> {res['url']}")
                elif sev == "HIGH":
                    print_warning(f"[{sev}] {res['name']} -> {res['url']}")
                else:
                    print_info(f"[{sev}] {res['name']} -> {res['url']}")

    findings.sort(key=lambda x: (0 if x["severity"] == "CRITICAL" else 1 if x["severity"] == "HIGH" else 2))
    
    table_rows = []
    for f in findings:
        sev_color = Colors.RED if f["severity"] == "CRITICAL" else Colors.YELLOW if f["severity"] == "HIGH" else Colors.CYAN
        colored_sev = f"{sev_color}{f['severity']}{Colors.RESET}"
        table_rows.append([colored_sev, f["name"], f["path"], f["category"]])
        
    print("\n")
    if findings:
        print_danger(f"Identified {len(findings)} potential security vulnerabilities:")
        print_table(["Severity", "Vulnerability Name", "Matched Path", "Category"], table_rows)
    else:
        print_success("No template vulnerabilities detected matching loaded rules.")
        
    return {
        "templates_tested": len(templates),
        "vulnerabilities_found": len(findings),
        "findings": findings
    }

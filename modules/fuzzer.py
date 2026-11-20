"""
Optimized Sensitive Directory & Files Fuzzing Module.
Includes Smart Heuristics and Persistent Keep-Alive Sessions.
"""

from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.http_client import PersistentSession
from core.ui import print_info, print_success, print_warning, print_table, Colors
from core.config import BUILTIN_SENSITIVE_PATHS

def apply_heuristics(paths: list, detected_tech: list = None) -> list:
    """
    Smart Heuristics:
    Filters out irrelevant paths based on detected tech stack to optimize scan speed.
    """
    if not detected_tech:
        return paths
        
    tech_str = " ".join(detected_tech).lower()
    filtered = []
    
    is_php = any(t in tech_str for t in ["php", "wordpress", "laravel"])
    is_node = any(t in tech_str for t in ["node", "express", "next"])
    
    for p in paths:
        # If server is explicitly Node.js / React and not PHP, skip phpinfo & php files
        if is_node and not is_php and p.endswith(".php"):
            continue
        filtered.append(p)
        
    return filtered

def check_path_persistent(session: PersistentSession, base_url: str, path: str):
    """Test a single sensitive path using persistent keep-alive session"""
    full_url = urljoin(base_url, path)
    try:
        resp = session.request("GET", full_url)
        status = resp["status"]
        size = len(resp["bytes"])
        
        if status in [200, 301, 302]:
            return (path, status, f"{size} B", full_url)
        elif status in [401, 403]:
            return (path, status, "Restricted", full_url)
    except Exception:
        pass
    return None

def run_directory_fuzzer(url: str, custom_paths=None, threads=20, detected_tech=None):
    """
    Main runner for optimized sensitive file & directory fuzzer.
    """
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url
    if not url.endswith("/"):
        url += "/"

    base_paths = custom_paths if custom_paths else BUILTIN_SENSITIVE_PATHS
    optimized_paths = apply_heuristics(base_paths, detected_tech)
    
    if len(optimized_paths) < len(base_paths):
        print_info(f"Smart Heuristics active: Filtered {len(base_paths) - len(optimized_paths)} irrelevant paths.")
        
    print_info(f"Fuzzing {len(optimized_paths)} paths with Keep-Alive connection pool ({threads} threads)...")

    session = PersistentSession(timeout=4.0)
    found_entries = []
    
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(check_path_persistent, session, url, p): p for p in optimized_paths}
        for future in as_completed(futures):
            res = future.result()
            if res:
                path, status, size, full_url = res
                found_entries.append(res)
                if status == 200:
                    print_success(f"[{status}] {path} ({size}) -> {full_url}")
                elif status in [301, 302]:
                    print_info(f"[{status}] {path} (Redirect) -> {full_url}")
                elif status in [401, 403]:
                    print_warning(f"[{status}] {path} (Protected / Auth Required)")

    found_entries.sort(key=lambda x: x[1])
    
    table_rows = [[p, str(code), size, u] for p, code, size, u in found_entries]
    print("\n")
    print_table(["Path", "Status", "Size", "URL"], table_rows)
    
    return {
        "scanned_paths": len(optimized_paths),
        "found_count": len(found_entries),
        "findings": [f"[{code}] {p} ({u})" for p, code, size, u in found_entries]
    }

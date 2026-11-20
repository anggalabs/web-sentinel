"""
Sensitive Directory and Files Fuzzing Module.
"""

import ssl
import urllib.request
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.ui import print_info, print_success, print_warning, print_table, Colors
from core.config import BUILTIN_SENSITIVE_PATHS, DEFAULT_USER_AGENT, DEFAULT_TIMEOUT

def check_path(base_url: str, path: str, ctx: ssl.SSLContext):
    """Test a single sensitive path against base_url"""
    full_url = urllib.parse.urljoin(base_url, path)
    req = urllib.request.Request(
        full_url,
        headers={"User-Agent": DEFAULT_USER_AGENT}
    )
    
    try:
        with urllib.request.urlopen(req, timeout=DEFAULT_TIMEOUT, context=ctx) as resp:
            status = resp.status
            size = len(resp.read(4096))
            if status in [200, 301, 302, 403]:
                return (path, status, f"{size} bytes", full_url)
    except urllib.error.HTTPError as e:
        if e.code in [401, 403]:
            return (path, e.code, "Restricted", full_url)
    except Exception:
        pass
    return None

def run_directory_fuzzer(url: str, custom_paths=None, threads=15):
    """
    Main runner for sensitive file & directory fuzzer.
    """
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url
    if not url.endswith("/"):
        url += "/"

    paths = custom_paths if custom_paths else BUILTIN_SENSITIVE_PATHS
    print_info(f"Fuzzing {len(paths)} sensitive paths on: {Colors.BOLD}{url}{Colors.RESET}")

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    found_entries = []
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(check_path, url, p, ctx): p for p in paths}
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
                    print_warning(f"[{status}] {path} (Forbidden/Auth Required)")

    found_entries.sort(key=lambda x: x[1])
    
    table_rows = [[p, str(code), size, u] for p, code, size, u in found_entries]
    print("\n")
    print_table(["Path", "Status", "Size", "URL"], table_rows)
    
    return {
        "scanned_paths": len(paths),
        "found_count": len(found_entries),
        "findings": [f"[{code}] {p} ({u})" for p, code, size, u in found_entries]
    }

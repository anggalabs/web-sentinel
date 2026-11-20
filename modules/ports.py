"""
Fast Multi-threaded Port and Service Scanner.
"""

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.ui import print_info, print_success, print_warning, print_table, Colors
from core.config import TOP_WEB_PORTS, DEFAULT_TIMEOUT

def check_port(target_ip: str, port: int, service_name: str, timeout: float):
    """Attempt TCP connect to target_ip:port and grab banner if possible"""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        result = s.connect_ex((target_ip, port))
        if result == 0:
            banner = ""
            try:
                # Send basic probe to elicit a banner
                s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                raw_banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
                if raw_banner:
                    first_line = raw_banner.splitlines()[0]
                    banner = first_line[:40]
            except Exception:
                banner = "-"
            return (port, service_name, "OPEN", banner if banner else "-")
    except Exception:
        pass
    finally:
        s.close()
    return None

def run_port_scanner(target_host: str, ports_dict=None, threads=20, timeout=1.5):
    """
    Main runner for Port Scanner.
    """
    ports_to_scan = ports_dict if ports_dict else TOP_WEB_PORTS
    
    print_info(f"Resolving host: {Colors.BOLD}{target_host}{Colors.RESET}")
    try:
        target_ip = socket.gethostbyname(target_host)
        print_success(f"Target IP: {Colors.CYAN}{target_ip}{Colors.RESET}")
    except socket.gaierror as e:
        print_warning(f"Could not resolve {target_host}: {e}")
        return {"error": str(e), "open_ports": []}

    print_info(f"Scanning {len(ports_to_scan)} common ports with {threads} threads...")
    
    open_ports = []
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(check_port, target_ip, port, svc, timeout): port
            for port, svc in ports_to_scan.items()
        }
        for future in as_completed(futures):
            res = future.result()
            if res:
                open_ports.append(res)
                print_success(f"Port {res[0]} ({res[1]}) is OPEN")

    open_ports.sort(key=lambda x: x[0])
    
    table_rows = [[str(p), svc, status, banner] for p, svc, status, banner in open_ports]
    print("\n")
    print_table(["Port", "Service", "State", "Banner / Info"], table_rows)
    
    return {
        "target_ip": target_ip,
        "total_open": len(open_ports),
        "open_ports": [f"{p}/{svc} ({banner})" for p, svc, status, banner in open_ports]
    }

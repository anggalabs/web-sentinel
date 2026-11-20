"""
Terminal UI formatter with ANSI colors, boxes, and banner displays.
Requires zero third-party dependencies.
"""

import sys
import time
import re

ANSI_REGEX = re.compile(r'\x1b\[[0-9;]*m')

def visible_len(text):
    return len(ANSI_REGEX.sub('', str(text)))

class Colors:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    
    # Colors
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    
    # Backgrounds
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_BLUE = "\033[44m"


def banner():
    art = f"""{Colors.CYAN}{Colors.BOLD}
  ██╗    ██╗███████╗██████╗     ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗     
  ██║    ██║██╔════╝██╔══██╗    ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║     
  ██║ █╗ ██║█████╗  ██████╔╝    ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║     
  ██║███╗██║██╔══╝  ██╔══██╗    ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║     
  ╚███╔███╔╝███████╗██████╔╝    ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
   ╚══╝╚══╝ ╚══════╝╚═════╝     ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝
{Colors.RESET}{Colors.MAGENTA}          Modular Web Reconnaissance & Vulnerability Audit Toolkit (Python StdLib)
{Colors.RESET}"""
    print(art)


def print_info(msg):
    print(f" {Colors.BLUE}[*]{Colors.RESET} {msg}")

def print_success(msg):
    print(f" {Colors.GREEN}[+]{Colors.RESET} {msg}")

def print_warning(msg):
    print(f" {Colors.YELLOW}[!]{Colors.RESET} {msg}")

def print_danger(msg):
    print(f" {Colors.RED}[-]{Colors.RESET} {Colors.BOLD}{msg}{Colors.RESET}")

def print_header(title):
    line = "━" * 58
    print(f"\n{Colors.CYAN}{line}")
    print(f"  {Colors.BOLD}{title}{Colors.RESET}")
    print(f"{Colors.CYAN}{line}{Colors.RESET}")

def print_table(headers, rows):
    """Formatted ASCII table with ANSI-aware padding"""
    if not rows:
        print_info("No data available to display.")
        return
        
    col_widths = [visible_len(h) for h in headers]
    for row in rows:
        for i, val in enumerate(row):
            col_widths[i] = max(col_widths[i], visible_len(val))
            
    header_str = " │ ".join(f"{h:<{col_widths[i]}}" for i, h in enumerate(headers))
    sep_str = "─┼─".join("─" * col_widths[i] for i in range(len(headers)))
    
    print(f"{Colors.BOLD}{header_str}{Colors.RESET}")
    print(f"{Colors.DIM}{sep_str}{Colors.RESET}")
    for row in rows:
        formatted_cols = []
        for i, v in enumerate(row):
            v_str = str(v)
            pad = col_widths[i] - visible_len(v_str)
            formatted_cols.append(v_str + (" " * pad))
        print(" │ ".join(formatted_cols))


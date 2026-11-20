"""
Web Spider & Crawler Module.
Parses HTML and JavaScript code to discover hidden internal endpoints, forms, and API routes.
Uses pure Python standard library (html.parser & re).
"""

import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse
from core.http_client import PersistentSession
from core.ui import print_info, print_success, print_warning, print_table, Colors

JS_ENDPOINT_REGEX = re.compile(r"""(?i)["']((?:/api/|/v1/|/v2/|/graphql|/[a-zA-Z0-9_\-\.]+\.(?:json|php|action|do))[a-zA-Z0-9_\-\./\?&=]*)["']""")

class LinkExtractor(HTMLParser):
    def __init__(self, base_url):
        super().__init__()
        self.base_url = base_url
        self.links = set()
        self.forms = []
        self.scripts = set()
        self._current_form = None

    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)
        
        # 1. Links & Anchors
        if tag in ["a", "link", "iframe"] and "href" in attrs_dict:
            target = urljoin(self.base_url, attrs_dict["href"])
            self.links.add(target)
            
        # 2. Form Actions & Inputs
        elif tag == "form":
            action = urljoin(self.base_url, attrs_dict.get("action", ""))
            method = attrs_dict.get("method", "GET").upper()
            self._current_form = {"action": action, "method": method, "inputs": []}
            self.forms.append(self._current_form)
            
        elif tag == "input" and self._current_form is not None:
            name = attrs_dict.get("name")
            itype = attrs_dict.get("type", "text")
            if name:
                self._current_form["inputs"].append({"name": name, "type": itype})
                
        # 3. JavaScript Assets
        elif tag == "script" and "src" in attrs_dict:
            src = urljoin(self.base_url, attrs_dict["src"])
            self.scripts.add(src)

    def handle_endtag(self, tag):
        if tag == "form":
            self._current_form = None

def is_same_domain(url: str, target_domain: str) -> bool:
    parsed = urlparse(url)
    return (parsed.hostname == target_domain) or (parsed.hostname and parsed.hostname.endswith("." + target_domain))

def run_web_crawler(target_url: str, max_pages=30, proxy=None):
    """
    Crawls internal pages starting from target_url and extracts API routes, forms, and parameters.
    """
    if not target_url.startswith("http://") and not target_url.startswith("https://"):
        target_url = "https://" + target_url

    parsed_target = urlparse(target_url)
    target_domain = parsed_target.hostname

    print_info(f"Initiating Web Crawler on: {Colors.BOLD}{target_url}{Colors.RESET} (Limit: {max_pages} pages)")
    
    session = PersistentSession(timeout=5.0, proxy_url=proxy)
    queue = [target_url]
    visited = set()
    
    discovered_endpoints = set()
    discovered_params = set()
    discovered_forms = []
    
    while queue and len(visited) < max_pages:
        current_url = queue.pop(0)
        if current_url in visited:
            continue
        visited.add(current_url)
        
        try:
            resp = session.request("GET", current_url)
            if resp["status"] != 200:
                continue
                
            body = resp["body"]
            
            # Extract query parameters from URL
            p_parsed = urlparse(current_url)
            if p_parsed.query:
                discovered_endpoints.add(current_url)
                for q in p_parsed.query.split("&"):
                    if "=" in q:
                        discovered_params.add(q.split("=")[0])

            # Parse HTML
            extractor = LinkExtractor(current_url)
            extractor.feed(body)
            
            # Record discovered forms
            for form in extractor.forms:
                discovered_forms.append(form)
                discovered_endpoints.add(form["action"])
                for inp in form["inputs"]:
                    discovered_params.add(inp["name"])
                    
            # Parse JavaScript endpoints via regex
            js_matches = JS_ENDPOINT_REGEX.findall(body)
            for jm in js_matches:
                full_api_route = urljoin(current_url, jm)
                discovered_endpoints.add(full_api_route)
                
            # Queue new in-scope links
            for link in extractor.links:
                # Strip fragments
                link_clean = link.split("#")[0]
                if is_same_domain(link_clean, target_domain) and link_clean not in visited and link_clean not in queue:
                    # Filter out static media extensions
                    if not any(link_clean.lower().endswith(ext) for ext in [".png", ".jpg", ".jpeg", ".svg", ".css", ".ico", ".woff", ".pdf"]):
                        queue.append(link_clean)
                        discovered_endpoints.add(link_clean)
                        
        except Exception:
            pass

    print_success(f"Crawling complete: Inspected {len(visited)} pages.")
    print_info(f"Discovered {len(discovered_endpoints)} unique endpoints & {len(discovered_params)} parameters.")
    
    table_rows = []
    for ep in list(discovered_endpoints)[:15]:
        table_rows.append([ep[:65] + ("..." if len(ep) > 65 else "")])
        
    if table_rows:
        print("\n")
        print_table(["Sample Discovered Endpoints / Routes"], table_rows)
        
    if discovered_params:
        print_info(f"Parameters identified for DAST testing: {Colors.CYAN}{', '.join(discovered_params)}{Colors.RESET}")
        
    return {
        "pages_visited": len(visited),
        "total_endpoints": len(discovered_endpoints),
        "endpoints": list(discovered_endpoints),
        "parameters": list(discovered_params),
        "forms": discovered_forms
    }

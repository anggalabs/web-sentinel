"""
Lightweight High-Performance HTTP Client with Connection Pooling, Keep-Alive & Upstream Proxy Support.
Pure Python standard library (http.client & ssl) with zero dependencies.
Supports Burp Suite, OWASP ZAP, and Corporate Proxies.
"""

import ssl
import http.client
from urllib.parse import urlparse
import threading

class PersistentSession:
    """
    Maintains persistent HTTP/HTTPS connections per thread.
    Supports connection pooling, HTTP Keep-Alive, and HTTP proxy tunneling (CONNECT).
    """
    def __init__(self, timeout=5.0, user_agent=None, proxy_url=None):
        self.timeout = timeout
        self.user_agent = user_agent or "Mozilla/5.0 (Windows NT 10.0; Win64; x64) WebSentinel/3.0"
        self.proxy_url = proxy_url
        self._local = threading.local()
        
        self.ssl_ctx = ssl.create_default_context()
        self.ssl_ctx.check_hostname = False
        self.ssl_ctx.verify_mode = ssl.CERT_NONE
        
        # Parse proxy if provided (e.g. http://127.0.0.1:8080)
        self.proxy_host = None
        self.proxy_port = None
        if proxy_url:
            parsed_proxy = urlparse(proxy_url)
            self.proxy_host = parsed_proxy.hostname
            self.proxy_port = parsed_proxy.port or 8080

    def _get_connection(self, host: str, port: int, is_ssl: bool):
        if not hasattr(self._local, "connections"):
            self._local.connections = {}
            
        key = (host, port, is_ssl, self.proxy_host, self.proxy_port)
        conn = self._local.connections.get(key)
        
        if conn is None:
            if self.proxy_host and self.proxy_port:
                # Upstream Proxy Route (e.g. Burp Suite on 127.0.0.1:8080)
                if is_ssl:
                    # HTTPS through HTTP Proxy via CONNECT tunnel
                    conn = http.client.HTTPSConnection(
                        self.proxy_host, port=self.proxy_port,
                        timeout=self.timeout, context=self.ssl_ctx
                    )
                    conn.set_tunnel(host, port)
                else:
                    # Plain HTTP through Proxy
                    conn = http.client.HTTPConnection(
                        self.proxy_host, port=self.proxy_port, timeout=self.timeout
                    )
            else:
                # Direct Connection
                if is_ssl:
                    conn = http.client.HTTPSConnection(
                        host, port=port, timeout=self.timeout, context=self.ssl_ctx
                    )
                else:
                    conn = http.client.HTTPConnection(
                        host, port=port, timeout=self.timeout
                    )
            self._local.connections[key] = conn
            
        return conn

    def request(self, method: str, url: str, headers=None, body=None):
        parsed = urlparse(url)
        is_ssl = (parsed.scheme == "https")
        host = parsed.hostname
        port = parsed.port or (443 if is_ssl else 80)
        
        # When using plain HTTP proxy without CONNECT, request-URI must be absolute
        if self.proxy_host and not is_ssl:
            path = url
        else:
            path = parsed.path or "/"
            if parsed.query:
                path += "?" + parsed.query
            
        req_headers = {
            "Host": host,
            "User-Agent": self.user_agent,
            "Accept": "*/*",
            "Connection": "keep-alive"
        }
        if headers:
            req_headers.update(headers)
            
        conn = self._get_connection(host, port, is_ssl)
        
        try:
            conn.request(method, path, body=body, headers=req_headers)
            resp = conn.getresponse()
            content = resp.read()
            return {
                "status": resp.status,
                "headers": dict(resp.getheaders()),
                "body": content.decode("utf-8", errors="ignore"),
                "bytes": content
            }
        except Exception:
            # Reconnect once on broken socket / closed keep-alive
            try:
                conn.close()
            except Exception:
                pass
            key = (host, port, is_ssl, self.proxy_host, self.proxy_port)
            if hasattr(self._local, "connections") and key in self._local.connections:
                del self._local.connections[key]
                
            new_conn = self._get_connection(host, port, is_ssl)
            new_conn.request(method, path, body=body, headers=req_headers)
            resp = new_conn.getresponse()
            content = resp.read()
            return {
                "status": resp.status,
                "headers": dict(resp.getheaders()),
                "body": content.decode("utf-8", errors="ignore"),
                "bytes": content
            }

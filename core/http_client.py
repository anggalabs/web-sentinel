"""
Lightweight High-Performance HTTP Client with Connection Pooling & Keep-Alive.
Uses pure Python standard library (http.client & ssl) with zero dependencies.
"""

import ssl
import http.client
from urllib.parse import urlparse
import threading

class PersistentSession:
    """
    Maintains persistent HTTP/HTTPS connections per thread (Connection Pooling).
    Reuses TCP & TLS sockets to eliminate handshake latency.
    """
    def __init__(self, timeout=5.0, user_agent=None):
        self.timeout = timeout
        self.user_agent = user_agent or "Mozilla/5.0 (Windows NT 10.0; Win64; x64) WebSentinel/2.0"
        self._local = threading.local()
        
        self.ssl_ctx = ssl.create_default_context()
        self.ssl_ctx.check_hostname = False
        self.ssl_ctx.verify_mode = ssl.CERT_NONE

    def _get_connection(self, host: str, port: int, is_ssl: bool):
        if not hasattr(self._local, "connections"):
            self._local.connections = {}
            
        key = (host, port, is_ssl)
        conn = self._local.connections.get(key)
        
        if conn is None:
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
            # Socket broke or server closed keep-alive; reset connection and retry once
            try:
                conn.close()
            except Exception:
                pass
            key = (host, port, is_ssl)
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

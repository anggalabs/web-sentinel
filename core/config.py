"""
Global configurations and constants for Web-Sentinel.
"""

import os

DEFAULT_TIMEOUT = 5.0
DEFAULT_THREADS = 15
DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 WebSentinel/3.0"

# Common ports for web applications and critical services
TOP_WEB_PORTS = {
    21: "FTP",
    22: "SSH",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    1433: "MSSQL",
    1521: "Oracle DB",
    3000: "Node/React Dev",
    3306: "MySQL",
    3389: "RDP",
    5000: "Flask/Dev",
    5432: "PostgreSQL",
    6379: "Redis",
    8000: "HTTP-Alt (Django/Dev)",
    8080: "HTTP-Proxy / Tomcat",
    8443: "HTTPS-Alt",
    8888: "HTTP-Alt / Jupyter",
    9000: "PHP-FPM / SonarQube",
    9200: "Elasticsearch",
    27017: "MongoDB"
}

# Essential subdomains for fast active brute-force
BUILTIN_SUBDOMAINS = [
    "www", "api", "dev", "staging", "test", "admin", "mail", "app", "beta",
    "portal", "auth", "login", "cdn", "static", "vpn", "remote", "corp",
    "internal", "monitor", "status", "git", "gitlab", "jenkins", "jira",
    "cloud", "db", "mysql", "redis", "grafana", "kibana", "docs", "help"
]

# Sensitive paths for rapid security fuzzing
BUILTIN_SENSITIVE_PATHS = [
    # Environment & Config
    "/.env",
    "/.env.example",
    "/.env.local",
    "/.git/HEAD",
    "/.git/config",
    "/.gitignore",
    "/config.json",
    "/configuration.php",
    "/web.config",
    "/settings.py",
    # Backups & Dumps
    "/backup.zip",
    "/backup.sql",
    "/backup.tar.gz",
    "/dump.sql",
    "/database.sql",
    "/db.sql",
    # Informational & Crawlers
    "/robots.txt",
    "/sitemap.xml",
    "/phpinfo.php",
    "/info.php",
    "/health",
    "/metrics",
    # API Documentation & Schema
    "/swagger.json",
    "/swagger-ui.html",
    "/v2/api-docs",
    "/v3/api-docs",
    "/openapi.json",
    "/graphql",
    # Administration
    "/admin",
    "/admin/",
    "/administrator/",
    "/wp-admin/",
    "/login",
    "/cpanel",
    "/phpmyadmin/"
]

def load_wordlist_file(filepath: str) -> list:
    """Load wordlist lines from custom file path"""
    if not filepath or not os.path.exists(filepath):
        return []
    lines = []
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                lines.append(line)
    return lines

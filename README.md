# Web-Sentinel 🛡️

**Web-Sentinel** adalah toolkit audit keamanan, pengintaian (*reconnaissance*), dan pemindai celah keamanan web (*DAST*) tingkat industri berbasis Python. Dirancang dengan arsitektur **Zero External Dependencies** (menggunakan Python Standard Library murni), tool ini dapat langsung dijalankan di Termux Android, Linux, macOS, dan Windows tanpa perlu instalasi `pip` tambahan.

---

## ⚡ Fitur Utama & Modul Lengkap

1. **Subdomain Enumeration (Opsi 1):**
   * Mengambil data subdomain dari *Certificate Transparency* (`crt.sh`) secara pasif.
   * Melakukan validasi aktif (resolusi DNS) multi-threading untuk memvalidasi subdomain yang hidup.

2. **Open Ports & Service Scanner (Opsi 2):**
   * Memindai port penting web dan infrastruktur (80, 443, 8080, 3306, 5432, 22, dll.).
   * Mengambil *service banner* dari port yang terbuka.

3. **Security Headers & Tech Stack Fingerprinting (Opsi 3):**
   * Menganalisis *security headers* (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy).
   * Mendeteksi server dan framework yang digunakan (Nginx, Apache, Cloudflare, WordPress, Laravel, Next.js, Express, dll.).

4. **Web Spider & Crawler (Opsi 4) — *Baru!*:**
   * Menganalisis dokumen HTML & script JavaScript untuk mengekstrak seluruh link internal, tag `<form action="...">`, parameter input, dan endpoint API tersembunyi (`/api/v1/...`).

5. **Sensitive Files & Directory Fuzzer (Opsi 5) — *Accelerated & Custom Wordlist*:**
   * Dioptimalkan dengan **HTTP Keep-Alive Connection Pooling** dan **Smart Heuristics** (otomatis memfilter ekstensi yang tidak relevan dengan tech stack).
   * Mendukung berkas wordlist eksternal kustom (`-w /path/to/wordlist.txt`).

6. **Web Misconfiguration Audit (Opsi 6):**
   * **CORS Audit:** Menguji refleksi origin liar dengan kredensial aktif (`Access-Control-Allow-Credentials`).
   * **Clickjacking Audit:** Memeriksa keberadaan header pelindung framing (`X-Frame-Options` dan `frame-ancestors`).

7. **Critical & High Vulnerability Scanner (Opsi 7) — *Template Engine*:**
   * Mendeteksi celah tingkat **Critical & High** menggunakan sistem template modular JSON/YAML (terinspirasi dari arsitektur *Nuclei*).
   * Koleksi 12+ template mencakup: `.env` leak, `.git/config` & `.git/HEAD` exposure, Docker Registry v2, Elasticsearch indices, Firebase DB publik, GraphQL Introspection, WordPress REST user enum, dan Spring Boot Actuator.

8. **Threat Intelligence & CVE Hunter (Opsi 8) — *Zero-Auth Cloud Intel*:**
   * Terhubung dengan **Shodan InternetDB** (tanpa perlu API key) untuk memetakan seluruh port terbuka, software CPEs, dan riwayat CVE global pada IP target secara instan.
   * Mengintegrasikan database **OSV.dev** untuk mencocokkan software framework target dengan basis data Known CVE.

9. **Active DAST Injection Audit (Opsi 9) — *Baru!*:**
   * **Reflected XSS Canary:** Menguji apakah input parameter di-escape dengan benar atau direfleksikan mentah ke respons HTML.
   * **SQL Injection Error Anomaly:** Menguji injeksi pemutus sintaks pada parameter dan mencocokkan respons dengan regex error database (MySQL, PostgreSQL, MSSQL, Oracle, SQLite).
   * **Local File Inclusion (LFI):** Menguji path traversal canary pada parameter file (`/etc/passwd`).

10. **Full Automated Pipeline (Opsi 10):**
    * Menjalankan seluruh modul 1 sampai 9 secara berantai dan otomatis.

11. **Upstream Proxy Support (Opsi 11) — *Burp Suite & ZAP Ready*:**
    * Mendukung perutean traffic melalui HTTP proxy (`-p http://127.0.0.1:8080`) termasuk TLS CONNECT tunneling.

12. **Export Laporan (Opsi 12):**
    * Menyimpan hasil audit lengkap ke format **Markdown (.md)** dan **JSON (.json)** di folder `reports/`.

---

## 💻 Cara Menggunakan

### 1. Mode Menu Interaktif
Cukup ketik perintah global di mana saja di terminal Termux Anda:
```bash
web-sentinel
```

### 2. Mode Command-Line Arguments (Otomasi)
```bash
# Full Automated Scan (Pipeline Mode)
web-sentinel -t target.com --all

# Menggunakan Custom Wordlist (SecLists)
web-sentinel -t target.com -m 5 -w /path/to/common.txt

# Menghubungkan Traffic ke Burp Suite / OWASP ZAP Proxy
web-sentinel -t target.com --all -p http://127.0.0.1:8080

# Menjalankan Spidering + DAST Injection saja
web-sentinel -t target.com -m 4,9
```

---

## 📁 Struktur Direktori
```text
web-sentinel/
├── sentinel.py              # CLI & Menu interaktif utama
├── setup.py / pyproject.toml# Konfigurasi instalasi package
├── .github/workflows/ci.yml # Automated CI pipeline testing
├── core/
│   ├── http_client.py       # Keep-Alive pool + Upstream Proxy tunneling
│   ├── config.py            # Konfigurasi port, wordlist loader, timeout
│   ├── ui.py                # ANSI colors & dynamic ASCII tables
│   └── reporter.py          # Generator laporan Markdown & JSON
├── modules/
│   ├── subdomains.py        # Pasif CT logs & DNS lookup
│   ├── ports.py             # TCP port scanner & banner grabber
│   ├── headers_tech.py      # Security headers & tech fingerprint
│   ├── crawler.py           # Web spider: HTML/JS endpoints & forms extractor
│   ├── fuzzer.py            # Keep-Alive fuzzer, wordlists, heuristics
│   ├── misconfigs.py        # CORS & Clickjacking audit
│   ├── templates_scanner.py # Template engine untuk celah Critical/High
│   ├── threat_intel.py      # Shodan InternetDB & OSV.dev CVE hunter
│   └── dast_scanner.py      # Active injection: XSS Canary, SQLi, LFI
├── templates/               # Koleksi rule deteksi celah keamanan (12+ Templates)
└── reports/                 # Laporan hasil scan (Markdown & JSON)
```

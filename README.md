# Web-Sentinel 🛡️

**Web-Sentinel** adalah toolkit keamanan, pengintaian (*reconnaissance*), dan audit kerentanan aplikasi web berbasis Python yang dirancang modular dengan arsitektur **Zero External Dependencies** (menggunakan pustaka standar Python murni). Tool ini dapat langsung dijalankan di sistem apa pun (Linux, Termux Android, Windows, macOS) tanpa perlu instalasi modul `pip` tambahan.

---

## ⚡ Fitur Utama & Pilihan Modul

1. **Subdomain Enumeration (Opsi 1):**
   * Mengambil data subdomain dari *Certificate Transparency* (`crt.sh`) secara pasif.
   * Melakukan validasi aktif (resolusi DNS) multi-threading untuk memastikan subdomain yang masih aktif.

2. **Open Ports & Service Scanner (Opsi 2):**
   * Memindai port penting web dan infrastruktur (80, 443, 8080, 3306, 5432, 22, dll.).
   * Mengambil *service banner* dari port yang terbuka.

3. **Security Headers & Tech Stack Fingerprinting (Opsi 3):**
   * Menganalisis *security headers* (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy).
   * Mendeteksi server dan framework yang digunakan (Nginx, Apache, Cloudflare, WordPress, Laravel, Next.js, Express, dll.).

4. **Sensitive Files & Directory Fuzzer (Opsi 4) — *Accelerated*:**
   * Dioptimalkan dengan **HTTP Keep-Alive Connection Pooling** dan **Smart Heuristics** (otomatis memfilter path yang tidak relevan dengan tech stack untuk menghemat bandwidth dan waktu).

5. **Web Misconfiguration Audit (Opsi 5):**
   * **CORS Audit:** Menguji refleksi origin liar dengan kredensial aktif (`Access-Control-Allow-Credentials`).
   * **Clickjacking Audit:** Memeriksa keberadaan header pelindung framing (`X-Frame-Options` dan `frame-ancestors`).

6. **Critical & High Vulnerability Scanner (Opsi 6) — *Template Engine*:**
   * Mendeteksi celah tingkat **Critical & High** menggunakan sistem template modular (berbasis JSON/YAML).
   * Celah bawaan meliputi:
     * Kebocoran berkas `.env` (Database credentials & API Keys).
     * Eksposur `.git/config` & `.git/HEAD` (Potensi Source Code Leakage).
     * Eksposur Docker Registry v2 (`/v2/_catalog`).
     * Eksposur Elasticsearch Open Indices (`/_cat/indices?v`).
     * Eksposur Firebase Database publik (`/.json`).
     * Introspeksi skema GraphQL terbuka (`/graphql`).
     * Enumerasi User WordPress (`/wp-json/wp/v2/users`).
     * Indikator Open Redirect.
     * Eksposur Spring Boot Actuator (`/actuator/env`).
     * Paparan `phpinfo.php` dan skema Swagger/OpenAPI.

7. **Threat Intelligence & CVE Hunter (Opsi 7) — *Zero-Auth Cloud Intel*:**
   * Integrasi langsung dengan **Shodan InternetDB** (tanpa perlu API key) untuk memetakan seluruh port terbuka, software CPEs, dan riwayat CVE yang terdeteksi secara global pada IP target.
   * Cross-referencing otomatis ke database **OSV.dev** (Open Source Vulnerabilities) untuk mencari Known CVEs.

8. **Full Automated Audit (Opsi 8):**
   * Menjalankan seluruh modul 1 s/d 7 secara sekuensial dan otomatis.

9. **Export Laporan (Opsi 9):**
   * Menyimpan hasil audit ke dalam format **Markdown (.md)** dan **JSON (.json)** di folder `reports/`.

---

## 💻 Cara Menjalankan

### 1. Jalankan Langsung dari Terminal
```bash
python3 sentinel.py
```
Masukkan nama domain/URL target saat diminta, lalu pilih nomor scan yang ingin dijalankan (`1` s/d `9`).

### 2. Jalankan Mode Flag Otomatis
```bash
# Menjalankan seluruh modul audit sekaligus
python3 sentinel.py -t example.com --all

# Menjalankan modul spesifik (misal modul 6: Template Vuln, dan modul 7: Threat Intel)
python3 sentinel.py -t example.com -m 6,7
```

### 3. Akses Perintah Global di Mana Saja (`web-sentinel`)
Tool ini telah dilengkapi launcher di Termux:
```bash
web-sentinel -t target.com --all
```

---

## 📁 Struktur Direktori
```text
web-sentinel/
├── sentinel.py              # CLI & Menu interaktif utama
├── setup.py / pyproject.toml# Konfigurasi instalasi package
├── .github/workflows/ci.yml # Automated CI pipeline testing
├── core/
│   ├── http_client.py       # Persistent Keep-Alive connection pool (Zero Dep)
│   ├── config.py            # Konfigurasi port, timeout, dan wordlists
│   ├── ui.py                # ANSI colors & formatted tables
│   └── reporter.py          # Generator laporan Markdown & JSON
├── modules/
│   ├── subdomains.py        # Pasif CT logs & DNS lookup
│   ├── ports.py             # TCP port scanner & banner grabber
│   ├── headers_tech.py      # Security headers & tech fingerprint
│   ├── fuzzer.py            # Keep-Alive fuzzer & smart heuristics
│   ├── misconfigs.py        # CORS & Clickjacking audit
│   ├── templates_scanner.py # Template engine untuk celah Critical/High
│   └── threat_intel.py      # Shodan InternetDB & OSV.dev CVE hunter
├── templates/               # Koleksi rule deteksi celah keamanan (10+ Templates)
└── reports/                 # Laporan hasil scan (Markdown & JSON)
```

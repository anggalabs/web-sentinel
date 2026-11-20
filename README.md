# Web-Sentinel 🛡️

**Web-Sentinel** adalah toolkit keamanan dan pengintaian (*reconnaissance*) aplikasi web berbasis Python yang dirancang modular dengan arsitektur **Zero External Dependencies** (menggunakan Python Standard Library). Tool ini dapat langsung dijalankan di sistem apa pun (Linux, Termux Android, Windows, macOS) tanpa perlu instalasi `pip` tambahan.

---

## ⚡ Fitur Utama & Modul

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
   * Dioptimalkan dengan **HTTP Keep-Alive Connection Pooling** dan **Smart Heuristics** (otomatis memfilter path yang tidak relevan dengan tech stack untuk menghemat request).

5. **Web Misconfiguration Audit (Opsi 5):**
   * **CORS Audit:** Menguji refleksi origin liar dengan kredensial aktif (`Access-Control-Allow-Credentials`).
   * **Clickjacking Audit:** Memeriksa keberadaan header pelindung framing (`X-Frame-Options` dan `frame-ancestors`).

6. **Critical & High Vulnerability Scanner (Opsi 6) — *Template Engine*:**
   * Mendeteksi celah tingkat **Critical & High** menggunakan sistem template modular (berbasis JSON/YAML).
   * Celah bawaan meliputi:
     * Kebocoran berkas `.env` (Database credentials & API Keys).
     * Eksposur `.git/config` (Potensi Source Code Leakage).
     * Eksposur Spring Boot Actuator (`/actuator/env`).
     * Paparan `phpinfo.php` dan skema Swagger/OpenAPI tak terproteksi.
   * Pengguna dapat dengan mudah menambahkan template deteksi baru di folder `templates/`.

7. **Full Automated Audit (Opsi 7):**
   * Menjalankan seluruh modul secara sekuensial dan otomatis.

8. **Export Laporan (Opsi 8):**
   * Menyimpan hasil pemindaian ke dalam format **Markdown (.md)** dan **JSON (.json)** di folder `reports/`.

---

## 💻 Cara Menjalankan

### Mode Menu Interaktif
```bash
python3 sentinel.py
```
Masukkan nama domain/URL target saat diminta, lalu pilih nomor scan yang ingin dijalankan (`1` s/d `8`).

### Mode Command-Line Arguments (Otomasi)
Jalankan full scan langsung:
```bash
python3 sentinel.py -t example.com --all
```

Jalankan hanya modul tertentu (misal modul 3 dan modul 6):
```bash
python3 sentinel.py -t example.com -m 3,6
```

---

## 📁 Struktur Proyek
```text
web-sentinel/
├── sentinel.py              # CLI & Menu interaktif utama
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
│   └── templates_scanner.py # Template engine untuk celah Critical/High
├── templates/               # Koleksi rule deteksi celah keamanan
│   ├── env_file_leak.json
│   ├── git_config_leak.json
│   ├── spring_actuator_env.json
│   ├── phpinfo_exposure.json
│   └── swagger_api_docs.json
└── reports/                 # Laporan hasil scan (Markdown & JSON)
```

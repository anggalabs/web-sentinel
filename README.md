# Web-Sentinel 🛡️

**Web-Sentinel** adalah toolkit keamanan dan pengintaian (*reconnaissance*) aplikasi web berbasis Python yang dirancang modular dengan arsitektur **Zero External Dependencies** (menggunakan Python Standard Library). Tool ini dapat langsung dijalankan di sistem apa pun (Linux, Termux Android, Windows, macOS) tanpa perlu instalasi `pip` tambahan.

---

## 🚀 Fitur & Pilihan Modul

1. **Subdomain Enumeration (Opsi 1):**
   * Mengambil data subdomain dari *Certificate Transparency* (`crt.sh`) secara pasif.
   * Melakukan validasi aktif (resolusi DNS) multi-threading untuk memastikan subdomain yang masih aktif.

2. **Open Ports & Service Scanner (Opsi 2):**
   * Memindai port penting web dan infrastruktur (80, 443, 8080, 3306, 5432, 22, dll.).
   * Mengambil *service banner* dari port yang terbuka.

3. **Security Headers & Tech Stack Fingerprinting (Opsi 3):**
   * Menganalisis *security headers* (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy).
   * Mendeteksi server dan framework yang digunakan (Nginx, Apache, Cloudflare, WordPress, Laravel, Next.js, Express, dll.).

4. **Sensitive Files & Directory Fuzzer (Opsi 4):**
   * Memindai berkas sensitif dan titik akhir berbahaya (`.env`, `.git/HEAD`, `backup.zip`, `phpinfo.php`, `robots.txt`, `swagger.json`, `/admin`).

5. **Web Misconfiguration Audit (Opsi 5):**
   * **CORS Audit:** Menguji refleksi origin liar dengan kredensial aktif (`Access-Control-Allow-Credentials`).
   * **Clickjacking Audit:** Memeriksa keberadaan header pelindung framing (`X-Frame-Options` dan `frame-ancestors`).

6. **Full Automated Audit (Opsi 6):**
   * Menjalankan seluruh modul secara sekuensial dan otomatis.

7. **Export Laporan (Opsi 7):**
   * Menyimpan hasil pemindaian ke dalam format **Markdown (.md)** dan **JSON (.json)** di folder `reports/`.

---

## 💻 Cara Menjalankan

### Mode Menu Interaktif
Cukup jalankan:
```bash
python3 sentinel.py
```
Anda akan diminta memasukkan target (contoh: `example.com`), kemudian menu interaktif bernomor `[0-7]` akan muncul.

### Mode Command-Line Arguments (Otomasi)
Jalankan full scan langsung:
```bash
python3 sentinel.py -t example.com --all
```

Jalankan hanya modul tertentu (misal modul 1 dan modul 3):
```bash
python3 sentinel.py -t example.com -m 1,3
```

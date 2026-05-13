# 🛡️ Enterprise SecOps Panel & DevSecOps Suite

**SecOps Panel** adalah platform dasbor pemantauan keamanan server, manajemen kontainer, dan sistem deteksi intrusi proaktif (*Host Intrusion Detection System - HIDS*) yang dikembangkan dengan arsitektur **Python Flask** dan antarmuka **Glassmorphism Premium**.

Aplikasi ini dirancang untuk memberikan visibilitas penuh secara *real-time* terhadap pemanfaatan sumber daya host, analitik jaringan, integritas berkas sistem, serta memitigasi serangan peretas otonom.

---

## ✨ Fitur Utama

### 🔬 1. Proactive HIDS & FIM (File Integrity Monitoring)
- **SHA-256 Cryptographic Audit**: Melacak sidik jari hash fisik dari berkas krusial host secara konstan. Modifikasi sekecil apa pun tanpa izin akan memicu status **MODIFIED** berdenyut kritis.
- **Sistem Otorisasi Sekali Klik**: Memperbarui acuan acak *baseline* kode secara praktis langsung melalui antarmuka web.

### 🧱 2. Stateful Firewall & Access Ban Manager
- **Proteksi Brute-Force Otomatis**: Mendeteksi percobaan login ilegal (gagal $\ge$ 3 kali berturut-turut) dan langsung memblokir alamat IP penyerang selama 5 menit.
- **Blacklist Permanen**: Pencekalan alamat IP penjahat siber seumur hidup yang didukung dengan fitur pencabutan cekal instan (*Unban*).

### 📊 3. Vulnerability Auditor & System Risk Score
- **Analisis Risiko Otomatis**: Menghitung **System Risk Score (0-100)** secara riil dengan mengevaluasi pemakaian memori kritis, integritas file, dan paparan port fisik rentan (seperti FTP port 21 atau Telnet port 23).
- **Rekomendasi Mitigasi Fisik**: Menyajikan rincian tingkat bahaya (*Severity*: `CRITICAL` / `WARNING`) serta solusi perbaikan bagi administrator.

### 🐳 4. Manajemen Ekosistem Docker
- **Pure SDK Integration**: Memantau daftar lengkap instans kontainer yang berjalan di sistem host.
- **Kendali Jarak Jauh**: Instruksi nyata untuk melakukan **Start**, **Stop**, dan **Restart** kontainer tanpa membuka CLI eksternal.

### ⚡ 5. Stateful Speedometer & Live Socket Auditor
- **Meteran Kecepatan Real-Time**: Laju transfer *Download* dan *Upload* aktual diperbarui periodik setiap 3 detik.
- **Inspeksi Soket Otentik**: Menautkan identitas koneksi jaringan (IP/Port) secara akurat ke nama proses aslinya (*Process Name*).

### 🖥️ 6. Web Terminal Console Emulator
- **Eksekusi Perintah Host**: Konsol interaktif bernuansa *cyber matrix* pekat untuk menjalankan perintah dasar sistem operasi (seperti `ipconfig`, `netstat -ano`, `tasklist`).
- **Failsafe Timeout 7 Detik**: Menghentikan paksa instruksi tanpa ujung untuk menjaga kestabilan subsistem server.

### 📁 7. Eksportir Laporan Forensik Sekali Klik
- Rute otomatis `/api/report/export` merakit seluruh data metrik, jejak soket, status FIM, dan aturan Firewall aktif menjadi dokumen `.json` portabel untuk keperluan audit kepatuhan standar (*compliance*).

---

## 🚀 Panduan Instalasi & Eksekusi

### Persyaratan Lingkungan
Pastikan kamu telah memasang **Python 3.8+** pada sistem operasi host.

### 1. Kloning Repositori
```bash
git clone https://github.com/frambudi75/secops-panel.git
cd secops-panel
```

### 2. Pemasangan Dependensi
```bash
pip install -r requirements.txt
```

### 3. Konfigurasi Lingkungan (`.env`)
Buat berkas bernama `.env` pada direktori root proyekmu untuk mengatur kredensial kustom dan menyambungkan notifikasi Telegram (*opsional*):

```ini
SECRET_KEY=kunci_rahasia_sesi_flask_kamu
PANEL_USER=admin
PANEL_PASS=admin123
TELEGRAM_TOKEN=123456789:ABCdefGhIJKlmNoPQRsTUVwxyZ
TELEGRAM_CHAT_ID=987654321
```

### 4. Menjalankan Aplikasi
```bash
python panel.py
```

Aplikasi akan berjalan secara optimal pada alamat lokal:
👉 **`http://localhost:5025`** atau **`http://<IP_Host>:5025`**

---

## 🔑 Autentikasi Bawaan
Jika berkas `.env` belum dikonfigurasi, gunakan kredensial masuk (*login*) standar berikut:
- **Username**: `admin`
- **Password**: `admin123`

---

## 📚 Struktur Antarmuka & Modul Utama
- `panel.py`: Gateway pengarah rute web, REST API terpadu, dan pengawas tugas latar belakang.
- `fim.py`: Mesin enkripsi SHA-256 pelacak integritas berkas.
- `auditor.py`: Mesin analitik penilai risiko kerentanan host.
- `network.py`: Pengelola kecepatan transfer data dan inventarisasi soket.
- `services.py`: Pemantau utilisasi host dan pengendali terminasi proses (*Kill action*).
- `terminal.py`: Jembatan eksekusi shell yang diisolasi dengan batas waktu aman.
- `containers.py`: Jembatan komunikasi soket kernel Docker.

---

## 🛡️ Keamanan & Peringatan Penggunaan
> **Catatan Administrator**: Fitur **Kill Process**, **Kendali Docker**, dan **Terminal Console** memerlukan hak akses *root/administrator* pada sistem operasi agar sanggup mengeksekusi sinyal tingkat kernel secara nyata.

---
*Diberdayakan oleh kerangka kerja DevSecOps Modern — Rilis v2.5 Enterprise Engine.*

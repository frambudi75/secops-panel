import os
import datetime

LOG_PATHS = {
    "syslog": "/var/log/syslog",
    "auth": "/var/log/auth.log",
    "assistant": "logs/assistant.log",
}

def baca_konten_log(tipe_log, max_lines=150):
    """Membaca isi file log terpusat. Dilengkapi fallback mode simulasi untuk Windows."""
    path = LOG_PATHS.get(tipe_log)
    
    # Deteksi jika membaca dari hasil laporan scan
    if tipe_log.startswith("report_"):
        filename = tipe_log.replace("report_", "")
        path = os.path.join("reports", filename)
        
    if not path:
        return f"[ERROR] Tipe log '{tipe_log}' tidak tersedia di konfigurasi."
        
    # Penanganan jika file fisik tidak ada
    if not os.path.exists(path):
        # Jika itu log internal, otomatis buatkan agar tidak error
        if tipe_log == "assistant":
            os.makedirs("logs", exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                f.write(f"[{now}] [SISTEM] Daemon asisten keamanan dan pemantauan aktif.\n")
            return f"[{now}] [SISTEM] Daemon asisten keamanan dan pemantauan aktif.\n"
            
        # Fallback dummy cerdas untuk syslog/auth di Windows
        return (
            f"=== BUKTI LOG SIMULASI: {path} (Mode Pengujian Lokal) ===\n"
            f"[!] Catatan: Sistem file fisik tidak terdeteksi pada OS Windows. Menampilkan simulasi data real-time:\n\n"
            "[08:00:12] dockerd[1042]: Loading containers: security-monitor, redis-cache, app-backend...\n"
            "[08:01:05] kernel: [  22.104] audit: type=1400 audit(1700000000.000:1): apparmor=\"STATUS\" operation=\"profile_load\"\n"
            "[08:15:30] sshd[2050]: Accepted publickey for admin from 192.168.1.50 port 54322 ssh2\n"
            "[08:20:01] security-agent[3001]: [MONITOR] Memantau 145 service aktif. Tidak ada anomali terdeteksi.\n"
            "[08:35:44] dockerd[1042]: Container security-monitor logs streaming normal."
        )
        
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
        return "".join(lines[-max_lines:])
    except Exception as e:
        return f"[ERROR] Gagal membaca isi berkas {path}: {str(e)}"

def dapatkan_daftar_laporan():
    """Mengambil daftar semua laporan file scan dari direktori reports/."""
    os.makedirs("reports", exist_ok=True)
    files = [f for f in os.listdir("reports") if f.endswith(".txt")]
    return sorted(files, reverse=True)

def tulis_log_internal(pesan):
    """Mencatat aktivitas sistem ke dalam assistant.log."""
    os.makedirs("logs", exist_ok=True)
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open("logs/assistant.log", "a", encoding="utf-8") as f:
        f.write(f"[{now}] {pesan}\n")

# --- KELAS / FUNGSI LAMA UNTUK BACKWARD COMPATIBILITY DENGAN main.py ---
def cek_log_sistem():
    try:
        with open("/var/log/syslog", "r") as f:
            lines = f.readlines()[-10:]
        return "[LOG] 10 baris terakhir:\n" + "".join(lines)
    except:
        return "[LOG] Tidak bisa baca /var/log/syslog (Gunakan Web Dashboard untuk mode simulasi)"

def reset_log_aplikasi(path="/var/www/html/logs/app.log"):
    try:
        open(path, "w").close()
        return "[LOG] Log aplikasi direset."
    except:
        return "[LOG] Gagal reset log aplikasi."

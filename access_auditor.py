import psutil
import os
from datetime import datetime
from services import terminate_service
from fim import get_fim_status

LOG_FILE = "logs/remote_access.log"
_recorded_sessions = set()

def detect_remote_sessions():
    """Memindai koneksi aktif pada port kendali jarak jauh utama (22, 3389) dan mencatat riwayat log otomatis."""
    os.makedirs("logs", exist_ok=True)
    
    # Ambil daftar nama file yang termodifikasi dari mesin FIM
    fim_mods = [f["filename"] for f in get_fim_status() if f["status"] == "MODIFIED"]
    
    active_sessions = []
    try:
        conns = psutil.net_connections(kind="inet")
        for c in conns:
            laddr = c.laddr
            raddr = c.raddr
            status = c.status
            pid = c.pid
            
            if laddr and laddr.port in (22, 3389):
                proto = "SSH / SFTP / WinSCP" if laddr.port == 22 else "RDP (Remote Desktop)"
                
                remote_ip = raddr.ip if raddr else "N/A"
                remote_port = raddr.port if raddr else "N/A"
                
                # Resolusi nama proses kernel
                pname = "Service Host"
                if pid:
                    try:
                        pname = psutil.Process(pid).name()
                    except Exception:
                        pass
                        
                session_id = f"{remote_ip}:{laddr.port}:{pid}"
                
                # Catat ke log fisik jika sesi eksternal berstatus ESTABLISHED
                if status == "ESTABLISHED" and remote_ip != "N/A" and session_id not in _recorded_sessions:
                    _recorded_sessions.add(session_id)
                    waktu = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    korelasi = f" | Correlated Tampering: {', '.join(fim_mods)}" if fim_mods else ""
                    baris_log = f"[{waktu}] PROTOCOL: {proto} | REMOTE_HOST: {remote_ip}:{remote_port} | PID: {pid} | STATUS: {status}{korelasi}\n"
                    try:
                        with open(LOG_FILE, "a", encoding="utf-8") as f:
                            f.write(baris_log)
                    except Exception:
                        pass
                        
                active_sessions.append({
                    "protocol": proto,
                    "local_port": laddr.port,
                    "remote_ip": remote_ip,
                    "remote_port": remote_port,
                    "status": status,
                    "pid": pid or "N/A",
                    "process_name": pname,
                    "correlated_tampering": fim_mods if status == "ESTABLISHED" else []
                })
    except Exception:
        pass
        
    return active_sessions

def get_historical_access_logs():
    """Membaca riwayat log jejak akses jarak jauh dari berkas penyimpanan persisten."""
    if not os.path.exists(LOG_FILE):
        return []
        
    logs = []
    try:
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            lines = f.readlines()
            for line in reversed(lines):
                line = line.strip()
                if line:
                    logs.append(line)
    except Exception:
        pass
    return logs[:100]  # Kembalikan maksimal 100 baris terbaru

def terminate_remote_session(pid):
    """Memutuskan paksa koneksi penyusup dengan menghentikan proses host (Kill PID)."""
    try:
        return terminate_service(int(pid))
    except Exception as e:
        return {"status": "error", "message": f"Gagal memutus sesi jarak jauh: {str(e)}"}

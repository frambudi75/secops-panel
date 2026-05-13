import psutil
import os

def get_system_metrics():
    """Mengambil metrik sumber daya sistem utama secara aman (mendukung Windows & Linux)."""
    try:
        cpu_usage = psutil.cpu_percent(interval=0.1)
        ram = psutil.virtual_memory()
        # Ambil partisi root atau drive utama
        disk = psutil.disk_usage(os.path.abspath(os.sep))
        
        return {
            "cpu_percent": cpu_usage,
            "ram_percent": ram.percent,
            "ram_used_mb": round(ram.used / (1024 * 1024), 1),
            "ram_total_mb": round(ram.total / (1024 * 1024), 1),
            "disk_percent": disk.percent,
            "disk_free_gb": round(disk.free / (1024**3), 1),
            "status": "Optimal" if cpu_usage < 85 and ram.percent < 90 else "Warning"
        }
    except Exception as e:
        return {
            "cpu_percent": 0,
            "ram_percent": 0,
            "ram_used_mb": 0,
            "ram_total_mb": 0,
            "disk_percent": 0,
            "disk_free_gb": 0,
            "status": "Error",
            "error": str(e)
        }

def get_running_services(limit=150):
    """Mengambil daftar proses/service yang aktif di sistem, diurutkan dari konsumsi memori tertinggi."""
    services = []
    for proc in psutil.process_iter(['pid', 'name', 'status', 'memory_info']):
        try:
            info = proc.info
            mem_mb = round(info['memory_info'].rss / (1024 * 1024), 2) if info['memory_info'] else 0
            
            # Percantik representasi status
            status_text = str(info['status']).capitalize()
            
            services.append({
                "pid": info['pid'],
                "name": info['name'] or "Unknown Service",
                "status": status_text,
                "memory_mb": mem_mb
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
            
    # Urutkan berdasarkan memori terbesar
    services = sorted(services, key=lambda x: x['memory_mb'], reverse=True)[:limit]
    return services

def terminate_service(pid):
    """Menghentikan paksa proses host berdasarkan PID secara aman."""
    try:
        proc = psutil.Process(pid)
        name = proc.name()
        proc.terminate() # Kirim sinyal SIGTERM
        return {"status": "success", "message": f"Proses '{name}' (PID: {pid}) berhasil dihentikan."}
    except psutil.NoSuchProcess:
        return {"status": "error", "message": f"Proses dengan PID {pid} tidak lagi aktif."}
    except psutil.AccessDenied:
        return {"status": "error", "message": f"Akses ditolak menghentikan PID {pid}. Diperlukan hak akses setingkat Administrator/Root."}
    except Exception as e:
        return {"status": "error", "message": f"Gagal menghentikan proses: {str(e)}"}


import psutil
import socket
import time

# Cache kalkulasi laju kecepatan lalu lintas jaringan (stateful speedometer)
_last_net_io = None
_last_net_time = 0

def get_network_connections():
    """Mengekstraksi koneksi TCP/UDP host, port terbuka, dan nama proses terkait secara real-time."""
    hasil = []
    proc_names = {}
    for p in psutil.process_iter(['pid', 'name']):
        try:
            proc_names[p.info['pid']] = p.info['name']
        except Exception:
            pass
            
    try:
        for conn in psutil.net_connections(kind='inet'):
            laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "Unknown"
            raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "None"
            
            status = conn.status if conn.status else "NONE"
            proto = "UDP" if conn.type == socket.SOCK_DGRAM else "TCP"
            
            app_name = proc_names.get(conn.pid, "System / Administrator Socket") if conn.pid else "System / Kernel"
            
            hasil.append({
                "protocol": proto,
                "local_address": laddr,
                "remote_address": raddr,
                "status": status,
                "pid": conn.pid or "N/A",
                "process_name": app_name
            })
    except Exception:
        pass
        
    return hasil

def get_network_traffic():
    """Mengukur kecepatan unggah/unduh aktual dan rekapitulasi volume lalu lintas jaringan host."""
    global _last_net_io, _last_net_time
    
    try:
        current_io = psutil.net_io_counters()
        current_time = time.time()
        
        if _last_net_io is None:
            _last_net_io = current_io
            _last_net_time = current_time
            return {
                "upload_speed_kbs": 0.0,
                "download_speed_kbs": 0.0,
                "total_bytes_sent": current_io.bytes_sent,
                "total_bytes_recv": current_io.bytes_recv,
                "total_packets": current_io.packets_sent + current_io.packets_recv
            }
            
        delta_time = current_time - _last_net_time
        if delta_time <= 0: delta_time = 1.0
        
        # Kalkulasi kecepatan laju transfer data dalam satuan KB/s
        up_speed = (current_io.bytes_sent - _last_net_io.bytes_sent) / delta_time / 1024.0
        down_speed = (current_io.bytes_recv - _last_net_io.bytes_recv) / delta_time / 1024.0
        
        if up_speed < 0: up_speed = 0.0
        if down_speed < 0: down_speed = 0.0
        
        _last_net_io = current_io
        _last_net_time = current_time
        
        return {
            "upload_speed_kbs": round(up_speed, 2),
            "download_speed_kbs": round(down_speed, 2),
            "total_bytes_sent": current_io.bytes_sent,
            "total_bytes_recv": current_io.bytes_recv,
            "total_packets": current_io.packets_sent + current_io.packets_recv
        }
    except Exception:
        return {
            "upload_speed_kbs": 0.0,
            "download_speed_kbs": 0.0,
            "total_bytes_sent": 0,
            "total_bytes_recv": 0,
            "total_packets": 0
        }

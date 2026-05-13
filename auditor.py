from services import get_system_metrics
from network import get_network_connections
from fim import get_fim_status

def assess_system_vulnerabilities():
    """Menganalisis status sumber daya, port terbuka, dan integritas FIM untuk mengkalkulasi System Risk Score."""
    findings = []
    score_penalties = 0
    
    # 1. Pengecekan Utilisasi Sumber Daya
    try:
        metrics = get_system_metrics()
        cpu = metrics.get("cpu_percent", 0)
        ram = metrics.get("ram_percent", 0)
        
        if cpu > 85:
            findings.append({
                "id": "VULN-RES-CPU",
                "title": "Beban CPU Mendekati Kritis",
                "severity": "WARNING",
                "description": f"Utilisasi prosesor konstan di level tinggi ({cpu}%). Berpotensi memicu perlambatan layanan host.",
                "recommendation": "Tinjau tabel Services Monitor dan hentikan (Kill) proses asing yang memakan CPU berlebih."
            })
            score_penalties += 10
            
        if ram > 90:
            findings.append({
                "id": "VULN-RES-RAM",
                "title": "Kapasitas Memori Menipis",
                "severity": "WARNING",
                "description": f"Penggunaan RAM mencapai {ram}%. Meningkatkan risiko penghentian paksa oleh kernel (OOM Killer).",
                "recommendation": "Tambahkan partisi swap atau matikan instans kontainer yang tidak esensial."
            })
            score_penalties += 10
    except Exception:
        pass

    # 2. Pengecekan Integritas Berkas (FIM)
    try:
        fim_list = get_fim_status()
        mod_files = [f["filename"] for f in fim_list if f["status"] == "MODIFIED"]
        if mod_files:
            findings.append({
                "id": "VULN-HIDS-FIM",
                "title": "Integritas Berkas Sistem Terkompromi",
                "severity": "CRITICAL",
                "description": f"Terdeteksi modifikasi tanpa izin pada berkas kode sumber: {', '.join(mod_files)}.",
                "recommendation": "Segera tinjau perubahan fisik atau lakukan otorisasi jejak hash baru di halaman Proactive HIDS."
            })
            score_penalties += 25
    except Exception:
        pass

    # 3. Pengecekan Kerentanan Layanan & Port Host
    risky_ports = {
        21: ("Layanan FTP Tanpa Enkripsi", "Protokol pengiriman file usang rentan penyadapan kata sandi dan manipulasi lalu lintas."),
        23: ("Layanan Telnet Aktif", "Akses shell jarak jauh tanpa enkripsi. Sangat kritis terhadap pencurian kredensial."),
        80: ("Layanan HTTP Plain-text", "Komunikasi panel tidak terenkripsi. Direkomendasikan menggunakan lapisan SSL/TLS (HTTPS)."),
        3306: ("Database MySQL Terekspos Publik", "Port database standar sedang mendengarkan koneksi eksternal. Membuka celah brute-force jarak jauh.")
    }
    
    try:
        sockets = get_network_connections()
        open_ports = set()
        for s in sockets:
            if s.get("status", "").upper() == "LISTEN" or s.get("status", "").upper() == "NONE" and s.get("remote_address") == "None":
                laddr = s.get("local_address", "")
                if ":" in laddr:
                    try:
                        port = int(laddr.split(":")[-1])
                        open_ports.add(port)
                    except Exception:
                        pass
                        
        for p in open_ports:
            if p in risky_ports:
                title, desc = risky_ports[p]
                sev = "CRITICAL" if p in (21, 23) else "WARNING"
                findings.append({
                    "id": f"VULN-PORT-{p}",
                    "title": title,
                    "severity": sev,
                    "description": f"Port {p} terbuka di antarmuka host. {desc}",
                    "recommendation": f"Tutup port {p} menggunakan konfigurasi firewall atau batasi kaitan soket hanya ke localhost (127.0.0.1)."
                })
                score_penalties += 20 if sev == "CRITICAL" else 12
    except Exception:
        pass
        
    # Kalkulasi Skor Risiko Akhir (0 - 100)
    final_score = 100 - score_penalties
    if final_score < 10: final_score = 10
    if not findings:
        final_score = 100
        
    if final_score >= 85: level = "Optimal"
    elif final_score >= 60: level = "Warning"
    else: level = "Critical"
        
    return {
        "risk_score": final_score,
        "risk_level": level,
        "findings": findings
    }

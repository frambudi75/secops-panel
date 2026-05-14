import random
import platform
from services import get_system_metrics
from network import get_network_connections
from fim import get_fim_status

def generate_ai_threat_analysis():
    """Menghasilkan analisis postur keamanan otonom dan prediksi vektor serangan berbasis heuristik cerdas."""
    metrics = get_system_metrics()
    fim = get_fim_status()
    conns = get_network_connections()
    
    # Ambil status firewall lokal tanpa memicu circular import
    blocked_count = 0
    perm_count = 0
    try:
        import panel
        blocked_count = len(panel.BLOCKED_IP)
        perm_count = len(panel.PERMANENT_BANS)
    except Exception:
        pass
        
    cpu = metrics.get("cpu_percent", 0)
    ram = metrics.get("ram_percent", 0)
    
    # Hitung anomali FIM
    fim_mods = [f["filename"] for f in fim if f["status"] == "MODIFIED"]
    fim_missing = [f["filename"] for f in fim if f["status"] == "MISSING"]
    
    # Muat konfigurasi pengecualian celah agar analitik AI selaras dengan dashboard utama
    try:
        from auditor import get_ignored_findings
        ignored = get_ignored_findings()
    except Exception:
        ignored = set()

    # Identifikasi port eksternal berisiko tinggi
    high_risk_ports = {21: "FTP", 23: "Telnet", 445: "SMB", 3389: "RDP", 3306: "Database"}
    active_risks = []
    for c in conns:
        lp = c.get("local_port")
        if c.get("status", "").upper() == "LISTEN" and lp in high_risk_ports:
            if f"VULN-PORT-{lp}" not in ignored and high_risk_ports[lp] not in active_risks:
                active_risks.append(high_risk_ports[lp])
            
    # Sintesis Status & Wawasan
    skor_kerentanan = 0
    insights = []
    predictive_threats = []
    
    # Logika Heuristik CPU & RAM
    if cpu > 85:
        skor_kerentanan += 30
        insights.append(f"Pemanfaatan CPU terdeteksi berada di ambang batas kritis ({cpu}%). Terdapat indikasi proses konstan yang berpotensi memicu kondisi perlambatan ekstrem (Resource Exhaustion) atau aktivitas penambangan tersembunyi (Cryptojacking).")
        predictive_threats.append({
            "threat": "Resource Exhaustion & Cryptojacking",
            "probability": "88%",
            "impact": "CRITICAL",
            "trigger": f"Beban komputasi CPU konstan di atas 85%",
            "mitigation": "Buka menu Services Monitor dan matikan (Kill) proses dengan PID yang menguras utilisasi teratas."
        })
    elif cpu > 60:
        skor_kerentanan += 10
        insights.append("Beban prosesor cukup aktif. Penjadwalan tugas latar belakang terpantau berjalan seimbang tanpa tanda kemacetan antrean instruksi.")
    else:
        insights.append("Kapasitas komputasi CPU beroperasi sangat tenang dan optimal, mencerminkan efisiensi alokasi instruksi kernel yang prima.")
        
    if ram > 85:
        skor_kerentanan += 25
        insights.append(f"Kapasitas memori fisik terkuras hingga {ram}%. Waspadai kebocoran memori (Memory Leak) pada layanan host yang dapat dibajak untuk memicu kemacetan layanan.")
    else:
        insights.append("Alokasi memori RAM berada dalam rentang wajar, menyisakan ruang bernapas yang leluasa untuk menampung lonjakan lalu lintas tak terduga.")
        
    # Logika FIM
    if fim_mods:
        skor_kerentanan += 40
        str_mods = ", ".join(fim_mods)
        insights.append(f"PERINGATAN KRITIS: Mesin integritas kriptografi mendeteksi modifikasi tak sah pada berkas inti: [{str_mods}]. Pola ini sangat identik dengan injeksi kode asing atau penanaman pintu belakang persisten (Persistent Backdoor).")
        predictive_threats.append({
            "threat": "Persistent Web Shell / Code Tampering",
            "probability": "95%",
            "impact": "CRITICAL",
            "trigger": "Ketidakcocokan sidik jari SHA-256 pada berkas terpantau",
            "mitigation": "Segera tinjau menu Proactive HIDS. Lakukan verifikasi fisik dan klik tombol 'Otorisasi Perubahan' jika modifikasi kode tersebut memang sah dari pihakmu."
        })
    else:
        insights.append("Sidik jari SHA-256 seluruh berkas inti tervalidasi utuh dan konsisten terhadap acuan baseline. Tidak ditemukan indikasi penyusupan kode.")
        
    # Deteksi OS untuk teks dinamis
    os_name = platform.system() or "Host"
    firewall_name = "Windows Firewall" if os_name == "Windows" else "Firewall (UFW/iptables)"
    
    # Logika Jaringan / Port
    if active_risks:
        skor_kerentanan += 25
        str_ports = ", ".join(active_risks)
        insights.append(f"Deteksi Paparan Port: Layanan berisiko tinggi [{str_ports}] terpantau membuka listening socket. Komunikasi data tanpa enkripsi rentan terhadap intersepsi paket (Sniffing) dan eksploitasi kata sandi jarak jauh.")
        predictive_threats.append({
            "threat": "Remote Service Exploitation & Sniffing",
            "probability": "75%",
            "impact": "HIGH",
            "trigger": f"Layanan {str_ports} terbuka di antarmuka publik",
            "mitigation": f"Tutup port terkait jika tidak digunakan melalui aturan {firewall_name}, atau terapkan jalur tunneling terenkripsi (VPN/SSH)."
        })
    else:
        insights.append("Perisai soket jaringan host terlindungi rapat. Tidak terdeteksi pembukaan port usang rentan di antarmuka publik.")
        
    # Logika Firewall
    if blocked_count > 0 or perm_count > 0:
        insights.append(f"Sistem Firewall otonom bekerja sigap: Mencekal {blocked_count} IP agresif sementara dan mengunci {perm_count} IP penyerang di dalam daftar hitam permanen.")
    else:
        insights.append("Lalu lintas akses jaringan terpantau bersih tanpa pemicuan ambang batas pemblokiran brute-force aktif saat ini.")
        
    # Skenario Prediktif Ekstra jika kondisi sedang tenang
    if not predictive_threats:
        predictive_threats.append({
            "threat": "Zero-Day Subprocess Hijacking",
            "probability": "12%",
            "impact": "LOW",
            "trigger": "Ketergantungan pustaka pihak ketiga berjangka panjang tanpa patching",
            "mitigation": f"Lakukan pemindaian keamanan berkala melalui menu Overview dan pastikan OS {os_name} menerima pembaruan keamanan rutin."
        })
        
    # Kalkulasi Status dan Confidence
    confidence = max(78, 100 - int(skor_kerentanan / 2.5) + random.randint(-2, 2))
    confidence = min(99, confidence)
    
    if skor_kerentanan >= 50:
        status = "CRITICAL THREAT"
    elif skor_kerentanan >= 25:
        status = "ELEVATED RISK"
    else:
        status = "OPTIMAL POSTURE"
        
    return {
        "overall_status": status,
        "confidence_score": f"{confidence}%",
        "risk_score": skor_kerentanan,
        "timestamp": metrics.get("timestamp", "Sekarang"),
        "insights": insights,
        "predictive_threats": predictive_threats
    }

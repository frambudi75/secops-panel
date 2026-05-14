from flask import Flask, render_template, request, redirect, session, jsonify
from main import run_scan, get_status_ringkas
from services import get_system_metrics, get_running_services, terminate_service
from logger import baca_konten_log, dapatkan_daftar_laporan, tulis_log_internal
from containers import get_docker_containers, perform_container_action
from network import get_network_connections, get_network_traffic, perform_speedtest, lookup_ip_details, get_local_ip
from fim import get_fim_status, authorize_file_update
from auditor import assess_system_vulnerabilities
from terminal import execute_system_command
from ai_advisor import generate_ai_threat_analysis
from access_auditor import detect_remote_sessions, get_historical_access_logs, terminate_remote_session
import os
import time
import platform
from datetime import datetime, timedelta
from dotenv import load_dotenv
import asyncio
from threading import Thread

load_dotenv()
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", os.urandom(24))

USER = os.getenv("PANEL_USER", "admin")
PASS = os.getenv("PANEL_PASS", "admin123")
TOKEN = os.getenv("TELEGRAM_TOKEN")
CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")
LOGIN_ATTEMPT = {}
BLOCKED_IP = {}
PERMANENT_BANS = {}

os.makedirs("logs", exist_ok=True)
os.makedirs("reports", exist_ok=True)
tulis_log_internal("[SISTEM] Subsistem Remote Access Auditor Berjalan Penuh.")

@app.context_processor
def inject_global_context():
    return dict(
        os_name=platform.system() or "Linux",
        local_ip=get_local_ip()
    )

@app.route("/", methods=["GET", "POST"])
def login():
    if session.get("logged_in"): return redirect("/dashboard")
        
    ip = request.remote_addr
    
    if ip in PERMANENT_BANS:
        tulis_log_internal(f"[FIREWALL] Penolakan instan terhadap IP Blacklist: {ip}.")
        return render_template("login.html", error="Akses IP Anda telah DIBLOKIR PERMANEN oleh Administrator.")
        
    if BLOCKED_IP.get(ip) and datetime.now() < BLOCKED_IP[ip]:
        sisa = (BLOCKED_IP[ip] - datetime.now()).seconds
        return render_template("login.html", error=f"Akses IP diblokir sementara. Coba lagi dalam {sisa} detik.")

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        
        if username == USER and password == PASS:
            session["logged_in"] = True
            LOGIN_ATTEMPT[ip] = 0
            tulis_log_internal(f"[AUTH] Autentikasi berhasil dari IP {ip}.")
            return redirect("/dashboard")
        else:
            LOGIN_ATTEMPT[ip] = LOGIN_ATTEMPT.get(ip, 0) + 1
            tulis_log_internal(f"[AUTH] Upaya masuk ilegal ({LOGIN_ATTEMPT[ip]}x) dari IP {ip}.")
            if LOGIN_ATTEMPT[ip] >= 3:
                BLOCKED_IP[ip] = datetime.now().replace(microsecond=0) + timedelta(minutes=5)
                tulis_log_internal(f"[FIREWALL] IP {ip} diblokir selama 5 menit akibat brute-force.")
            return render_template("login.html", error="Kredensial tidak tepat!")
            
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    tulis_log_internal("[AUTH] Sesi diakhiri.")
    return redirect("/")

@app.route("/dashboard")
def dashboard():
    if not session.get("logged_in"): return redirect("/")
    return render_template("index.html")

@app.route("/services")
def services_page():
    if not session.get("logged_in"): return redirect("/")
    return render_template("services.html")

@app.route("/containers")
def containers_page():
    if not session.get("logged_in"): return redirect("/")
    return render_template("containers.html")

@app.route("/network")
def network_page():
    if not session.get("logged_in"): return redirect("/")
    return render_template("network.html")

@app.route("/security")
def security_page():
    if not session.get("logged_in"): return redirect("/")
    return render_template("security.html")

@app.route("/ai-advisor")
def ai_advisor_page():
    if not session.get("logged_in"): return redirect("/")
    return render_template("ai_advisor.html")

@app.route("/access-auditor")
def access_auditor_page():
    if not session.get("logged_in"): return redirect("/")
    return render_template("access_auditor.html")

@app.route("/speedtest")
def speedtest_page():
    if not session.get("logged_in"): return redirect("/")
    return render_template("speedtest.html")

@app.route("/ip-lookup")
def ip_lookup_page():
    if not session.get("logged_in"): return redirect("/")
    return render_template("ip_lookup.html")

@app.route("/console")
def console_page():
    if not session.get("logged_in"): return redirect("/")
    return render_template("console.html")

@app.route("/logs")
def logs_page():
    if not session.get("logged_in"): return redirect("/")
    return render_template("logs.html", laporan_list=dapatkan_daftar_laporan())

@app.route("/settings", methods=["GET", "POST"])
def settings_page():
    if not session.get("logged_in"): return redirect("/")
    
    success_msg = None
    error_msg = None
    global USER, PASS, TOKEN, CHAT_ID
    
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        telegram_token = request.form.get("telegram_token", "").strip()
        telegram_chat_id = request.form.get("telegram_chat_id", "").strip()
        discord_webhook = request.form.get("discord_webhook", "").strip()
        
        # Update memori aplikasi secara live
        if username: USER = username
        if password: PASS = password
        if telegram_token: TOKEN = telegram_token
        if telegram_chat_id: CHAT_ID = telegram_chat_id
        
        # Update os.environ agar fungsi-fungsi lain dan notifier.py seketika mengadopsi
        if username: os.environ["PANEL_USER"] = username
        if password: os.environ["PANEL_PASS"] = password
        if telegram_token: os.environ["TELEGRAM_TOKEN"] = telegram_token
        if telegram_chat_id: os.environ["TELEGRAM_CHAT_ID"] = telegram_chat_id
        os.environ["DISCORD_WEBHOOK"] = discord_webhook
        
        # Tulis secara persisten ke dalam berkas .env lokal
        try:
            import dotenv
            env_path = os.path.join(os.getcwd(), ".env")
            if not os.path.exists(env_path):
                with open(env_path, "w") as f:
                    f.write("# Konfigurasi SecOps Panel\n")
            if username: dotenv.set_key(env_path, "PANEL_USER", username)
            if password: dotenv.set_key(env_path, "PANEL_PASS", password)
            if telegram_token: dotenv.set_key(env_path, "TELEGRAM_TOKEN", telegram_token)
            if telegram_chat_id: dotenv.set_key(env_path, "TELEGRAM_CHAT_ID", telegram_chat_id)
            dotenv.set_key(env_path, "DISCORD_WEBHOOK", discord_webhook)
            
            success_msg = "Kredensial dan API Key berhasil diperbarui! Efek langsung aktif tanpa restart server."
            tulis_log_internal("[PENGATURAN] Kredensial dan saluran notifikasi ganda diperbarui secara visual.")
        except Exception as e:
            error_msg = f"Gagal menulis ke berkas .env: {str(e)}"
            tulis_log_internal(f"[ERROR] Kegagalan pembaruan file .env: {str(e)}")

    cfg = {
        "username": USER,
        "telegram_token": os.getenv("TELEGRAM_TOKEN", ""),
        "telegram_chat_id": os.getenv("TELEGRAM_CHAT_ID", ""),
        "discord_webhook": os.getenv("DISCORD_WEBHOOK", "")
    }
    return render_template("settings.html", config=cfg, success_msg=success_msg, error_msg=error_msg)

@app.route("/scan", methods=["POST"])
def scan():
    if not session.get("logged_in"): return jsonify({"error": "Unauthorized"}), 401
    tulis_log_internal("[SCAN] Pemindaian anomali dipicu manual via antarmuka web.")
    try:
        run_scan()
        return jsonify({"status": "success", "message": "Instruksi pemindaian selesai dieksekusi!"})
    except Exception as e:
        tulis_log_internal(f"[ERROR] Gagal menjalankan subsistem scan: {str(e)}")
        return jsonify({"status": "error", "message": str(e)}), 500


# --- REST API ENDPOINTS ---
@app.route("/api/stats")
def api_stats():
    if not session.get("logged_in"): return jsonify({"error": "Unauthorized"}), 401
    return jsonify(get_system_metrics())

@app.route("/api/services")
def api_services():
    if not session.get("logged_in"): return jsonify({"error": "Unauthorized"}), 401
    limit = request.args.get("limit", 150, type=int)
    return jsonify(get_running_services(limit))

@app.route("/api/services/kill", methods=["POST"])
def api_kill_service():
    if not session.get("logged_in"): return jsonify({"error": "Unauthorized"}), 401
    data = request.get_json() or {}
    pid = data.get("pid")
    if not pid: return jsonify({"status": "error", "message": "PID tidak disediakan."}), 400
    tulis_log_internal(f"[ACTION] Perintah penghentian proses (Kill) ditujukan ke PID {pid}.")
    return jsonify(terminate_service(int(pid)))

@app.route("/api/containers")
def api_containers():
    if not session.get("logged_in"): return jsonify({"error": "Unauthorized"}), 401
    return jsonify(get_docker_containers())

@app.route("/api/containers/action", methods=["POST"])
def api_container_action():
    if not session.get("logged_in"): return jsonify({"error": "Unauthorized"}), 401
    data = request.get_json() or {}
    cid = data.get("id")
    aksi = data.get("action")
    if not cid or not aksi: return jsonify({"status": "error", "message": "Parameter tidak lengkap."}), 400
    tulis_log_internal(f"[DOCKER] Mengirim sinyal aksi '{aksi}' ke kontainer ID {cid}.")
    return jsonify(perform_container_action(cid, aksi))

@app.route("/api/network")
def api_network():
    if not session.get("logged_in"): return jsonify({"error": "Unauthorized"}), 401
    return jsonify(get_network_connections())

@app.route("/api/traffic")
def api_traffic():
    if not session.get("logged_in"): return jsonify({"error": "Unauthorized"}), 401
    return jsonify(get_network_traffic())

@app.route("/api/security/fim")
def api_fim():
    if not session.get("logged_in"): return jsonify({"error": "Unauthorized"}), 401
    return jsonify(get_fim_status())

@app.route("/api/security/fim/update", methods=["POST"])
def api_fim_update():
    if not session.get("logged_in"): return jsonify({"error": "Unauthorized"}), 401
    data = request.get_json() or {}
    fn = data.get("filename")
    if not fn: return jsonify({"status": "error", "message": "Nama berkas tidak disuplai."}), 400
    tulis_log_internal(f"[HIDS] Memperbarui acuan baseline hash untuk berkas '{fn}'.")
    return jsonify(authorize_file_update(fn))

@app.route("/api/security/firewall")
def api_firewall():
    if not session.get("logged_in"): return jsonify({"error": "Unauthorized"}), 401
    hasil = []
    now = datetime.now()
    for ip, untill in list(BLOCKED_IP.items()):
        if now < untill:
            sisa = (untill - now).seconds
            hasil.append({"ip": ip, "type": "Temporary Ban (Brute-force)", "expires_in": f"{sisa} detik", "reason": "Upaya login ilegal >= 3x"})
    for ip, reason in PERMANENT_BANS.items():
        hasil.append({"ip": ip, "type": "Permanent Blacklist", "expires_in": "Selamanya", "reason": reason})
    return jsonify(hasil)

@app.route("/api/security/firewall/ban", methods=["POST"])
def api_firewall_ban():
    if not session.get("logged_in"): return jsonify({"error": "Unauthorized"}), 401
    data = request.get_json() or {}
    ip = data.get("ip")
    alasan = data.get("reason", "Anomali terdeteksi oleh Administrator")
    if not ip: return jsonify({"status": "error", "message": "Alamat IP wajib diisi."}), 400
    PERMANENT_BANS[ip] = alasan
    tulis_log_internal(f"[FIREWALL] IP '{ip}' resmi didaftarkan ke Blacklist Permanen. Alasan: {alasan}")
    return jsonify({"status": "success", "message": f"IP {ip} berhasil diblokir permanen."})

@app.route("/api/security/firewall/unban", methods=["POST"])
def api_firewall_unban():
    if not session.get("logged_in"): return jsonify({"error": "Unauthorized"}), 401
    data = request.get_json() or {}
    ip = data.get("ip")
    if not ip: return jsonify({"status": "error", "message": "Alamat IP wajib disuplai."}), 400
    
    dihapus = False
    if ip in PERMANENT_BANS:
        del PERMANENT_BANS[ip]
        dihapus = True
    if ip in BLOCKED_IP:
        del BLOCKED_IP[ip]
        dihapus = True
        
    if dihapus:
        tulis_log_internal(f"[FIREWALL] Akses blokir untuk IP '{ip}' resmi DICABUT.")
        return jsonify({"status": "success", "message": f"Blokir IP {ip} berhasil dicabut."})
    return jsonify({"status": "error", "message": f"IP {ip} tidak terdaftar dalam pemblokiran."})

# Endpoints Kerentanan, AI Advisor, Access Auditor, Ekspor, & Console Shell
@app.route("/api/auditor/assessment")
def api_auditor_assessment():
    if not session.get("logged_in"): return jsonify({"error": "Unauthorized"}), 401
    return jsonify(assess_system_vulnerabilities())

@app.route("/api/ai/analyze")
def api_ai_analyze():
    if not session.get("logged_in"): return jsonify({"error": "Unauthorized"}), 401
    tulis_log_internal("[AI-ADVISOR] Menerbitkan laporan cerdas prediktif ancaman masa depan.")
    return jsonify(generate_ai_threat_analysis())

@app.route("/api/audit/access")
def api_audit_access():
    if not session.get("logged_in"): return jsonify({"error": "Unauthorized"}), 401
    return jsonify({
        "active_sessions": detect_remote_sessions(),
        "historical_logs": get_historical_access_logs()
    })

@app.route("/api/audit/access/kill", methods=["POST"])
def api_audit_access_kill():
    if not session.get("logged_in"): return jsonify({"error": "Unauthorized"}), 401
    data = request.get_json() or {}
    pid = data.get("pid")
    if not pid: return jsonify({"status": "error", "message": "PID sesi tidak disuplai."}), 400
    tulis_log_internal(f"[ACCESS-AUDITOR] Menghentikan paksa sesi remote pada PID {pid}.")
    return jsonify(terminate_remote_session(pid))

@app.route("/api/report/export")
def api_report_export():
    if not session.get("logged_in"): return jsonify({"error": "Unauthorized"}), 401
    
    laporan = {
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "system_metrics": get_system_metrics(),
        "vulnerability_assessment": assess_system_vulnerabilities(),
        "ai_threat_intelligence": generate_ai_threat_analysis(),
        "remote_access_audit": detect_remote_sessions(),
        "file_integrity_monitoring": get_fim_status(),
        "docker_ecosystem": get_docker_containers(),
        "network_bandwidth": get_network_traffic(),
        "firewall_rules": {
            "temporarily_blocked": list(BLOCKED_IP.keys()),
            "permanent_blacklist": PERMANENT_BANS
        }
    }
    
    response = jsonify(laporan)
    response.headers["Content-Disposition"] = "attachment; filename=secops_audit_report.json"
    return response

@app.route("/api/console/run", methods=["POST"])
def api_console_run():
    if not session.get("logged_in"): return jsonify({"error": "Unauthorized"}), 401
    data = request.get_json() or {}
    cmd = data.get("command", "")
    tulis_log_internal(f"[CONSOLE] Eksekusi shell instruksi OS: '{cmd}'")
    return jsonify(execute_system_command(cmd))

@app.route("/api/logs")
def api_logs():
    if not session.get("logged_in"): return jsonify({"error": "Unauthorized"}), 401
    tipe = request.args.get("type", "assistant")
    return jsonify({"content": baca_konten_log(tipe)})
@app.route("/api/speedtest")
def api_speedtest():
    if not session.get("logged_in"): return jsonify({"error": "Unauthorized"}), 401
    tulis_log_internal("[SPEEDTEST] Pengujian bandwidth jaringan dan latensi ping dipicu.")
    return jsonify(perform_speedtest())

@app.route("/api/ip-lookup")
def api_ip_lookup():
    if not session.get("logged_in"): return jsonify({"error": "Unauthorized"}), 401
    ip_target = request.args.get("ip", "")
    tulis_log_internal(f"[IP-LOOKUP] Menelusuri reputasi dan geolokasi alamat IP: '{ip_target or 'Server Host'}'")
    return jsonify(lookup_ip_details(ip_target))


# --- DAEMON PENGAWAS SUMBER DAYA & HIDS OTOMATIS (WATCHDOG) ---
def resource_and_hids_watchdog():
    time.sleep(15)
    high_cpu_counter = 0
    reported_mods = set()
    
    while True:
        try:
            metrics = get_system_metrics()
            cpu = metrics.get("cpu_percent", 0)
            ram = metrics.get("ram_percent", 0)
            
            if cpu > 90: high_cpu_counter += 1
            else: high_cpu_counter = 0
                
            if high_cpu_counter >= 3:
                pesan_darurat = f"⚠️ [WATCHDOG ALERT] Beban utilisasi CPU konstan di level Kritis: {cpu}%! Kapasitas memori: {ram}%."
                tulis_log_internal(pesan_darurat)
                from notifier import kirim_notifikasi_telegram
                kirim_notifikasi_telegram(pesan_darurat)
                high_cpu_counter = 0
                
            fim_list = get_fim_status()
            for item in fim_list:
                fn = item["filename"]
                if item["status"] == "MODIFIED" and fn not in reported_mods:
                    pesan_fim = f"🚨 [HIDS INTRUSION ALERT] Berkas sistem krusial terdeteksi mengalami PERUBAHAN TANPA IZIN: {fn}! Jejak hash fisik tidak cocok dengan acuan baseline."
                    tulis_log_internal(pesan_fim)
                    from notifier import kirim_notifikasi_telegram
                    kirim_notifikasi_telegram(pesan_fim)
                    reported_mods.add(fn)
                elif item["status"] == "SECURE" and fn in reported_mods:
                    reported_mods.remove(fn)
                    
            # Pemicu pengawasan sesi remote latar belakang
            detect_remote_sessions()
        except Exception:
            pass
        time.sleep(60)

Thread(target=resource_and_hids_watchdog, daemon=True).start()


# --- TELEGRAM BOT DAEMON ---
if TOKEN:
    try:
        from telegram import Update
        from telegram.ext import ApplicationBuilder, CommandHandler, ContextTypes
        
        async def scan_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
            run_scan()
            await update.message.reply_text("✅ Pemindaian selesai. Catatan log diperbarui.")

        async def status_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
            await update.message.reply_text(f"📊 Laporan Server Terkini:\n{get_status_ringkas()}")

        async def log_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
            await update.message.reply_text(f"📝 Log Aktivitas:\n{baca_konten_log('assistant', max_lines=20)}")

        def start_bot():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            app_bot = ApplicationBuilder().token(TOKEN).build()
            app_bot.add_handler(CommandHandler("scan", scan_command))
            app_bot.add_handler(CommandHandler("status", status_command))
            app_bot.add_handler(CommandHandler("log", log_command))
            loop.run_until_complete(app_bot.initialize())
            loop.run_until_complete(app_bot.start())
            loop.run_until_complete(app_bot.updater.start_polling())
            loop.run_forever()

        Thread(target=start_bot, daemon=True).start()
        tulis_log_internal("[SISTEM] Subsistem Telegram Bot tersambung.")
    except Exception as e:
        tulis_log_internal(f"[ERROR] Telegram Bot gagal diinisialisasi: {e}")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5025)

import os
import requests
from datetime import datetime
from dotenv import load_dotenv

# Muat konfigurasi awal dari .env jika ada
load_dotenv()

def kirim_notifikasi_telegram(pesan):
    """
    Fungsi penyiar ganda (Dual Broadcaster).
    Mengirimkan sinyal siaga/notifikasi serentak ke aplikasi Telegram
    dan saluran teks Discord menggunakan format pesan embed berwarna premium.
    Mengambil token/key secara dinamis dari environment agar pembaruan via dasbor
    langsung berlaku tanpa perlu menyentuh kode sumber atau memulai ulang server.
    """
    # Ambil konfigurasi terkini
    tg_token = os.getenv("TELEGRAM_TOKEN")
    tg_chat_id = os.getenv("TELEGRAM_CHAT_ID")
    discord_url = os.getenv("DISCORD_WEBHOOK")
    
    hasil_log = []

    # 1. Siaran ke Telegram
    if tg_token and tg_chat_id and tg_token != "isi_token_bot_kamu":
        url_tg = f"https://api.telegram.org/bot{tg_token}/sendMessage"
        data_tg = {"chat_id": tg_chat_id, "text": pesan, "parse_mode": "Markdown"}
        try:
            resp = requests.post(url_tg, data=data_tg, timeout=5)
            if resp.status_code == 200:
                hasil_log.append("Telegram: Terkirim")
            else:
                hasil_log.append(f"Telegram: Gagal ({resp.status_code})")
        except Exception as e:
            hasil_log.append(f"Telegram: Error ({str(e)})")
    else:
        hasil_log.append("Telegram: Token/Chat ID tidak dikonfigurasi")

    # 2. Siaran ke Discord Webhook (Embed Premium)
    if discord_url and discord_url.startswith("http"):
        # Tentukan warna dan judul embed berdasarkan tingkat urgensi/konten pesan
        pesan_upper = pesan.upper()
        if "WATCHDOG" in pesan_upper or "UTILISASI" in pesan_upper or "KRITIS" in pesan_upper:
            judul = "⚠️ Peringatan Kritis: Utilisasi Server Tinggi"
            warna = 16753920  # Premium Amber / Orange
        elif "HIDS" in pesan_upper or "INTRUSION" in pesan_upper or "PERUBAHAN TANPA IZIN" in pesan_upper:
            judul = "🚨 Peringatan Keamanan: Modifikasi FIM Terdeteksi"
            warna = 16711680  # Premium Crimson Red
        else:
            judul = "🛡️ Pemberitahuan Sistem SecOps Panel"
            warna = 4849663   # Premium Cyber Cyan

        embed_payload = {
            "username": "SecOps Panel Sentinel",
            "avatar_url": "https://img.icons8.com/color/96/000000/cyber-security.png",
            "embeds": [
                {
                    "title": judul,
                    "description": pesan,
                    "color": warna,
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "footer": {
                        "text": "SecOps Dashboard Automated Broadcast • Dual Sentinel"
                    }
                }
            ]
        }
        try:
            resp = requests.post(discord_url, json=embed_payload, timeout=5)
            if resp.status_code in [200, 204]:
                hasil_log.append("Discord: Terkirim Embed Premium")
            else:
                hasil_log.append(f"Discord: Gagal ({resp.status_code})")
        except Exception as e:
            hasil_log.append(f"Discord: Error ({str(e)})")
    else:
        hasil_log.append("Discord: Webhook URL tidak dikonfigurasi")

    return f"[NOTIF BROADCASTER] {' | '.join(hasil_log)}"

# Alias fungsi agar nama lebih representatif untuk siaran ganda
kirim_notifikasi_ganda = kirim_notifikasi_telegram

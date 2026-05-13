import subprocess

def execute_system_command(command_str):
    """Mengeksekusi instruksi shell OS dengan batasan waktu aman (timeout)."""
    if not command_str or not command_str.strip():
        return {"status": "error", "output": "Perintah kosong."}
        
    # Penolakan perintah destruktif ekstrim atau interaktif murni yang memblokir
    forbidden = ["cmd", "powershell", "format", "del /f /s /q", "rmdir /s /q", "python -i", "diskpart"]
    lowered = command_str.lower().strip()
    
    for f in forbidden:
        if lowered.startswith(f) or lowered == f:
            return {
                "status": "error", 
                "output": f"Akses perintah interaktif atau berisiko tinggi '{f}' dicekal demi kestabilan panel."
            }
            
    try:
        # Eksekusi dengan subprocess shell asli
        result = subprocess.run(
            command_str,
            shell=True,
            capture_output=True,
            text=True,
            timeout=7
        )
        out = result.stdout.strip()
        err = result.stderr.strip()
        
        kombinasi = []
        if out: kombinasi.append(out)
        if err: kombinasi.append(f"[STDERR]\n{err}")
        
        if not kombinasi:
            return {"status": "success", "output": "[Sistem] Eksekusi tuntas tanpa keluaran teks balik."}
            
        return {"status": "success", "output": "\n\n".join(kombinasi)}
    except subprocess.TimeoutExpired:
        return {
            "status": "error", 
            "output": "Waktu eksekusi habis (Timeout melebihi 7 detik). Proses diakhiri paksa oleh kernel."
        }
    except Exception as e:
        return {"status": "error", "output": f"Gagal menjalankan perintah: {str(e)}"}

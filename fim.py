import hashlib
import os
from datetime import datetime

# Daftar berkas krusial yang dipantau integritasnya
MONITORED_FILES = [
    "requirements.txt",
    ".env",
    "main.py",
    "panel.py",
    "services.py",
    "network.py",
    "terminal.py",
    "ai_advisor.py",
    "access_auditor.py"
]

# Memori penyimpan jejak hash awal (baseline)
_baselines = {}
_last_checked = {}

def calculate_sha256(filepath):
    """Menghitung jejak hash SHA-256 murni dari isi berkas fisik."""
    if not os.path.exists(filepath):
        return None
    sha256_hash = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception:
        return None

def initialize_baselines():
    """Menginisialisasi acuan baseline hash awal untuk seluruh berkas pantauan."""
    global _baselines, _last_checked
    for f in MONITORED_FILES:
        h = calculate_sha256(f)
        if h:
            _baselines[f] = h
            _last_checked[f] = datetime.now().strftime("%H:%M:%S")

def get_fim_status():
    """Memeriksa integritas fisik terkini dan membandingkannya dengan acuan baseline."""
    global _baselines, _last_checked
    
    # Lakukan inisialisasi otomatis jika memori baseline masih kosong
    if not _baselines:
        initialize_baselines()
        
    hasil = []
    for f in MONITORED_FILES:
        current_hash = calculate_sha256(f)
        base_hash = _baselines.get(f)
        
        if current_hash is None:
            status = "MISSING"
        elif base_hash is None:
            # Daftarkan jika berkas baru tercipta
            _baselines[f] = current_hash
            _last_checked[f] = datetime.now().strftime("%H:%M:%S")
            status = "SECURE"
            base_hash = current_hash
        elif current_hash == base_hash:
            status = "SECURE"
        else:
            status = "MODIFIED"
            
        hasil.append({
            "filename": f,
            "baseline_hash": base_hash[:12] + "..." if base_hash else "N/A",
            "current_hash": current_hash[:12] + "..." if current_hash else "N/A",
            "status": status,
            "last_checked": _last_checked.get(f, datetime.now().strftime("%H:%M:%S"))
        })
    return hasil

def authorize_file_update(filename):
    """Mengotorisasi modifikasi berkas sah dengan memperbarui jejak hash acuan."""
    global _baselines, _last_checked
    if filename in MONITORED_FILES:
        h = calculate_sha256(filename)
        if h:
            _baselines[filename] = h
            _last_checked[filename] = datetime.now().strftime("%H:%M:%S")
            return {"status": "success", "message": f"Baseline acuan untuk '{filename}' resmi diperbarui."}
        else:
            return {"status": "error", "message": f"Berkas fisik '{filename}' tidak ditemukan."}
    return {"status": "error", "message": "Berkas tidak berada dalam pengawasan FIM."}

FROM python:3.9-slim

# Mencegah penulisan bytecode dan memastikan log langsung tercetak
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Memasang dependensi sistem yang dibutuhkan untuk psutil dan pemantauan jaringan
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    python3-dev \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Menyalin dan memasang pustaka Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Menyalin seluruh berkas proyek ke dalam direktori kerja kontainer
COPY . .

# Mengekspos port default antarmuka web SecOps Panel
EXPOSE 5025

# Menjalankan aplikasi utama
CMD ["python", "panel.py"]

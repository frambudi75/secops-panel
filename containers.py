def get_docker_containers():
    """Mengambil metrik dan status daftar kontainer host dari Docker socket secara riil. Tanpa mode simulasi."""
    try:
        import docker
        client = docker.from_env(timeout=3)
        containers = client.containers.list(all=True)
        
        hasil = []
        for c in containers:
            # Rangkai pemetaan port
            ports_list = []
            for p_key, p_val in c.ports.items():
                if p_val:
                    for mapping in p_val:
                        ports_list.append(f"{mapping.get('HostPort', '')}->{p_key}")
                else:
                    ports_list.append(p_key)
            
            ports_str = ", ".join(ports_list) if ports_list else "None"
            image_name = c.image.tags[0] if c.image.tags else "custom-image:latest"
            
            hasil.append({
                "id": c.short_id,
                "name": c.name,
                "status": c.status.capitalize(),
                "image": image_name,
                "ports": ports_str
            })
        return hasil
    except Exception:
        # Menghilangkan data tiruan, mengembalikan daftar kosong murni jika Docker host luring
        return []

def perform_container_action(container_id, action):
    """Menyampaikan instruksi Start/Stop/Restart secara nyata ke soket kontainer."""
    try:
        import docker
        client = docker.from_env(timeout=3)
        container = client.containers.get(container_id)
        
        if action == "start":
            container.start()
            return {"status": "success", "message": f"Kontainer '{container.name}' berhasil dinyalakan."}
        elif action == "stop":
            container.stop()
            return {"status": "success", "message": f"Kontainer '{container.name}' berhasil dihentikan."}
        elif action == "restart":
            container.restart()
            return {"status": "success", "message": f"Kontainer '{container.name}' berhasil dimulai ulang."}
        else:
            return {"status": "error", "message": "Instruksi tidak valid."}
    except Exception as e:
        # Mengembalikan error nyata jika gagal menghubungi daemon Docker
        return {
            "status": "error",
            "message": f"Koneksi ke daemon Docker gagal: {str(e)}"
        }

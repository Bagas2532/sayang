import hmac
import hashlib
import base64
import json

# Kunci rahasia yang hanya disimpan dengan aman di server
SECRET_KEY = b"super_secret_server_key_12345"

def buat_cookie_aman(payload):
    # 1. Encode data JSON ke Base64
    json_data = json.dumps(payload).encode('utf-8')
    encoded_payload = base64.b64encode(json_data)
    
    # 2. Buat tanda tangan digital berdasarkan payload dan kunci rahasia
    signature = hmac.new(SECRET_KEY, encoded_payload, hashlib.sha256).digest()
    encoded_signature = base64.b64encode(signature)
    
    # 3. Gabungkan payload dan tanda tangan dengan pemisah titik (.)
    return encoded_payload + b"." + encoded_signature

def verifikasi_cookie_aman(cookie_diterima):
    try:
        encoded_payload, encoded_signature = cookie_diterima.split(b".")
        
        # Hitung ulang tanda tangan berdasarkan payload yang diterima
        expected_signature = hmac.new(SECRET_KEY, encoded_payload, hashlib.sha256).digest()
        encoded_expected_signature = base64.b64encode(expected_signature)
        
        # Cocokkan tanda tangan secara aman untuk mencegah timing attack
        if hmac.compare_digest(encoded_signature, encoded_expected_signature):
            # Jika valid, data aman untuk di-decode dan digunakan
            decoded_data = base64.b64decode(encoded_payload)
            return json.loads(decoded_data)
        else:
            raise ValueError("Tanda tangan tidak valid! Data telah dimanipulasi.")
    except Exception:
        return "Akses Ditolak: Sesi Tidak Valid"

# --- CONTOH PENGGUNAAN ---
session_data = {"user_id": 1, "username": "guest", "role": "guest"}
cookie_untuk_klien = buat_cookie_aman(session_data)
print(f"Cookie yang dikirim ke klien: {cookie_untuk_klien.decode()}\n")

# Jika klien mencoba mengubah data secara ilegal, verifikasi akan gagal otomatis di server

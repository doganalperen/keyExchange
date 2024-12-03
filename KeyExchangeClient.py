from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization, hmac
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import sys
import random
import datetime
import requests
import json
from flask import Flask, jsonify
from flask_apscheduler import APScheduler

def load_certificate_from_file(file_path, is_der=True):
    """
    Load a certificate from a file.
    :param file_path: Path to the certificate file.
    :param is_der: True if the file is in DER format, False if it's PEM.
    :return: Loaded x509 certificate object.
    """
    with open(file_path, "rb") as f:
        cert_data = f.read()
        if is_der:
            return x509.load_der_x509_certificate(cert_data, default_backend())
        else:
            return x509.load_pem_x509_certificate(cert_data, default_backend())

def verify_certificate_chain(cert_to_verify, root_cert):
    """
    Verify if the given certificate is signed by the EC root certificate.
    :param cert_to_verify: The certificate to verify (x509.Certificate).
    :param root_cert: The root EC certificate (x509.Certificate).
    """
    # Get the root public key
    public_key = root_cert.public_key()
    
    # Ensure the public key is EC
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise ValueError("The root certificate does not contain an EC public key.")
    
    # Verify the signature on the certificate
    try:
        public_key.verify(
            cert_to_verify.signature,
            cert_to_verify.tbs_certificate_bytes,
            ec.ECDSA(SHA256())  # EC signature with SHA256
        )
        print("The certificate is valid and signed by the root EC certificate.")
    except Exception as e:
        print(f"Certificate verification failed: {e}")

    """
    Load an EC certificate from DER-encoded bytes.
    """
    # Parse the DER certificate
    cert = x509.load_der_x509_certificate(cert_der_bytes, default_backend())
    return cert

def verify_signature(cert, message, signature):
    """
    Verify a digital signature using an EC public key extracted from a certificate.
    """
    # Extract the public key from the certificate
    public_key = cert.public_key()
    
    # Verify the signature
    try:
        public_key.verify(
            signature,
            message,
            ec.ECDSA(hashes.SHA256())
        )
        print("The signature is valid.")
        return 1
    except Exception as e:
        print(f"The signature is invalid: {e}")
        return -1

# AES şifreleme için yardımcı fonksiyonlar
def convert(hex_string):
    """Hexadecimal string'i byte array'e dönüştürür."""
    result_bytes = int(hex_string, 16).to_bytes((len(hex_string) + 1) // 2, 'big')
    return result_bytes

def encrypt_data(data):
    """Veriyi AES ile şifreler."""
    AES128Secrets = {'key': 'b7f3c9576e12dd0db63e8f8fac2b9a39', 'iv': 'c80f095d8bb1a060699f7c19974a1aa0'}
    derived_key = None
    try:
        response = requests.get("http://10.1.23.142:8181/api/salt")
        while True:
            if response.status_code == 200:
                resp_dict = json.loads(response.text, strict=False)
                salt = base64.b64decode(resp_dict["salt"])
                signature = base64.b64decode(resp_dict["signature"])
                if verify_signature(cert, salt, signature) == 1:
                    derived_key = HKDF(algorithm=hashes.SHA512(), length=64, salt=salt, info='label').derive(shared_key)
                else:
                    print("Tuz Dogrulanamadi")
                    return None, None
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Tuz Aliminda Hata Olustu: {e}")
    

    # Şifreleme için gerekli key ve iv dönüşümü
    cipher = AES.new(derived_key[:16], mode=AES.MODE_CBC, iv=derived_key[16:32])
    
    # Veriyi şifreleme
    ciphertext = cipher.encrypt(pad(data.encode('utf-8'), 16))
    return ciphertext.hex()  # Şifrelenmiş veriyi hex formatında döndür

def keyExchange():
    cert = None
    shared_key = None
    derived_key = None
    try:
        response = requests.get("http://10.1.23.142:8181/api/cert")
        while True:
            if response.status_code == 200:
                cert_dict = json.loads(response.text, strict=False)
                cert_pem = cert_dict["cert"].encode()
                cert = x509.load_pem_x509_certificate(cert_pem, default_backend())
                root_cert = load_certificate_from_file("ca.crt", is_der=False)
                verify_certificate_chain(cert, root_cert)
                break
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Sertifika Aliminda Hata Olustu: {e}")
    
    try:
        eph_private_key = ec.generate_private_key(curve=curve)
        eph_public_key = private_key.public_key()
        eph_public_key_bytes = public_key.public_bytes(encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo)
        payload = {"data": eph_public_key_bytes}
        response = requests.post("http://10.1.23.142:8181/api/keyexchange", json = payload)
        while True:
            if response.status_code == 200:
                resp_dict = json.loads(response.text, strict=False)
                peer_eph_public_key_pem = base64.b64decode(resp_dict["eph_public"])
                signature = base64.b64decode(resp_dict["signature"])
                if verify_signature(cert, peer_eph_public_key_pem, signature) == 1:
                    peer_eph_public_key = serialization.load_pem_public_key(peer_eph_public_key_pem)
                    shared_key = eph_private_key.exchange(ec.ECDH(), peer_eph_public_key)
                else:
                    print("Gecici Acik Anahtar Dogrulanamadi")
                    return None, None
                break
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Gecici Acik Anahtar Aliminda Hata Olustu: {e}")
    
    try:
        response = requests.get("http://10.1.23.142:8181/api/initSalt")
        while True:
            if response.status_code == 200:
                resp_dict = json.loads(response.text, strict=False)
                salt = base64.b64decode(resp_dict["salt"])
                signature = base64.b64decode(resp_dict["signature"])
                if verify_signature(cert, salt, signature) == 1:
                    derived_key = HKDF(algorithm=hashes.SHA512(), length=64, salt=salt, info='label').derive(shared_key)
                else:
                    print("Tuz Dogrulanamadi")
                    return None, None
                break
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Tuz Aliminda Hata Olustu: {e}")
    
    try:
        msg = b'alperen'
        h = hmac.HMAC(derived_key, hashes.SHA512())
        h.update(msg)
        MAC = h.finalize()
        payload = {"data": MAC}
        response = requests.post("http://10.1.23.142:8181/api/checkhmac", json = payload)
        while True:
            if response.status_code == 200:
                resp_dict = json.loads(response.text, strict=False)
                resp_msg = resp_dict["response"].encode()
                signature = base64.b64decode(resp_dict["signature"])
                if verify_signature(cert, resp_msg, signature) == 1:
                    print(resp_msg)
                    return cert, shared_key
                else:
                    print("HMAC Desponse Dogrulanamadi")
                    return None, None
                break
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] HMAC Uretiminde Hata Olustu: {e}")

# Flask uygulaması başlatma
app = Flask(__name__)

# Zamanlanmış görevler için APScheduler yapılandırması
class Config:
    SCHEDULER_API_ENABLED = True

app.config.from_object(Config)
scheduler = APScheduler()
scheduler.init_app(app)

# JSON formatında veri saklama alanı
generated_data = []

# Hedef sunucu URL'si ve gerekli başlıklar
SERVER_URL = "http://10.1.23.142:8181/api/write"
HEADERS = {
    "Content-Type": "application/json",
    "Destination-Path": "user/hive/warehouse/sensor_data_db.db/sensor_data",
    "Filename": "sensordaily.txt",
    "Client-Secret": "BPdxa5tw738Wto4YCqZBBQuOcbW80KEX"
}

# JSON Veri Üretme ve Server'a POST Etme Fonksiyonu
def generate_and_post_data():
    global generated_data
    # Yeni veri üretimi
    data = {
        "id": len(generated_data) + 1,
        "timestamp": datetime.datetime.now().isoformat(),
        "sensor_name": f"Sensor-{random.randint(1, 10)}",
        "value": round(random.uniform(20.5, 100.0), 2)
    }
    generated_data.append(data)
    print(f"[DEBUG] Yeni Veri Üretildi: {data}")

    # Şifrelenmiş veri hazırlama
    encrypted_data = encrypt_data(str(data))
    
    # POST isteği için veriyi hazırlama
    payload = {
        "data": encrypted_data  # Şifrelenmiş veri gönderilir
    }

    # Veriyi hedef sunucuya gönderme
    try:
        response = requests.post(SERVER_URL, json=payload, headers=HEADERS)
        if response.status_code in (200, 201):
            print(f"[INFO] Veri başarıyla POST edildi: {payload}")
        else:
            print(f"[ERROR] POST işlemi başarısız oldu. Status Code: {response.status_code}, Response: {response.text}")
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Veri gönderiminde hata oluştu: {e}")

# Zamanlanmış Görev
scheduler.add_job(id='generate_data_job', func=generate_and_post_data, trigger='interval', seconds=10)

# Endpoint: Tüm JSON Veriyi Listele
@app.route('/api/data', methods=['GET'])
def get_data():
    return jsonify({"data": generated_data})


if __name__ == '__main__':
    server_cert, shared_secret = keyExchange()
    if server_cert == None and shared_secret == None:
        print("Some signature could not be verified")
    print("[DEBUG] Uygulama Başlatılıyor...")
    scheduler.start()
    app.run(host='0.0.0.0', port=5005)

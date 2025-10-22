import os
import json
import base64
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import pkcs1_15
from Cryptodome.Hash import SHA256
import datetime

CERTS_DIR = "certificates"
os.makedirs(CERTS_DIR, exist_ok=True)

# Generate RSA key pair
def generate_rsa_keypair():
    key = RSA.generate(2048)
    return key.export_key(), key.publickey().export_key()

# Create Root CA
def create_root_ca():
    private_key, public_key = generate_rsa_keypair()
    cert_data = {
        "issuer": "MyCustomCA",
        "subject": "MyCustomCA",
        "public_key": base64.b64encode(public_key).decode(),
        "valid_from": str(datetime.datetime.now(datetime.UTC)),
        "valid_to": str(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=365)),
        "serial_number": 1001,
        "type": "CA",
        "is_ca": True
    }
    cert_json = json.dumps(cert_data, sort_keys=True, separators=(",", ":"))
    cert_hash = SHA256.new(cert_json.encode())
    signature = pkcs1_15.new(RSA.import_key(private_key)).sign(cert_hash)
    cert_data["signed_json"] = cert_json
    cert_data["signature"] = base64.b64encode(signature).decode()
    return private_key, cert_data

# Create signed certificate for server/client
def create_signed_certificate(name, ca_privkey, ca_cert):
    private_key, public_key = generate_rsa_keypair()
    cert_data = {
        "issuer": ca_cert["subject"],
        "subject": name,
        "public_key": base64.b64encode(public_key).decode(),
        "valid_from": str(datetime.datetime.now(datetime.UTC)),
        "valid_to": str(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=365)),
        "serial_number": random_serial(),
        "type": "Server" if name == "ChatServer" else "Client",
        "is_ca": False
    }
    cert_json = json.dumps(cert_data, sort_keys=True, separators=(",", ":"))
    cert_hash = SHA256.new(cert_json.encode())
    signature = pkcs1_15.new(RSA.import_key(ca_privkey)).sign(cert_hash)
    cert_data["signed_json"] = cert_json
    cert_data["signature"] = base64.b64encode(signature).decode()
    return private_key, cert_data

# Random serial number generator
def random_serial():
    return int.from_bytes(os.urandom(8), byteorder="big")

# Save cert as JSON
def save_certificate_json(cert, filename):
    path = os.path.join(CERTS_DIR, filename)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(cert, f, indent=4)
    print(f"[SAVED] Certificate: {path}")

# Save key as PEM
def save_private_key_pem(private_key, filename):
    path = os.path.join(CERTS_DIR, filename)
    with open(path, "wb") as f:
        f.write(private_key)
    print(f"[SAVED] Private key: {path}")

# Create everything
ca_private_key, ca_cert = create_root_ca()
server_key, server_cert = create_signed_certificate("ChatServer", ca_private_key, ca_cert)
a_key, a_cert = create_signed_certificate("A", ca_private_key, ca_cert)
b_key, b_cert = create_signed_certificate("B", ca_private_key, ca_cert)
c_key, c_cert = create_signed_certificate("C", ca_private_key, ca_cert)

# Save certs and keys
save_certificate_json(ca_cert, "RootCA.json")
save_certificate_json(server_cert, "ChatServer.json")
save_certificate_json(a_cert, "A.json")
save_certificate_json(b_cert, "B.json")
save_certificate_json(c_cert, "C.json")

save_private_key_pem(ca_private_key, "RootCA.pem")
save_private_key_pem(server_key, "ChatServer.pem")
save_private_key_pem(a_key, "A.pem")
save_private_key_pem(b_key, "B.pem")
save_private_key_pem(c_key, "C.pem")

print("[SUCCESS] Certificates and keys generated.")

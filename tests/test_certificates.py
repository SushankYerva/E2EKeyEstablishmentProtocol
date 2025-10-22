# tests/test_certificates.py
import base64, json
from Cryptodome.PublicKey import RSA
from Cryptodome.Hash import SHA256
from Cryptodome.Signature import pkcs1_15

# Import from src
from src.certificates import create_root_ca, create_signed_certificate

def test_root_and_signed_cert_verify():
    ca_priv, ca_cert = create_root_ca()
    # create a leaf cert (e.g., "A")
    a_priv, a_cert = create_signed_certificate("A", ca_priv, ca_cert)

    # verify signature on A using root public key
    root_pub = RSA.import_key(base64.b64decode(ca_cert["public_key"]))
    signed_json = a_cert["signed_json"]
    sig = base64.b64decode(a_cert["signature"])
    h = SHA256.new(signed_json.encode())
    pkcs1_15.new(root_pub).verify(h, sig)  # no exception -> OK

    # sanity checks
    assert a_cert["issuer"] == ca_cert["subject"]
    assert a_cert["subject"] == "A"
    assert a_cert["is_ca"] is False

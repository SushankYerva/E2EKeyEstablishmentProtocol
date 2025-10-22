# tests/test_protocol_sanity.py
import importlib

def test_modules_import():
    for mod in ("src.server", "src.client", "src.certificates"):
        importlib.import_module(mod)

def test_cert_api_shape():
    certs = importlib.import_module("src.certificates")
    assert hasattr(certs, "create_root_ca")
    assert hasattr(certs, "create_signed_certificate")

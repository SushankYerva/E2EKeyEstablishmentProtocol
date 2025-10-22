# tests/test_protocol_sanity.py
import importlib
import sys
import os
# Import from src
# Add the src directory to the sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

def test_modules_import():
    for mod in ("server", "client", "certificates"):
        importlib.import_module(mod)

def test_cert_api_shape():
    certs = importlib.import_module("src.certificates")
    assert hasattr(certs, "create_root_ca")
    assert hasattr(certs, "create_signed_certificate")

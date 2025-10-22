
# 🔐 Three-Party Session Key Protocol (A–B–C)

A Python reference implementation of a key establishment protocol that derives a mutually agreed session key between three entities A, B, and C. The session key then secures a group chat with **Confidentiality, Integrity, Availability**, and **Non-Repudiation**.

[![Build](https://github.com/SushankYerva/E2EKeyEstablishmentProtocol/actions/workflows/ci.yml/badge.svg)](https://github.com/SushankYerva/E2EKeyEstablishmentProtocol/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![License](https://img.shields.io/badge/license-MIT-informational)

---

## 🗂 Project Structure

```
src/
  certificates.py   # Root CA & leaf cert generation/signing
  server.py         # Authenticates clients, relays messages, signals start_key
  client.py         # Auths to server, exchanges signed key shares, secures chat
tests/
  test_certificates.py
  test_protocol_sanity.py
```

---

## 🚀 Quickstart

### 1) Install
```bash
git clone https://github.com/SushankYerva/E2EKeyEstablishmentProtocol.git
cd three-party-session-key
python -m venv .venv
# Windows: .venv\Scriptsctivate
# macOS/Linux:
source .venv/bin/activate
pip install -r requirements.txt
```

### 2) Generate certificates
```bash
python -m src.certificates
```
This creates `certificates/` with `RootCA`, `ChatServer`, and `A/B/C` keypairs + JSON certs.

### 3) Run the server
```bash
python -m src.server
# [SERVER] Listening on 127.0.0.1:5000
```

### 4) Run three clients (in three terminals)
```bash
# Terminal 1
python -m src.client A
# Terminal 2
python -m src.client B
# Terminal 3
python -m src.client C
```

When all three authenticate, the server broadcasts `start_key`. Each client:
- fetches peer certificates,
- sends its **signed** key share (RSA),
- derives the common **group key**,
- and can send **AES-GCM** encrypted messages.

> You should see `Group key established.` on each client, then type messages to chat.

---

## 🧪 Tests & CI

Run tests locally:
```bash
pytest -q
```

CI runs on **push/PR** against `main`:
- Python **3.11** & **3.12**
- Install → (optional) lint → tests
- Badge reflects current build status

---

## 🔒 Security Notes

- RSA certs and keys are created for demo purposes and stored under `certificates/`.
- **Do not** check real/production secrets into Git.
- This implementation focuses on clarity for teaching—production protocols require formal proofs, forward secrecy (e.g., ECDH), replay protection, rotation, etc.

---

## 📜 License

MIT — see [LICENSE](./LICENSE).

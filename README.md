# 🔐 Three-Party Session Key Protocol (A–B–C)

A Python reference implementation of a **key establishment protocol** that derives a **mutually agreed session key** between three entities **A, B, C**. The session key then secures a group chat channel with **Confidentiality, Integrity, Availability, and Non-Repudiation**.

[![Build](https://github.com/<your-username>/three-party-session-key/actions/workflows/ci.yml/badge.svg)](https://github.com/<your-username>/three-party-session-key/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![License](https://img.shields.io/badge/license-MIT-informational)

---

## ✨ Highlights

- **X.509-like JSON certs** issued by a custom **Root CA** (RSA-2048, SHA-256, PKCS#1 v1.5)
- **Mutual authentication**: server & clients validate cert signatures + validity window
- **Three-party key establishment**: each client contributes random bytes → sorted, concatenated → `SHA-256` → **shared session key**
- **Secure group chat**: AES-GCM for **confidentiality & integrity** + HMAC for an extra integrity check
- **Non-repudiation**: key shares are digitally **signed** with RSA and verified by peers
- Clean **CI** (matrix for 3.11/3.12), unit tests, and ready-to-extend structure

> ⚠️ Educational reference. Use only with explicit authorization.

---

## 🗂 Project Structure



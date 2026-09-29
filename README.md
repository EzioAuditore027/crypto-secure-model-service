# Cryptography-Based Secure Model Service

[![Course](https://img.shields.io/badge/Course-DSC4110%2FDSC6111-blue.svg)](https://www.iisertvm.ac.in)
[![Security](https://img.shields.io/badge/Cryptography-Post--Quantum%20Lattice%20KEM%20%2B%20AEAD-green.svg)](#)
[![Python](https://img.shields.io/badge/Python-3.10%2B-brightgreen.svg)](#)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](#)

> **Course**: Modern Cryptography and AI/ML Security (DSC4110 / DSC6111)  
> **Institution**: Indian Institute of Science Education and Research Thiruvananthapuram (IISER TVM)  
> **Instructor**: Dr. Laltu Sardar  
> **Assignment**: Project 1 — Cryptography-Based Secure Model Service  

---

## 📖 Overview

This repository implements an end-to-end client-server system providing a machine learning model service to authorized users over an untrusted network. The implementation strictly implements all cryptographic mechanisms rather than relying on standard TLS/HTTPS as a black box:
* **Post-Quantum Key Encapsulation (Lattice-KEM)**: Module/Ring-LWE over polynomial ring $R_q = \mathbb{Z}_q[X]/(X^{256}+1)$ with $q=3329$ (Kyber-style parameterization), with optional Classical X25519-KEM fallback.
* **Key Derivation Function (KDF)**: HKDF-SHA256 (RFC 5869) deriving directional symmetric keys and salts.
* **Authenticated Encryption (AEAD)**: ChaCha20-Poly1305 (RFC 8439) with 96-bit unique nonces and 128-bit MAC tags.
* **Anti-Replay Defense**: Monotonic sequence counters preventing duplicate or reordered packet injection.
* **Memory Key Zeroization**: Explicit buffer zeroization upon session termination.
* **Continuous ML Adaptation**: Lightweight Phishing/Spam Classifier with initial calibration $BuildModel(D) \to M$ and incremental user-feedback retraining $RebuildModel(D, D') \to M'$.

---

## 🏛️ System Architecture

```text
+------------------------+             +------------------------+
|  Owner / Admin Portal  |             |  Authorized User App   |
|   (Web UI & CLI)       |             |   (Web UI & CLI)       |
+-----------+------------+             +-----------+------------+
            |                                      |
            | Manage Users & Retrain               | Handshake & Encrypted Query
            v                                      v
+---------------------------------------------------------------+
|                      Server Application                       |
|   - Cryptographic Dispatcher (Lattice-KEM / HKDF / AEAD)      |
|   - ML Inference Engine (Tfidf + Logistic Regression M)       |
|   - Anti-Replay Guard & Session State Machine                 |
|   - SQLite Database (Users, Models, Feedback D')              |
+---------------------------------------------------------------+
```

---

## 🚀 Quick Start Guide

### 1. Start the Server & Web Application
In your terminal, navigate to the project directory and run:

```bash
python run_server.py
```

The server starts at `http://127.0.0.1:8000`:
* 🌐 **Landing Page & Switcher**: [http://127.0.0.1:8000/](http://127.0.0.1:8000/)
* 👑 **Owner / Admin Portal**: [http://127.0.0.1:8000/admin](http://127.0.0.1:8000/admin)
* 👤 **Authorized User Portal**: [http://127.0.0.1:8000/user](http://127.0.0.1:8000/user)

---

### 2. Standalone Terminal / CLI Applications (Optional)

If you prefer testing or demonstrating from the command line:

* **Start the Admin CLI**:
  ```bash
  python run_admin.py
  ```
  *(Approve pending users, revoke access, view collected feedback $D'$, and trigger model retraining $M'$).*

* **Start the User CLI**:
  ```bash
  python run_user.py
  ```
  *(Register with public key, execute KEM handshake, send encrypted queries, submit feedback, terminate session).*

---

## 🧪 Automated Verification & Attack Simulations

### Run the Core Protocol Test Suite:
```bash
python test_protocol.py
```
*Verifies HKDF derivation, AEAD ChaCha20-Poly1305 encryption/decryption, Post-Quantum Lattice KEM, X25519 KEM, anti-replay defense, memory key zeroization, and ML retraining.*

### Run Active Adversary Attack Simulations:
```bash
python test_attacks.py
```
*Simulates active network attacks: Eavesdropping, MITM Bit-Flipping / Tampering, Packet Replay Attack, Unauthorized User Handshake, and Nonce Reuse checks.*

---

## 📁 Repository Structure

```text
crypto-secure-model-service/
├── crypto/                  # Cryptographic protocol core
│   ├── __init__.py
│   ├── kem.py               # Post-Quantum Lattice KEM & Classical X25519
│   ├── kdf.py               # HKDF-SHA256 (RFC 5869)
│   ├── aead.py              # ChaCha20-Poly1305 AEAD (RFC 8439)
│   └── channel.py           # SecureSession, Nonces, Anti-Replay Guard
├── ml/                      # Machine learning serving pipeline
│   ├── __init__.py
│   ├── dataset.py           # Base dataset D and feedback dataset D'
│   └── model.py             # BuildModel(D) and RebuildModel(D, D')
├── server/                  # Central server & database
│   ├── __init__.py
│   ├── database.py          # SQLite persistence layer
│   ├── service.py           # Cryptographic orchestration & ML handling
│   └── app.py               # HTTP REST API server
├── web/                     # Web Applications
│   ├── index.html           # Landing page
│   ├── admin.html           # Owner / Admin Web Portal
│   ├── user.html            # Authorized User Web Portal with Live Inspector
│   └── static/              # CSS stylesheet
├── docs/                    # Deliverables & documentation
│   ├── PROTOCOL_SPEC.md     # Full Cryptographic Protocol Specification
│   ├── THREAT_MODEL.md      # Threat Model & Security Analysis
│   └── REPORT.md            # Final Submission Report
├── run_server.py            # Server startup script
├── run_admin.py             # Owner CLI tool
├── run_user.py              # User CLI tool
├── test_protocol.py         # Automated test suite
├── test_attacks.py          # Adversary simulation script
└── README.md
```

---

## 📋 Expected Deliverables Mapping

| # | Required Deliverable | Location in Repository |
| :-: | :--- | :--- |
| **1** | Owner / Admin Application | `web/admin.html` and `run_admin.py` |
| **2** | User Application | `web/user.html` and `run_user.py` |
| **3** | Server Application / API | `server/app.py` and `run_server.py` |
| **4** | Database | SQLite embedded in `server/database.py` (`secure_service.db`) |
| **5** | Cryptographic Protocol Specification | [`docs/PROTOCOL_SPEC.md`](docs/PROTOCOL_SPEC.md) |
| **6** | Threat Model and Security Analysis | [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) |
| **7** | Source Code | `crypto/`, `ml/`, `server/`, `web/` |
| **8** | Final Project Report | [`docs/REPORT.md`](docs/REPORT.md) |
| **9** | Final Demonstration | Verified via `test_protocol.py`, `test_attacks.py`, and Web UI |

---

## 📄 License
This project is developed for educational purposes under the MIT License.

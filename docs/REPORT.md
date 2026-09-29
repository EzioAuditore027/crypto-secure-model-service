# Modern Cryptography and AI/ML Security
## Project 1: Cryptography-Based Secure Model Service
**Course Code**: DSC4110 / DSC6111 &bull; **Institution**: IISER Thiruvananthapuram &bull; **Instructor**: Dr. Laltu Sardar  

---

## Executive Summary
This project presents an end-to-end implementation of a **Cryptography-Based Secure Machine Learning Model Service**. The system enables an Owner/Admin to train, deploy, and continuously update a machine learning model, while authorized users can perform confidential inference queries over an untrusted network. Rather than relying on generic TLS/HTTPS black boxes, all security guarantees—including Post-Quantum Key Encapsulation (Lattice-KEM), Key Derivation (HKDF-SHA256), Authenticated Symmetric Encryption (ChaCha20-Poly1305), Strict Anti-Replay Nonce Management, and Memory Key Zeroization—are designed and implemented explicitly.

---

## 1. Selected Cryptographic Primitives & Justifications

### 1.1 Key Encapsulation Mechanism (KEM)
* **Algorithm**: **Lattice-Based KEM (Module-LWE / Ring-LWE)** (with optional Classical X25519-KEM fallback).
* **Parameters**:
  - Polynomial Ring: $R_q = \mathbb{Z}_q[X] / (X^n + 1)$ with dimension $n = 256$ and prime modulus $q = 3329$.
  - Noise Distribution: Centered Binomial Distribution $\psi_\eta$ with $\eta = 2$.
* **Rationale**: Directly aligns with modern Post-Quantum Cryptography (PQC) standards (NIST FIPS 203 ML-KEM / CRYSTALS-Kyber). It provides security against both classical and quantum adversaries (Shor's algorithm).

### 1.2 Key Derivation Function (KDF)
* **Algorithm**: **HKDF-SHA256 (RFC 5869)**.
* **Mechanism**:
  - `HKDF-Extract(salt, IKM) -> PRK`
  - `HKDF-Expand(PRK, info, length) -> OKM`
* **Rationale**: Derives independent directional session keys (`K_client_write`, `K_server_write`) and context-bound salts, ensuring domain separation and preventing reflection attacks.

### 1.3 Symmetric Encryption Algorithm
* **Algorithm**: **ChaCha20-Poly1305 AEAD (RFC 8439)**.
* **Key Size**: 256 bits (32 bytes).
* **Nonce Size**: 96 bits (12 bytes).
* **MAC Tag**: 128 bits (16 bytes) evaluated modulo prime $2^{130}-5$.
* **Rationale**: Authenticated Encryption with Associated Data (AEAD) ensures both ciphertext confidentiality and cryptographic tamper-detection in a single primitive.

---

## 2. Machine Learning Model & Continuous Serving

* **Domain & Application**: Phishing and Malicious Message Detection for Secure Communications.
* **Machine Learning Pipeline**:
  - Feature Extractor: TF-IDF n-gram vectorizer ($n \in \{1, 2\}$).
  - Classifier Head: Lightweight Regularized Logistic Regression / Linear SGD Classifier.
* **Model Serving Lifecycle**:
  1. `BuildModel(D) -> M`: Initializes and trains initial model $M$ on dataset $D$.
  2. `Query(x) -> y`: Authorized client submits encrypted input text $x$ and receives encrypted classification label $y$ and confidence score.
  3. `StoreFeedback(UID, x, y, f)`: User provides ground truth label $f$ and qualitative rating.
  4. `RebuildModel(D, D') -> M'`: Owner aggregates new feedback $D'$, triggers incremental retraining, updates model version to $M'$, and deploys the new weights to the server.

---

## 3. Cryptographic Protocol Implementation Details

### 3.1 Key Generation Procedure
- **Server**: Generates $(pk_B, sk_B)$ where $pk_B = (seed_A, t)$ with $t = A \cdot s + e \pmod{q}$, and $sk_B = s$.
- **User / Admin**: Generates $(pk_A, sk_A)$ similarly and registers $pk_A$ with the Server.

### 3.2 Secure Session Establishment Protocol
1. Client fetches Server Public Key $pk_B$.
2. Client samples ephemeral randomness $r, e_1, e_2$ and generates $(ct, K) \leftarrow \text{Encaps}(pk_B)$.
3. Client sends $(UID, ct)$ to Server via `/api/session/handshake`.
4. Server verifies $UID$ status is `approved`.
5. Server decapsulates $K \leftarrow \text{Decaps}(sk_B, ct)$.
6. Both parties independently execute HKDF with context `"SECURE-CHANNEL-v1:" || session_id` to derive $K_{\text{client\_write}}$, $K_{\text{server\_write}}$, $\text{Salt}_{\text{client}}$, $\text{Salt}_{\text{server}}$.

### 3.3 Nonce Management & Monotonic Anti-Replay Guard
To ensure nonces are never reused:
$$\text{Nonce}_i = \text{Salt}[0:4] \parallel \text{uint64\_be}(seq_i)$$
The receiver validates:
$$seq_i > \text{last\_seen\_seq}$$
Replayed messages with equal or lower sequence numbers are immediately dropped before decryption.

### 3.4 Session Termination & Memory Key Zeroization
Upon session completion, the application calls `session.terminate()`. The key memory buffers are actively overwritten with zeros (`b"\x00" * 32`) to prevent cold-boot or memory inspection attacks.

---

## 4. Threat Model & Security Evaluation

| Threat Vector | Defense Implemented | Verification Result |
| :--- | :--- | :--- |
| **Passive Eavesdropping** | Post-Quantum Lattice KEM + ChaCha20 AEAD | ✅ Ciphertext is IND-CPA secure. Plaintext reveals 0 bits. |
| **Active Bit-Flipping / MITM** | 128-bit Poly1305 MAC tag over Ciphertext + AAD | ✅ Modified packets fail tag verification and are dropped. |
| **Replay Attacks** | Monotonic sequence numbering + Nonce sequence derivation | ✅ Replayed packets trigger `ReplayAttackError`. |
| **Unauthorized Access** | Server-side user authorization gate before handshake | ✅ Pending / revoked UIDs cannot establish session. |
| **Cross-Protocol / Reflection** | Directional keys + Role binding in AAD | ✅ Client cannot decrypt its own transmitted packet. |

---

## 5. Verification & Test Suite Summary

The project includes two automated test suites:
- `test_protocol.py`: Verifies mathematical correctness of HKDF, Lattice-KEM, X25519-KEM, AEAD round-trips, and continuous ML retraining.
- `test_attacks.py`: Actively simulates eavesdropping, packet bit-flipping, replay attacks, and unauthorized access, confirming zero vulnerabilities.

---

## 6. Deliverables Matrix

1. **Owner / Admin Application**: Web Dashboard (`/admin`) and CLI (`run_admin.py`).
2. **Authorized User Application**: Web Portal (`/user`) with live Cryptographic Inspector and CLI (`run_user.py`).
3. **Server Application / REST API**: Standalone HTTP Server (`run_server.py`).
4. **Database**: Persistent SQLite schema (`secure_service.db`).
5. **Cryptographic Protocol Specification**: `docs/PROTOCOL_SPEC.md`.
6. **Threat Model and Security Analysis**: `docs/THREAT_MODEL.md`.
7. **Source Code**: Fully commented modular Python implementation in `crypto/`, `ml/`, and `server/`.
8. **Final Project Report**: This document (`docs/REPORT.md`).

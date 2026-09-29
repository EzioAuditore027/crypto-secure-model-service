# Cryptographic Protocol Specification

## 1. System Overview & Assumptions

The **Cryptography-Based Secure Model Service** defines an end-to-end authenticated, confidential, and replay-protected channel between three system entities:
1. **Owner / Admin**: Trains initial model $M = \text{BuildModel}(D)$, approves authorized users, collects feedback $D'$, retrains updated model $M' = \text{RebuildModel}(D, D')$, and revokes user access.
2. **Server**: Central cloud service provider maintaining the SQLite database, validating user access status, handling KEM handshakes, and executing machine learning inference.
3. **Authorized User**: Authenticated client querying the deployed model ($x \to y$) and submitting labeled feedback $f$.

### Cryptographic Assumptions
- Each entity $i$ possesses a public/private keypair $(pk_i, sk_i)$.
- The public key of the Server is accessible to all entities (e.g. via public directory endpoint).
- PKI and digital certificate hierarchies are outside the assignment scope.
- The underlying communication network is assumed to be fully **untrusted and insecure**: an active adversary $\mathcal{A}$ may intercept, tamper with, drop, inject, or replay network packets.

---

## 2. Cryptographic Primitives Selection

| Mechanism | Primitive | Specification | Purpose |
| :--- | :--- | :--- | :--- |
| **KEM** | Lattice-KEM (Module/Ring-LWE) | $R_q = \mathbb{Z}_q[X]/(X^{256} + 1), q = 3329$ | Post-Quantum Key Encapsulation (Kyber-style) |
| **KEM (Classical)** | X25519-KEM | Curve25519 Montgomery ladder (RFC 7748) | Classical Elliptic Curve alternative |
| **KDF** | HKDF-SHA256 | RFC 5869 Extract-and-Expand | Derives directional symmetric keys & IV salts |
| **AEAD** | ChaCha20-Poly1305 | RFC 8439 Authenticated Encryption | Confidentiality & 128-bit MAC Integrity |
| **Replay Defense** | Monotonic Counter + Salt | 96-bit Nonce ($4\text{B salt} \parallel 8\text{B seq}$) | Strictly non-repeating nonces & replay rejection |

---

## 3. Protocol Execution Flow

```text
       Client (User / Admin)                             Server
                 |                                          |
                 |-------- 1. Request pk_Server ----------->|
                 |<------- 2. Returns pk_Server ------------|
                 |                                          |
  (ct, K) <- Encaps(pk_Server)                              |
                 |                                          |
                 |-------- 3. Handshake(UID, ct) ---------->|
                 |                                    K <- Decaps(sk_Server, ct)
                 |                                    Verify User status == 'approved'
                 |                                    Derive Session Keys via HKDF
                 |<------- 4. Ack(session_id) --------------|
                 |                                          |
  Derive Session Keys via HKDF                              |
                 |                                          |
                 |==== 5. Encrypted Query: Query(x) =======>|
                 |    c_req = Enc(K_client, Nonce_1, x)     | Decrypt & Verify Tag
                 |    AAD = session_id || seq || "CLIENT"   | y = Model.predict(x)
                 |                                          | Encrypt response:
                 |<=== 6. Encrypted Response: Result(y) ====| c_resp = Enc(K_server, Nonce_1, y)
                 |                                          |
```

### Step 1: KEM Key Establishment
1. Client fetches Server Public Key $pk_B$.
2. Client executes:
   $$(ct, K) \leftarrow \text{Encaps}(pk_B)$$
3. Client transmits $ct$ alongside its registered identity $UID$:
   $$\text{Client} \longrightarrow \text{Server} : (UID, ct)$$
4. Server verifies $UID$ access status in the database.
5. Server executes:
   $$K \leftarrow \text{Decaps}(sk_B, ct)$$
6. Both parties now possess an identical, fresh ephemeral secret:
   $$K_A = K_B = K \in \{0, 1\}^{256}$$

### Step 2: Key Derivation Function (KDF)
To prevent cross-protocol leakage and reflection attacks, directional session keys and IV salts are derived independently using HKDF-SHA256 (RFC 5869):

$$\text{PRK} = \text{HKDF-Extract}(\text{salt}=\text{"SESSION-SALT-v1"}, \text{IKM}=K)$$
$$\text{OKM} = \text{HKDF-Expand}(\text{PRK}, \text{info}=\text{"SECURE-CHANNEL-v1:"} \parallel \text{session\_id}, L=96)$$

The 96-byte output is segmented into:
- $K_{\text{client\_write}} = \text{OKM}[0:32]$ (32 bytes)
- $K_{\text{server\_write}} = \text{OKM}[32:64]$ (32 bytes)
- $\text{Salt}_{\text{client}} = \text{OKM}[64:80]$ (16 bytes)
- $\text{Salt}_{\text{server}} = \text{OKM}[80:96]$ (16 bytes)

### Step 3: Nonce Generation & Management
Nonces must **never** repeat for the same key. The 96-bit (12-byte) nonce for message $i$ is deterministically derived as:

$$\text{Nonce}_i = \text{Salt}[0:4] \;\parallel\; \text{uint64\_be}(seq_i)$$

Because $seq_i$ is monotonically incremented for each sent message, duplicate nonces are mathematically impossible.

### Step 4: Authenticated Encryption (AEAD)
For message payload $m$ with sequence number $seq$:

$$\text{AAD} = \text{session\_id} \;\parallel\; \text{str}(seq) \;\parallel\; \text{Role}$$
$$c \parallel \tau \leftarrow \text{ChaCha20Poly1305.Encrypt}(K_{\text{write}}, \text{Nonce}, m, \text{AAD})$$

The receiver validates the 16-byte Poly1305 tag $\tau$ before attempting any plaintext processing.

### Step 5: Anti-Replay Guard
The receiver maintains `last_seen_seq` for each active session:
1. When a packet arrives with sequence $s$, the receiver verifies:
   $$s > \text{last\_seen\_seq} \quad \text{and} \quad s \notin \text{seen\_cache}$$
2. If $s \le \text{last\_seen\_seq}$, the packet is immediately dropped with `ReplayAttackError`.
3. Upon successful cryptographic tag validation, `last_seen_seq` is updated to $s$.

### Step 6: Session Termination & Key Zeroization
When an entity calls `terminate()` or revokes access:
- The symmetric keys $K_{\text{client\_write}}$ and $K_{\text{server\_write}}$ in memory are actively overwritten with byte zeros (`\x00`).
- The session entry is purged from active lookup tables.
- Any subsequent packets referencing the terminated `session_id` are rejected.

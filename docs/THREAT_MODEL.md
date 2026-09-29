# Threat Model and Formal Security Analysis

## 1. Adversary Capabilities & Threat Model (Dolev-Yao Model)

We consider the standard **Dolev-Yao network attacker model** wherein the adversary $\mathcal{A}$ has complete control over the physical communication channels:
1. **Eavesdropping**: $\mathcal{A}$ can intercept and inspect all packets in transit.
2. **Packet Manipulation**: $\mathcal{A}$ can alter bits, splice headers, or modify payload contents.
3. **Replay & Reordering**: $\mathcal{A}$ can duplicate legitimate packets and inject them at arbitrary later times.
4. **Impersonation**: $\mathcal{A}$ may attempt to register unauthorized identities or query models without Owner approval.
5. **Quantum Advantage**: $\mathcal{A}$ may possess or harvest encrypted traffic for future cryptanalysis using quantum algorithms (Shor's algorithm for factorizing / discrete log).

---

## 2. Security Properties & Formal Proofs

### Property 1: Message Confidentiality (IND-CPA / IND-CCA2)
* **Goal**: An attacker observing network communications learns zero information regarding model query $x$ or model prediction $y$.
* **Analysis**:
  - The shared secret $K$ is established using **Lattice-KEM (Module-LWE)** whose security reduces to the hardness of the Shortest Vector Problem (SVP) over ideal/module lattices in $R_q = \mathbb{Z}_q[X]/(X^{256} + 1)$. This provides post-quantum IND-CCA security against both classical and quantum polynomial-time adversaries.
  - Message encryption uses **ChaCha20 stream cipher** with a unique 96-bit nonce derived per message. Given that nonces are strictly non-repeating and the session key is pseudo-randomly output by HKDF-SHA256, the symmetric encryption scheme provides IND-CPA security.

### Property 2: Ciphertext Integrity & Authenticity (INT-CTXT)
* **Goal**: Any tampering with ciphertext or associated metadata must be detected and rejected before decryption.
* **Analysis**:
  - Poly1305 computes a 16-byte polynomial MAC tag $\tau$ evaluated modulo the prime $2^{130} - 5$:
    $$\tau = \left( \sum_{i=1}^k c_i \cdot r^i \pmod{2^{130}-5} \right) + s \pmod{2^{128}}$$
  - The evaluation key $(r, s)$ is generated freshly for each message from block 0 of the ChaCha20 keystream.
  - Modifying any single bit in the ciphertext or Associated Data alters the evaluation polynomial with negligible forgery probability:
    $$\text{Pr}[\mathcal{A}\text{ succeeds in forgery}] \le \frac{8 \cdot L}{2^{106}} \approx 2^{-100}$$
  - The receiver checks the MAC in constant time using `hmac.compare_digest` to prevent timing side-channels.

### Property 3: Forward Secrecy & Fresh Session Keys
* **Goal**: Compromise of a single session key or long-term entity key does not compromise past communication sessions.
* **Analysis**:
  - Every handshake generates fresh ephemeral randomness ($r, e_1, e_2$ in Lattice-KEM or ephemeral scalar $k$ in X25519).
  - The resulting shared secret $K$ is unique per session.
  - Even if the server's long-term private key were compromised in the future, the ephemeral randomness generated during individual past sessions is erased upon handshake completion.

### Property 4: Replay Protection & Sequence Integrity
* **Goal**: An adversary capturing packet $i$ cannot re-inject it to duplicate a query or trick the model service.
* **Analysis**:
  - Every packet carries a monotonic sequence integer $seq \in \mathbb{N}$ bound cryptographically into the Associated Data (AAD):
    $$\text{AAD} = \text{session\_id} \;\parallel\; seq \;\parallel\; \text{Role}$$
  - The receiver validates:
    $$seq_{\text{incoming}} > seq_{\text{last\_received}}$$
  - Replayed packets have $seq_{\text{incoming}} \le seq_{\text{last\_received}}$ and are rejected immediately.
  - An attacker attempting to modify $seq$ to bypass this check causes the Poly1305 MAC verification to fail because $seq$ is authenticated inside AAD.

### Property 5: Reflection & Cross-Protocol Attack Prevention
* **Goal**: An attacker cannot reflect a client request back to the client as a server response.
* **Analysis**:
  - HKDF expands distinct directional write keys:
    $$K_{\text{client\_write}} \neq K_{\text{server\_write}}$$
  - Furthermore, the AAD incorporates the entity's expected role (`"CLIENT"` vs `"SERVER"`). A client cannot decrypt its own transmitted packet using its receive cipher.

### Property 6: Secure Session Termination & Key Zeroization
* **Goal**: Keys lingering in memory must not be recoverable after session closure.
* **Analysis**:
  - Upon calling `terminate()`, the internal key bytearrays `_k_client` and `_k_server` are explicitly overwritten with zeroes before deletion.
  - The server deletes the session mapping, invalidating any subsequent requests bearing the terminated `session_id`.

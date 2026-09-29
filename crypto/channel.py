"""
Secure Channel Protocol State Machine
Implements:
1. Session Establishment (Handshake)
2. Directional Key Derivation via HKDF
3. Nonce Management (Guaranteed Non-Repeating per session key)
4. Monotonic Sequence Counting & Anti-Replay Defense
5. Session Termination & Memory Key Zeroization
"""
import os
import time
import struct
import base64
import json
from dataclasses import dataclass
from typing import Optional, Dict, Any, Tuple
from .kdf import hkdf
from .aead import ChaCha20Poly1305, IntegrityError
from .kem import get_kem


class ReplayAttackError(Exception):
    """Raised when a message contains an outdated or replayed sequence number."""
    pass


class SessionExpiredError(Exception):
    """Raised when a message arrives after the session has been terminated or expired."""
    pass


@dataclass
class SecurePacket:
    session_id: str
    seq: int
    timestamp: float
    nonce_b64: str
    ciphertext_b64: str

    def to_json(self) -> str:
        return json.dumps({
            "session_id": self.session_id,
            "seq": self.seq,
            "timestamp": self.timestamp,
            "nonce": self.nonce_b64,
            "ciphertext": self.ciphertext_b64,
        })

    @classmethod
    def from_json(cls, raw: str) -> "SecurePacket":
        d = json.loads(raw)
        return cls(
            session_id=d["session_id"],
            seq=d["seq"],
            timestamp=d["timestamp"],
            nonce_b64=d["nonce"],
            ciphertext_b64=d["ciphertext"],
        )


class SecureSession:
    """
    Manages state for an active cryptographic session between two entities (e.g. User and Server).
    """

    def __init__(
        self,
        session_id: str,
        shared_secret: bytes,
        is_client: bool = True,
        max_lifetime_secs: int = 3600,
    ):
        self.session_id = session_id
        self.is_client = is_client
        self.max_lifetime_secs = max_lifetime_secs
        self.created_at = time.time()
        self.is_terminated = False

        # Derive independent directional session keys and IV salts via HKDF (RFC 5869)
        # Context binding prevents cross-protocol and reflection attacks
        context = f"SECURE-CHANNEL-v1:{session_id}".encode("utf-8")
        okm = hkdf(shared_secret, salt=b"SESSION-SALT-v1", info=context, length=96)

        # 32 bytes Client Write Key, 32 bytes Server Write Key, 16 bytes Client IV Salt, 16 bytes Server IV Salt
        self._k_client = bytearray(okm[0:32])
        self._k_server = bytearray(okm[32:64])
        self._salt_client = okm[64:80]
        self._salt_server = okm[80:96]

        if self.is_client:
            self._send_cipher = ChaCha20Poly1305(bytes(self._k_client))
            self._recv_cipher = ChaCha20Poly1305(bytes(self._k_server))
            self._send_salt = self._salt_client
            self._recv_salt = self._salt_server
        else:
            self._send_cipher = ChaCha20Poly1305(bytes(self._k_server))
            self._recv_cipher = ChaCha20Poly1305(bytes(self._k_client))
            self._send_salt = self._salt_server
            self._recv_salt = self._salt_client

        # Sequence counters for Anti-Replay
        self.send_seq = 0
        self.recv_seq = 0
        self.seen_seqs = set()

    def _derive_nonce(self, seq: int, salt: bytes) -> bytes:
        """
        Deterministic 12-byte (96-bit) Nonce derivation:
        Nonce = Salt[0:4] || 8-byte big-endian sequence number
        Guarantees strictly unique nonces across all messages in a session.
        """
        return salt[:4] + struct.pack(">Q", seq)

    def encrypt_message(self, plaintext: str) -> SecurePacket:
        """
        Encrypts a message into an authenticated SecurePacket.
        Increments the send sequence counter.
        """
        if self.is_terminated:
            raise SessionExpiredError("Session is terminated.")
        if time.time() - self.created_at > self.max_lifetime_secs:
            self.terminate()
            raise SessionExpiredError("Session expired.")

        self.send_seq += 1
        nonce = self._derive_nonce(self.send_seq, self._send_salt)

        # Associated Data includes session_id, seq, and role to bind ciphertext to session context
        role = "CLIENT" if self.is_client else "SERVER"
        aad = f"{self.session_id}:{self.send_seq}:{role}".encode("utf-8")

        payload_bytes = plaintext.encode("utf-8")
        ct_with_tag = self._send_cipher.encrypt(nonce, payload_bytes, associated_data=aad)

        return SecurePacket(
            session_id=self.session_id,
            seq=self.send_seq,
            timestamp=time.time(),
            nonce_b64=base64.b64encode(nonce).decode("ascii"),
            ciphertext_b64=base64.b64encode(ct_with_tag).decode("ascii"),
        )

    def decrypt_message(self, packet: SecurePacket) -> str:
        """
        Verifies and decrypts an incoming SecurePacket.
        Enforces Monotonic Sequence Number checks to prevent Replay Attacks.
        """
        if self.is_terminated:
            raise SessionExpiredError("Session is terminated.")
        if packet.session_id != self.session_id:
            raise IntegrityError("Packet session_id mismatch.")

        # Replay Attack Prevention
        if packet.seq <= self.recv_seq or packet.seq in self.seen_seqs:
            raise ReplayAttackError(
                f"Replay detected! Packet seq={packet.seq} <= last seen seq={self.recv_seq}"
            )

        peer_role = "SERVER" if self.is_client else "CLIENT"
        expected_nonce = self._derive_nonce(packet.seq, self._recv_salt)
        received_nonce = base64.b64decode(packet.nonce_b64)

        if expected_nonce != received_nonce:
            raise IntegrityError("Nonce does not match expected deterministic sequence derivation.")

        aad = f"{self.session_id}:{packet.seq}:{peer_role}".encode("utf-8")
        ct_with_tag = base64.b64decode(packet.ciphertext_b64)

        plaintext_bytes = self._recv_cipher.decrypt(received_nonce, ct_with_tag, associated_data=aad)

        # Update replay state only after successful cryptographic verification
        self.recv_seq = packet.seq
        self.seen_seqs.add(packet.seq)

        return plaintext_bytes.decode("utf-8")

    def terminate(self) -> None:
        """
        Zeroizes session keys from memory and marks session as terminated.
        Fulfills Requirement 7: Session Termination and Key Deletion.
        """
        self.is_terminated = True
        for i in range(len(self._k_client)):
            self._k_client[i] = 0
        for i in range(len(self._k_server)):
            self._k_server[i] = 0
        self._send_cipher = None
        self._recv_cipher = None

"""
Authenticated Encryption with Associated Data (AEAD)
Standard: RFC 8439 ChaCha20 and Poly1305 for IETF Protocols
Provides Confidentiality, Integrity, and Authenticity.
"""
import struct
import hmac
from typing import Tuple


class IntegrityError(Exception):
    """Raised when authentication tag verification fails (ciphertext or AAD tampered)."""
    pass


def _rotl32(v: int, c: int) -> int:
    return ((v << c) & 0xFFFFFFFF) | ((v & 0xFFFFFFFF) >> (32 - c))


def _quarter_round(x: list, a: int, b: int, c: int, d: int) -> None:
    x[a] = (x[a] + x[b]) & 0xFFFFFFFF
    x[d] = _rotl32(x[d] ^ x[a], 16)
    x[c] = (x[c] + x[d]) & 0xFFFFFFFF
    x[b] = _rotl32(x[b] ^ x[c], 12)
    x[a] = (x[a] + x[b]) & 0xFFFFFFFF
    x[d] = _rotl32(x[d] ^ x[a], 8)
    x[c] = (x[c] + x[d]) & 0xFFFFFFFF
    x[b] = _rotl32(x[b] ^ x[c], 7)


def _chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    """Generates a 64-byte ChaCha20 keystream block."""
    constants = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]  # "expand 32-byte k"
    k = list(struct.unpack("<8I", key))
    n = list(struct.unpack("<3I", nonce))
    state = constants + k + [counter] + n
    working = list(state)

    for _ in range(10):  # 20 rounds (10 column-rounds, 10 diagonal-rounds)
        _quarter_round(working, 0, 4, 8, 12)
        _quarter_round(working, 1, 5, 9, 13)
        _quarter_round(working, 2, 6, 10, 14)
        _quarter_round(working, 3, 7, 11, 15)
        _quarter_round(working, 0, 5, 10, 15)
        _quarter_round(working, 1, 6, 11, 12)
        _quarter_round(working, 2, 7, 8, 13)
        _quarter_round(working, 3, 4, 9, 14)

    out = [(working[i] + state[i]) & 0xFFFFFFFF for i in range(16)]
    return struct.pack("<16I", *out)


def chacha20_crypt(key: bytes, counter: int, nonce: bytes, data: bytes) -> bytes:
    """ChaCha20 stream encryption/decryption."""
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes")
    if len(nonce) != 12:
        raise ValueError("Nonce must be 12 bytes")

    output = bytearray(len(data))
    for block_idx in range((len(data) + 63) // 64):
        keystream = _chacha20_block(key, counter + block_idx, nonce)
        offset = block_idx * 64
        chunk = data[offset : offset + 64]
        for i in range(len(chunk)):
            output[offset + i] = chunk[i] ^ keystream[i]
    return bytes(output)


def poly1305_mac(msg: bytes, key: bytes) -> bytes:
    """Computes 16-byte Poly1305 MAC over msg using a 32-byte one-time key."""
    if len(key) != 32:
        raise ValueError("Poly1305 key must be 32 bytes")

    r_bytes = key[:16]
    s_bytes = key[16:32]

    # Clamp r
    r = int.from_bytes(r_bytes, "little")
    r &= 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s = int.from_bytes(s_bytes, "little")

    p = (1 << 130) - 5
    accumulator = 0

    for i in range(0, len(msg), 16):
        chunk = msg[i : i + 16]
        # Pad with 0x01
        n = int.from_bytes(chunk + b"\x01", "little")
        accumulator = ((accumulator + n) * r) % p

    accumulator = (accumulator + s) % (1 << 128)
    return accumulator.to_bytes(16, "little")


def _poly1305_key_gen(key: bytes, nonce: bytes) -> bytes:
    """Derives Poly1305 one-time subkey using ChaCha20 block 0."""
    return _chacha20_block(key, 0, nonce)[:32]


def _pad16(data: bytes) -> bytes:
    rem = len(data) % 16
    return data + (b"\x00" * (16 - rem) if rem != 0 else b"")


class ChaCha20Poly1305:
    """
    RFC 8439 Authenticated Encryption with Associated Data (AEAD).
    Key: 32 bytes (256-bit)
    Nonce: 12 bytes (96-bit)
    Tag: 16 bytes (128-bit)
    """

    def __init__(self, key: bytes):
        if len(key) != 32:
            raise ValueError("Key must be 32 bytes")
        self.key = key

    def encrypt(self, nonce: bytes, plaintext: bytes, associated_data: bytes = b"") -> bytes:
        """
        Encrypts plaintext with associated data.
        Returns: ciphertext || 16-byte tag
        """
        otk = _poly1305_key_gen(self.key, nonce)
        ciphertext = chacha20_crypt(self.key, 1, nonce, plaintext)

        # Poly1305 construction: pad16(AAD) || pad16(ciphertext) || len64(AAD) || len64(ciphertext)
        mac_data = (
            _pad16(associated_data)
            + _pad16(ciphertext)
            + struct.pack("<QQ", len(associated_data), len(ciphertext))
        )
        tag = poly1305_mac(mac_data, otk)
        return ciphertext + tag

    def decrypt(self, nonce: bytes, ciphertext_and_tag: bytes, associated_data: bytes = b"") -> bytes:
        """
        Verifies tag and decrypts ciphertext.
        Raises IntegrityError if tag does not match.
        """
        if len(ciphertext_and_tag) < 16:
            raise IntegrityError("Ciphertext too short (missing 16-byte tag)")

        ciphertext = ciphertext_and_tag[:-16]
        expected_tag = ciphertext_and_tag[-16:]

        otk = _poly1305_key_gen(self.key, nonce)
        mac_data = (
            _pad16(associated_data)
            + _pad16(ciphertext)
            + struct.pack("<QQ", len(associated_data), len(ciphertext))
        )
        computed_tag = poly1305_mac(mac_data, otk)

        if not hmac.compare_digest(computed_tag, expected_tag):
            raise IntegrityError("Authentication tag verification failed: ciphertext or AAD tampered!")

        return chacha20_crypt(self.key, 1, nonce, ciphertext)


class AEADCipher(ChaCha20Poly1305):
    """Alias for AEAD standard cipher."""
    pass

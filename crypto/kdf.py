"""
Key Derivation Function (KDF) Implementation
Standard: RFC 5869 HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
Hash Function: SHA-256 (32-byte digest length)
"""
import hashlib
import hmac
from typing import Optional

HASH_LEN = 32  # SHA-256 output length in bytes


def hkdf_extract(salt: Optional[bytes], ikm: bytes) -> bytes:
    """
    HKDF-Extract(salt, IKM) -> PRK
    Extracts a pseudorandom key (PRK) of fixed length from input keying material (IKM).
    """
    if salt is None or len(salt) == 0:
        salt = b"\x00" * HASH_LEN
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """
    HKDF-Expand(PRK, info, L) -> OKM
    Expands the pseudorandom key (PRK) to output keying material (OKM) of length L.
    """
    if length > 255 * HASH_LEN:
        raise ValueError(f"Cannot expand to more than {255 * HASH_LEN} bytes using SHA-256")

    n = (length + HASH_LEN - 1) // HASH_LEN
    okm = bytearray()
    t = b""

    for i in range(1, n + 1):
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm.extend(t)

    return bytes(okm[:length])


def hkdf(ikm: bytes, salt: Optional[bytes] = None, info: bytes = b"", length: int = 32) -> bytes:
    """
    Complete HKDF pipeline: HKDF(ikm, salt, info, length) -> OKM
    Convenience function combining Extract and Expand.
    """
    prk = hkdf_extract(salt, ikm)
    return hkdf_expand(prk, info, length)

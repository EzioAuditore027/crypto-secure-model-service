"""
Key Encapsulation Mechanisms (KEM)
Provides:
1. LatticeKEM: Post-Quantum Lattice-Based Key Encapsulation (Module/Ring-LWE, Kyber-style polynomial arithmetic)
2. X25519KEM: Classical Elliptic Curve Diffie-Hellman Key Encapsulation (RFC 7748)
"""
import os
import hashlib
import struct
from typing import Tuple
from .kdf import hkdf

# =====================================================================
# 1. Classical Elliptic Curve KEM: X25519 (RFC 7748)
# =====================================================================

P = 2**255 - 19
A24 = 121665


def _clamp(k: bytearray) -> bytearray:
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    return k


def _x25519_eval(scalar_bytes: bytes, u_bytes: bytes) -> bytes:
    """RFC 7748 Montgomery ladder scalar multiplication on Curve25519."""
    k = _clamp(bytearray(scalar_bytes))
    u = int.from_bytes(u_bytes, "little") % P

    x_1 = u
    x_2 = 1
    z_2 = 0
    x_3 = u
    z_3 = 1
    swap = 0

    for t in reversed(range(255)):
        k_t = (k[t // 8] >> (t % 8)) & 1
        swap ^= k_t
        if swap:
            x_2, x_3 = x_3, x_2
            z_2, z_3 = z_3, z_2
        swap = k_t

        A = (x_2 + z_2) % P
        AA = (A * A) % P
        B = (x_2 - z_2) % P
        BB = (B * B) % P
        E = (AA - BB) % P
        C = (x_3 + z_3) % P
        D = (x_3 - z_3) % P
        DA = (D * A) % P
        CB = (C * B) % P
        x_3 = ((DA + CB) ** 2) % P
        z_3 = (x_1 * ((DA - CB) ** 2)) % P
        x_2 = (AA * BB) % P
        z_2 = (E * (AA + (A24 * E) % P)) % P

    if swap:
        x_2, x_3 = x_3, x_2
        z_2, z_3 = z_3, z_2

    res = (x_2 * pow(z_2, P - 2, P)) % P
    return res.to_bytes(32, "little")


class X25519KEM:
    """
    Standard Elliptic Curve KEM over Curve25519.
    Keygen -> (pk, sk)
    Encaps(pk_B) -> (ct, K)
    Decaps(sk_B, ct) -> K
    """

    BASE_POINT = bytes([9] + [0] * 31)

    @staticmethod
    def keygen() -> Tuple[bytes, bytes]:
        sk = os.urandom(32)
        pk = _x25519_eval(sk, X25519KEM.BASE_POINT)
        return pk, sk

    @staticmethod
    def encaps(pk: bytes) -> Tuple[bytes, bytes]:
        ephemeral_sk = os.urandom(32)
        ct = _x25519_eval(ephemeral_sk, X25519KEM.BASE_POINT)
        shared_point = _x25519_eval(ephemeral_sk, pk)
        shared_secret = hkdf(shared_point, salt=b"X25519-KEM-SALT", info=b"KEM-Shared-Secret", length=32)
        return ct, shared_secret

    @staticmethod
    def decaps(sk: bytes, ct: bytes) -> bytes:
        shared_point = _x25519_eval(sk, ct)
        return hkdf(shared_point, salt=b"X25519-KEM-SALT", info=b"KEM-Shared-Secret", length=32)


# =====================================================================
# 2. Post-Quantum Lattice-Based KEM (Ring/Module-LWE, Kyber-style)
# Ring: R_q = Z_q[X] / (X^n + 1), n=256, q=3329
# Centered Binomial Distribution for noise e, s, r
# =====================================================================

N = 256
Q = 3329


def _poly_add(a: list, b: list) -> list:
    return [(a[i] + b[i]) % Q for i in range(N)]


def _poly_sub(a: list, b: list) -> list:
    return [(a[i] - b[i]) % Q for i in range(N)]


def _poly_mul_negacyclic(a: list, b: list) -> list:
    """Multiplication in Z_q[X] / (X^n + 1)."""
    res = [0] * (2 * N)
    for i in range(N):
        ai = a[i]
        for j in range(N):
            res[i + j] = (res[i + j] + ai * b[j]) % Q
    # Reduce modulo X^N + 1: X^{N+k} = -X^k
    out = [0] * N
    for i in range(N):
        out[i] = (res[i] - res[i + N]) % Q
    return out


def _cbd2(random_bytes: bytes) -> list:
    """Centered Binomial Distribution eta=2 from pseudorandom seed."""
    poly = []
    idx = 0
    for _ in range(N):
        b = random_bytes[idx]
        idx += 1
        # sum of 2 bits minus sum of 2 bits
        a_bits = (b & 1) + ((b >> 1) & 1)
        b_bits = ((b >> 2) & 1) + ((b >> 3) & 1)
        poly.append((a_bits - b_bits) % Q)
    return poly


def _sample_uniform_poly(seed: bytes) -> list:
    """Samples uniform polynomial in R_q deterministically using SHAKE/SHA256."""
    h = hashlib.sha256(seed).digest()
    coeffs = []
    ctr = 0
    while len(coeffs) < N:
        digest = hashlib.sha256(h + struct.pack("<I", ctr)).digest()
        ctr += 1
        for i in range(0, len(digest) - 1, 2):
            val = struct.pack("<H", digest[i] | ((digest[i + 1] & 0x0F) << 8))
            num = struct.unpack("<H", val)[0]
            if num < Q:
                coeffs.append(num)
                if len(coeffs) == N:
                    break
    return coeffs


def _pack_poly(p: list) -> bytes:
    return b"".join(struct.pack("<H", c) for c in p)


def _unpack_poly(b: bytes) -> list:
    return list(struct.unpack(f"<{N}H", b))


class LatticeKEM:
    """
    Post-Quantum Lattice-based Key Encapsulation (LWE/Kyber-style arithmetic).
    Resistant to quantum computer cryptanalysis (Shor's algorithm).
    """

    @staticmethod
    def keygen() -> Tuple[bytes, bytes]:
        seed_a = os.urandom(32)
        a = _sample_uniform_poly(seed_a)
        s = _cbd2(os.urandom(N))
        e = _cbd2(os.urandom(N))
        # t = a * s + e (mod X^N + 1, Q)
        t = _poly_add(_poly_mul_negacyclic(a, s), e)

        pk = seed_a + _pack_poly(t)
        sk = _pack_poly(s)
        return pk, sk

    @staticmethod
    def encaps(pk: bytes) -> Tuple[bytes, bytes]:
        seed_a = pk[:32]
        t = _unpack_poly(pk[32:])
        a = _sample_uniform_poly(seed_a)

        # Ephemeral random vectors
        r = _cbd2(os.urandom(N))
        e1 = _cbd2(os.urandom(N))
        e2 = _cbd2(os.urandom(N))

        # 32-byte symmetric message
        msg_bytes = os.urandom(32)
        # Encode 256 bits into polynomial: bit 1 -> round(Q/2), bit 0 -> 0
        msg_poly = []
        for byte_idx in range(32):
            b = msg_bytes[byte_idx]
            for bit_idx in range(8):
                bit = (b >> bit_idx) & 1
                msg_poly.append((Q // 2) if bit else 0)

        # u = a * r + e1
        u = _poly_add(_poly_mul_negacyclic(a, r), e1)
        # v = t * r + e2 + msg_poly
        tr = _poly_mul_negacyclic(t, r)
        v = _poly_add(_poly_add(tr, e2), msg_poly)

        ct = _pack_poly(u) + _pack_poly(v)
        shared_secret = hashlib.sha256(msg_bytes + b"LATTICE-KEM-SHARED").digest()
        return ct, shared_secret

    @staticmethod
    def decaps(sk: bytes, ct: bytes) -> bytes:
        s = _unpack_poly(sk)
        u = _unpack_poly(ct[: N * 2])
        v = _unpack_poly(ct[N * 2 :])

        # Decrypt: diff = v - s * u
        su = _poly_mul_negacyclic(s, u)
        diff = _poly_sub(v, su)

        # Decode message bits: round(diff) close to Q/2 is 1, close to 0/Q is 0
        half_q = Q // 2
        quarter_q = Q // 4
        msg_bytes = bytearray(32)
        for byte_idx in range(32):
            b = 0
            for bit_idx in range(8):
                coeff = diff[byte_idx * 8 + bit_idx]
                dist_zero = min(coeff, Q - coeff)
                dist_half = abs(coeff - half_q)
                bit = 1 if dist_half < dist_zero else 0
                b |= bit << bit_idx
            msg_bytes[byte_idx] = b

        return hashlib.sha256(bytes(msg_bytes) + b"LATTICE-KEM-SHARED").digest()


def get_kem(algorithm: str = "lattice"):
    """Factory to retrieve requested KEM algorithm ('lattice' or 'x25519')."""
    if algorithm.lower() in ("lattice", "kyber", "pqc"):
        return LatticeKEM
    elif algorithm.lower() in ("x25519", "ecdh", "classical"):
        return X25519KEM
    raise ValueError(f"Unknown KEM algorithm: {algorithm}. Supported: 'lattice', 'x25519'")

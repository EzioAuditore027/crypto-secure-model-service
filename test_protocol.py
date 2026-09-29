"""
Automated Test Suite for Cryptographic Protocol and Model Service
Tests:
1. HKDF-SHA256 Derivation
2. AEAD ChaCha20-Poly1305 Encryption, Decryption, & Integrity Detection
3. Lattice-Based KEM (Post-Quantum) & X25519 KEM
4. Secure Channel Handshake & Anti-Replay Defense
5. Session Termination & Memory Key Zeroization
6. ML Model Inference & Retraining Pipeline
"""
import unittest
import base64
import json
from crypto.kdf import hkdf, hkdf_extract, hkdf_expand
from crypto.aead import ChaCha20Poly1305, IntegrityError
from crypto.kem import LatticeKEM, X25519KEM
from crypto.channel import SecureSession, SecurePacket, ReplayAttackError, SessionExpiredError
from ml.dataset import get_initial_dataset
from ml.model import ModelService, MLModel


class TestCryptoProtocol(unittest.TestCase):

    def test_01_hkdf(self):
        """Verify HKDF-SHA256 deterministic expansion and independence."""
        ikm = b"initial-keying-material-test"
        salt = b"test-salt"
        key1 = hkdf(ikm, salt=salt, info=b"context-1", length=32)
        key2 = hkdf(ikm, salt=salt, info=b"context-2", length=32)
        self.assertEqual(len(key1), 32)
        self.assertEqual(len(key2), 32)
        self.assertNotEqual(key1, key2, "Different context info must yield distinct keys")

    def test_02_aead_encrypt_decrypt(self):
        """Verify ChaCha20-Poly1305 AEAD round-trip."""
        key = b"\x01" * 32
        nonce = b"\x02" * 12
        aad = b"authenticated-associated-data"
        plaintext = b"Confidential Medical / Model Query Message"

        cipher = ChaCha20Poly1305(key)
        ciphertext = cipher.encrypt(nonce, plaintext, associated_data=aad)
        decrypted = cipher.decrypt(nonce, ciphertext, associated_data=aad)
        self.assertEqual(plaintext, decrypted)

    def test_03_aead_tamper_detection(self):
        """Verify active tampering with ciphertext or AAD raises IntegrityError."""
        key = b"\x05" * 32
        nonce = b"\x06" * 12
        aad = b"header-data"
        plaintext = b"Sensitive Payload"

        cipher = ChaCha20Poly1305(key)
        ct = bytearray(cipher.encrypt(nonce, plaintext, associated_data=aad))

        # 1. Flip a single bit in ciphertext
        ct[0] ^= 0x01
        with self.assertRaises(IntegrityError):
            cipher.decrypt(nonce, bytes(ct), associated_data=aad)

        # 2. Tamper with AAD
        ct[0] ^= 0x01  # restore bit
        with self.assertRaises(IntegrityError):
            cipher.decrypt(nonce, bytes(ct), associated_data=b"tampered-aad")

    def test_04_lattice_kem(self):
        """Verify Post-Quantum Lattice KEM encapsulation and decapsulation."""
        pk, sk = LatticeKEM.keygen()
        ct, secret_sender = LatticeKEM.encaps(pk)
        secret_receiver = LatticeKEM.decaps(sk, ct)
        self.assertEqual(
            secret_sender, secret_receiver, "Lattice-KEM shared secrets must match exactly"
        )
        self.assertEqual(len(secret_sender), 32)

    def test_05_x25519_kem(self):
        """Verify Classical X25519 KEM encapsulation and decapsulation."""
        pk, sk = X25519KEM.keygen()
        ct, secret_sender = X25519KEM.encaps(pk)
        secret_receiver = X25519KEM.decaps(sk, ct)
        self.assertEqual(secret_sender, secret_receiver)

    def test_06_secure_session_exchange(self):
        """Verify full bidirectional secure channel message exchange."""
        shared_secret = b"\xaa" * 32
        session_id = "sess_test_123"

        client = SecureSession(session_id, shared_secret, is_client=True)
        server = SecureSession(session_id, shared_secret, is_client=False)

        # Client -> Server
        msg1 = json.dumps({"x": "Check this urgent email text"})
        pkt1 = client.encrypt_message(msg1)
        decrypted1 = server.decrypt_message(pkt1)
        self.assertEqual(msg1, decrypted1)

        # Server -> Client
        msg2 = json.dumps({"prediction": "Phishing", "confidence": 98.5})
        pkt2 = server.encrypt_message(msg2)
        decrypted2 = client.decrypt_message(pkt2)
        self.assertEqual(msg2, decrypted2)

    def test_07_anti_replay_defense(self):
        """Verify that replaying a captured packet is rejected by the receiver."""
        shared_secret = b"\xbb" * 32
        session_id = "sess_replay_test"

        client = SecureSession(session_id, shared_secret, is_client=True)
        server = SecureSession(session_id, shared_secret, is_client=False)

        pkt = client.encrypt_message("Original Transaction Query")
        server.decrypt_message(pkt)  # First receipt: valid

        # Adversary attempts replay of same packet:
        with self.assertRaises(ReplayAttackError):
            server.decrypt_message(pkt)

    def test_08_session_termination_and_zeroization(self):
        """Verify session termination zeroizes keys and blocks further operations."""
        shared_secret = b"\xcc" * 32
        session = SecureSession("sess_term", shared_secret, is_client=True)

        session.terminate()
        self.assertTrue(session.is_terminated)
        self.assertEqual(bytes(session._k_client), b"\x00" * 32)
        self.assertEqual(bytes(session._k_server), b"\x00" * 32)

        with self.assertRaises(SessionExpiredError):
            session.encrypt_message("Message after termination")

    def test_09_ml_pipeline(self):
        """Verify BuildModel(D) -> M and RebuildModel(D, D') -> M'."""
        dataset = get_initial_dataset()
        model_v1 = ModelService.build_model(dataset, version="1.0")

        # Test inference
        res = model_v1.predict("Urgent: Account locked! Click here immediately")
        self.assertEqual(res["prediction"], "Phishing / Malicious")
        self.assertEqual(res["version"], "1.0")

        # Retrain with feedback D'
        feedback_d_prime = [
            {"text": "Special campus discount for seminar attendees", "label": 0}
        ]
        model_v2 = ModelService.rebuild_model(dataset, feedback_d_prime, new_version="1.1")
        self.assertEqual(model_v2.version, "1.1")


if __name__ == "__main__":
    unittest.main(verbosity=2)

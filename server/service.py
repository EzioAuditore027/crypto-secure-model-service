"""
Server Business Logic and Cryptographic Orchestration
"""
import base64
import json
import uuid
from typing import Dict, Any, Optional, List, Tuple
from crypto.kem import LatticeKEM, X25519KEM
from crypto.channel import SecureSession, SecurePacket, SessionExpiredError, ReplayAttackError
from crypto.aead import IntegrityError
from ml.model import ModelService, MLModel
from ml.dataset import get_initial_dataset
from .database import Database


class ModelServiceManager:
    """Central server manager coordinating Cryptography, Machine Learning, and DB."""

    def __init__(self, db: Database, kem_algo: str = "lattice"):
        self.db = db
        self.kem_algo = kem_algo
        self.kem = LatticeKEM if kem_algo == "lattice" else X25519KEM

        # Server's long-term public/private keypair
        self.server_pk, self.server_sk = self.kem.keygen()
        self.server_pk_b64 = base64.b64encode(self.server_pk).decode("ascii")

        # Active encrypted sessions in memory: session_id -> {"session": SecureSession, "uid": str}
        self.active_sessions: Dict[str, Dict[str, Any]] = {}

        # Initialize or load active ML model M
        self.active_model: Optional[MLModel] = None
        self._load_or_build_initial_model()

    def _load_or_build_initial_model(self) -> None:
        """Loads active model from DB or builds M = BuildModel(D)."""
        active_tuple = self.db.get_active_model_blob()
        if active_tuple:
            version, blob, _ = active_tuple
            self.active_model = MLModel.deserialize(blob)
            print(f"[*] Loaded active model version {version} from database.")
        else:
            initial_d = get_initial_dataset()
            print("[*] Building initial model M = BuildModel(D)...")
            self.active_model = ModelService.build_model(initial_d, version="1.0")
            blob = self.active_model.serialize()
            self.db.save_model("1.0", blob, set_active=True)
            print("[+] Initial model v1.0 successfully built and deployed.")

    def get_server_public_key(self) -> Dict[str, str]:
        return {
            "algorithm": self.kem_algo,
            "public_key_b64": self.server_pk_b64,
        }

    # =========================================================================
    # User Lifecycle: Registration, Approval, Revocation
    # =========================================================================

    def register_user(self, username: str, user_pk_b64: str) -> Dict[str, Any]:
        """RequestForUserRegistration()"""
        existing = self.db.get_user_by_username(username)
        if existing:
            return {"success": False, "error": f"Username '{username}' already exists."}
        uid = self.db.register_user(username, user_pk_b64)
        return {
            "success": True,
            "uid": uid,
            "username": username,
            "status": "pending",
            "message": "Registration submitted. Awaiting Owner/Admin approval.",
        }

    def list_pending_approvals(self) -> List[Dict[str, Any]]:
        """RequestForApproval(UID)"""
        return self.db.list_pending_users()

    def approve_user(self, uid: str) -> Dict[str, Any]:
        """Owner: ApproveUser(UID)"""
        success = self.db.approve_user(uid)
        return {"success": success, "uid": uid, "status": "approved" if success else "not_found"}

    def revoke_user(self, uid: str) -> Dict[str, Any]:
        """Owner: RemoveUser(UID)"""
        success = self.db.revoke_user(uid)
        # Terminate any existing sessions for this revoked user
        to_terminate = [
            sid for sid, data in self.active_sessions.items() if data.get("uid") == uid
        ]
        for sid in to_terminate:
            self.terminate_session(sid)
        return {"success": success, "uid": uid, "status": "revoked"}

    # =========================================================================
    # Secure Channel Handshake & Session Management
    # =========================================================================

    def establish_session(self, uid: str, kem_ciphertext_b64: str) -> Dict[str, Any]:
        """
        Step 1 & Step 2 of Secure Protocol:
        Recovers shared secret K = Decaps(sk_Server, ct)
        Derives session keys via HKDF and creates active session state.
        """
        user = self.db.get_user_by_id(uid)
        if not user:
            return {"success": False, "error": "User not found."}
        if user["status"] != "approved":
            return {
                "success": False,
                "error": f"Access denied. User status is '{user['status']}'. Must be 'approved'.",
            }

        try:
            kem_ct = base64.b64decode(kem_ciphertext_b64)
            # K <- Decaps(sk_Server, ct)
            shared_secret = self.kem.decaps(self.server_sk, kem_ct)

            session_id = f"sess_{uuid.uuid4().hex[:12]}"
            session = SecureSession(session_id=session_id, shared_secret=shared_secret, is_client=False)

            self.active_sessions[session_id] = {
                "session": session,
                "uid": uid,
                "username": user["username"],
            }

            return {
                "success": True,
                "session_id": session_id,
                "uid": uid,
                "message": "Secure channel established successfully.",
            }
        except Exception as e:
            return {"success": False, "error": f"Handshake failed: {str(e)}"}

    def terminate_session(self, session_id: str) -> Dict[str, Any]:
        """Session termination and key deletion (zeroization)."""
        entry = self.active_sessions.pop(session_id, None)
        if entry:
            entry["session"].terminate()
            return {"success": True, "message": "Session terminated and session keys zeroized."}
        return {"success": False, "error": "Session not found."}

    # =========================================================================
    # Encrypted Query and Feedback Operations
    # =========================================================================

    def handle_encrypted_query(self, packet: SecurePacket) -> Tuple[bool, Any]:
        """
        Query(x) -> y:
        1. Checks anti-replay sequence number
        2. Verifies AEAD authentication tag and decrypts input x
        3. Executes ML inference y = Model.predict(x)
        4. Encrypts response y and increments server sequence counter
        """
        entry = self.active_sessions.get(packet.session_id)
        if not entry:
            return False, {"error": "Invalid or expired session. Please perform handshake again."}

        session: SecureSession = entry["session"]
        uid = entry["uid"]

        # Verify user still active
        user = self.db.get_user_by_id(uid)
        if not user or user["status"] != "approved":
            return False, {"error": "User authorization revoked."}

        try:
            # Decrypt incoming message
            plaintext_req = session.decrypt_message(packet)
            req_data = json.loads(plaintext_req)
            query_text = req_data.get("x", "")

            # Run ML model inference
            inference_result = self.active_model.predict(query_text)
            inference_result["query_x"] = query_text

            # Encrypt response with Server Write Key
            response_plaintext = json.dumps(inference_result)
            resp_packet = session.encrypt_message(response_plaintext)

            return True, resp_packet
        except (IntegrityError, ReplayAttackError, SessionExpiredError) as crypto_err:
            return False, {"error": f"Cryptographic Verification Failed: {str(crypto_err)}"}
        except Exception as err:
            return False, {"error": f"Query processing error: {str(err)}"}

    def handle_encrypted_feedback(self, packet: SecurePacket) -> Tuple[bool, Any]:
        """
        StoreFeedback(UID, x, y, f):
        Stores user feedback for retraining.
        """
        entry = self.active_sessions.get(packet.session_id)
        if not entry:
            return False, {"error": "Session not found."}

        session: SecureSession = entry["session"]
        uid = entry["uid"]

        try:
            plaintext = session.decrypt_message(packet)
            data = json.loads(plaintext)

            query_text = data.get("x", "")
            prediction = data.get("y", "")
            feedback_label = int(data.get("f", 0))
            rating = data.get("rating", "")

            fid = self.db.store_feedback(uid, query_text, prediction, feedback_label, rating)

            ack_data = {"status": "success", "feedback_id": fid, "message": "Feedback securely recorded."}
            resp_packet = session.encrypt_message(json.dumps(ack_data))
            return True, resp_packet
        except Exception as e:
            return False, {"error": f"Feedback processing error: {str(e)}"}

    # =========================================================================
    # Owner Operations: Retraining and Deploying Model
    # =========================================================================

    def view_new_data(self) -> List[Dict[str, Any]]:
        """ViewNewData(): View feedback data collected from authorized users."""
        return self.db.get_all_feedback()

    def download_new_data(self) -> List[Dict[str, Any]]:
        """DownloadNewData() -> D': Export collected feedback for retraining."""
        return self.db.get_all_feedback()

    def rebuild_and_deploy_model(self) -> Dict[str, Any]:
        """
        Owner Operation:
        RebuildModel(D, D') -> M' and UpdateModel(M')
        """
        feedback_list = self.db.get_all_feedback()
        formatted_feedback = [
            {"text": fb["query_text"], "label": fb["feedback_label"]}
            for fb in feedback_list
        ]

        curr_ver = self.active_model.version if self.active_model else "1.0"
        try:
            major, minor = curr_ver.split(".")
            next_ver = f"{major}.{int(minor) + 1}"
        except Exception:
            next_ver = "2.0"

        initial_d = get_initial_dataset()
        print(f"[*] Rebuilding model with {len(formatted_feedback)} user feedback samples...")
        updated_model = ModelService.rebuild_model(initial_d, formatted_feedback, new_version=next_ver)

        blob = updated_model.serialize()
        self.db.save_model(next_ver, blob, set_active=True)
        self.active_model = updated_model

        print(f"[+] Model updated to version {next_ver} and securely deployed!")
        return {
            "success": True,
            "version": next_ver,
            "feedback_count": len(formatted_feedback),
            "message": f"Model successfully rebuilt and deployed as version {next_ver}.",
        }

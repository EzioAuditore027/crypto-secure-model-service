"""
User Application CLI Tool
Allows User to:
1. Register with the Server (RequestForRegistration)
2. Establish Secure Channel via KEM Handshake
3. Send Encrypted Queries to the Model (Query(x) -> y)
4. Submit Labeled Feedback (SubmitFeedback(f))
5. Terminate Session & Zeroize Keys
"""
import sys
import os
import json
import base64
import urllib.request

# Add root directory to python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from crypto.kem import LatticeKEM
from crypto.channel import SecureSession, SecurePacket

SERVER_URL = "http://127.0.0.1:8000"


def http_post(endpoint: str, payload: dict) -> dict:
    url = f"{SERVER_URL}{endpoint}"
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json", "User-Agent": "UserCLI/1.0"}
    )
    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8")
        try:
            return json.loads(err_body)
        except Exception:
            return {"success": False, "error": str(e)}


def http_get(endpoint: str) -> dict:
    url = f"{SERVER_URL}{endpoint}"
    req = urllib.request.Request(url, headers={"User-Agent": "UserCLI/1.0"})
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode("utf-8"))


def main():
    print("=" * 60)
    print("[*] AUTHORIZED USER SECURE CLI")
    print("=" * 60)

    # 1. User Key Generation
    print("[*] Initializing Lattice-based keypair (pk_User, sk_User)...")
    user_pk, user_sk = LatticeKEM.keygen()
    user_pk_b64 = base64.b64encode(user_pk).decode("ascii")

    uid = None
    session: SecureSession = None
    session_id = None
    last_query_text = ""
    last_pred_label = ""

    while True:
        print("\nOperations:")
        print("1. Register User (RequestForRegistration)")
        print("2. Establish Secure Channel (KEM Handshake)")
        print("3. Query Model (Encrypted Query(x) -> y)")
        print("4. Submit Feedback (SubmitFeedback(f))")
        print("5. Terminate Session (SessionTermination)")
        print("6. Exit")
        choice = input("\nEnter choice [1-6]: ").strip()

        if choice == "1":
            username = input("Enter username: ").strip()
            if not username:
                continue
            res = http_post("/api/auth/register", {"username": username, "user_pk_b64": user_pk_b64})
            if res.get("success"):
                uid = res["uid"]
                print(f"[+] Registration successful! UID: {uid}")
                print("    Status: PENDING approval from Owner/Admin.")
            else:
                print(f"[!] Registration failed: {res.get('error')}")

        elif choice == "2":
            if not uid:
                uid = input("Enter your assigned UID: ").strip()
            print("[*] 1. Requesting Server Public Key...")
            pk_info = http_get("/api/server/public_key")
            server_pk = base64.b64decode(pk_info["public_key_b64"])

            print("[*] 2. Encapsulating shared secret (ct, K) <- Encaps(pk_Server)...")
            ct, shared_secret = LatticeKEM.encaps(server_pk)
            ct_b64 = base64.b64encode(ct).decode("ascii")

            print("[*] 3. Transmitting ciphertext ct to Server...")
            hs_res = http_post("/api/session/handshake", {"uid": uid, "kem_ct_b64": ct_b64})

            if hs_res.get("success"):
                session_id = hs_res["session_id"]
                session = SecureSession(session_id=session_id, shared_secret=shared_secret, is_client=True)
                print(f"[+] Secure Channel Established! Session ID: {session_id}")
                print("[+] Derived Session Keys via HKDF-SHA256 successfully.")
            else:
                print(f"[!] Handshake failed: {hs_res.get('error')}")

        elif choice == "3":
            if not session:
                print("[!] No active session. Please perform KEM Handshake first.")
                continue
            text = input("Enter text/message to classify: ").strip()
            if not text:
                continue
            last_query_text = text

            # Encrypt request
            query_payload = json.dumps({"x": text})
            packet = session.encrypt_message(query_payload)
            print(f"[*] Sent Encrypted Packet (seq={packet.seq}, nonce={packet.nonce_b64[:12]}...)")

            resp_json = http_post("/api/model/query", json.loads(packet.to_json()))
            if resp_json.get("success"):
                resp_packet = SecurePacket.from_json(json.dumps(resp_json["packet"]))
                plaintext_resp = session.decrypt_message(resp_packet)
                pred = json.loads(plaintext_resp)
                last_pred_label = pred["prediction"]
                print("\n--- Model Output (y) ---")
                print(f"Prediction:  {pred['prediction']}")
                print(f"Confidence:  {pred['confidence']}%")
                print(f"Model Ver:   v{pred['version']}")
                print("------------------------")
            else:
                print(f"[!] Query failed: {resp_json.get('error')}")

        elif choice == "4":
            if not session:
                print("[!] No active session.")
                continue
            f_val = input("Enter ground truth (1 for Phishing, 0 for Clean): ").strip()
            rating = input("Enter optional comments/rating: ").strip()
            fb_payload = json.dumps({
                "x": last_query_text,
                "y": last_pred_label,
                "f": int(f_val) if f_val in ("0", "1") else 0,
                "rating": rating,
            })
            packet = session.encrypt_message(fb_payload)
            resp_json = http_post("/api/model/feedback", json.loads(packet.to_json()))
            if resp_json.get("success"):
                resp_packet = SecurePacket.from_json(json.dumps(resp_json["packet"]))
                ack = json.loads(session.decrypt_message(resp_packet))
                print(f"[+] Feedback stored! Server Ack: {ack.get('message')}")
            else:
                print(f"[!] Feedback failed: {resp_json.get('error')}")

        elif choice == "5":
            if session and session_id:
                http_post("/api/session/terminate", {"session_id": session_id})
                session.terminate()
                session = None
                session_id = None
                print("[+] Session terminated and keys zeroized in memory.")
            else:
                print("[*] No active session to terminate.")

        elif choice == "6":
            if session:
                session.terminate()
            print("Goodbye.")
            break


if __name__ == "__main__":
    main()

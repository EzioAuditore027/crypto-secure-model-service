"""
HTTP Web Server & REST API Application
Provides:
- Web Portals for Owner/Admin and Authorized Users
- Cryptographic Handshake & Key Establishment API
- Encrypted Model Serving API
"""
import os
import json
import mimetypes
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from .database import Database
from .service import ModelServiceManager
from crypto.channel import SecurePacket

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WEB_DIR = os.path.join(BASE_DIR, "web")
DB_PATH = os.path.join(BASE_DIR, "secure_service.db")

# Global Singleton Manager
db_instance = Database(DB_PATH)
manager = ModelServiceManager(db_instance, kem_algo="lattice")


class SecureServiceHandler(BaseHTTPRequestHandler):

    def _send_json(self, data: dict, status_code: int = 200) -> None:
        payload = json.dumps(data).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()
        self.wfile.write(payload)

    def _serve_file(self, filepath: str) -> None:
        if not os.path.exists(filepath) or os.path.isdir(filepath):
            self.send_error(404, "File Not Found")
            return
        mime_type, _ = mimetypes.guess_type(filepath)
        if not mime_type:
            mime_type = "text/plain"
        with open(filepath, "rb") as f:
            content = f.read()
        self.send_response(200)
        self.send_header("Content-Type", mime_type)
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def _read_json_body(self) -> dict:
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length == 0:
            return {}
        body = self.rfile.read(content_length)
        return json.loads(body.decode("utf-8"))

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        # Static / Web UI routes
        if path in ("/", "/index", "/index.html"):
            return self._serve_file(os.path.join(WEB_DIR, "index.html"))
        elif path in ("/admin", "/admin.html"):
            return self._serve_file(os.path.join(WEB_DIR, "admin.html"))
        elif path in ("/user", "/user.html"):
            return self._serve_file(os.path.join(WEB_DIR, "user.html"))
        elif path.startswith("/static/"):
            rel_path = path[len("/static/"):]
            return self._serve_file(os.path.join(WEB_DIR, "static", rel_path))

        # API routes
        elif path == "/api/server/public_key":
            return self._send_json(manager.get_server_public_key())
        elif path == "/api/admin/pending_users":
            return self._send_json({"users": manager.list_pending_approvals()})
        elif path == "/api/admin/all_users":
            return self._send_json({"users": manager.db.list_all_users()})
        elif path == "/api/admin/view_data":
            return self._send_json({"data": manager.view_new_data()})
        elif path == "/api/model/info":
            ver = manager.active_model.version if manager.active_model else "none"
            return self._send_json({"active_version": ver, "active_sessions": len(manager.active_sessions)})
        else:
            self.send_error(404, "Not Found")

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        body = self._read_json_body()

        if path == "/api/auth/register":
            username = body.get("username", "").strip()
            user_pk = body.get("user_pk_b64", "").strip()
            if not username or not user_pk:
                return self._send_json({"success": False, "error": "Missing username or public key."}, 400)
            res = manager.register_user(username, user_pk)
            return self._send_json(res, 200 if res["success"] else 400)

        elif path == "/api/admin/approve_user":
            uid = body.get("uid", "")
            res = manager.approve_user(uid)
            return self._send_json(res)

        elif path == "/api/admin/revoke_user":
            uid = body.get("uid", "")
            res = manager.revoke_user(uid)
            return self._send_json(res)

        elif path == "/api/session/handshake":
            uid = body.get("uid", "")
            kem_ct_b64 = body.get("kem_ct_b64", "")
            res = manager.establish_session(uid, kem_ct_b64)
            return self._send_json(res, 200 if res["success"] else 400)

        elif path == "/api/model/query":
            try:
                packet = SecurePacket.from_json(json.dumps(body))
                success, result = manager.handle_encrypted_query(packet)
                if success:
                    return self._send_json({"success": True, "packet": json.loads(result.to_json())})
                else:
                    return self._send_json({"success": False, "error": result["error"]}, 400)
            except Exception as e:
                return self._send_json({"success": False, "error": str(e)}, 400)

        elif path == "/api/model/feedback":
            try:
                packet = SecurePacket.from_json(json.dumps(body))
                success, result = manager.handle_encrypted_feedback(packet)
                if success:
                    return self._send_json({"success": True, "packet": json.loads(result.to_json())})
                else:
                    return self._send_json({"success": False, "error": result["error"]}, 400)
            except Exception as e:
                return self._send_json({"success": False, "error": str(e)}, 400)

        elif path == "/api/admin/rebuild_model":
            res = manager.rebuild_and_deploy_model()
            return self._send_json(res)

        elif path == "/api/session/terminate":
            session_id = body.get("session_id", "")
            res = manager.terminate_session(session_id)
            return self._send_json(res)

        # Client-Side Cryptographic Simulator endpoints for Web UI
        elif path == "/api/client_helper/generate_keys":
            kem = manager.kem
            pk, sk = kem.keygen()
            return self._send_json({
                "public_key_b64": base64.b64encode(pk).decode("ascii"),
                "secret_key_b64": base64.b64encode(sk).decode("ascii"),
            })

        elif path == "/api/client_helper/encaps":
            kem = manager.kem
            server_pk_b64 = body.get("server_pk_b64", "")
            server_pk = base64.b64decode(server_pk_b64)
            ct, shared_secret = kem.encaps(server_pk)
            return self._send_json({
                "kem_ct_b64": base64.b64encode(ct).decode("ascii"),
                "shared_secret_b64": base64.b64encode(shared_secret).decode("ascii"),
            })

        elif path == "/api/client_helper/encrypt":
            session_id = body.get("session_id", "")
            shared_secret_b64 = body.get("shared_secret_b64", "")
            shared_secret = base64.b64decode(shared_secret_b64)
            plaintext = body.get("plaintext", "")
            seq = int(body.get("seq", 1))

            client_session = SecureSession(session_id=session_id, shared_secret=shared_secret, is_client=True)
            client_session.send_seq = seq - 1
            packet = client_session.encrypt_message(plaintext)
            return self._send_json({
                "packet": json.loads(packet.to_json()),
                "k_client_b64": base64.b64encode(client_session._k_client).decode("ascii"),
            })

        elif path == "/api/client_helper/decrypt":
            session_id = body.get("session_id", "")
            shared_secret_b64 = body.get("shared_secret_b64", "")
            shared_secret = base64.b64decode(shared_secret_b64)
            packet_data = body.get("packet", {})
            packet = SecurePacket.from_json(json.dumps(packet_data))

            client_session = SecureSession(session_id=session_id, shared_secret=shared_secret, is_client=True)
            # Reconstruct sequence state
            client_session.recv_seq = packet.seq - 1
            plaintext = client_session.decrypt_message(packet)
            return self._send_json({"plaintext": plaintext})

        else:
            self.send_error(404, "Endpoint Not Found")


def run(host: str = "127.0.0.1", port: int = 8000):
    server_address = (host, port)
    httpd = HTTPServer(server_address, SecureServiceHandler)
    print("=" * 70)
    print(f"[*] Cryptography-Based Secure Model Service running at http://{host}:{port}")
    print(f"[*] Owner / Admin Portal: http://{host}:{port}/admin")
    print(f"[*] User Portal:          http://{host}:{port}/user")
    print(f"[*] Overview / Switcher:  http://{host}:{port}/")
    print("=" * 70)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down server gracefully...")
        httpd.server_close()


if __name__ == "__main__":
    run()

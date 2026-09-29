"""
Database Management Layer
SQLite-backed persistent storage for Users, Models, Feedback, and Cryptographic Public Keys.
"""
import sqlite3
import time
import os
import uuid
from typing import List, Dict, Any, Optional, Tuple


class Database:
    """Embedded SQLite database handling state for Owner, Server, and Users."""

    def __init__(self, db_path: str = "secure_service.db"):
        self.db_path = db_path
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._get_conn() as conn:
            conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                uid TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                public_key_b64 TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                created_at REAL NOT NULL
            );

            CREATE TABLE IF NOT EXISTS models (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                version TEXT NOT NULL,
                weights_blob BLOB NOT NULL,
                deployed_at REAL NOT NULL,
                is_active INTEGER NOT NULL DEFAULT 1
            );

            CREATE TABLE IF NOT EXISTS feedback (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                uid TEXT NOT NULL,
                query_text TEXT NOT NULL,
                prediction TEXT NOT NULL,
                feedback_label INTEGER NOT NULL,
                rating TEXT,
                created_at REAL NOT NULL
            );

            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                uid TEXT NOT NULL,
                created_at REAL NOT NULL,
                is_active INTEGER NOT NULL DEFAULT 1
            );
            """)

    def register_user(self, username: str, public_key_b64: str) -> str:
        uid = f"usr_{uuid.uuid4().hex[:10]}"
        with self._get_conn() as conn:
            conn.execute(
                "INSERT INTO users (uid, username, public_key_b64, status, created_at) VALUES (?, ?, ?, 'pending', ?)",
                (uid, username, public_key_b64, time.time()),
            )
        return uid

    def get_user_by_id(self, uid: str) -> Optional[Dict[str, Any]]:
        with self._get_conn() as conn:
            cur = conn.execute("SELECT * FROM users WHERE uid = ?", (uid,))
            row = cur.fetchone()
            return dict(row) if row else None

    def get_user_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        with self._get_conn() as conn:
            cur = conn.execute("SELECT * FROM users WHERE username = ?", (username,))
            row = cur.fetchone()
            return dict(row) if row else None

    def list_pending_users(self) -> List[Dict[str, Any]]:
        with self._get_conn() as conn:
            cur = conn.execute("SELECT uid, username, status, created_at FROM users WHERE status = 'pending'")
            return [dict(r) for r in cur.fetchall()]

    def list_all_users(self) -> List[Dict[str, Any]]:
        with self._get_conn() as conn:
            cur = conn.execute("SELECT uid, username, status, created_at FROM users ORDER BY created_at DESC")
            return [dict(r) for r in cur.fetchall()]

    def approve_user(self, uid: str) -> bool:
        with self._get_conn() as conn:
            cur = conn.execute("UPDATE users SET status = 'approved' WHERE uid = ?", (uid,))
            return cur.rowcount > 0

    def revoke_user(self, uid: str) -> bool:
        with self._get_conn() as conn:
            cur = conn.execute("UPDATE users SET status = 'revoked' WHERE uid = ?", (uid,))
            return cur.rowcount > 0

    def save_model(self, version: str, weights_blob: bytes, set_active: bool = True) -> int:
        with self._get_conn() as conn:
            if set_active:
                conn.execute("UPDATE models SET is_active = 0")
            cur = conn.execute(
                "INSERT INTO models (version, weights_blob, deployed_at, is_active) VALUES (?, ?, ?, ?)",
                (version, weights_blob, time.time(), 1 if set_active else 0),
            )
            return cur.lastrowid

    def get_active_model_blob(self) -> Optional[Tuple[str, bytes, float]]:
        with self._get_conn() as conn:
            cur = conn.execute(
                "SELECT version, weights_blob, deployed_at FROM models WHERE is_active = 1 ORDER BY id DESC LIMIT 1"
            )
            row = cur.fetchone()
            if row:
                return row["version"], row["weights_blob"], row["deployed_at"]
            return None

    def store_feedback(self, uid: str, query_text: str, prediction: str, feedback_label: int, rating: str = "") -> int:
        with self._get_conn() as conn:
            cur = conn.execute(
                "INSERT INTO feedback (uid, query_text, prediction, feedback_label, rating, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (uid, query_text, prediction, feedback_label, rating, time.time()),
            )
            return cur.lastrowid

    def get_all_feedback(self) -> List[Dict[str, Any]]:
        with self._get_conn() as conn:
            cur = conn.execute("SELECT id, uid, query_text, prediction, feedback_label, rating, created_at FROM feedback ORDER BY id ASC")
            return [dict(r) for r in cur.fetchall()]

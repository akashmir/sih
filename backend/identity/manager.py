"""
Identity Manager — Offline PKI for user registration and key management.

Server stores ONLY public keys. Private keys are returned to the user
as a downloadable .key bundle file (JSON format).
"""

import os
import sqlite3
import base64
import time
from dataclasses import dataclass
from typing import Optional, List

from ..crypto import pq_engine

DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'identity.db')


@dataclass
class UserRecord:
    """Public user record (no private keys stored server-side)."""
    user_id: str
    display_name: str
    kem_public_key: str     # Base64-encoded
    kem_algorithm: str
    sig_public_key: str     # Base64-encoded
    sig_algorithm: str
    registered_at: float


class IdentityManager:
    """Offline identity & key management."""

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or os.path.abspath(DB_PATH)
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._init_db()

    def _init_db(self):
        self.conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                user_id TEXT PRIMARY KEY,
                display_name TEXT NOT NULL,
                kem_public_key TEXT NOT NULL,
                kem_algorithm TEXT NOT NULL,
                sig_public_key TEXT NOT NULL,
                sig_algorithm TEXT NOT NULL,
                registered_at REAL NOT NULL
            )
        ''')
        self.conn.commit()

    def register_user(self, user_id: str, display_name: str) -> dict:
        """
        Register a new user: generate keypairs, store public keys,
        return private key bundle for download.

        Returns:
            {
                "user": UserRecord,
                "private_key_bundle": bytes  (JSON .key file content)
            }
        """
        # Check if user already exists
        existing = self.get_user(user_id)
        if existing:
            raise ValueError(f"User '{user_id}' already exists")

        # Generate keypairs
        kem_kp = pq_engine.generate_kem_keypair()
        sig_kp = pq_engine.generate_signing_keypair()

        # Store ONLY public keys
        user = UserRecord(
            user_id=user_id,
            display_name=display_name,
            kem_public_key=base64.b64encode(kem_kp.public_key).decode(),
            kem_algorithm=kem_kp.algorithm,
            sig_public_key=base64.b64encode(sig_kp.public_key).decode(),
            sig_algorithm=sig_kp.algorithm,
            registered_at=time.time(),
        )

        self.conn.execute(
            '''INSERT INTO users
               (user_id, display_name, kem_public_key, kem_algorithm,
                sig_public_key, sig_algorithm, registered_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)''',
            (user.user_id, user.display_name, user.kem_public_key,
             user.kem_algorithm, user.sig_public_key, user.sig_algorithm,
             user.registered_at),
        )
        self.conn.commit()

        # Generate downloadable private key bundle
        key_bundle = pq_engine.export_key_bundle(kem_kp, sig_kp, user_id)

        return {
            "user": user,
            "private_key_bundle": key_bundle,
        }

    def get_user(self, user_id: str) -> Optional[UserRecord]:
        """Fetch a user by ID."""
        row = self.conn.execute(
            'SELECT * FROM users WHERE user_id = ?', (user_id,)
        ).fetchone()
        if row is None:
            return None
        return UserRecord(*row)

    def list_users(self) -> List[UserRecord]:
        """List all registered users."""
        rows = self.conn.execute(
            'SELECT * FROM users ORDER BY registered_at DESC'
        ).fetchall()
        return [UserRecord(*row) for row in rows]

    def get_kem_public_key(self, user_id: str) -> Optional[bytes]:
        """Get a user's KEM public key (raw bytes)."""
        user = self.get_user(user_id)
        if user is None:
            return None
        return base64.b64decode(user.kem_public_key)

    def get_sig_public_key(self, user_id: str) -> Optional[bytes]:
        """Get a user's signing public key (raw bytes)."""
        user = self.get_user(user_id)
        if user is None:
            return None
        return base64.b64decode(user.sig_public_key)

    def close(self):
        self.conn.close()

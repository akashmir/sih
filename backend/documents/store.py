"""
Document Store — Persists encrypted documents in SQLite.

Only ciphertext, per-recipient wrapped keys and metadata are stored;
the server never holds a document's plaintext or AES key.
"""

import json
import os
import sqlite3
import time
from typing import List, Optional

DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'documents.db')


class DocumentStore:
    """SQLite-backed store of encrypted document records."""

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or os.path.abspath(DB_PATH)
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._init_db()

    def _init_db(self):
        self.conn.execute('''
            CREATE TABLE IF NOT EXISTS documents (
                doc_id TEXT PRIMARY KEY,
                record TEXT NOT NULL,
                created_at REAL NOT NULL
            )
        ''')
        self.conn.commit()

    def put(self, doc_id: str, record: dict) -> None:
        """Store an encrypted document record (JSON-serializable dict)."""
        self.conn.execute(
            'INSERT INTO documents (doc_id, record, created_at) VALUES (?, ?, ?)',
            (doc_id, json.dumps(record), time.time()),
        )
        self.conn.commit()

    def get(self, doc_id: str) -> Optional[dict]:
        """Fetch a document record by ID."""
        row = self.conn.execute(
            'SELECT record FROM documents WHERE doc_id = ?', (doc_id,)
        ).fetchone()
        return json.loads(row[0]) if row else None

    def list(self) -> List[tuple]:
        """List (doc_id, record) pairs, newest first."""
        rows = self.conn.execute(
            'SELECT doc_id, record FROM documents ORDER BY created_at DESC'
        ).fetchall()
        return [(doc_id, json.loads(record)) for doc_id, record in rows]

    def count(self) -> int:
        """Number of stored documents."""
        return self.conn.execute('SELECT COUNT(*) FROM documents').fetchone()[0]

    def close(self):
        self.conn.close()

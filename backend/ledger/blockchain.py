"""
Hash Chain Ledger — Offline, tamper-evident audit trail.

Each decryption event is recorded as a block in a SHA-256 hash chain
stored in SQLite. No external dependencies, fully air-gapped.
"""

import hashlib
import json
import sqlite3
import threading
import time
import os
from dataclasses import dataclass, asdict
from typing import List, Optional

DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'ledger.db')


@dataclass
class LedgerBlock:
    """A single block in the hash chain."""
    block_index: int
    timestamp: float
    watermark_id: str
    recipient_id: str
    document_hash: str
    signature: str        # Base64-encoded ML-DSA signature
    sig_algorithm: str
    prev_hash: str
    block_hash: str
    # Fields the decryption signature covers. Empty/0 on blocks written
    # before they were recorded (those are hashed without them).
    doc_id: str = ""
    watermark_timestamp: int = 0


_COLUMNS = (
    "block_index, timestamp, watermark_id, recipient_id, document_hash, "
    "signature, sig_algorithm, prev_hash, block_hash, doc_id, watermark_timestamp"
)


def _block_data(block: "LedgerBlock") -> str:
    """Canonical JSON of a block's hashed payload."""
    fields = {
        "watermark_id": block.watermark_id,
        "recipient_id": block.recipient_id,
        "document_hash": block.document_hash,
        "signature": block.signature,
        "sig_algorithm": block.sig_algorithm,
    }
    if block.doc_id:
        fields["doc_id"] = block.doc_id
        fields["watermark_timestamp"] = block.watermark_timestamp
    return json.dumps(fields, sort_keys=True)


def _compute_hash(block_index: int, timestamp: float, data: str, prev_hash: str) -> str:
    """Compute SHA-256 hash for a block."""
    raw = f"{block_index}:{timestamp}:{data}:{prev_hash}"
    return hashlib.sha256(raw.encode()).hexdigest()


class HashChainLedger:
    """SQLite-backed hash chain for immutable decryption audit records."""

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or os.path.abspath(DB_PATH)
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._lock = threading.Lock()
        self._init_db()

    def _init_db(self):
        """Create the ledger table if it doesn't exist."""
        self.conn.execute('''
            CREATE TABLE IF NOT EXISTS blocks (
                block_index INTEGER PRIMARY KEY,
                timestamp REAL NOT NULL,
                watermark_id TEXT NOT NULL,
                recipient_id TEXT NOT NULL,
                document_hash TEXT NOT NULL,
                signature TEXT NOT NULL,
                sig_algorithm TEXT NOT NULL,
                prev_hash TEXT NOT NULL,
                block_hash TEXT NOT NULL UNIQUE,
                doc_id TEXT NOT NULL DEFAULT '',
                watermark_timestamp INTEGER NOT NULL DEFAULT 0
            )
        ''')
        # Migrate ledgers created before doc_id/watermark_timestamp existed
        existing = {row[1] for row in self.conn.execute('PRAGMA table_info(blocks)')}
        if 'doc_id' not in existing:
            self.conn.execute(
                "ALTER TABLE blocks ADD COLUMN doc_id TEXT NOT NULL DEFAULT ''"
            )
        if 'watermark_timestamp' not in existing:
            self.conn.execute(
                "ALTER TABLE blocks ADD COLUMN watermark_timestamp INTEGER NOT NULL DEFAULT 0"
            )
        self.conn.execute('''
            CREATE INDEX IF NOT EXISTS idx_watermark_id
            ON blocks (watermark_id)
        ''')
        self.conn.execute('''
            CREATE INDEX IF NOT EXISTS idx_recipient_id
            ON blocks (recipient_id)
        ''')
        self.conn.commit()

    def _get_latest_block(self) -> Optional[LedgerBlock]:
        """Get the most recent block."""
        row = self.conn.execute(
            f'SELECT {_COLUMNS} FROM blocks ORDER BY block_index DESC LIMIT 1'
        ).fetchone()
        if row is None:
            return None
        return LedgerBlock(*row)

    def get_chain_length(self) -> int:
        """Get the number of blocks in the chain."""
        result = self.conn.execute('SELECT COUNT(*) FROM blocks').fetchone()
        return result[0] if result else 0

    def add_block(
        self,
        watermark_id: str,
        recipient_id: str,
        document_hash: str,
        signature: str,
        sig_algorithm: str,
        doc_id: str = "",
        watermark_timestamp: int = 0,
    ) -> LedgerBlock:
        """
        Add a new decryption record to the hash chain.

        Args:
            watermark_id: Unique watermark identifier
            recipient_id: ID of the recipient who decrypted
            document_hash: SHA-256 of the original document
            signature: Base64-encoded digital signature
            sig_algorithm: Algorithm used for signing
            doc_id: Document the decryption was for (covered by the signature)
            watermark_timestamp: Watermark timestamp (covered by the signature)

        Returns:
            The newly created LedgerBlock
        """
        # Serialize read-latest + insert so concurrent requests can't fork the chain
        with self._lock:
            latest = self._get_latest_block()
            block = LedgerBlock(
                block_index=(latest.block_index + 1) if latest else 0,
                timestamp=time.time(),
                watermark_id=watermark_id,
                recipient_id=recipient_id,
                document_hash=document_hash,
                signature=signature,
                sig_algorithm=sig_algorithm,
                prev_hash=latest.block_hash if latest else ("0" * 64),
                block_hash="",
                doc_id=doc_id,
                watermark_timestamp=watermark_timestamp,
            )
            block.block_hash = _compute_hash(
                block.block_index, block.timestamp, _block_data(block), block.prev_hash
            )

            self.conn.execute(
                f'''INSERT INTO blocks ({_COLUMNS})
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                (block.block_index, block.timestamp, block.watermark_id,
                 block.recipient_id, block.document_hash, block.signature,
                 block.sig_algorithm, block.prev_hash, block.block_hash,
                 block.doc_id, block.watermark_timestamp),
            )
            self.conn.commit()
        return block

    def find_by_watermark(self, watermark_id: str) -> Optional[LedgerBlock]:
        """Look up a block by watermark ID."""
        row = self.conn.execute(
            f'SELECT {_COLUMNS} FROM blocks WHERE watermark_id = ?',
            (watermark_id,),
        ).fetchone()
        if row is None:
            return None
        return LedgerBlock(*row)

    def find_by_recipient(self, recipient_id: str) -> List[LedgerBlock]:
        """Find all blocks for a given recipient."""
        rows = self.conn.execute(
            f'SELECT {_COLUMNS} FROM blocks WHERE recipient_id = ? ORDER BY block_index',
            (recipient_id,),
        ).fetchall()
        return [LedgerBlock(*row) for row in rows]

    def get_all_blocks(self, limit: int = 100, offset: int = 0) -> List[LedgerBlock]:
        """Get blocks with pagination."""
        rows = self.conn.execute(
            f'SELECT {_COLUMNS} FROM blocks ORDER BY block_index DESC LIMIT ? OFFSET ?',
            (limit, offset),
        ).fetchall()
        return [LedgerBlock(*row) for row in rows]

    def validate_chain(self) -> dict:
        """
        Validate the entire hash chain for tamper detection.

        Returns:
            {"valid": bool, "blocks_checked": int, "errors": [...]}
        """
        rows = self.conn.execute(
            f'SELECT {_COLUMNS} FROM blocks ORDER BY block_index ASC'
        ).fetchall()

        if not rows:
            return {"valid": True, "blocks_checked": 0, "errors": []}

        errors = []
        prev_hash = "0" * 64

        for row in rows:
            block = LedgerBlock(*row)

            # Check prev_hash linkage
            if block.prev_hash != prev_hash:
                errors.append({
                    "block_index": block.block_index,
                    "error": "prev_hash mismatch",
                    "expected": prev_hash,
                    "actual": block.prev_hash,
                })

            # Recompute block hash
            expected_hash = _compute_hash(
                block.block_index, block.timestamp, _block_data(block), block.prev_hash
            )

            if block.block_hash != expected_hash:
                errors.append({
                    "block_index": block.block_index,
                    "error": "block_hash mismatch",
                    "expected": expected_hash,
                    "actual": block.block_hash,
                })

            prev_hash = block.block_hash

        return {
            "valid": len(errors) == 0,
            "blocks_checked": len(rows),
            "errors": errors,
        }

    def close(self):
        """Close the database connection."""
        self.conn.close()

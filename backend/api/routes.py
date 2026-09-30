"""
NISHAN API Routes — FastAPI endpoints for document lifecycle.

Endpoints:
- POST /api/users/register          — register user, download .key bundle
- GET  /api/users                   — list registered users
- POST /api/documents/encrypt       — encrypt doc for multi-recipient distribution
- POST /api/documents/decrypt       — decrypt + watermark + sign + ledger
- POST /api/forensics/investigate   — extract watermark, match ledger, verify sig
- GET  /api/ledger/blocks           — browse the hash chain
- GET  /api/ledger/verify           — validate chain integrity
- GET  /api/system/info             — crypto backend info
"""

import base64
import hashlib
import io
import json
import os
import re
import uuid
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import quote

from fastapi import APIRouter, UploadFile, File, Form, HTTPException
from fastapi.responses import StreamingResponse, JSONResponse

from ..crypto import pq_engine, symmetric
from ..watermark.encoder import generate_watermark, recipient_hash
from ..watermark.embedder import (
    embed_watermark, output_filename, validate_document, UnsupportedDocumentError,
)
from ..watermark.extractor import extract_watermark
from ..ledger.blockchain import HashChainLedger
from ..identity.manager import IdentityManager
from ..documents.store import DocumentStore

router = APIRouter(prefix="/api")

# ---------------------------------------------------------------------------
# Shared resources (initialized in main.py via lifespan)
# ---------------------------------------------------------------------------
_ledger: Optional[HashChainLedger] = None
_identity: Optional[IdentityManager] = None
_documents: Optional[DocumentStore] = None

_USER_ID_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")


def init_services(
    ledger: HashChainLedger, identity: IdentityManager, documents: DocumentStore,
):
    """Called by main.py to inject shared resources."""
    global _ledger, _identity, _documents
    _ledger = ledger
    _identity = identity
    _documents = documents


def _content_disposition(filename: str) -> str:
    """Attachment header safe for any filename (RFC 6266 / 5987)."""
    ascii_name = re.sub(r'[^A-Za-z0-9._-]', '_', filename) or "download"
    return f"attachment; filename=\"{ascii_name}\"; filename*=UTF-8''{quote(filename)}"


# ---------------------------------------------------------------------------
# System
# ---------------------------------------------------------------------------
@router.get("/system/info")
async def system_info():
    """Return system info including crypto backend."""
    crypto_info = pq_engine.get_crypto_info()
    chain_length = _ledger.get_chain_length() if _ledger else 0
    users_count = len(_identity.list_users()) if _identity else 0
    return {
        "project": "NISHAN",
        "version": "1.0.0",
        "description": "Cryptographic Attribution & Immutable Decryption Provenance",
        "organization": "Ministry of Defence — Indian Navy (WESEE)",
        "crypto": crypto_info,
        "chain_length": chain_length,
        "registered_users": users_count,
        "documents_encrypted": _documents.count() if _documents else 0,
    }


# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------
@router.post("/users/register")
async def register_user(
    user_id: str = Form(...),
    display_name: str = Form(...),
):
    """
    Register a new user. Returns the private key bundle as a
    downloadable .key file. Server retains ONLY public keys.
    """
    if not _USER_ID_RE.match(user_id):
        raise HTTPException(
            status_code=400,
            detail="User ID must be 1-64 characters: letters, digits, '_', '.', '-'",
        )
    try:
        result = _identity.register_user(user_id, display_name)
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e))

    user = result["user"]
    key_bundle = result["private_key_bundle"]

    return StreamingResponse(
        io.BytesIO(key_bundle),
        media_type="application/json",
        headers={
            "Content-Disposition": _content_disposition(f"{user_id}_private_keys.key"),
            "X-User-Id": user.user_id,
            "X-KEM-Algorithm": user.kem_algorithm,
            "X-SIG-Algorithm": user.sig_algorithm,
        },
    )


@router.get("/users")
async def list_users():
    """List all registered users (public info only)."""
    users = _identity.list_users()
    return [
        {
            "user_id": u.user_id,
            "display_name": u.display_name,
            "kem_algorithm": u.kem_algorithm,
            "sig_algorithm": u.sig_algorithm,
            "registered_at": u.registered_at,
        }
        for u in users
    ]


# ---------------------------------------------------------------------------
# Documents — Encrypt
# ---------------------------------------------------------------------------
@router.post("/documents/encrypt")
async def encrypt_document(
    document: UploadFile = File(...),
    recipients: str = Form(...),  # Comma-separated user IDs
):
    """
    Encrypt a document for multi-recipient distribution.
    Uses ML-KEM to encapsulate the AES key for each recipient.
    """
    doc_data = await document.read()
    filename = document.filename or "document.txt"
    recipient_ids = [r.strip() for r in recipients.split(",") if r.strip()]

    if not recipient_ids:
        raise HTTPException(status_code=400, detail="No recipients specified")

    # Reject anything we can't watermark now, not at decryption time
    try:
        validate_document(doc_data, filename)
    except UnsupportedDocumentError as e:
        raise HTTPException(status_code=415, detail=str(e))

    # Generate a single AES-256 key for the document
    doc_key = os.urandom(32)
    doc_hash = hashlib.sha256(doc_data).hexdigest()

    # Encrypt the document
    encrypted = symmetric.encrypt(doc_key, doc_data, filename.encode())

    # Encapsulate the doc key for each recipient
    encapsulated_keys = {}
    for rid in recipient_ids:
        pub_key = _identity.get_kem_public_key(rid)
        if pub_key is None:
            raise HTTPException(
                status_code=404,
                detail=f"Recipient '{rid}' not found",
            )
        encap_result = pq_engine.encapsulate(pub_key)
        encrypted_key = symmetric.encrypt(encap_result.shared_secret, doc_key)
        encapsulated_keys[rid] = {
            "ciphertext": base64.b64encode(encap_result.ciphertext).decode(),
            "encrypted_doc_key": base64.b64encode(encrypted_key.ciphertext).decode(),
            "encrypted_doc_key_nonce": base64.b64encode(encrypted_key.nonce).decode(),
        }

    doc_id = uuid.uuid4().hex[:12]
    _documents.put(doc_id, {
        "filename": filename,
        "doc_hash": doc_hash,
        "encrypted_nonce": base64.b64encode(encrypted.nonce).decode(),
        "encrypted_data": base64.b64encode(encrypted.ciphertext).decode(),
        "encrypted_aad": base64.b64encode(encrypted.aad).decode(),
        "recipients": encapsulated_keys,
    })

    return {
        "doc_id": doc_id,
        "filename": filename,
        "doc_hash": doc_hash,
        "recipients": list(encapsulated_keys.keys()),
        "message": f"Document encrypted for {len(recipient_ids)} recipients",
    }


# ---------------------------------------------------------------------------
# Documents — Decrypt (with watermarking + signing + ledger)
# ---------------------------------------------------------------------------
@router.post("/documents/decrypt")
async def decrypt_document(
    doc_id: str = Form(...),
    user_id: str = Form(...),
    key_file: UploadFile = File(...),  # The .key bundle
):
    """
    Decrypt a document for a specific recipient.

    Flow:
    1. Validate recipient identity
    2. Import private key bundle from uploaded .key file
    3. Decapsulate AES key using ML-KEM private key
    4. Decrypt the document
    5. Generate unique forensic watermark
    6. Embed invisible watermark in decrypted copy
    7. Sign decryption record with ML-DSA private key
    8. Commit signed record to hash chain ledger
    9. Return watermarked document
    """
    # Verify document exists
    doc_info = _documents.get(doc_id)
    if doc_info is None:
        raise HTTPException(status_code=404, detail="Document not found")

    # Verify recipient is authorized
    if user_id not in doc_info["recipients"]:
        raise HTTPException(
            status_code=403,
            detail="You are not an authorized recipient of this document",
        )

    # Import private key bundle
    key_data = await key_file.read()
    try:
        key_bundle = pq_engine.import_key_bundle(key_data)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid key file: {e}")

    if key_bundle["user_id"] != user_id:
        raise HTTPException(
            status_code=403,
            detail="Key file does not match the specified user",
        )

    engine_kem = pq_engine.get_crypto_info()["kem_algorithm"]
    if key_bundle["kem_algorithm"] and key_bundle["kem_algorithm"] != engine_kem:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Key file was generated for {key_bundle['kem_algorithm']}, "
                f"but the server is running {engine_kem}"
            ),
        )

    # Decapsulate the shared secret using recipient's ML-KEM private key
    encap_data = doc_info["recipients"][user_id]
    ciphertext = base64.b64decode(encap_data["ciphertext"])
    try:
        shared_secret = pq_engine.decapsulate(key_bundle["kem_private_key"], ciphertext)
    except Exception:
        raise HTTPException(status_code=400, detail="Key decapsulation failed")

    # Decrypt the document key using the shared secret
    encrypted_key_payload = symmetric.EncryptedPayload(
        nonce=base64.b64decode(encap_data["encrypted_doc_key_nonce"]),
        ciphertext=base64.b64decode(encap_data["encrypted_doc_key"]),
        aad=b"",
    )

    try:
        doc_key = symmetric.decrypt(shared_secret, encrypted_key_payload)
    except Exception:
        raise HTTPException(status_code=400, detail="Key decapsulation failed")

    # Decrypt the actual document
    encrypted_payload = symmetric.EncryptedPayload(
        nonce=base64.b64decode(doc_info["encrypted_nonce"]),
        ciphertext=base64.b64decode(doc_info["encrypted_data"]),
        aad=base64.b64decode(doc_info["encrypted_aad"]),
    )

    try:
        plaintext = symmetric.decrypt(doc_key, encrypted_payload)
    except Exception:
        raise HTTPException(status_code=400, detail="Decryption failed")

    # Generate unique watermark for this decryption session
    wm_payload = generate_watermark(user_id, doc_id)

    # Embed invisible watermark
    filename = doc_info["filename"]
    watermarked_doc = embed_watermark(plaintext, filename, wm_payload)

    # Sign the decryption record with recipient's ML-DSA private key
    record_data = json.dumps({
        "doc_id": doc_id,
        "doc_hash": doc_info["doc_hash"],
        "watermark_id": wm_payload.watermark_id,
        "recipient_id": user_id,
        "timestamp": wm_payload.timestamp,
    }, sort_keys=True).encode()

    sig_result = pq_engine.sign(key_bundle["sig_private_key"], record_data)

    # Commit to hash chain ledger
    block = _ledger.add_block(
        watermark_id=wm_payload.watermark_id,
        recipient_id=user_id,
        document_hash=doc_info["doc_hash"],
        signature=base64.b64encode(sig_result.signature).decode(),
        sig_algorithm=sig_result.algorithm,
        doc_id=doc_id,
        watermark_timestamp=wm_payload.timestamp,
    )

    # Return the watermarked document
    return StreamingResponse(
        io.BytesIO(watermarked_doc),
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": _content_disposition(
                f"decrypted_{output_filename(filename)}"
            ),
            "X-Watermark-Id": wm_payload.watermark_id,
            "X-Block-Index": str(block.block_index),
            "X-Block-Hash": block.block_hash,
            "X-Signed-With": sig_result.algorithm,
        },
    )


# ---------------------------------------------------------------------------
# Forensics — Investigate leaked document
# ---------------------------------------------------------------------------
@router.post("/forensics/investigate")
async def investigate_document(
    document: UploadFile = File(...),
):
    """
    Forensic investigation: extract watermark from a leaked document,
    look it up in the ledger, and return attribution proof.
    """
    doc_data = await document.read()
    filename = document.filename or "leaked_document"

    # Step 1: Extract watermark
    extracted = extract_watermark(doc_data, filename)

    if extracted is None:
        return {
            "found": False,
            "message": "No forensic watermark detected in this document",
        }

    # Step 2: Look up in the ledger
    block = _ledger.find_by_watermark(extracted.watermark_id)

    if block is None:
        return {
            "found": True,
            "watermark_extracted": True,
            "watermark_id": extracted.watermark_id,
            "ledger_match": False,
            "message": "Watermark found but no matching ledger record",
        }

    # Step 3: Verify the digital signature
    user = _identity.get_user(block.recipient_id)
    sig_public_key = _identity.get_sig_public_key(block.recipient_id)

    # Cross-check the watermark against the ledger record. Blocks written
    # before doc_id was recorded fall back to the watermark's own values.
    signed_doc_id = block.doc_id or extracted.doc_id
    signed_timestamp = block.watermark_timestamp if block.doc_id else extracted.timestamp
    watermark_consistent = (
        extracted.recipient_hash == recipient_hash(block.recipient_id)
        and extracted.doc_id == signed_doc_id
        and extracted.timestamp == signed_timestamp
    )

    signature_valid = False
    if sig_public_key:
        record_data = json.dumps({
            "doc_id": signed_doc_id,
            "doc_hash": block.document_hash,
            "watermark_id": block.watermark_id,
            "recipient_id": block.recipient_id,
            "timestamp": signed_timestamp,
        }, sort_keys=True).encode()

        try:
            signature_valid = pq_engine.verify(
                sig_public_key,
                record_data,
                base64.b64decode(block.signature),
            )
        except Exception:
            signature_valid = False

    return {
        "found": True,
        "watermark_extracted": True,
        "watermark_id": extracted.watermark_id,
        "ledger_match": True,
        "attribution": {
            "recipient_id": block.recipient_id,
            "recipient_name": user.display_name if user else "Unknown",
            "decryption_timestamp": block.timestamp,
            "document_hash": block.document_hash,
            "signature_algorithm": block.sig_algorithm,
            "signature_verified": signature_valid,
            "watermark_consistent": watermark_consistent,
            "doc_id": signed_doc_id,
        },
        "ledger_proof": {
            "block_index": block.block_index,
            "block_hash": block.block_hash,
            "prev_hash": block.prev_hash,
            "signature": block.signature[:40] + "...",
        },
        "message": (
            f"ATTRIBUTION: Document was decrypted by "
            f"'{user.display_name if user else block.recipient_id}' "
            f"at {datetime.fromtimestamp(block.timestamp, timezone.utc):%Y-%m-%d %H:%M:%S} UTC. "
            f"Digital signature {'VERIFIED ✓' if signature_valid else 'UNVERIFIED ✗'}."
            + ("" if watermark_consistent else
               " WARNING: watermark contents do not match the ledger record.")
        ),
    }


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------
@router.get("/ledger/blocks")
async def get_ledger_blocks(limit: int = 50, offset: int = 0):
    """Get blocks from the hash chain ledger."""
    blocks = _ledger.get_all_blocks(limit=limit, offset=offset)
    return {
        "total": _ledger.get_chain_length(),
        "blocks": [asdict(b) for b in blocks],
    }


@router.get("/ledger/verify")
async def verify_ledger():
    """Validate the entire hash chain for tamper detection."""
    result = _ledger.validate_chain()
    return result


@router.get("/documents")
async def list_documents():
    """List all encrypted documents (metadata only)."""
    return [
        {
            "doc_id": doc_id,
            "filename": info["filename"],
            "doc_hash": info["doc_hash"],
            "recipients": list(info["recipients"].keys()),
        }
        for doc_id, info in _documents.list()
    ]

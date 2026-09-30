"""
End-to-end API test — full workflow from registration to investigation.
"""
import pytest
import sys
import os
import io
import json
import tempfile
import asyncio
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from fastapi.testclient import TestClient
from backend.main import app


@pytest.fixture
def client(tmp_path, monkeypatch):
    """Create test client with lifespan triggered, backed by throwaway databases."""
    monkeypatch.setenv("NISHAN_DATA_DIR", str(tmp_path))
    with TestClient(app) as c:
        yield c


def test_system_info(client):
    """System info endpoint returns expected structure."""
    response = client.get("/api/system/info")
    assert response.status_code == 200
    data = response.json()
    assert data["project"] == "NISHAN"
    assert "crypto" in data
    assert "chain_length" in data
    assert "registered_users" in data


def test_register_user(client):
    """Register a new user and download key bundle."""
    import uuid
    uid = f"test_user_{uuid.uuid4().hex[:8]}"
    response = client.post(
        "/api/users/register",
        data={"user_id": uid, "display_name": "Test User"},
    )
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/json"
    # Key bundle should be JSON
    bundle = response.json()
    assert bundle["user_id"] == uid
    assert "kem_private_key" in bundle
    assert "sig_private_key" in bundle


def test_register_duplicate_user_fails(client):
    """Registering same user twice should fail."""
    client.post(
        "/api/users/register",
        data={"user_id": "dup_user", "display_name": "Duplicate"},
    )
    response = client.post(
        "/api/users/register",
        data={"user_id": "dup_user", "display_name": "Duplicate"},
    )
    assert response.status_code == 409


def test_list_users(client):
    """List registered users."""
    client.post(
        "/api/users/register",
        data={"user_id": "list_test_user", "display_name": "List Test"},
    )
    response = client.get("/api/users")
    assert response.status_code == 200
    users = response.json()
    assert len(users) >= 1
    user_ids = [u["user_id"] for u in users]
    assert "list_test_user" in user_ids


def test_full_workflow_text_document(client):
    """Full E2E: register 3 users → encrypt → decrypt for each → investigate."""
    import uuid
    suffix = uuid.uuid4().hex[:8]
    # Step 1: Register 3 users
    users = []
    for i in range(3):
        response = client.post(
            "/api/users/register",
            data={"user_id": f"e2e_user_{suffix}_{i}", "display_name": f"E2E User {i}"},
        )
        assert response.status_code == 200
        users.append(response.json())

    # Step 2: Encrypt a text document
    doc_content = b"This is a classified naval operations document.\nIt contains sensitive strategic information.\nDistribution is restricted to authorized personnel only."
    response = client.post(
        "/api/documents/encrypt",
        files={"document": ("classified.txt", doc_content, "text/plain")},
        data={"recipients": f"e2e_user_{suffix}_0,e2e_user_{suffix}_1,e2e_user_{suffix}_2"},
    )
    assert response.status_code == 200
    enc_result = response.json()
    doc_id = enc_result["doc_id"]
    assert doc_id is not None
    assert len(enc_result["recipients"]) == 3

    # Step 3: Decrypt for each user
    watermark_ids = []
    for i, user_bundle in enumerate(users):
        response = client.post(
            "/api/documents/decrypt",
            data={"doc_id": doc_id, "user_id": f"e2e_user_{suffix}_{i}"},
            files={"key_file": ("key.json", io.BytesIO(json.dumps(user_bundle).encode()), "application/json")},
        )
        assert response.status_code == 200
        wm_id = response.headers.get("X-Watermark-Id")
        assert wm_id is not None
        watermark_ids.append(wm_id)

        # Save watermarked doc for investigation
        if i == 0:
            leaked_doc = response.content

    # Step 4: Verify 3 distinct watermarks
    assert len(set(watermark_ids)) == 3

    # Step 5: Investigate the leaked document (from user 0)
    response = client.post(
        "/api/forensics/investigate",
        files={"document": ("leaked.txt", leaked_doc, "text/plain")},
    )
    assert response.status_code == 200
    inv_result = response.json()
    assert inv_result["found"] is True
    assert inv_result["watermark_extracted"] is True
    assert inv_result["ledger_match"] is True
    assert inv_result["attribution"]["recipient_id"] == f"e2e_user_{suffix}_0"
    assert inv_result["attribution"]["signature_verified"] is True
    assert inv_result["ledger_proof"]["block_index"] >= 0


def test_full_workflow_image_document(client):
    """Full E2E with image document."""
    import uuid
    from PIL import Image

    # Register user
    suffix = uuid.uuid4().hex[:8]
    response = client.post(
        "/api/users/register",
        data={"user_id": f"img_user_{suffix}", "display_name": "Image User"},
    )
    assert response.status_code == 200
    user_bundle = response.json()

    # Create test image (large enough for watermark)
    img = Image.new('RGB', (50, 30), color=(100, 150, 200))
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    img_data = buf.getvalue()

    # Encrypt
    response = client.post(
        "/api/documents/encrypt",
        files={"document": ("test.png", img_data, "image/png")},
        data={"recipients": f"img_user_{suffix}"},
    )
    assert response.status_code == 200
    doc_id = response.json()["doc_id"]

    # Decrypt
    response = client.post(
        "/api/documents/decrypt",
        data={"doc_id": doc_id, "user_id": f"img_user_{suffix}"},
        files={"key_file": ("key.json", io.BytesIO(json.dumps(user_bundle).encode()), "application/json")},
    )
    assert response.status_code == 200
    watermarked_img = response.content

    # Investigate
    response = client.post(
        "/api/forensics/investigate",
        files={"document": ("leaked.png", watermarked_img, "image/png")},
    )
    assert response.status_code == 200
    inv_result = response.json()
    assert inv_result["found"] is True
    assert inv_result["attribution"]["recipient_id"] == f"img_user_{suffix}"
    assert inv_result["attribution"]["signature_verified"] is True


def test_unauthorized_decrypt_fails(client):
    """Decrypting with wrong user's key should fail."""
    import uuid
    suffix = uuid.uuid4().hex[:8]
    # Register two users
    user0 = client.post(
        "/api/users/register",
        data={"user_id": f"auth_user_{suffix}_0", "display_name": "Auth User 0"},
    ).json()
    user1 = client.post(
        "/api/users/register",
        data={"user_id": f"auth_user_{suffix}_1", "display_name": "Auth User 1"},
    ).json()

    # Encrypt for user 0 only
    doc_content = b"Secret document for user 0 only."
    response = client.post(
        "/api/documents/encrypt",
        files={"document": ("secret.txt", doc_content, "text/plain")},
        data={"recipients": f"auth_user_{suffix}_0"},
    )
    doc_id = response.json()["doc_id"]

    # Try to decrypt as user 1
    response = client.post(
        "/api/documents/decrypt",
        data={"doc_id": doc_id, "user_id": f"auth_user_{suffix}_1"},
        files={"key_file": ("key.json", io.BytesIO(json.dumps(user1).encode()), "application/json")},
    )
    assert response.status_code == 403


def test_investigate_clean_document(client):
    """Investigating a document with no watermark returns not found."""
    response = client.post(
        "/api/forensics/investigate",
        files={"document": ("clean.txt", b"No watermark here.", "text/plain")},
    )
    assert response.status_code == 200
    result = response.json()
    assert result["found"] is False


def test_ledger_blocks_endpoint(client):
    """Ledger blocks endpoint returns blocks."""
    import uuid
    suffix = uuid.uuid4().hex[:8]
    # First create some activity
    user = client.post(
        "/api/users/register",
        data={"user_id": f"ledger_user_{suffix}", "display_name": "Ledger User"},
    ).json()

    client.post(
        "/api/documents/encrypt",
        files={"document": ("doc.txt", b"Content", "text/plain")},
        data={"recipients": f"ledger_user_{suffix}"},
    )

    response = client.get("/api/ledger/blocks")
    assert response.status_code == 200
    data = response.json()
    assert "total" in data
    assert "blocks" in data


def test_ledger_verify_endpoint(client):
    """Ledger verify endpoint returns validation result."""
    response = client.get("/api/ledger/verify")
    assert response.status_code == 200
    data = response.json()
    assert "valid" in data
    assert "blocks_checked" in data
    assert "errors" in data





def _register(client, user_id):
    response = client.post(
        "/api/users/register",
        data={"user_id": user_id, "display_name": user_id},
    )
    assert response.status_code == 200
    return response.json()


def _decrypt(client, doc_id, user_id, bundle):
    return client.post(
        "/api/documents/decrypt",
        data={"doc_id": doc_id, "user_id": user_id},
        files={"key_file": ("key.json", io.BytesIO(json.dumps(bundle).encode()), "application/json")},
    )


def test_encrypt_rejects_unsupported_format(client):
    """Formats that can't be watermarked are refused at distribution time."""
    _register(client, "fmt_user")
    response = client.post(
        "/api/documents/encrypt",
        files={"document": ("report.docx", b"PK\x03\x04binary", "application/octet-stream")},
        data={"recipients": "fmt_user"},
    )
    assert response.status_code == 415


def test_register_rejects_bad_user_id(client):
    """User IDs are restricted to a safe character set."""
    response = client.post(
        "/api/users/register",
        data={"user_id": "bad id\r\nX-Evil: 1", "display_name": "Bad"},
    )
    assert response.status_code == 400


def test_documents_persist_across_restart(tmp_path, monkeypatch):
    """Encrypted documents survive a server restart."""
    monkeypatch.setenv("NISHAN_DATA_DIR", str(tmp_path))
    with TestClient(app) as c:
        bundle = _register(c, "persist_user")
        doc_id = c.post(
            "/api/documents/encrypt",
            files={"document": ("memo.txt", b"Persist me\nplease", "text/plain")},
            data={"recipients": "persist_user"},
        ).json()["doc_id"]

    with TestClient(app) as c:
        assert doc_id in [d["doc_id"] for d in c.get("/api/documents").json()]
        response = _decrypt(c, doc_id, "persist_user", bundle)
        assert response.status_code == 200
        assert b"Persist me" in response.content


def test_decrypt_non_ascii_filename_and_ledger_fields(client):
    """Unicode filenames download safely; the ledger records doc_id."""
    bundle = _register(client, "uni_user")
    doc_id = client.post(
        "/api/documents/encrypt",
        files={"document": ("रिपोर्ट.txt", "गोपनीय\nदस्तावेज़".encode(), "text/plain")},
        data={"recipients": "uni_user"},
    ).json()["doc_id"]

    response = _decrypt(client, doc_id, "uni_user", bundle)
    assert response.status_code == 200
    assert "filename*=UTF-8''" in response.headers["content-disposition"]

    blocks = client.get("/api/ledger/blocks").json()["blocks"]
    assert blocks[0]["doc_id"] == doc_id
    assert blocks[0]["watermark_timestamp"] > 0

    result = client.post(
        "/api/forensics/investigate",
        files={"document": ("leak.txt", response.content, "text/plain")},
    ).json()
    assert result["attribution"]["signature_verified"] is True
    assert result["attribution"]["watermark_consistent"] is True
    assert result["attribution"]["doc_id"] == doc_id


def test_jpeg_download_named_png(client):
    """A JPEG source is delivered as PNG with a matching filename."""
    from PIL import Image
    bundle = _register(client, "jpg_user")
    buf = io.BytesIO()
    Image.new('RGB', (60, 40), color=(90, 120, 150)).save(buf, format='JPEG')
    doc_id = client.post(
        "/api/documents/encrypt",
        files={"document": ("photo.jpg", buf.getvalue(), "image/jpeg")},
        data={"recipients": "jpg_user"},
    ).json()["doc_id"]

    response = _decrypt(client, doc_id, "jpg_user", bundle)
    assert response.status_code == 200
    assert response.content.startswith(b"\x89PNG")
    assert 'filename="decrypted_photo.png"' in response.headers["content-disposition"]

"""
Watermark embed/extract tests — text, image, and PDF.
"""
import pytest
import sys
import os
import io
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from backend.watermark.encoder import (
    generate_watermark,
    payload_to_bytes,
    bytes_to_payload,
    encode_for_text,
    decode_from_text,
    WatermarkPayload,
)
from backend.watermark.embedder import embed_watermark, embed_in_text, embed_in_image
from backend.watermark.extractor import extract_watermark, extract_from_text, extract_from_image
from PIL import Image


def test_watermark_generation():
    """Generate watermark with all fields populated."""
    wm = generate_watermark("user123", "abc123def456")
    assert wm.watermark_id is not None
    assert len(wm.watermark_id) == 32  # UUID hex
    assert wm.recipient_hash is not None
    assert len(wm.recipient_hash) == 32
    assert wm.timestamp > 0
    assert wm.doc_id == "abc123def456"
    assert wm.checksum is not None


def test_watermark_uniqueness():
    """Two watermarks for same user must be different."""
    wm1 = generate_watermark("user123", "abc123def456")
    wm2 = generate_watermark("user123", "abc123def456")
    assert wm1.watermark_id != wm2.watermark_id


def test_payload_serialization_roundtrip():
    """Serialize and deserialize payload preserves all fields."""
    wm = generate_watermark("admiral_kumar", "abc123def456")
    raw = payload_to_bytes(wm)
    assert len(raw) == 50

    recovered = bytes_to_payload(raw)
    assert recovered.watermark_id == wm.watermark_id
    assert recovered.recipient_hash == wm.recipient_hash
    assert recovered.timestamp == wm.timestamp
    assert recovered.doc_id == wm.doc_id
    assert recovered.checksum == wm.checksum


def test_text_encode_decode():
    """Encode payload to ZW chars and decode back."""
    wm = generate_watermark("user1", "aaaa1111bbbb")
    encoded = encode_for_text(wm)
    assert '\u200b' in encoded or '\u200c' in encoded  # Has ZW chars
    assert encoded.startswith('\ufeff')  # Starts with delimiter
    assert encoded.endswith('\ufeff')    # Ends with delimiter

    decoded = decode_from_text(encoded)
    assert decoded is not None
    assert decoded.watermark_id == wm.watermark_id
    assert decoded.recipient_hash == wm.recipient_hash
    assert decoded.timestamp == wm.timestamp
    assert decoded.doc_id == wm.doc_id


def test_text_embed_extract():
    """Embed watermark in text and extract it back."""
    wm = generate_watermark("user1", "aaaa1111bbbb")
    original = b"This is a classified document with sensitive information.\nIt spans multiple lines."
    watermarked = embed_in_text(original, wm)

    # Watermarked text should be different (contains ZW chars)
    assert watermarked != original

    extracted = extract_from_text(watermarked)
    assert extracted is not None
    assert extracted.watermark_id == wm.watermark_id
    assert extracted.doc_id == wm.doc_id


def test_text_embed_extract_multiple_lines():
    """Watermark survives in multi-line text."""
    wm = generate_watermark("user2", "cccc2222dddd")
    original = b"Line 1\nLine 2\nLine 3\nLine 4\nLine 5"
    watermarked = embed_in_text(original, wm)

    extracted = extract_from_text(watermarked)
    assert extracted is not None
    assert extracted.watermark_id == wm.watermark_id


def test_image_embed_extract():
    """Embed watermark in image and extract it back."""
    # Create a large enough test image (need 1296 pixels minimum)
    img = Image.new('RGB', (50, 30), color=(100, 150, 200))
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    original_data = buf.getvalue()

    wm = generate_watermark("user3", "eeee3333ffff")
    watermarked_data = embed_in_image(original_data, wm)

    # Watermarked image should be different
    assert watermarked_data != original_data

    extracted = extract_from_image(watermarked_data)
    assert extracted is not None
    assert extracted.watermark_id == wm.watermark_id
    assert extracted.doc_id == wm.doc_id


def test_image_embed_small_image_fails():
    """Embedding in too-small image raises error."""
    img = Image.new('RGB', (5, 5), color=(100, 150, 200))
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    small_data = buf.getvalue()

    wm = generate_watermark("user4", "abcd4444ef01")
    with pytest.raises(ValueError):
        embed_in_image(small_data, wm)


def test_extract_from_clean_text_returns_none():
    """Extracting from text without watermark returns None."""
    clean = b"This is just normal text with no watermark."
    result = extract_from_text(clean)
    assert result is None


def test_extract_from_clean_image_returns_none():
    """Extracting from image without watermark returns None."""
    img = Image.new('RGB', (50, 30), color=(100, 150, 200))
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    clean_data = buf.getvalue()

    result = extract_from_image(clean_data)
    assert result is None


def test_format_detection():
    """detect_format returns correct format for extensions."""
    from backend.watermark.embedder import detect_format
    assert detect_format("doc.txt") == "text"
    assert detect_format("doc.md") == "text"
    assert detect_format("doc.csv") == "text"
    assert detect_format("doc.pdf") == "pdf"
    assert detect_format("doc.png") == "image"
    assert detect_format("doc.jpg") == "image"
    assert detect_format("doc.jpeg") == "image"
    assert detect_format("unknown.xyz") == "text"  # default


def test_embed_watermark_dispatch():
    """embed_watermark dispatches to correct embedder based on filename."""
    wm = generate_watermark("user5", "ffff5555aaaa")

    # Text
    text_result = embed_watermark(b"Hello world\nSecond line", "test.txt", wm)
    assert text_result != b"Hello world\nSecond line"

    # Image
    img = Image.new('RGB', (50, 30), color=(100, 150, 200))
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    img_result = embed_watermark(buf.getvalue(), "test.png", wm)
    assert img_result != buf.getvalue()

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
    assert detect_format("unknown.xyz") is None
    assert detect_format("report.docx") is None


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


def test_embed_rejects_unsupported_format():
    """Binary formats are rejected instead of being corrupted as text."""
    from backend.watermark.embedder import UnsupportedDocumentError
    wm = generate_watermark("user6", "0123456789ab")
    with pytest.raises(UnsupportedDocumentError):
        embed_watermark(bytes(range(256)), "report.docx", wm)


def test_validate_document():
    """validate_document accepts supported docs and rejects the rest."""
    from backend.watermark.embedder import validate_document, UnsupportedDocumentError
    validate_document("Plain UTF-8 text".encode(), "a.txt")
    with pytest.raises(UnsupportedDocumentError):
        validate_document(b"\xff\xfe\x00bad", "a.txt")      # not UTF-8
    with pytest.raises(UnsupportedDocumentError):
        validate_document(b"not an image", "a.png")
    tiny = io.BytesIO()
    Image.new('RGB', (10, 10)).save(tiny, format='PNG')
    with pytest.raises(UnsupportedDocumentError):
        validate_document(tiny.getvalue(), "a.png")          # too small
    with pytest.raises(UnsupportedDocumentError):
        validate_document(b"PK\x03\x04", "a.docx")


def test_tampered_checksum_rejected():
    """A watermark whose checksum doesn't match its fields is ignored."""
    import dataclasses
    wm = generate_watermark("user7", "0123456789ab")
    forged = dataclasses.replace(wm, recipient_hash="0" * 32)
    assert decode_from_text("x" + encode_for_text(forged) + "y") is None


def test_text_with_leading_bom():
    """A BOM at the start of a UTF-8 file doesn't hide the watermark."""
    wm = generate_watermark("user8", "0123456789ab")
    content = "\ufeffFirst line\nSecond line".encode('utf-8')
    result = extract_from_text(embed_in_text(content, wm))
    assert result is not None
    assert result.watermark_id == wm.watermark_id


def _sample_pdf(pages=2):
    import fitz
    doc = fitz.open()
    for i in range(pages):
        doc.new_page().insert_text((72, 72), f"Classified page {i + 1}")
    data = doc.tobytes()
    doc.close()
    return data


def test_pdf_survives_metadata_and_annotation_stripping():
    """The invisible text layer still carries the watermark."""
    import fitz
    wm = generate_watermark("user9", "0123456789ab")
    doc = fitz.open(stream=embed_watermark(_sample_pdf(), "a.pdf", wm), filetype="pdf")
    for page in doc:
        while page.first_annot:
            page.delete_annot(page.first_annot)
    doc.set_metadata({})
    stripped = doc.tobytes()
    doc.close()

    result = extract_watermark(stripped, "a.pdf")
    assert result is not None
    assert result.watermark_id == wm.watermark_id


def test_pdf_watermark_on_every_page():
    """A single page extracted from the PDF still carries the watermark."""
    import fitz
    wm = generate_watermark("user10", "0123456789ab")
    src = fitz.open(stream=embed_watermark(_sample_pdf(3), "a.pdf", wm), filetype="pdf")
    single = fitz.open()
    single.insert_pdf(src, from_page=2, to_page=2)
    data = single.tobytes()
    result = extract_watermark(data, "page3.pdf")
    assert result is not None
    assert result.watermark_id == wm.watermark_id


def test_pdf_text_layer_is_invisible():
    """Watermarked PDF renders identically to the original."""
    import fitz
    wm = generate_watermark("user11", "0123456789ab")
    original = _sample_pdf(1)
    marked = embed_watermark(original, "a.pdf", wm)
    render = lambda d: fitz.open(stream=d, filetype="pdf")[0].get_pixmap(annots=False).samples
    assert render(original) == render(marked)


def test_extract_sniffs_renamed_file():
    """A watermarked image renamed to .txt is still recognised as an image."""
    wm = generate_watermark("user12", "0123456789ab")
    img = Image.new('RGB', (50, 30), color=(10, 20, 30))
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    marked = embed_watermark(buf.getvalue(), "photo.png", wm)
    result = extract_watermark(marked, "innocent.txt")
    assert result is not None
    assert result.watermark_id == wm.watermark_id


def test_image_output_filename_is_png():
    """JPEG inputs are delivered with a .png name matching their content."""
    from backend.watermark.embedder import output_filename
    assert output_filename("photo.jpg") == "photo.png"
    assert output_filename("scan.JPEG") == "scan.png"
    assert output_filename("memo.txt") == "memo.txt"

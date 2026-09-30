"""
Watermark Embedder — Format-aware invisible watermark injection.

Supports:
- Plain text (.txt, .md, .csv, ...): Zero-width character injection
- Images (.png, .jpg, .bmp): LSB steganography in blue channel (output is PNG)
- PDF (.pdf): Metadata + annotation + invisible text layer on every page

Any other format is rejected: embedding into binary formats such as .docx
would corrupt the file.
"""

import io
import os
import struct
from typing import Optional

from PIL import Image
import fitz  # PyMuPDF

from .encoder import (
    WatermarkPayload,
    encode_for_text,
    bytes_to_bits,
    payload_to_bytes,
    apply_redundancy,
)

TEXT_EXTENSIONS = ('.txt', '.md', '.csv', '.log', '.json', '.xml', '.html')
IMAGE_EXTENSIONS = ('.png', '.jpg', '.jpeg', '.bmp')
PDF_EXTENSIONS = ('.pdf',)

# Marker for the PDF invisible text layer; followed by the payload as hex.
PDF_TEXT_MARKER = "NISHAN-WM:"

# (4-byte length prefix + 50-byte payload) * 8 bits * 3x repetition
IMAGE_MIN_PIXELS = (4 + 50) * 8 * 3


class UnsupportedDocumentError(ValueError):
    """Document can't be watermarked (unknown format or unreadable content)."""


def detect_format(filename: str) -> Optional[str]:
    """Detect document format from filename; None if unsupported."""
    ext = os.path.splitext(filename)[1].lower()
    if ext in TEXT_EXTENSIONS:
        return 'text'
    elif ext in IMAGE_EXTENSIONS:
        return 'image'
    elif ext in PDF_EXTENSIONS:
        return 'pdf'
    return None


def output_filename(filename: str) -> str:
    """Filename for the watermarked copy — images are always re-encoded as PNG."""
    if detect_format(filename) == 'image':
        return os.path.splitext(filename)[0] + '.png'
    return filename


def validate_document(document_data: bytes, filename: str) -> None:
    """
    Check up front that a document can be watermarked, so a bad upload is
    rejected at distribution time rather than failing at decryption.

    Raises:
        UnsupportedDocumentError: with a user-facing reason
    """
    fmt = detect_format(filename)
    supported = ', '.join(TEXT_EXTENSIONS + IMAGE_EXTENSIONS + PDF_EXTENSIONS)
    if fmt is None:
        raise UnsupportedDocumentError(
            f"Unsupported file type '{filename}'. Supported: {supported}"
        )

    if fmt == 'text':
        try:
            document_data.decode('utf-8')
        except UnicodeDecodeError:
            raise UnsupportedDocumentError("Text documents must be UTF-8 encoded")
    elif fmt == 'image':
        try:
            img = Image.open(io.BytesIO(document_data))
            width, height = img.size
        except Exception:
            raise UnsupportedDocumentError("File is not a readable image")
        if width * height < IMAGE_MIN_PIXELS:
            raise UnsupportedDocumentError(
                f"Image too small for watermark: need {IMAGE_MIN_PIXELS} pixels, "
                f"have {width * height}"
            )
    elif fmt == 'pdf':
        try:
            doc = fitz.open(stream=document_data, filetype="pdf")
            page_count = len(doc)
            doc.close()
        except Exception:
            raise UnsupportedDocumentError("File is not a readable PDF")
        if page_count == 0:
            raise UnsupportedDocumentError("PDF has no pages")


def embed_in_text(content: bytes, payload: WatermarkPayload) -> bytes:
    """
    Embed watermark in plain text using zero-width characters.
    Inserts the encoded watermark after the first paragraph/line break,
    or at the beginning if no line break found.
    """
    try:
        text = content.decode('utf-8')
    except UnicodeDecodeError:
        raise UnsupportedDocumentError("Text documents must be UTF-8 encoded")
    zw_encoded = encode_for_text(payload)

    # Insert after first newline for natural placement
    newline_pos = text.find('\n')
    if newline_pos != -1:
        watermarked = text[:newline_pos+1] + zw_encoded + text[newline_pos+1:]
    else:
        # No newline — insert at position len//2 for stealth
        mid = len(text) // 2
        watermarked = text[:mid] + zw_encoded + text[mid:]

    return watermarked.encode('utf-8')


def embed_in_image(image_data: bytes, payload: WatermarkPayload) -> bytes:
    """
    Embed watermark in image using LSB steganography (blue channel).
    Row-major order, least significant bit of each blue pixel value.
    """
    img = Image.open(io.BytesIO(image_data))
    if img.mode != 'RGB':
        img = img.convert('RGB')

    pixels = list(img.getdata())
    width, height = img.size

    # Prepare bit payload
    raw = payload_to_bytes(payload)
    length_prefix = struct.pack('>I', len(raw))
    full_data = length_prefix + raw
    bits = bytes_to_bits(full_data)
    redundant = apply_redundancy(bits, 3)

    total_bits = len(redundant)
    if total_bits > len(pixels):
        raise ValueError(
            f"Image too small for watermark: need {total_bits} pixels, "
            f"have {len(pixels)}"
        )

    # Embed in blue channel LSB
    new_pixels = []
    for i, (r, g, b) in enumerate(pixels):
        if i < total_bits:
            bit = int(redundant[i])
            b = (b & 0xFE) | bit  # Set LSB
        new_pixels.append((r, g, b))

    new_img = Image.new('RGB', (width, height))
    new_img.putdata(new_pixels)

    # Save as PNG to avoid lossy compression destroying the watermark
    buf = io.BytesIO()
    new_img.save(buf, format='PNG')
    return buf.getvalue()


def embed_in_pdf(pdf_data: bytes, payload: WatermarkPayload) -> bytes:
    """
    Embed watermark in PDF using multiple strategies for robustness:
    1. Invisible text annotation with ZW-encoded payload
    2. PDF metadata keywords field
    3. Invisible text layer (render mode 3) with the hex payload on every
       page — survives annotation removal, metadata stripping and
       extracting individual pages
    """
    doc = fitz.open(stream=pdf_data, filetype="pdf")
    zw_encoded = encode_for_text(payload)
    page = doc[0]

    # Strategy 1: Add invisible text annotation
    annot = page.add_text_annot(
        fitz.Point(0, 0),
        zw_encoded,
    )
    annot.set_opacity(0)
    annot.update()

    # Strategy 2: Embed in PDF metadata
    metadata = doc.metadata or {}
    metadata["keywords"] = metadata.get("keywords", "") + " " + zw_encoded
    doc.set_metadata(metadata)

    # Strategy 3: Invisible text layer on every page. Zero-width characters
    # can't be used here — the base-14 fonts drop them — so the payload is
    # written as hex. Render mode 3 draws nothing but stays extractable.
    marker_text = PDF_TEXT_MARKER + payload_to_bytes(payload).hex()
    for p in doc:
        rect = p.rect
        p.insert_text(
            fitz.Point(rect.x0 + 2, rect.y1 - 2),
            marker_text,
            fontsize=1,
            render_mode=3,
            overlay=True,
        )

    # Save
    buf = io.BytesIO()
    doc.save(buf)
    doc.close()
    return buf.getvalue()


def embed_watermark(
    document_data: bytes,
    filename: str,
    payload: WatermarkPayload,
) -> bytes:
    """
    Embed invisible forensic watermark in a document.

    Args:
        document_data: Raw document bytes
        filename: Original filename (for format detection)
        payload: Watermark payload to embed

    Returns:
        Watermarked document bytes

    Raises:
        UnsupportedDocumentError: if the format can't be watermarked
    """
    fmt = detect_format(filename)

    if fmt == 'text':
        return embed_in_text(document_data, payload)
    elif fmt == 'image':
        return embed_in_image(document_data, payload)
    elif fmt == 'pdf':
        return embed_in_pdf(document_data, payload)
    raise UnsupportedDocumentError(f"Unsupported file type '{filename}'")

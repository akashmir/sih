"""
Watermark Embedder — Format-aware invisible watermark injection.

Supports:
- Plain text (.txt, .md, .csv): Zero-width character injection
- Images (.png, .jpg): LSB steganography in blue channel
- PDF (.pdf): Zero-width character injection into text content
"""

import io
import os
from typing import Optional

from PIL import Image
import fitz  # PyMuPDF

from .encoder import (
    WatermarkPayload,
    encode_for_text,
    encode_for_image,
    bytes_to_bits,
    payload_to_bytes,
    apply_redundancy,
)


def detect_format(filename: str) -> str:
    """Detect document format from filename."""
    ext = os.path.splitext(filename)[1].lower()
    if ext in ('.txt', '.md', '.csv', '.log', '.json', '.xml', '.html'):
        return 'text'
    elif ext in ('.png', '.jpg', '.jpeg', '.bmp'):
        return 'image'
    elif ext == '.pdf':
        return 'pdf'
    else:
        return 'text'  # Default to text for unknown formats


def embed_in_text(content: bytes, payload: WatermarkPayload) -> bytes:
    """
    Embed watermark in plain text using zero-width characters.
    Inserts the encoded watermark after the first paragraph/line break,
    or at the beginning if no line break found.
    """
    text = content.decode('utf-8', errors='replace')
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
    import struct
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
    3. Invisible text rendered on the page (white, tiny font)
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

    # Strategy 3: Insert invisible text directly on the page
    # White text, 1pt font, positioned at bottom-right corner
    # This survives annotation removal and metadata stripping
    rect = page.rect
    insert_point = fitz.Point(rect.width - 5, rect.height - 5)
    page.insert_text(
        insert_point,
        zw_encoded,
        fontsize=1,
        color=(1, 1, 1),  # White text on white background
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
    """
    fmt = detect_format(filename)

    if fmt == 'text':
        return embed_in_text(document_data, payload)
    elif fmt == 'image':
        return embed_in_image(document_data, payload)
    elif fmt == 'pdf':
        return embed_in_pdf(document_data, payload)
    else:
        return embed_in_text(document_data, payload)

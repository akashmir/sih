"""
Watermark Extractor — Recover forensic watermark from a document.

Reverses the embedding process to extract the watermark payload,
using majority-vote decoding for error resilience.
"""

import io
import os
import re
import struct
from typing import Optional

from PIL import Image
import fitz  # PyMuPDF

from .encoder import (
    WatermarkPayload,
    decode_from_text,
    decode_redundancy,
    bits_to_bytes,
    bytes_to_payload,
    is_valid_payload,
)
from .embedder import PDF_TEXT_MARKER, IMAGE_EXTENSIONS

_PDF_MARKER_RE = re.compile(re.escape(PDF_TEXT_MARKER) + r"\s*([0-9a-f]{100})")


def extract_from_text(content: bytes) -> Optional[WatermarkPayload]:
    """Extract watermark from plain text content."""
    text = content.decode('utf-8', errors='replace')
    return decode_from_text(text)


def extract_from_image(image_data: bytes) -> Optional[WatermarkPayload]:
    """
    Extract watermark from image by reading LSB of blue channel.
    """
    try:
        img = Image.open(io.BytesIO(image_data))
        if img.mode != 'RGB':
            img = img.convert('RGB')

        pixels = list(img.getdata())

        # We need at least enough pixels for: (4 + 50) * 8 * 3 = 1296 bits
        min_pixels = (4 + 50) * 8 * 3
        if len(pixels) < min_pixels:
            return None

        # Read enough LSBs to cover the maximum payload
        # First read 32*3 = 96 bits for the length prefix
        length_redundant = ''
        for i in range(96):
            if i >= len(pixels):
                return None
            _, _, b = pixels[i]
            length_redundant += str(b & 1)

        length_decoded = decode_redundancy(length_redundant, 3)
        length_bytes = bits_to_bytes(length_decoded)
        payload_length = struct.unpack('>I', length_bytes[:4])[0]

        if payload_length != 50:
            return None

        # Read the full payload: (4 + 50) * 8 * 3 = 1296 bits
        total_redundant_bits = (4 + payload_length) * 8 * 3
        if len(pixels) < total_redundant_bits:
            return None

        all_bits = ''
        for i in range(total_redundant_bits):
            _, _, b = pixels[i]
            all_bits += str(b & 1)

        # Decode with majority vote
        decoded = decode_redundancy(all_bits, 3)

        # Skip length prefix (32 bits), get payload
        payload_bits = decoded[32:32 + payload_length * 8]
        raw_bytes = bits_to_bytes(payload_bits)

        payload = bytes_to_payload(raw_bytes[:50])
        return payload if is_valid_payload(payload) else None

    except Exception:
        return None


def extract_from_pdf(pdf_data: bytes) -> Optional[WatermarkPayload]:
    """
    Extract watermark from PDF metadata/annotations.
    Tries multiple extraction strategies.
    """
    try:
        doc = fitz.open(stream=pdf_data, filetype="pdf")

        # Strategy 1: Check metadata keywords for ZW chars
        metadata = doc.metadata or {}
        keywords = metadata.get("keywords", "")
        payload = decode_from_text(keywords)
        if payload:
            doc.close()
            return payload

        # Strategy 2: Check text annotations on first page
        if len(doc) > 0:
            page = doc[0]
            for annot in page.annots() or []:
                text = annot.info.get("content", "")
                payload = decode_from_text(text)
                if payload:
                    doc.close()
                    return payload

        # Strategy 3: Invisible hex text layer (or ZW chars) on any page
        for page in doc:
            text = page.get_text()
            for match in _PDF_MARKER_RE.finditer(text):
                try:
                    payload = bytes_to_payload(bytes.fromhex(match.group(1)))
                except ValueError:
                    continue
                if is_valid_payload(payload):
                    doc.close()
                    return payload
            payload = decode_from_text(text)
            if payload:
                doc.close()
                return payload

        doc.close()
        return None

    except Exception:
        return None


def extract_watermark(
    document_data: bytes,
    filename: str,
) -> Optional[WatermarkPayload]:
    """
    Extract forensic watermark from a document.

    Args:
        document_data: Raw document bytes
        filename: Filename (for format detection)

    Returns:
        WatermarkPayload if found, None otherwise
    """
    # Sniff the content first: a leaked file may have been renamed.
    if document_data.startswith(b'%PDF'):
        return extract_from_pdf(document_data)
    if document_data.startswith((b'\x89PNG', b'\xff\xd8\xff', b'BM')):
        return extract_from_image(document_data)

    ext = os.path.splitext(filename)[1].lower()
    if ext in IMAGE_EXTENSIONS:
        return extract_from_image(document_data)
    elif ext == '.pdf':
        return extract_from_pdf(document_data)
    return extract_from_text(document_data)

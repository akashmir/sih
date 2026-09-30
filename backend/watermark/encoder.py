"""
Watermark Encoder — Binary encoding with 3x repetition coding.

Converts a watermark payload (UUID + recipient hash + timestamp) into a
redundant binary bitstring, and decodes it back with majority-vote error correction.
"""

import hashlib
import re
import struct
import uuid
import time
from dataclasses import dataclass
from typing import Optional


@dataclass
class WatermarkPayload:
    """Structured watermark data."""
    watermark_id: str    # UUID hex string
    recipient_hash: str  # SHA-256 hex of recipient ID (first 32 chars)
    timestamp: int       # Unix timestamp
    doc_id: str          # Document ID (12-char hex)
    checksum: str        # SHA-256 hex of above fields (first 8 chars)


# ---------------------------------------------------------------------------
# Zero-width character mapping
# ---------------------------------------------------------------------------
ZW_ZERO = '\u200b'      # Zero-Width Space = 0
ZW_ONE = '\u200c'       # Zero-Width Non-Joiner = 1
ZW_DELIM = '\ufeff'     # BOM = delimiter (start/end marker)

_ZW_BLOCK = re.compile(f"{ZW_DELIM}([{ZW_ZERO}{ZW_ONE}]+){ZW_DELIM}")


def recipient_hash(recipient_id: str) -> str:
    """Truncated SHA-256 of a recipient ID, as carried in the watermark."""
    return hashlib.sha256(recipient_id.encode()).hexdigest()[:32]


def _compute_checksum(wm_id: str, r_hash: str, ts: int, doc_id: str) -> str:
    raw = f"{wm_id}:{r_hash}:{ts}:{doc_id}"
    return hashlib.sha256(raw.encode()).hexdigest()[:8]


def is_valid_payload(payload: WatermarkPayload) -> bool:
    """Check the payload's embedded checksum against its fields."""
    expected = _compute_checksum(
        payload.watermark_id, payload.recipient_hash,
        payload.timestamp, payload.doc_id,
    )
    return payload.checksum == expected


def generate_watermark(recipient_id: str, doc_id: str = "") -> WatermarkPayload:
    """Generate a unique watermark payload for a decryption session."""
    wm_id = uuid.uuid4().hex
    ts = int(time.time())
    r_hash = recipient_hash(recipient_id)
    checksum = _compute_checksum(wm_id, r_hash, ts, doc_id)
    return WatermarkPayload(
        watermark_id=wm_id,
        recipient_hash=r_hash,
        timestamp=ts,
        doc_id=doc_id,
        checksum=checksum,
    )


def payload_to_bytes(payload: WatermarkPayload) -> bytes:
    """
    Serialize watermark payload to compact binary.
    Layout: [16B uuid] [16B recipient_hash_prefix] [8B timestamp] [6B doc_id] [4B checksum_prefix]
    Total: 50 bytes
    """
    wm_bytes = bytes.fromhex(payload.watermark_id)           # 16 bytes
    rh_bytes = bytes.fromhex(payload.recipient_hash)          # 16 bytes
    ts_bytes = struct.pack('>Q', payload.timestamp)           # 8 bytes
    di_bytes = bytes.fromhex(payload.doc_id)                  # 6 bytes
    ck_bytes = bytes.fromhex(payload.checksum)                # 4 bytes
    return wm_bytes + rh_bytes + ts_bytes + di_bytes + ck_bytes


def bytes_to_payload(data: bytes) -> WatermarkPayload:
    """Deserialize binary back to WatermarkPayload."""
    if len(data) < 50:
        raise ValueError(f"Payload too short: {len(data)} bytes, expected 50")
    wm_id = data[0:16].hex()
    r_hash = data[16:32].hex()
    ts = struct.unpack('>Q', data[32:40])[0]
    doc_id = data[40:46].hex()
    checksum = data[46:50].hex()
    return WatermarkPayload(
        watermark_id=wm_id,
        recipient_hash=r_hash,
        timestamp=ts,
        doc_id=doc_id,
        checksum=checksum,
    )


def bytes_to_bits(data: bytes) -> str:
    """Convert bytes to binary string."""
    return ''.join(format(b, '08b') for b in data)


def bits_to_bytes(bits: str) -> bytes:
    """Convert binary string back to bytes."""
    # Pad to multiple of 8
    padded = bits.ljust((len(bits) + 7) // 8 * 8, '0')
    return bytes(int(padded[i:i+8], 2) for i in range(0, len(padded), 8))


def apply_redundancy(bits: str, factor: int = 3) -> str:
    """Apply repetition coding: each bit repeated `factor` times."""
    return ''.join(b * factor for b in bits)


def decode_redundancy(redundant_bits: str, factor: int = 3) -> str:
    """Majority-vote decoding of repetition-coded bits."""
    result = []
    for i in range(0, len(redundant_bits), factor):
        chunk = redundant_bits[i:i+factor]
        ones = chunk.count('1')
        zeros = chunk.count('0')
        result.append('1' if ones > zeros else '0')
    return ''.join(result)


def encode_for_text(payload: WatermarkPayload) -> str:
    """
    Encode watermark as zero-width character string for text embedding.
    Format: DELIM + (3x-repeated bits as ZW chars) + DELIM
    """
    raw_bytes = payload_to_bytes(payload)
    bits = bytes_to_bits(raw_bytes)
    redundant = apply_redundancy(bits, 3)
    zw_chars = ''.join(ZW_ZERO if b == '0' else ZW_ONE for b in redundant)
    return ZW_DELIM + zw_chars + ZW_DELIM


def decode_from_text(text: str) -> Optional[WatermarkPayload]:
    """
    Extract and decode watermark from text containing zero-width characters.
    Returns None if no valid watermark found.

    Every delimited run of ZW bits is tried, so a leading BOM in the
    source file (or a second, damaged watermark) can't mask a valid one.
    """
    for match in _ZW_BLOCK.finditer(text):
        redundant_bits = match.group(1).replace(ZW_ZERO, '0').replace(ZW_ONE, '1')
        decoded_bits = decode_redundancy(redundant_bits, 3)
        raw_bytes = bits_to_bytes(decoded_bits)
        try:
            payload = bytes_to_payload(raw_bytes[:50])
        except (ValueError, struct.error):
            continue
        if is_valid_payload(payload):
            return payload
    return None


def encode_for_image(payload: WatermarkPayload) -> bytes:
    """
    Encode watermark as binary data for LSB image embedding.
    Format: [4B length] + [50B payload] — each bit repeated 3x.
    Returns the full redundant bitstream as bytes for the embedder.
    """
    raw = payload_to_bytes(payload)
    length_prefix = struct.pack('>I', len(raw))
    full_data = length_prefix + raw
    bits = bytes_to_bits(full_data)
    redundant = apply_redundancy(bits, 3)
    return redundant.encode('ascii')  # '0' and '1' characters


def decode_from_image(redundant_bits_str: str) -> Optional[WatermarkPayload]:
    """
    Decode watermark from extracted LSB bit string.
    """
    if len(redundant_bits_str) < 32 * 3:  # Need at least length prefix
        return None

    decoded = decode_redundancy(redundant_bits_str, 3)

    # First 32 bits = 4 bytes length
    length_bits = decoded[:32]
    length = struct.unpack('>I', bits_to_bytes(length_bits))[0]

    if length != 50:
        return None  # Not a valid watermark

    total_bits = 32 + length * 8
    if len(decoded) < total_bits:
        return None

    payload_bits = decoded[32:total_bits]
    raw_bytes = bits_to_bytes(payload_bits)

    try:
        payload = bytes_to_payload(raw_bytes[:50])
    except (ValueError, struct.error):
        return None
    return payload if is_valid_payload(payload) else None

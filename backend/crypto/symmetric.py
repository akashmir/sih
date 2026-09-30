"""
Symmetric Encryption — AES-256-GCM
Uses the shared secret from ML-KEM key exchange as the encryption key.
"""

import os
from dataclasses import dataclass
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


@dataclass
class EncryptedPayload:
    """Encrypted document payload."""
    nonce: bytes      # 12-byte nonce
    ciphertext: bytes  # Encrypted data + GCM tag
    aad: bytes        # Additional Authenticated Data (metadata)


def encrypt(key: bytes, plaintext: bytes, associated_data: bytes = b"") -> EncryptedPayload:
    """
    Encrypt data using AES-256-GCM.

    Args:
        key: 32-byte symmetric key (from ML-KEM shared secret)
        plaintext: Data to encrypt
        associated_data: Optional AAD for authenticated metadata

    Returns:
        EncryptedPayload with nonce, ciphertext, and AAD
    """
    if len(key) != 32:
        raise ValueError(f"Key must be 32 bytes, got {len(key)}")

    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, plaintext, associated_data or None)

    return EncryptedPayload(
        nonce=nonce,
        ciphertext=ct,
        aad=associated_data,
    )


def decrypt(key: bytes, payload: EncryptedPayload) -> bytes:
    """
    Decrypt data using AES-256-GCM.

    Args:
        key: 32-byte symmetric key
        payload: EncryptedPayload from encrypt()

    Returns:
        Decrypted plaintext bytes

    Raises:
        cryptography.exceptions.InvalidTag: If ciphertext was tampered
    """
    if len(key) != 32:
        raise ValueError(f"Key must be 32 bytes, got {len(key)}")

    aesgcm = AESGCM(key)
    return aesgcm.decrypt(
        payload.nonce,
        payload.ciphertext,
        payload.aad or None,
    )

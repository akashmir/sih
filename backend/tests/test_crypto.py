"""
Crypto round-trip tests — ML-KEM key exchange and ML-DSA signatures.
"""
import pytest
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from backend.crypto import pq_engine, symmetric


def test_kem_keypair_generation():
    """Generate KEM keypair and verify structure."""
    kp = pq_engine.generate_kem_keypair()
    assert kp.public_key is not None
    assert kp.private_key is not None
    assert len(kp.public_key) > 0
    assert len(kp.private_key) > 0
    assert kp.algorithm is not None


def test_kem_encapsulate_decapsulate():
    """Encapsulate with public key, decapsulate with private key — shared secrets must match."""
    kp = pq_engine.generate_kem_keypair()
    encap_result = pq_engine.encapsulate(kp.public_key)
    assert encap_result.ciphertext is not None
    assert len(encap_result.shared_secret) == 32

    shared_secret = pq_engine.decapsulate(kp.private_key, encap_result.ciphertext)
    assert shared_secret == encap_result.shared_secret


def test_signing_keypair_generation():
    """Generate signing keypair and verify structure."""
    kp = pq_engine.generate_signing_keypair()
    assert kp.public_key is not None
    assert kp.private_key is not None
    assert len(kp.public_key) > 0
    assert len(kp.private_key) > 0


def test_sign_and_verify():
    """Sign a message, verify the signature."""
    kp = pq_engine.generate_signing_keypair()
    message = b"Test decryption record for user admiral_kumar"
    sig_result = pq_engine.sign(kp.private_key, message)
    assert sig_result.signature is not None
    assert len(sig_result.signature) > 0

    valid = pq_engine.verify(kp.public_key, message, sig_result.signature)
    assert valid is True


def test_signature_tampering_detection():
    """Verify fails when message is tampered after signing."""
    kp = pq_engine.generate_signing_keypair()
    message = b"Original message"
    sig_result = pq_engine.sign(kp.private_key, message)

    tampered = b"Tampered message"
    valid = pq_engine.verify(kp.public_key, tampered, sig_result.signature)
    assert valid is False


def test_signature_wrong_key_fails():
    """Verify fails when using a different public key."""
    kp1 = pq_engine.generate_signing_keypair()
    kp2 = pq_engine.generate_signing_keypair()
    message = b"Test message"
    sig_result = pq_engine.sign(kp1.private_key, message)

    valid = pq_engine.verify(kp2.public_key, message, sig_result.signature)
    assert valid is False


def test_aes_gcm_encrypt_decrypt():
    """AES-256-GCM round-trip with 32-byte key."""
    key = os.urandom(32)
    plaintext = b"Classified document content - TOP SECRET"
    aad = b"metadata"

    encrypted = symmetric.encrypt(key, plaintext, aad)
    assert encrypted.ciphertext != plaintext
    assert len(encrypted.nonce) == 12

    decrypted = symmetric.decrypt(key, encrypted)
    assert decrypted == plaintext


def test_aes_gcm_wrong_key_fails():
    """Decryption fails with wrong key."""
    key1 = os.urandom(32)
    key2 = os.urandom(32)
    plaintext = b"Secret data"

    encrypted = symmetric.encrypt(key1, plaintext)
    with pytest.raises(Exception):
        symmetric.decrypt(key2, encrypted)


def test_aes_gcm_tampering_detection():
    """Decryption fails when ciphertext is tampered."""
    key = os.urandom(32)
    plaintext = b"Secret data"

    encrypted = symmetric.encrypt(key, plaintext)
    # Tamper with ciphertext
    tampered_ct = bytes([encrypted.ciphertext[0] ^ 0xFF]) + encrypted.ciphertext[1:]
    tampered_payload = symmetric.EncryptedPayload(
        nonce=encrypted.nonce,
        ciphertext=tampered_ct,
        aad=encrypted.aad,
    )

    with pytest.raises(Exception):
        symmetric.decrypt(key, tampered_payload)


def test_key_bundle_export_import():
    """Export and import key bundle preserves keys."""
    kem_kp = pq_engine.generate_kem_keypair()
    sig_kp = pq_engine.generate_signing_keypair()

    bundle = pq_engine.export_key_bundle(kem_kp, sig_kp, "test_user")
    imported = pq_engine.import_key_bundle(bundle)

    assert imported["user_id"] == "test_user"
    assert imported["kem_private_key"] == kem_kp.private_key
    assert imported["sig_private_key"] == sig_kp.private_key


def test_crypto_info():
    """get_crypto_info returns expected structure."""
    info = pq_engine.get_crypto_info()
    assert "post_quantum" in info
    assert "kem_algorithm" in info
    assert "sig_algorithm" in info
    assert "library" in info

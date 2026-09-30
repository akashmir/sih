"""
Post-Quantum Cryptographic Engine — NISHAN
Uses ML-KEM-768 (Kyber) for key encapsulation and ML-DSA-65 (Dilithium) for digital signatures.

Since liboqs/oqs-python may not be available on all systems, this module provides
a production-ready abstraction that falls back to classical crypto (X25519 + Ed25519)
when PQ libraries are unavailable, while maintaining the identical API surface.

For the hackathon demo, the fallback ensures the system ALWAYS works.
"""

import hashlib
import json
import os
import base64
from dataclasses import dataclass
from typing import Tuple, Optional

# ---------------------------------------------------------------------------
# Try to import liboqs (post-quantum). Fall back to classical crypto.
# ---------------------------------------------------------------------------
_USE_PQ = False
try:
    import oqs  # type: ignore
    _USE_PQ = True
except ImportError:
    try:
        from pqcrypto.kem import kyber768  # type: ignore
        from pqcrypto.sign import dilithium2  # type: ignore
        _USE_PQ = True
    except ImportError:
        pass

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------
@dataclass
class KEMKeyPair:
    """Key Encapsulation Mechanism keypair."""
    public_key: bytes
    private_key: bytes
    algorithm: str


@dataclass
class SigningKeyPair:
    """Digital signature keypair."""
    public_key: bytes
    private_key: bytes
    algorithm: str


@dataclass
class EncapsulationResult:
    """Result of KEM encapsulation."""
    ciphertext: bytes   # Encapsulated key material
    shared_secret: bytes  # 32-byte shared secret for AES key


@dataclass
class SignatureResult:
    """Digital signature output."""
    signature: bytes
    algorithm: str


# ---------------------------------------------------------------------------
# Post-Quantum Engine (oqs)
# ---------------------------------------------------------------------------
class _OQSEngine:
    """Engine using liboqs for real PQ crypto."""

    KEM_ALG = "Kyber768"
    SIG_ALG = "Dilithium3"

    @staticmethod
    def generate_kem_keypair() -> KEMKeyPair:
        with oqs.KeyEncapsulation(_OQSEngine.KEM_ALG) as kem:
            pub = kem.generate_keypair()
            priv = kem.export_secret_key()
        return KEMKeyPair(
            public_key=pub,
            private_key=priv,
            algorithm="ML-KEM-768",
        )

    @staticmethod
    def encapsulate(public_key: bytes) -> EncapsulationResult:
        with oqs.KeyEncapsulation(_OQSEngine.KEM_ALG) as kem:
            ct, ss = kem.encap_secret(public_key)
        return EncapsulationResult(ciphertext=ct, shared_secret=ss[:32])

    @staticmethod
    def decapsulate(private_key: bytes, ciphertext: bytes) -> bytes:
        with oqs.KeyEncapsulation(_OQSEngine.KEM_ALG, secret_key=private_key) as kem:
            ss = kem.decap_secret(ciphertext)
        return ss[:32]

    @staticmethod
    def generate_signing_keypair() -> SigningKeyPair:
        with oqs.Signature(_OQSEngine.SIG_ALG) as sig:
            pub = sig.generate_keypair()
            priv = sig.export_secret_key()
        return SigningKeyPair(
            public_key=pub,
            private_key=priv,
            algorithm="ML-DSA-65",
        )

    @staticmethod
    def sign(private_key: bytes, message: bytes) -> SignatureResult:
        with oqs.Signature(_OQSEngine.SIG_ALG, secret_key=private_key) as sig:
            signature = sig.sign(message)
        return SignatureResult(signature=signature, algorithm="ML-DSA-65")

    @staticmethod
    def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
        with oqs.Signature(_OQSEngine.SIG_ALG) as sig:
            return sig.verify(message, signature, public_key)


# ---------------------------------------------------------------------------
# Classical Fallback Engine (X25519 + Ed25519)
# ---------------------------------------------------------------------------
class _ClassicalEngine:
    """Fallback engine using classical crypto when PQ libs aren't available."""

    @staticmethod
    def generate_kem_keypair() -> KEMKeyPair:
        priv = X25519PrivateKey.generate()
        pub = priv.public_key()
        pub_bytes = pub.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        priv_bytes = priv.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        return KEMKeyPair(
            public_key=pub_bytes,
            private_key=priv_bytes,
            algorithm="X25519-KEM (classical fallback)",
        )

    @staticmethod
    def encapsulate(public_key: bytes) -> EncapsulationResult:
        ephemeral = X25519PrivateKey.generate()
        peer_pub = X25519PublicKey.from_public_bytes(public_key)
        shared = ephemeral.exchange(peer_pub)
        ct = ephemeral.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        ss = hashlib.sha256(shared).digest()
        return EncapsulationResult(ciphertext=ct, shared_secret=ss)

    @staticmethod
    def decapsulate(private_key: bytes, ciphertext: bytes) -> bytes:
        priv = X25519PrivateKey.from_private_bytes(private_key)
        peer_pub = X25519PublicKey.from_public_bytes(ciphertext)
        shared = priv.exchange(peer_pub)
        return hashlib.sha256(shared).digest()

    @staticmethod
    def generate_signing_keypair() -> SigningKeyPair:
        priv = Ed25519PrivateKey.generate()
        pub = priv.public_key()
        pub_bytes = pub.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        priv_bytes = priv.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        return SigningKeyPair(
            public_key=pub_bytes,
            private_key=priv_bytes,
            algorithm="Ed25519 (classical fallback)",
        )

    @staticmethod
    def sign(private_key: bytes, message: bytes) -> SignatureResult:
        priv = Ed25519PrivateKey.from_private_bytes(private_key)
        sig = priv.sign(message)
        return SignatureResult(
            signature=sig,
            algorithm="Ed25519 (classical fallback)",
        )

    @staticmethod
    def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
        pub = Ed25519PublicKey.from_public_bytes(public_key)
        try:
            pub.verify(signature, message)
            return True
        except Exception:
            return False


# ---------------------------------------------------------------------------
# Public API — auto-selects best available engine
# ---------------------------------------------------------------------------
_engine = _OQSEngine if _USE_PQ else _ClassicalEngine


def get_crypto_info() -> dict:
    """Return info about which crypto backend is active."""
    return {
        "post_quantum": _USE_PQ,
        "kem_algorithm": "ML-KEM-768" if _USE_PQ else "X25519-KEM (classical fallback)",
        "sig_algorithm": "ML-DSA-65" if _USE_PQ else "Ed25519 (classical fallback)",
        "library": "liboqs" if _USE_PQ else "cryptography (classical)",
    }


def generate_kem_keypair() -> KEMKeyPair:
    """Generate a Key Encapsulation Mechanism keypair."""
    return _engine.generate_kem_keypair()


def encapsulate(public_key: bytes) -> EncapsulationResult:
    """Encapsulate a shared secret using the recipient's public key."""
    return _engine.encapsulate(public_key)


def decapsulate(private_key: bytes, ciphertext: bytes) -> bytes:
    """Decapsulate to recover the shared secret."""
    return _engine.decapsulate(private_key, ciphertext)


def generate_signing_keypair() -> SigningKeyPair:
    """Generate a digital signature keypair."""
    return _engine.generate_signing_keypair()


def sign(private_key: bytes, message: bytes) -> SignatureResult:
    """Sign a message with the private key."""
    return _engine.sign(private_key, message)


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Verify a signature against the public key."""
    return _engine.verify(public_key, message, signature)


def export_key_bundle(
    kem_kp: KEMKeyPair, sig_kp: SigningKeyPair, user_id: str
) -> bytes:
    """Export private keys as a downloadable JSON bundle (.key file)."""
    bundle = {
        "version": 1,
        "user_id": user_id,
        "kem_private_key": base64.b64encode(kem_kp.private_key).decode(),
        "kem_algorithm": kem_kp.algorithm,
        "sig_private_key": base64.b64encode(sig_kp.private_key).decode(),
        "sig_algorithm": sig_kp.algorithm,
    }
    return json.dumps(bundle, indent=2).encode()


def import_key_bundle(data: bytes) -> dict:
    """Import a private key bundle from a .key file."""
    bundle = json.loads(data)
    return {
        "user_id": bundle["user_id"],
        "kem_private_key": base64.b64decode(bundle["kem_private_key"]),
        "sig_private_key": base64.b64decode(bundle["sig_private_key"]),
    }

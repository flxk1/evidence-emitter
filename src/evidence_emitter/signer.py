"""The signing seam.

Signing key material is reserved: this module never generates, embeds, or reads
a private key of its own. A :class:`Signer` is injected; the default
:class:`DevSigner` is a clearly-labelled, non-production stand-in that provides
tamper-evidence but no authenticity. Production signing is an Ed25519 key the
host or a human supplies to :class:`Ed25519Signer`; minting and custody of that
key are a step outside this package.
"""
from __future__ import annotations

import hmac
from dataclasses import dataclass
from hashlib import sha256
from typing import Protocol, runtime_checkable

#: The shared constant the dev signer keys its HMAC on. It is published in the
#: source, so a dev-signed package proves only that its bytes were not altered
#: after signing — never who signed it. Never treat it as a secret.
_DEV_SHARED_KEY = b"evidence-emitter/dev-signer/INSECURE-SHARED-KEY/not-for-production"


@runtime_checkable
class Signer(Protocol):
    """Signs and re-verifies the DSSE pre-authentication encoding.

    ``production`` states plainly whether the signature carries authenticity. A
    verifier surfaces it; it never silently promotes a dev signature.
    """

    key_id: str
    algorithm: str
    production: bool

    def sign(self, message: bytes) -> bytes: ...

    def verify(self, message: bytes, signature: bytes) -> bool: ...

    def descriptor(self) -> dict: ...


@dataclass(frozen=True)
class DevSigner:
    """Non-production signer: HMAC-SHA256 under a published shared key.

    Round-trips and detects tampering, so emit/verify and the tamper tests work
    without key management. It authenticates nothing — anyone can reproduce the
    signature — and reports ``production=False`` so a verifier says so loudly.
    """

    key_id: str = "dev-insecure-shared-key"
    algorithm: str = "hmac-sha256"
    production: bool = False

    def sign(self, message: bytes) -> bytes:
        return hmac.new(_DEV_SHARED_KEY, message, sha256).digest()

    def verify(self, message: bytes, signature: bytes) -> bool:
        return hmac.compare_digest(self.sign(message), signature)

    def descriptor(self) -> dict:
        return {
            "key_id": self.key_id,
            "algorithm": self.algorithm,
            "production": self.production,
            "note": "DEV signer: published shared HMAC key — tamper-evident, not authentic",
        }


@dataclass(frozen=True)
class Ed25519Signer:
    """Production signer over a caller-supplied Ed25519 private key.

    The key is loaded and held by the caller; this class neither generates nor
    persists it. Construct via :meth:`from_private_pem` with key bytes the host
    provides. ``cryptography`` is imported lazily, so it is not a dependency of
    the default path.
    """

    key_id: str
    algorithm: str = "ed25519"
    production: bool = True
    _private_key: object = None

    @classmethod
    def from_private_pem(cls, pem: bytes, *, key_id: str, password: bytes | None = None) -> "Ed25519Signer":
        from cryptography.hazmat.primitives.serialization import load_pem_private_key

        return cls(key_id=key_id, _private_key=load_pem_private_key(pem, password=password))

    def sign(self, message: bytes) -> bytes:
        if self._private_key is None:
            raise ValueError("Ed25519Signer has no private key; construct via from_private_pem")
        return self._private_key.sign(message)

    def verify(self, message: bytes, signature: bytes) -> bool:
        from cryptography.exceptions import InvalidSignature

        try:
            self._private_key.public_key().verify(signature, message)
            return True
        except InvalidSignature:
            return False

    def descriptor(self) -> dict:
        return {"key_id": self.key_id, "algorithm": self.algorithm, "production": self.production}


@dataclass(frozen=True)
class Ed25519Verifier:
    """Verify-only side of a production signature, from a public key alone."""

    key_id: str
    algorithm: str = "ed25519"
    production: bool = True
    _public_key: object = None

    @classmethod
    def from_public_pem(cls, pem: bytes, *, key_id: str) -> "Ed25519Verifier":
        from cryptography.hazmat.primitives.serialization import load_pem_public_key

        return cls(key_id=key_id, _public_key=load_pem_public_key(pem))

    def sign(self, message: bytes) -> bytes:  # pragma: no cover - a verifier does not sign
        raise NotImplementedError("Ed25519Verifier verifies only")

    def verify(self, message: bytes, signature: bytes) -> bool:
        from cryptography.exceptions import InvalidSignature

        try:
            self._public_key.verify(signature, message)
            return True
        except InvalidSignature:
            return False

    def descriptor(self) -> dict:
        return {"key_id": self.key_id, "algorithm": self.algorithm, "production": self.production}

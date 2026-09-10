"""Canonical bytes, content digests, and the DSSE pre-authentication encoding.

The whole family binds evidence by hashing a canonical serialization, so a
verifier must reproduce the exact bytes the signer hashed. Two canonicalizers
are offered under stable names recorded in every package: ``rfc8785`` (the JSON
Canonicalization Scheme, RFC 8785, used across the assurance repos) and
``jcs-stdlib`` (a sort-keys/compact-separators approximation that needs no
dependency). A package names the scheme it was built with; verification selects
the matching one and fails closed when it is unavailable.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Callable

RFC8785 = "rfc8785"
JCS_STDLIB = "jcs-stdlib"

Canonicalize = Callable[[Any], bytes]


def _jcs_stdlib(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _rfc8785(value: Any) -> bytes:
    import rfc8785  # deferred: the stdlib scheme carries the dependency-free path

    return rfc8785.dumps(value)


def available_scheme(preferred: str = RFC8785) -> str:
    """The best canonicalization scheme available, preferring ``preferred``."""
    if preferred == RFC8785:
        try:
            import rfc8785  # noqa: F401

            return RFC8785
        except Exception:
            return JCS_STDLIB
    return JCS_STDLIB


def canonicalizer(scheme: str) -> Canonicalize:
    """Return the canonicalizer for ``scheme`` or raise ``LookupError``.

    ``LookupError`` — not a silent fallback — because a verifier that hashes with
    a different scheme than the signer used would reject a sound package.
    """
    if scheme == JCS_STDLIB:
        return _jcs_stdlib
    if scheme == RFC8785:
        try:
            import rfc8785  # noqa: F401
        except Exception as exc:
            raise LookupError(f"canonicalization scheme {scheme!r} unavailable: {exc}") from exc
        return _rfc8785
    raise LookupError(f"unknown canonicalization scheme {scheme!r}")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest_over(value: Any, canonicalize: Canonicalize) -> dict[str, str]:
    """``{"sha256": <hex>}`` over the canonical form of ``value``."""
    return {"sha256": sha256_hex(canonicalize(value))}


def pae(payload_type: str, body: bytes) -> bytes:
    """DSSE Pre-Authentication Encoding — the exact bytes a signature covers.

    ``DSSEv1 <len(type)> <type> <len(body)> <body>``, matching the assurance
    repos so their envelopes and this package's envelope share one signed-bytes
    rule.
    """
    kind = payload_type.encode("utf-8")
    return b"DSSEv1 " + str(len(kind)).encode() + b" " + kind + b" " + str(len(body)).encode() + b" " + body

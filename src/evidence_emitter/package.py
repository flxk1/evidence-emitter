"""Compose one signed, offline-verifiable evidence package.

The package is a DSSE-wrapped in-toto Statement. Its subject is the attested
work — an a2a-compliance decision or a privacy-shield egress decision —
digest-bound and inlined so the package is self-contained. Its predicate carries
one section per assurance component; the top-level signature covers the whole
statement, so altering any section, the subject, or the emitter metadata breaks
verification.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable

from . import canonical
from ._version import __version__
from .components import EvidenceContext, PRESENT, PRESENT_NO_INPUT, ABSENT, REGISTRY
from .signer import DevSigner, Signer
from .subjects import normalize

PREDICATE_TYPE = "https://ctrl.local/attestations/EvidencePackage/v1"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PAYLOAD_TYPE = "application/vnd.in-toto+json"


@dataclass(frozen=True)
class EvidencePackage:
    """A signed evidence package and its decoded statement."""

    envelope: dict
    statement: dict

    def to_dict(self) -> dict:
        return self.envelope

    @property
    def predicate(self) -> dict:
        return self.statement["predicate"]

    @property
    def sections(self) -> list[dict]:
        return self.predicate["sections"]

    @classmethod
    def from_dict(cls, envelope: dict) -> "EvidencePackage":
        import json

        statement = json.loads(base64.b64decode(envelope["payload"]))
        return cls(envelope=envelope, statement=statement)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def emit(
    subject: Any,
    *,
    kind: str | None = None,
    components: Iterable[str] | None = None,
    signer: Signer | None = None,
    context: EvidenceContext | None = None,
    issued_at: str | None = None,
) -> EvidencePackage:
    """Emit an evidence package attesting the governance applied to ``subject``.

    ``subject`` is an a2a-compliance decision/directive or a privacy-shield
    ScanReport (object or its dict form). ``components`` optionally restricts
    which assurance components are attempted; those omitted are marked absent,
    never faked. ``signer`` defaults to the non-production :class:`DevSigner`.
    ``context`` carries the governance inputs each present component attests.
    """
    signer = signer or DevSigner()
    context = context or EvidenceContext()
    allowed = None if components is None else set(components)
    scheme = canonical.available_scheme()
    canon = canonical.canonicalizer(scheme)
    issued_at = issued_at or _now_iso()
    if context.now is None:
        context.now = issued_at

    ns = normalize(subject, kind=kind)
    subject_digest = canonical.sha256_hex(canon(ns.body))

    sections = [
        component.build(context, sign=signer.sign, canonical=canon, scheme=scheme, allowed=allowed)
        for component in REGISTRY
    ]
    summary = {
        "present": [s["component"] for s in sections if s["status"] == PRESENT],
        "present_no_input": [s["component"] for s in sections if s["status"] == PRESENT_NO_INPUT],
        "absent": [s["component"] for s in sections if s["status"] == ABSENT],
    }

    statement = {
        "_type": STATEMENT_TYPE,
        "subject": [{"name": ns.name, "digest": {"sha256": subject_digest}}],
        "predicateType": PREDICATE_TYPE,
        "predicate": {
            "emitter": {"name": "evidence-emitter", "version": __version__, "signer": signer.descriptor()},
            "canonicalization": scheme,
            "issued_at": issued_at,
            "subject_kind": ns.kind,
            "action_class": ns.action_class,
            "subject_body": ns.body,
            "component_summary": summary,
            "sections": sections,
        },
    }

    payload = canon(statement)
    signature = signer.sign(canonical.pae(PAYLOAD_TYPE, payload))
    envelope = {
        "payloadType": PAYLOAD_TYPE,
        "payload": base64.b64encode(payload).decode("ascii"),
        "signatures": [{"keyid": signer.key_id, "sig": base64.b64encode(signature).decode("ascii")}],
    }
    return EvidencePackage(envelope=envelope, statement=statement)

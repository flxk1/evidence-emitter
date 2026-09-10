"""Offline verification of an evidence package.

Verification trusts nothing but the package bytes and a verifier. It re-checks
the top-level DSSE signature and canonical form, re-derives the subject digest
from the inlined body, and re-checks every present section through its
component's own verifier where installed and a generic check otherwise. Absent
and no-input sections are reported, never counted against the verdict; a
non-production signer is surfaced, never silently accepted.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass, field
from typing import Any

from . import canonical
from .components import BY_KEY, FAIL, PRESENT
from .package import EvidencePackage, PAYLOAD_TYPE, PREDICATE_TYPE
from .signer import DevSigner, Signer


@dataclass
class SectionVerdict:
    component: str
    status: str
    ok: bool
    findings: list[dict] = field(default_factory=list)


@dataclass
class VerdictReport:
    ok: bool
    signer_production: bool
    signer_descriptor: dict
    subject_kind: str | None
    present: list[str] = field(default_factory=list)
    absent: list[str] = field(default_factory=list)
    no_input: list[str] = field(default_factory=list)
    sections: list[SectionVerdict] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)

    def summary(self) -> str:
        head = "OK" if self.ok else "REJECTED"
        prod = "production" if self.signer_production else "DEV signer (non-production)"
        return f"{head} — {prod}; present={self.present} no-input={self.no_input} absent={self.absent}"


def _fail(code: str, detail: str) -> dict:
    return {"code": code, "detail": detail, "severity": FAIL}


def verify(package: Any, *, signer: Signer | None = None) -> VerdictReport:
    """Re-check an evidence package offline.

    ``package`` is an :class:`EvidencePackage` or a raw DSSE envelope dict.
    ``signer`` supplies the verify side (the same dev signer by default, or an
    ``Ed25519Verifier`` for a production package); its ``production`` flag is
    reported and never gates ``ok`` on its own.
    """
    signer = signer or DevSigner()
    envelope = package.to_dict() if isinstance(package, EvidencePackage) else package
    report = VerdictReport(
        ok=False, signer_production=bool(getattr(signer, "production", False)),
        signer_descriptor=signer.descriptor() if hasattr(signer, "descriptor") else {}, subject_kind=None,
    )

    try:
        payload = base64.b64decode(envelope["payload"])
        signatures = envelope.get("signatures") or []
        payload_type = str(envelope.get("payloadType"))
    except Exception as exc:
        report.findings.append(_fail("malformed-envelope", str(exc)))
        return report

    if payload_type != PAYLOAD_TYPE:
        report.findings.append(_fail("bad-envelope", f"payloadType {payload_type!r}"))
    if not signatures:
        report.findings.append(_fail("bad-envelope", "no signatures"))

    message = canonical.pae(PAYLOAD_TYPE, payload)
    sig_ok = False
    for s in signatures:
        try:
            if signer.verify(message, base64.b64decode(s["sig"])):
                sig_ok = True
                break
        except Exception:
            continue
    if not sig_ok:
        report.findings.append(_fail("bad-signature", "top-level DSSE signature did not verify"))

    import json

    try:
        statement = json.loads(payload)
        predicate = statement["predicate"]
    except Exception as exc:
        report.findings.append(_fail("malformed-statement", str(exc)))
        return report

    if statement.get("predicateType") != PREDICATE_TYPE:
        report.findings.append(_fail("wrong-predicate-type", str(statement.get("predicateType"))))

    scheme = predicate.get("canonicalization", canonical.RFC8785)
    try:
        canon = canonical.canonicalizer(scheme)
    except LookupError as exc:
        report.findings.append(_fail("canonicalizer-unavailable", str(exc)))
        return report

    if canon(statement) != payload:
        report.findings.append(_fail("non-canonical-payload", "payload is not the canonical form of its statement"))

    report.subject_kind = predicate.get("subject_kind")
    try:
        recomputed = canonical.sha256_hex(canon(predicate["subject_body"]))
        declared = statement["subject"][0]["digest"]["sha256"]
        if recomputed != declared:
            report.findings.append(_fail("subject-digest-mismatch", "inlined subject body does not match the bound digest"))
    except Exception as exc:
        report.findings.append(_fail("malformed-subject", str(exc)))

    sections_ok = True
    for section in predicate.get("sections", []):
        component = BY_KEY.get(section["component"])
        status = section["status"]
        if component is None:
            sv = SectionVerdict(section["component"], status, False, [_fail("unknown-component", section["component"])])
            report.sections.append(sv)
            sections_ok = False
            continue
        findings = component.check(section, verify_sig=signer.verify, canonical=canon)
        failing = [f for f in findings if f.get("severity") == FAIL]
        sv = SectionVerdict(section["component"], status, not failing, findings)
        report.sections.append(sv)
        if status == PRESENT:
            report.present.append(section["component"])
            if failing:
                sections_ok = False
        elif status == "present-no-input":
            report.no_input.append(section["component"])
        else:
            report.absent.append(section["component"])

    structural_ok = not report.findings
    report.ok = bool(sig_ok and structural_ok and sections_ok)
    return report

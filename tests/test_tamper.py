import base64
import json

from evidence_emitter import emit, verify
from evidence_emitter.canonical import available_scheme, canonicalizer

from fixtures import fake_a2a_decision, full_context


def _reencode(envelope: dict, statement: dict) -> dict:
    canon = canonicalizer(available_scheme())
    tampered = dict(envelope)
    tampered["payload"] = base64.b64encode(canon(statement)).decode("ascii")
    return tampered


def test_tampering_with_the_subject_body_fails_verification():
    pkg = emit(fake_a2a_decision(), context=full_context())
    statement = json.loads(base64.b64decode(pkg.envelope["payload"]))
    statement["predicate"]["subject_body"]["verb"] = "halt"  # was issue-directive
    tampered = _reencode(pkg.envelope, statement)

    report = verify(tampered)
    assert not report.ok
    codes = {f["code"] for f in report.findings}
    # Signature no longer covers the mutated payload; the digest binding also breaks.
    assert "bad-signature" in codes
    assert "subject-digest-mismatch" in codes


def test_tampering_with_a_section_result_fails_verification():
    pkg = emit(fake_a2a_decision(), context=full_context())
    statement = json.loads(base64.b64decode(pkg.envelope["payload"]))
    section = next(s for s in statement["predicate"]["sections"] if s["component"] == "effect-reconciliation")
    section["content"]["result"]["observed_not_authorised"] = ["smuggled-effect"]
    tampered = _reencode(pkg.envelope, statement)

    report = verify(tampered)
    assert not report.ok
    assert "bad-signature" in {f["code"] for f in report.findings}


def test_swapping_the_signature_fails_verification():
    pkg = emit(fake_a2a_decision(), context=full_context())
    tampered = dict(pkg.envelope)
    tampered["signatures"] = [{"keyid": "x", "sig": base64.b64encode(b"\x00" * 32).decode("ascii")}]

    report = verify(tampered)
    assert not report.ok
    assert "bad-signature" in {f["code"] for f in report.findings}

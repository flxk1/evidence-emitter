"""Synthetic subjects and governance context for the tests.

The subjects are hand-built dicts in the wire shapes of an a2a-compliance
decision/directive and a privacy-shield ScanReport, so the tests need neither
package installed. The context carries synthetic governance inputs for the two
assurance components installed in this environment (enforcement-posture,
effect-reconciliation) and a grounding reference.
"""
import hashlib

from evidence_emitter.components import EvidenceContext


def fake_a2a_decision() -> dict:
    return {
        "id": "msg-001",
        "ts": "2026-09-10T10:00:00Z",
        "from_": {"actor": "compliance-agent", "role": "policy-compliance"},
        "to": {"actor": "maker-7", "role": "maker"},
        "verb": "issue-directive",
        "body": {"instruction": "hold pending grounding", "kind": "fs.write"},
        "authority": {"basis": "role", "role": "policy-compliance", "reserved": False},
        "protocol": "a2a-compliance/0.1",
    }


def fake_scanreport() -> dict:
    return {
        "mode": "redact",
        "destination": "https://api.example.com",
        "root": "/data/case-7",
        "document_count": 2,
        "total_spans": 3,
        "all_allowed": False,
        "documents": [
            {"source": "brief.txt", "input_type": "text", "egress_allowed": True, "classification": "public", "span_count": 1},
            {"source": "client.txt", "input_type": "text", "egress_allowed": False, "classification": "confidential", "span_count": 2, "blocked_reason": "classification_external_blocked"},
        ],
    }


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def full_context() -> EvidenceContext:
    return EvidenceContext(
        posture={
            "engine": "claude-code",
            "controls": [
                {"name": "PreToolUse", "enabled": True, "mode": "hard-fail"},
                {"name": "egress_allowlist", "enabled": True},
            ],
            "effective_from": "2026-09-10T09:00:00Z",
        },
        evidence_window={
            "log_id": "session-log-42",
            "start": "2026-09-10T09:00:00Z",
            "end": "2026-09-10T11:00:00Z",
            "digest": _digest("evidence-window-body"),
        },
        posture_algorithm="hmac-sha256",
        authorisations=[
            {"id": "auth-1", "action": "fs.write", "subject": "maker-7", "at": "2026-09-10T10:00:00Z"},
        ],
        effects=[
            {"id": "eff-1", "action": "fs.write", "subject": "maker-7", "at": "2026-09-10T10:00:01Z", "authorisation_id": "auth-1"},
        ],
        recon_window=("2026-09-10T09:00:00Z", "2026-09-10T11:00:00Z"),
        grounding_ref={
            "scheme": "5d+nd",
            "ref": {"dimensions": ["causal", "structural"], "anchor": "versum://policy/egress#span-42"},
        },
    )

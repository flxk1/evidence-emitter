import pytest

from evidence_emitter.subjects import A2A_DECISION, SCANREPORT, normalize

from fixtures import fake_a2a_decision, fake_scanreport


def test_normalize_a2a_message():
    ns = normalize(fake_a2a_decision())
    assert ns.kind == A2A_DECISION
    assert ns.action_class == "a2a.issue-directive"
    assert ns.body["from"]["actor"] == "compliance-agent"  # from_ normalised to from


def test_normalize_steer_ruling():
    ns = normalize({"decision": "route-human", "kind": "fs.write", "reason": "reserved"})
    assert ns.kind == A2A_DECISION
    assert ns.action_class == "a2a.steer.route-human"


def test_normalize_scanreport():
    ns = normalize(fake_scanreport())
    assert ns.kind == SCANREPORT
    assert ns.action_class == "privacy-shield.egress"


def test_unrecognised_subject_raises():
    with pytest.raises(ValueError):
        normalize({"hello": "world"})


def test_kind_override():
    ns = normalize({"mode": "x", "destination": "y", "documents": []}, kind=SCANREPORT)
    assert ns.kind == SCANREPORT

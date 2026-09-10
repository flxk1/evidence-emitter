from evidence_emitter import emit, verify
from evidence_emitter.subjects import A2A_DECISION, SCANREPORT

from fixtures import fake_a2a_decision, fake_scanreport, full_context


def test_a2a_decision_round_trips():
    pkg = emit(fake_a2a_decision(), context=full_context())
    report = verify(pkg)
    assert report.ok, report.findings
    assert report.subject_kind == A2A_DECISION
    # The two components installed in this environment are consumed for real.
    assert "enforcement-posture" in report.present
    assert "effect-reconciliation" in report.present
    assert "5d-nd" in report.present
    assert report.signer_production is False


def test_scanreport_round_trips():
    pkg = emit(fake_scanreport(), context=full_context())
    report = verify(pkg)
    assert report.ok, report.findings
    assert report.subject_kind == SCANREPORT


def test_present_sections_verify_through_their_own_component():
    pkg = emit(fake_a2a_decision(), context=full_context())
    report = verify(pkg)
    ep = next(s for s in report.sections if s.component == "enforcement-posture")
    assert ep.ok and ep.status == "present"
    er = next(s for s in report.sections if s.component == "effect-reconciliation")
    assert er.ok and er.status == "present"


def test_absent_components_do_not_fail_the_verdict():
    # oversight-certificate and norm-freshness are not installed here.
    pkg = emit(fake_a2a_decision(), context=full_context())
    report = verify(pkg)
    assert "oversight-certificate" in report.absent
    assert "norm-freshness" in report.absent
    assert report.ok


def test_no_input_when_component_present_but_nothing_supplied():
    # No context: installed components have nothing to attest, and say so.
    pkg = emit(fake_a2a_decision())
    report = verify(pkg)
    assert report.ok
    assert "enforcement-posture" in report.no_input
    assert "effect-reconciliation" in report.no_input

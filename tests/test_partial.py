from evidence_emitter import emit, verify

from fixtures import fake_a2a_decision, full_context


def test_caller_excluded_component_is_marked_absent_not_faked():
    pkg = emit(fake_a2a_decision(), context=full_context(), components=["effect-reconciliation"])
    report = verify(pkg)
    assert report.ok, report.findings
    assert report.present == ["effect-reconciliation"]
    # Everything else is present as an honestly-marked absent section.
    ep = next(s for s in pkg.sections if s["component"] == "enforcement-posture")
    assert ep["status"] == "absent"
    assert ep["reason"] == "excluded by caller"
    assert "content" not in ep


def test_minimal_package_with_no_components_still_emits_and_verifies():
    pkg = emit(fake_a2a_decision(), components=[])
    report = verify(pkg)
    assert report.ok
    assert report.present == []
    # Every known component is still described, marked absent — a self-describing shell.
    assert len(pkg.sections) == 7
    assert all(s["status"] == "absent" for s in pkg.sections)


def test_partial_package_carries_the_installed_components_only():
    pkg = emit(fake_a2a_decision(), context=full_context())
    report = verify(pkg)
    # This environment installs two of the seven; the rest degrade to absent.
    assert set(report.present) >= {"enforcement-posture", "effect-reconciliation", "5d-nd"}
    assert set(report.absent) >= {"governance-certification", "oversight-certificate", "norm-freshness", "obligation-discharge"}
    assert report.ok

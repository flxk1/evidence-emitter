"""The assurance components the emitter composes, and how each is re-checked.

Every component is optional and probed independently. A present component whose
governance input the caller supplied contributes a real section; a present
component with no input, and an absent or caller-excluded one, contribute a
section marked as such — never a fabricated one. The two roles differ in how a
section proves out offline:

* **attestation** components (governance-certification, oversight-certificate,
  enforcement-posture) embed a DSSE sub-envelope re-checked by the component's
  own verifier when installed, and by a generic DSSE signature check otherwise;
* **computation** components (effect-reconciliation, norm-freshness,
  obligation-discharge) embed their inputs, result, and a digest; the result is
  recomputed from the inputs when the component is installed, and digest-checked
  always;
* the **grounding** resolver (5d+nd) embeds a scheme/ref/digest that is
  re-digested and re-validated; its ``resolve`` is an upstream stub, so a
  section names the resolver without claiming resolution.
"""
from __future__ import annotations

import base64
import importlib
import importlib.util
import inspect
from dataclasses import dataclass
from typing import Any, Callable

from .canonical import Canonicalize, digest_over, pae, sha256_hex

PRESENT = "present"
PRESENT_NO_INPUT = "present-no-input"
ABSENT = "absent"

FAIL = "fail"
NOTE = "note"


@dataclass
class EvidenceContext:
    """The governance an agent actually applied, fed to whichever components exist.

    Every field is optional. A field left unset means the agent supplied nothing
    for that component; the component's section is then marked present-no-input
    (when installed) rather than invented.
    """

    # enforcement-posture
    posture: Any = None
    evidence_window: Any = None
    posture_algorithm: str = "ed25519"
    # effect-reconciliation
    authorisations: Any = None
    effects: Any = None
    recon_window: tuple[str, str] | None = None
    recon_match_window_s: float = 0.0
    # norm-freshness
    rule_pins: Any = None
    observed_sources: Any = None
    # obligation-discharge
    obligations: Any = None
    pep_declaration: Any = None
    discharges: Any = None
    decided_at: str | None = None
    now: str | None = None
    # oversight-certificate: an OversightCertificate/dict to issue, or a minted envelope
    oversight_certificate: Any = None
    oversight_now: str | None = None
    # governance-certification: a pre-minted five-pillar DSSE envelope (no mint here)
    governance_certification: Any = None
    # 5d+nd grounding: {"scheme","ref"} or a bare ref dict
    grounding_ref: Any = None


def _finding(code: str, detail: str, severity: str = FAIL) -> dict:
    return {"code": code, "detail": detail, "severity": severity}


def _spec(module: str) -> bool:
    try:
        return importlib.util.find_spec(module) is not None
    except (ModuleNotFoundError, ImportError, ValueError):
        # A dotted path whose parent package is absent raises rather than
        # returning None; an absent component is a False, never an exception.
        return False


def _version(module: str) -> str | None:
    try:
        return getattr(importlib.import_module(module), "__version__", None)
    except Exception:
        return None


def _is_envelope(value: Any) -> bool:
    return isinstance(value, dict) and "payloadType" in value and "signatures" in value


def _dsse_signature_ok(envelope: dict, verify_sig: Callable[[bytes, bytes], bool]) -> bool:
    """Generic DSSE re-check used when a component's own verifier is not installed."""
    try:
        payload = base64.b64decode(envelope["payload"])
        message = pae(str(envelope["payloadType"]), payload)
        return any(verify_sig(message, base64.b64decode(s["sig"])) for s in envelope.get("signatures") or [])
    except Exception:
        return False


class Component:
    key: str
    module: str
    role: str
    attests: str

    def probe(self, allowed: set[str] | None) -> tuple[bool, str | None, str | None]:
        """Return (available, version, exclusion_reason)."""
        if allowed is not None and self.key not in allowed:
            return False, None, "excluded by caller"
        if not _spec(self.module):
            return False, None, None
        return True, _version(self.module), None

    def _base(self, status: str, version: str | None = None, **extra: Any) -> dict:
        section = {
            "component": self.key,
            "module": self.module,
            "role": self.role,
            "attests": self.attests,
            "status": status,
            "version": version,
        }
        section.update(extra)
        return section

    def build(self, ctx: EvidenceContext, *, sign, canonical: Canonicalize, scheme: str, allowed) -> dict:
        raise NotImplementedError

    def check(self, section: dict, *, verify_sig, canonical: Canonicalize) -> list[dict]:
        raise NotImplementedError


# --------------------------------------------------------------------------- #
# enforcement-posture (attestation)
# --------------------------------------------------------------------------- #

class EnforcementPosture(Component):
    key = "enforcement-posture"
    module = "enforcement_posture"
    role = "attestation"
    attests = "which enforcement controls were in force over the evidence window"

    def build(self, ctx, *, sign, canonical, scheme, allowed):
        available, version, reason = self.probe(allowed)
        if not available:
            return self._base(ABSENT, reason=reason or "component not installed")
        if ctx.posture is None or ctx.evidence_window is None:
            return self._base(PRESENT_NO_INPUT, version, reason="no posture/window supplied")
        ep = importlib.import_module(self.module)
        posture = self._coerce_posture(ep, ctx.posture)
        window = self._coerce_window(ep, ctx.evidence_window)
        envelope = ep.attest(
            posture, window, canonicalize=canonical, sign=sign,
            keyid="", algorithm=ctx.posture_algorithm or "",
        )
        return self._base(PRESENT, version, predicate_type=ep.PREDICATE_TYPE, content=envelope)

    def check(self, section, *, verify_sig, canonical):
        if section["status"] != PRESENT:
            return []
        envelope = section["content"]
        if _spec(self.module):
            ep = importlib.import_module(self.module)
            report = ep.verify(envelope, canonicalize=canonical, verify_sig=verify_sig)
            return [_finding(f.code, f.detail) for f in report.findings]
        findings = [] if _dsse_signature_ok(envelope, verify_sig) else [_finding("bad-signature", "sub-envelope signature did not verify")]
        findings.append(_finding("native-verifier-unavailable", f"{self.module} not installed; checked DSSE signature only", NOTE))
        return findings

    @staticmethod
    def _coerce_posture(ep, value):
        if isinstance(value, ep.Posture):
            return value
        # The Control dataclass has grown fields across versions; pass only the
        # ones this installed version accepts, so an older engine is not fed a
        # keyword it never defined.
        accepted = set(inspect.signature(ep.Control).parameters)
        controls = tuple(
            c if isinstance(c, ep.Control) else ep.Control(
                **{k: v for k, v in {
                    "name": c["name"], "enabled": bool(c["enabled"]), "mode": c.get("mode"),
                    "quantity": c.get("quantity"),
                    "weakens_when_enabled": bool(c.get("weakens_when_enabled", False)),
                }.items() if k in accepted}
            )
            for c in value["controls"]
        )
        return ep.Posture(engine=value["engine"], controls=controls,
                          effective_from=value["effective_from"], effective_to=value.get("effective_to"))

    @staticmethod
    def _coerce_window(ep, value):
        if isinstance(value, ep.EvidenceWindow):
            return value
        return ep.EvidenceWindow(log_id=value["log_id"], start=value["start"], end=value["end"], digest=value["digest"])


# --------------------------------------------------------------------------- #
# effect-reconciliation (computation)
# --------------------------------------------------------------------------- #

class EffectReconciliation(Component):
    key = "effect-reconciliation"
    module = "effect_reconciliation"
    role = "computation"
    attests = "granted permissions reconciled against observed effects"

    def build(self, ctx, *, sign, canonical, scheme, allowed):
        available, version, reason = self.probe(allowed)
        if not available:
            return self._base(ABSENT, reason=reason or "component not installed")
        if ctx.authorisations is None or ctx.recon_window is None:
            return self._base(PRESENT_NO_INPUT, version, reason="no authorisation ledger/window supplied")
        er = importlib.import_module(self.module)
        since, until = ctx.recon_window
        inputs = {
            "authorisations": [self._plain_auth(a) for a in ctx.authorisations],
            "effects": None if ctx.effects is None else [self._plain_eff(e) for e in ctx.effects],
            "since": since, "until": until, "match_window_s": ctx.recon_match_window_s,
        }
        result = self._compute(er, inputs)
        return self._base(PRESENT, version, content={
            "inputs": inputs, "result": result, "digest": digest_over(result, canonical),
        })

    def check(self, section, *, verify_sig, canonical):
        if section["status"] != PRESENT:
            return []
        content = section["content"]
        findings: list[dict] = []
        if digest_over(content["result"], canonical) != content["digest"]:
            findings.append(_finding("digest-mismatch", "stored result digest does not match its result"))
        if _spec(self.module):
            recomputed = self._compute(importlib.import_module(self.module), content["inputs"])
            if recomputed != content["result"]:
                findings.append(_finding("recompute-mismatch", "recomputed reconciliation differs from the stored result"))
        else:
            findings.append(_finding("recompute-unavailable", f"{self.module} not installed; digest-checked only", NOTE))
        return findings

    @staticmethod
    def _plain_auth(a):
        return a if isinstance(a, dict) else {"id": a.id, "action": a.action, "subject": a.subject, "at": a.at}

    @staticmethod
    def _plain_eff(e):
        if isinstance(e, dict):
            return e
        return {"id": e.id, "action": e.action, "subject": e.subject, "at": e.at, "authorisation_id": e.authorisation_id}

    @staticmethod
    def _compute(er, inputs):
        auths = [er.Authorisation(a["id"], a["action"], a["subject"], a["at"]) for a in inputs["authorisations"]]
        effs = None if inputs["effects"] is None else [
            er.Effect(e["id"], e["action"], e["subject"], e["at"], e.get("authorisation_id")) for e in inputs["effects"]
        ]
        r = er.reconcile(auths, effs, since=inputs["since"], until=inputs["until"], match_window_s=inputs["match_window_s"])
        return {
            "status": r.status.value,
            "matched": [{"authorisation_id": m.authorisation.id, "effect_id": m.effect.id, "binding": m.binding.value} for m in r.matched],
            "authorised_not_observed": [a.id for a in r.authorised_not_observed],
            "observed_not_authorised": [e.id for e in r.observed_not_authorised],
            "duplicated": [{"authorisation_id": d.authorisation.id, "excess": d.excess} for d in r.duplicated],
            "binding_rate": r.binding_rate,
            "unauthorised_rate": r.unauthorised_rate,
        }


# --------------------------------------------------------------------------- #
# norm-freshness (computation)
# --------------------------------------------------------------------------- #

class NormFreshness(Component):
    key = "norm-freshness"
    module = "norm_freshness"
    role = "computation"
    attests = "whether the enforced rules still match the sources they were compiled from"

    def build(self, ctx, *, sign, canonical, scheme, allowed):
        available, version, reason = self.probe(allowed)
        if not available:
            return self._base(ABSENT, reason=reason or "component not installed")
        if ctx.rule_pins is None:
            return self._base(PRESENT_NO_INPUT, version, reason="no rule pins supplied")
        nf = importlib.import_module(self.module)
        inputs = {
            "pins": [self._plain_pin(p) for p in ctx.rule_pins],
            "observed": None if ctx.observed_sources is None else {k: self._plain_state(v) for k, v in ctx.observed_sources.items()},
        }
        result = self._compute(nf, inputs)
        return self._base(PRESENT, version, content={
            "inputs": inputs, "result": result, "digest": digest_over(result, canonical),
        })

    def check(self, section, *, verify_sig, canonical):
        if section["status"] != PRESENT:
            return []
        content = section["content"]
        findings: list[dict] = []
        if digest_over(content["result"], canonical) != content["digest"]:
            findings.append(_finding("digest-mismatch", "stored result digest does not match its result"))
        if _spec(self.module):
            if self._compute(importlib.import_module(self.module), content["inputs"]) != content["result"]:
                findings.append(_finding("recompute-mismatch", "recomputed freshness differs from the stored result"))
        else:
            findings.append(_finding("recompute-unavailable", f"{self.module} not installed; digest-checked only", NOTE))
        return findings

    @staticmethod
    def _plain_pin(p):
        if isinstance(p, dict):
            return p
        src = None if p.source is None else {"uri": p.source.uri, "version": p.source.version, "fragment": p.source.fragment}
        return {"rule_id": p.rule_id, "source": src}

    @staticmethod
    def _plain_state(s):
        if isinstance(s, dict):
            return s
        ck = s.change_kind.value if s.change_kind is not None else None
        return {"uri": s.uri, "current_version": s.current_version, "change_kind": ck, "observed_at": s.observed_at}

    @staticmethod
    def _compute(nf, inputs):
        pins = []
        for p in inputs["pins"]:
            src = p.get("source")
            source = None if src is None else nf.SourceRef(src["uri"], src["version"], src.get("fragment"))
            pins.append(nf.RulePin(p["rule_id"], source))
        observed = None
        if inputs["observed"] is not None:
            observed = {}
            for k, v in inputs["observed"].items():
                ck = None if v.get("change_kind") is None else nf.ChangeKind(v["change_kind"])
                observed[k] = nf.SourceState(v["uri"], v.get("current_version"), ck, v.get("observed_at"))
        report = nf.assess(pins, observed)
        return {
            "ok": report.ok,
            "coverage": report.coverage,
            "verdicts": [{"rule_id": v.rule_id, "freshness": v.freshness.value} for v in report.verdicts],
            "determinations": [{"rule_id": d.rule_id, "freshness": d.freshness.value, "options": list(d.options)} for d in report.determinations],
        }


# --------------------------------------------------------------------------- #
# obligation-discharge (computation)
# --------------------------------------------------------------------------- #

class ObligationDischarge(Component):
    key = "obligation-discharge"
    module = "obligation_discharge"
    role = "computation"
    attests = "whether duties attached to the permit were admissible and discharged"

    def build(self, ctx, *, sign, canonical, scheme, allowed):
        available, version, reason = self.probe(allowed)
        if not available:
            return self._base(ABSENT, reason=reason or "component not installed")
        if ctx.obligations is None or ctx.pep_declaration is None:
            return self._base(PRESENT_NO_INPUT, version, reason="no obligations/PEP declaration supplied")
        od = importlib.import_module(self.module)
        inputs = {
            "obligations": [self._plain_ob(o) for o in ctx.obligations],
            "declaration": self._plain_decl(ctx.pep_declaration),
            "discharges": None if ctx.discharges is None else [self._plain_dis(d) for d in ctx.discharges],
            "decided_at": ctx.decided_at, "now": ctx.now,
        }
        result = self._compute(od, inputs)
        return self._base(PRESENT, version, content={
            "inputs": inputs, "result": result, "digest": digest_over(result, canonical),
        })

    def check(self, section, *, verify_sig, canonical):
        if section["status"] != PRESENT:
            return []
        content = section["content"]
        findings: list[dict] = []
        if digest_over(content["result"], canonical) != content["digest"]:
            findings.append(_finding("digest-mismatch", "stored result digest does not match its result"))
        if _spec(self.module):
            if self._compute(importlib.import_module(self.module), content["inputs"]) != content["result"]:
                findings.append(_finding("recompute-mismatch", "recomputed discharge differs from the stored result"))
        else:
            findings.append(_finding("recompute-unavailable", f"{self.module} not installed; digest-checked only", NOTE))
        return findings

    @staticmethod
    def _plain_ob(o):
        if isinstance(o, dict):
            return o
        return {"id": o.id, "type": o.type, "mandatory": o.mandatory, "deadline_s": o.deadline_s}

    @staticmethod
    def _plain_decl(d):
        if isinstance(d, dict):
            return d
        return {"pep": d.pep, "supports": sorted(d.supports), "unsupported": sorted(d.unsupported)}

    @staticmethod
    def _plain_dis(x):
        return x if isinstance(x, dict) else {"obligation_id": x.obligation_id, "at": x.at}

    @staticmethod
    def _compute(od, inputs):
        obs = [od.Obligation(o["id"], o["type"], o.get("mandatory", True), o.get("deadline_s")) for o in inputs["obligations"]]
        decl = od.Declaration(inputs["declaration"]["pep"],
                              frozenset(inputs["declaration"].get("supports", [])),
                              frozenset(inputs["declaration"].get("unsupported", [])))
        admitted = od.admit(obs, decl)
        out = {
            "admission": admitted.status.value,
            "may_permit": admitted.may_permit,
            "determinations": [{"obligation_id": d.obligation.id, "verdict": d.verdict.value} for d in admitted.determinations],
        }
        if inputs["discharges"] is not None and inputs["decided_at"] is not None and inputs["now"] is not None:
            dis = [od.Discharge(d["obligation_id"], d["at"]) for d in inputs["discharges"]]
            settled = od.settle(admitted, dis, decided_at=inputs["decided_at"], now=inputs["now"])
            out["settlement"] = settled.status.value
            out["settlement_ok"] = settled.ok
        return out


# --------------------------------------------------------------------------- #
# oversight-certificate (attestation)
# --------------------------------------------------------------------------- #

class OversightCertificate(Component):
    key = "oversight-certificate"
    module = "oversight_certificate"
    role = "attestation"
    attests = "that a qualified human exercised meaningful oversight"

    def build(self, ctx, *, sign, canonical, scheme, allowed):
        available, version, reason = self.probe(allowed)
        if not available:
            return self._base(ABSENT, reason=reason or "component not installed")
        if ctx.oversight_certificate is None:
            return self._base(PRESENT_NO_INPUT, version, reason="no oversight certificate supplied")
        oc = importlib.import_module(self.module)
        value = ctx.oversight_certificate
        if _is_envelope(value):
            envelope = value
        else:
            cert = self._coerce_cert(oc, value)
            envelope = oc.issue(cert, canonicalize=canonical, sign=sign, keyid="").to_dict()
        now = ctx.oversight_now or ctx.now
        return self._base(PRESENT, version, content={"envelope": envelope, "now": now})

    def check(self, section, *, verify_sig, canonical):
        if section["status"] != PRESENT:
            return []
        content = section["content"]
        envelope = content["envelope"]
        if _spec(self.module):
            oc = importlib.import_module(self.module)
            now = content.get("now")
            if now is None:
                return [_finding("no-verification-time", "oversight verification needs a reference time; none was recorded")]
            report = oc.verify(envelope, canonicalize=canonical, verify_sig=verify_sig, now=now)
            findings = [_finding(f.code, f.detail) for f in report.findings]
            findings.append(_finding("independence", report.independence.value, NOTE))
            return findings
        findings = [] if _dsse_signature_ok(envelope, verify_sig) else [_finding("bad-signature", "sub-envelope signature did not verify")]
        findings.append(_finding("native-verifier-unavailable", f"{self.module} not installed; checked DSSE signature only", NOTE))
        return findings

    @staticmethod
    def _coerce_cert(oc, value):
        if not isinstance(value, dict):
            return value
        human = None
        if value.get("human"):
            h = value["human"]
            human = oc.Human(h["id"], h["qualification"], h.get("credential_not_after"))
        assistance = None
        if value.get("assistance"):
            a = value["assistance"]
            assistance = oc.Assistance(oc.Aid(a["aid"]), a.get("system", ""), a.get("same_model_family"))
        return oc.OversightCertificate(
            id=value["id"], action=value["action"], disposition=oc.Disposition(value["disposition"]),
            at=value["at"], basis=value.get("basis", ""), evidence=tuple(value.get("evidence", ())),
            human=human, escalated_to=value.get("escalated_to"), assistance=assistance,
        )


# --------------------------------------------------------------------------- #
# governance-certification (attestation — verify-only consume; no mint here)
# --------------------------------------------------------------------------- #

class GovernanceCertification(Component):
    key = "governance-certification"
    module = "governance_certification.verify"
    role = "attestation"
    attests = "the composed five-pillar certificate that the action was grounded, overseen, enforced, intact and legitimate"

    def probe(self, allowed):
        if allowed is not None and self.key not in allowed:
            return False, None, "excluded by caller"
        if not _spec(self.module):
            return False, None, None
        return True, _version("governance_certification"), None

    def build(self, ctx, *, sign, canonical, scheme, allowed):
        if allowed is not None and self.key not in allowed:
            return self._base(ABSENT, reason="excluded by caller")
        available, version, reason = self.probe(allowed)
        if ctx.governance_certification is None:
            status = PRESENT_NO_INPUT if available else ABSENT
            return self._base(status, version if available else None,
                              reason="no pre-minted certificate supplied" if available else (reason or "component not installed"))
        return self._base(PRESENT, version, content={"envelope": ctx.governance_certification})

    def check(self, section, *, verify_sig, canonical):
        if section["status"] != PRESENT:
            return []
        envelope = section["content"]["envelope"]
        if _spec(self.module):
            gc = importlib.import_module(self.module)
            report = gc.verify(envelope, verify_sig=verify_sig)
            return [_finding(f["code"], f["detail"]) for f in report["findings"]]
        findings = [] if _dsse_signature_ok(envelope, verify_sig) else [_finding("bad-signature", "sub-envelope signature did not verify")]
        findings.append(_finding("native-verifier-unavailable", "governance_certification not installed; checked DSSE signature only", NOTE))
        return findings


# --------------------------------------------------------------------------- #
# 5d+nd grounding resolver
# --------------------------------------------------------------------------- #

class FiveDnDGrounding(Component):
    key = "5d-nd"
    module = "five_d_nd"
    role = "grounding"
    attests = "the versum span the decision rests on, addressed in the 5d+nd scheme"

    def build(self, ctx, *, sign, canonical, scheme, allowed):
        if allowed is not None and self.key not in allowed:
            return self._base(ABSENT, reason="excluded by caller")
        available, version, reason = self.probe(allowed)
        if ctx.grounding_ref is None:
            status = PRESENT_NO_INPUT if available else ABSENT
            return self._base(status, version if available else None,
                              reason="no grounding reference supplied" if available else (reason or "component not installed"))
        wrapped = ctx.grounding_ref
        ref = wrapped.get("ref", wrapped) if isinstance(wrapped, dict) else wrapped
        ref_scheme = wrapped.get("scheme", "5d+nd") if isinstance(wrapped, dict) else "5d+nd"
        content: dict[str, Any] = {"scheme": ref_scheme, "ref": ref, "resolvable": False, "resolver": "stub"}
        if available:
            fd = importlib.import_module(self.module)
            content["digest"] = fd.digest(ref)
            content["validated"] = bool(fd.validate(ref))
        else:
            content["digest"] = {"sha256": sha256_hex(canonical(ref))}
            content["validated"] = None
        return self._base(PRESENT, version if available else None, content=content)

    def check(self, section, *, verify_sig, canonical):
        if section["status"] != PRESENT:
            return []
        content = section["content"]
        ref = content["ref"]
        findings: list[dict] = []
        if _spec(self.module):
            fd = importlib.import_module(self.module)
            if fd.digest(ref) != content["digest"]:
                findings.append(_finding("digest-mismatch", "grounding ref digest does not match"))
            if content.get("validated") is True and not fd.validate(ref):
                findings.append(_finding("ref-invalid", "grounding ref no longer validates as 5d+nd"))
        else:
            if {"sha256": sha256_hex(canonical(ref))} != content["digest"]:
                findings.append(_finding("digest-mismatch", "grounding ref digest does not match"))
            findings.append(_finding("validator-unavailable", f"{self.module} not installed; digest-checked only", NOTE))
        findings.append(_finding("resolve-stubbed", "5d+nd resolve() is an upstream stub; the span is referenced, not dereferenced", NOTE))
        return findings


REGISTRY: list[Component] = [
    GovernanceCertification(),
    EnforcementPosture(),
    OversightCertificate(),
    EffectReconciliation(),
    NormFreshness(),
    ObligationDischarge(),
    FiveDnDGrounding(),
]

BY_KEY = {c.key: c for c in REGISTRY}

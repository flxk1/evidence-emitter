---
name: evidence-emitter
description: >-
  Emit a signed, offline-verifiable governance-evidence package proving what
  governance was applied to an action or piece of work, and verify such a package
  offline. It composes whichever loomground assurance components are installed
  (enforcement posture, effect reconciliation, norm freshness, obligation
  discharge, oversight certificate, governance certification, 5d-nd) into one
  DSSE / in-toto statement whose subject is digest-bound; absent components are
  marked absent, never faked. It attests a compliance-fleet decision or a
  privacy-shield scan report. The default signer is a clearly-labelled dev HMAC
  key with zero authenticity; a production Ed25519 signer takes host-supplied key
  material — no key is ever minted or embedded. Triggers on "prove this was
  governed", "emit a governance certificate", "make an audit-evidence package",
  "verify this evidence package", "attest this decision".
governance:
  grade: L1
  actions:
    - { kind: emit, risk: low }
    - { kind: verify, risk: low }
  reserved:
    - { kind: sign_with_a_production_key, by: host }
  prohibited:
    - mint_or_embed_a_real_signing_key
    - present_a_dev_signed_package_as_production
    - fabricate_an_absent_component_section
  obligations:
    - absent_components_marked_not_faked
    - dev_signer_flagged_non_production_on_every_verdict
    - subject_digest_bound_to_the_inlined_body
    - verify_runs_fully_offline
  redress:
    - { kind: reverify_from_source, by: any_verifier, overturn: true }
  budget: { usd: 1, iters: 20 }
  on-boundary: report-not-repair
---

# evidence-emitter

Implemented in the `evidence_emitter` package: `emit(subject, ...) ->
EvidencePackage` and `verify(package) -> VerdictReport`, plus the `evidence-emit`
and `evidence-verify` CLIs. The subject accepts an a2a-compliance decision or a
privacy-shield `ScanReport`; the package composes the installed assurance
components (absent ones marked, not faked) and the pluggable `Signer` contract is
described in the README. Production signing takes host key material; the default
dev signer has zero authenticity and is flagged on every verdict.

<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 flxk1 -->
# Subjects, components, and module layout

## The package shape

The package is one DSSE-signed in-toto Statement, and the library ships the
offline verifier that re-checks it. The emitter wraps the assurance components;
it reimplements none of them — each component's own logic is called where the
component is installed, and a generic DSSE or digest check stands in where it is
absent.

## What it attests

The emitter certifies the work of other capabilities. Two subject shapes are
recognised structurally, without importing their packages
(`src/evidence_emitter/subjects.py`):

- an **a2a-compliance decision/directive** — a control `Message` (a `verb`,
  `from`/`to` parties, an `authority`) or a `SteerRuling` (a `decision`, a
  `kind`, a `reason`);
- a **privacy-shield egress decision** — a `ScanReport` (a `mode`, a
  `destination`, `all_allowed`, `documents`).

A subject is passed as its object or its `to_dict()` form. `normalize()` yields a
kind, a stable name, an action class, and a plain-dict body. The body is
digest-bound and inlined into the package, so the package is self-contained: a
verifier re-derives the digest from the body it carries.

## The components it composes

Each component contributes one section. A present component with a supplied
input contributes a real section; a present component with no input, and an
absent or caller-excluded one, contribute a section marked as such — a
fabricated section is never emitted.

| Component | Module probed | Role | Contribution | Offline re-check |
|---|---|---|---|---|
| governance-certification | `governance_certification.verify` | attestation | embeds a pre-minted five-pillar certificate; this package mints none | the component's `verify`, else a generic DSSE signature check |
| oversight-certificate | `oversight_certificate` | attestation | issues or embeds a human-oversight certificate | the component's `verify`, else a generic DSSE signature check |
| enforcement-posture | `enforcement_posture` | attestation | attests which controls were in force over the evidence window | the component's `verify`, else a generic DSSE signature check |
| effect-reconciliation | `effect_reconciliation` | computation | reconciles granted permissions against observed effects | recompute from retained inputs, and a digest check |
| norm-freshness | `norm_freshness` | computation | assesses whether enforced rules still match their sources | recompute from retained inputs, and a digest check |
| obligation-discharge | `obligation_discharge` | computation | admits and settles duties attached to the permit | recompute from retained inputs, and a digest check |
| 5d-nd | `five_d_nd` | grounding | digest-binds the versum span the decision rests on | re-digest and re-validate the reference |

Attestation components embed a DSSE sub-envelope signed by the same signer;
computation components embed their inputs, result, and a digest; the grounding
section embeds a scheme, a reference, and a digest.

Registration order is `REGISTRY` in `src/evidence_emitter/components.py`;
`BY_KEY` maps a component key to its handler for verification.

## Module layout

```
src/evidence_emitter/
  canonical.py    canonical bytes, digests, the DSSE pre-authentication encoding
  signer.py       the signing seam: DevSigner, Ed25519Signer, Ed25519Verifier
  subjects.py     normalize an a2a decision / a ScanReport into a bound subject
  components.py   the assurance components and how each is re-checked offline
  package.py      emit()
  verify.py       verify()
  cli.py          evidence-emit / evidence-verify
```

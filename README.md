# evidence-emitter

A governance evidence exporter for ctrl-plane agents. An agent emits a
verifiable, offline-checkable package proving what governance it applied to an
action or a piece of work, and anyone can re-check that package later from its
bytes and a verifier alone.

The package composes the loomground assurance components into one DSSE-signed
in-toto Statement and ships an offline verifier. It wraps those components; it
does not reimplement them. Each component is optional and probed independently,
so the package degrades to whatever is installed and marks the rest absent.

## Install

From the `loomground-plugins` marketplace (publication pending):

```
/plugin marketplace add flxk1/loomground-plugins
/plugin install evidence-emitter@loomground
```

Directly from GitHub, with pip:

```
pip install "git+https://github.com/flxk1/evidence-emitter.git"
```

Base install has zero hard dependencies. Optional extras:

- `pip install -e .[canonical]` — `rfc8785` (RFC 8785 JSON canonicalization; a
  stdlib approximation is used when absent)
- `pip install -e .[ed25519]` — `cryptography` (production Ed25519 signing/verification)
- `pip install -e .[assurance]` — the loomground assurance components this package
  composes, when present
- `pip install -e .[dev]` — pytest + the above, for running the test suite

## What it attests

The emitter certifies the work of other capabilities. Two subject shapes are
recognised structurally, without importing their packages:

- an **a2a-compliance decision/directive** — a control `Message` (a `verb`,
  `from`/`to` parties, an `authority`) or a `SteerRuling` (a `decision`, a
  `kind`, a `reason`);
- a **privacy-shield egress decision** — a `ScanReport` (a `mode`, a
  `destination`, `all_allowed`, `documents`).

A subject is passed as its object or its `to_dict()` form. The subject is
digest-bound and inlined into the package, so the package is self-contained: a
verifier re-derives the digest from the body it carries.

## API

```python
from evidence_emitter import emit, verify, EvidenceContext, DevSigner

package = emit(
    subject,                     # an a2a-compliance decision or a privacy-shield ScanReport
    components=None,             # optional allowlist of component keys; others are marked absent
    signer=DevSigner(),          # default; a production signer supplies its own key
    context=EvidenceContext(...) # the governance inputs each present component attests
)

report = verify(package)         # offline re-check
report.ok                        # bool
report.summary()                 # one-line human summary
```

`emit(subject, *, kind=None, components=None, signer=None, context=None, issued_at=None) -> EvidencePackage`

`verify(package, *, signer=None) -> VerdictReport`

`EvidencePackage.to_dict()` is the DSSE envelope; `EvidencePackage.from_dict()`
reads one back.

## CLI

```
evidence-emit   <subject.json> [--kind KIND] [--context context.json] [--components a,b] [-o out.json]
evidence-verify <package.json>
```

Both default to the non-production dev signer. Production signing keys are
supplied to the library API, never on a command line.

## The components it composes

Each component contributes one section. A present component with a supplied
input contributes a real section; a present component with no input, and an
absent or caller-excluded one, contribute a section marked as such — never a
fabricated one.

| Component | Role | Contribution | Offline re-check |
|---|---|---|---|
| governance-certification | attestation | embeds a pre-minted five-pillar certificate (this package does not mint one) | the component's `verify`, else a generic DSSE signature check |
| oversight-certificate | attestation | issues or embeds a human-oversight certificate | the component's `verify`, else a generic DSSE signature check |
| enforcement-posture | attestation | attests which controls were in force over the evidence window | the component's `verify`, else a generic DSSE signature check |
| effect-reconciliation | computation | reconciles granted permissions against observed effects | recompute from retained inputs, and a digest check |
| norm-freshness | computation | assesses whether enforced rules still match their sources | recompute from retained inputs, and a digest check |
| obligation-discharge | computation | admits and settles duties attached to the permit | recompute from retained inputs, and a digest check |
| 5d-nd | grounding | digest-binds the versum span the decision rests on | re-digest and re-validate the reference |

Attestation components embed a DSSE sub-envelope signed by the same signer;
computation components embed their inputs, result, and a digest; the grounding
section embeds a scheme, a reference, and a digest.

## Signing

Signing key material is reserved. This package never generates, embeds, or
hardcodes a private key.

- `DevSigner` (the default) is a non-production stand-in: an HMAC under a shared
  key published in the source. It round-trips and detects tampering, so emit and
  verify work with no key management, but it authenticates nothing — anyone can
  reproduce its signature. It reports `production=False`, and `verify` surfaces
  that on every report.
- `Ed25519Signer` / `Ed25519Verifier` carry a real signature over an Ed25519 key
  the host supplies (`from_private_pem` / `from_public_pem`). Generating and
  holding that key is a host step outside this package.

A `Signer` is any object with `key_id`, `algorithm`, `production`, `sign`,
`verify`, and `descriptor`.

## What verification proves

`verify` trusts only the package bytes and the verifier. It re-checks the
top-level DSSE signature and canonical form, re-derives the subject digest from
the inlined body, and re-checks every present section through its component's own
verifier where installed and a generic DSSE check otherwise. Absent and no-input
sections are reported and never counted against the verdict; a tampered package
fails; a package signed by the dev signer verifies but is reported as
non-production.

## Relationship to RVND

The evidence attests the governance an agent applied. It imports no `rvnd.*`
module and depends on no RVND runtime. An RVND deployment can consume a package,
but the package neither requires nor references one.

## Honest limits

- **The dev signer is not production.** It provides tamper-evidence, not
  authenticity. A package that matters is signed with a host-held Ed25519 key.
- **5d+nd `resolve()` is an upstream stub.** The grounding section references and
  digest-binds a span; it does not dereference it. Every grounding section
  records `resolver: "stub"` and `resolvable: false`.
- **Partiality is per component.** With none of the assurance components
  installed, the package is a minimal self-describing shell — a signed subject
  with every component marked absent. It still emits and still verifies.
- **governance-certification is consumed verify-only.** The five-pillar
  certificate is minted upstream; this package embeds a supplied one and
  delegates verification. It does not compose the five pillars itself.
- **Canonicalization.** RFC 8785 (JCS) is used when available; otherwise a
  sort-keys/compact-separators stdlib approximation is used and named in the
  package. A verifier missing the scheme the package names fails closed rather
  than hashing with a different one.

## Layout

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

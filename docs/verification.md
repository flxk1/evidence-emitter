<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 flxk1 -->
# What verification proves, and its limits

## What `verify` re-checks

`verify` trusts only the package bytes and the verifier. It re-checks the
top-level DSSE signature and canonical form, re-derives the subject digest from
the inlined body, and re-checks every present section through its component's
own verifier where installed and a generic DSSE check otherwise. Absent and
no-input sections are reported and are never counted against the verdict; a
tampered package fails; a package signed by the dev signer verifies and is
reported as non-production.

`VerdictReport.ok` is the conjunction of three things: the top-level signature
verified, the report carries no structural finding, and every `present` section
came back without a `fail`-severity finding.

## Relationship to hosts

The evidence attests the governance an agent applied. It imports no host
module and depends on no host runtime. A deployment can consume a package;
the package neither requires nor references one.

## Honest limits

- **The dev signer is not production.** It provides tamper-evidence, not
  authenticity. A package that matters is signed with a host-held Ed25519 key.
- **5d+nd `resolve()` is an upstream stub.** The grounding section references and
  digest-binds a span; it does not dereference it. Every grounding section
  records `resolver: "stub"` and `resolvable: false`, and verification emits a
  `resolve-stubbed` note.
- **Partiality is per component.** With none of the assurance components
  installed, the package is a minimal self-describing shell — a signed subject
  with every component marked absent. It still emits and still verifies.
- **governance-certification is consumed verify-only.** The five-pillar
  certificate is minted upstream; this package embeds a supplied one and
  delegates verification. It does not compose the five pillars itself.
- **Canonicalization.** RFC 8785 (JCS) is used when available; otherwise a
  sort-keys/compact-separators stdlib approximation is used and named in the
  package as `jcs-stdlib`. A verifier missing the scheme the package names fails
  closed rather than hashing with a different one.

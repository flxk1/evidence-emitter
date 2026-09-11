<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 flxk1 -->
# Signing seam and CLI

## Signing

Signing key material is reserved. This package generates, embeds, and hardcodes
no private key.

- `DevSigner` (the default) is a non-production stand-in: HMAC-SHA256 under a
  shared key published in `src/evidence_emitter/signer.py`. It round-trips and
  detects tampering, so emit and verify work without key management, but it
  authenticates nothing — anyone can reproduce its signature. Its `key_id` is
  `dev-insecure-shared-key` and it reports `production=False`, which `verify`
  surfaces on every report.
- `Ed25519Signer` / `Ed25519Verifier` carry a real signature over an Ed25519 key
  the host supplies (`from_private_pem` / `from_public_pem`, both requiring the
  `ed25519` extra). Generating and holding that key is a host step outside this
  package. Both report `production=True`.

A `Signer` is any object with `key_id`, `algorithm`, `production`, `sign`,
`verify`, and `descriptor` — the `Signer` Protocol in
`src/evidence_emitter/signer.py`.

## CLI

```
evidence-emit   <subject.json> [--kind KIND] [--context context.json] [--components a,b] [-o out.json]
evidence-verify <package.json>
```

`evidence-emit` reads the subject JSON, optionally an `EvidenceContext` field
object via `--context`, and writes the DSSE envelope to `--out` or stdout.
`evidence-verify` prints `VerdictReport.summary()`, then one line per section
with its findings; it exits 0 when the report is `ok` and 1 otherwise.

Both default to the dev signer. A production signing key is supplied to the
library API, never on a command line.

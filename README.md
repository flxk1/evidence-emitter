<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 flxk1 -->
# evidence-emitter

**What governance was applied here, and can anyone re-check it?**

Compose loomground assurance components into one signed, offline-verifiable governance evidence package.

## Problem

A governance decision rests on the emitting agent's word. Evidence that re-checks offline, from bytes alone, replaces that word.

## Install

```
pip install "evidence-emitter @ git+https://github.com/flxk1/evidence-emitter@v0.1.0"
```

Import name `evidence_emitter`; zero required dependencies. Channels and extras: [docs/install.md](docs/install.md).

## Usage

```python
from evidence_emitter import emit, verify, EvidenceContext, DevSigner

decision = {"verb": "issue-directive", "from": "compliance-agent", "to": "maker-7",
            "authority": {"basis": "role", "role": "policy-compliance"}}
ctx = EvidenceContext(
    posture={"engine": "claude-code", "controls": [{"name": "PreToolUse", "enabled": True}],
             "effective_from": "2026-09-10T09:00:00Z"},
    evidence_window={"log_id": "session-42", "start": "2026-09-10T09:00:00Z",
                     "end": "2026-09-10T11:00:00Z", "digest": "00" * 32},
    posture_algorithm="hmac-sha256")

report = verify(emit(decision, signer=DevSigner(), context=ctx))
print(report.ok)
print(report.summary())
```

## Example

```
in : the snippet above, with enforcement-posture and effect-reconciliation installed
out: True
     OK — DEV signer (non-production); present=['enforcement-posture'] no-input=['effect-reconciliation'] absent=['governance-certification', 'oversight-certificate', 'norm-freshness', 'obligation-discharge', '5d-nd']
```

## Interface

- `emit(subject, *, kind=None, components=None, signer=None, context=None, issued_at=None) -> EvidencePackage`
- `verify(package, *, signer=None) -> VerdictReport` — `.ok` `.present` `.no_input` `.absent` `.sections` `.summary()`
- `EvidenceContext` carries the per-component inputs · `EvidencePackage.to_dict()` / `.from_dict()` is the DSSE envelope · `PREDICATE_TYPE`
- `normalize(subject, kind=None) -> NormalizedSubject` · `A2A_DECISION` · `SCANREPORT` · subjects and components: [docs/components.md](docs/components.md)
- `DevSigner`, `Ed25519Signer`, `Ed25519Verifier`, the `Signer` protocol, the `evidence-emit` / `evidence-verify` CLI: [docs/signing.md](docs/signing.md)
- What a verdict proves, and its limits: [docs/verification.md](docs/verification.md)

## Family

Assurance artifacts. Composes the installed loomground assurance components — governance-certification, oversight-certificate, enforcement-posture, effect-reconciliation, norm-freshness, obligation-discharge, 5d-nd — each an optional extra probed independently at emit time, absent ones marked. Each is optional to this package, which degrades to a signed subject shell. Consumed by ctrl-plane hosts. Catalogue: [CATALOGUE.json](https://github.com/flxk1/loomground/blob/main/CATALOGUE.json).

## Status

0.1.0 · 21 tests · Python >=3.11 · zero required dependencies

## License

Apache-2.0 — [LICENSES/Apache-2.0.txt](LICENSES/Apache-2.0.txt).

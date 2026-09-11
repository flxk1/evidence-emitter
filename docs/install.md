<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 flxk1 -->
# Install channels and extras

## pip

```
pip install "evidence-emitter @ git+https://github.com/flxk1/evidence-emitter@v0.1.0"
```

Import name `evidence_emitter`. `requires-python = ">=3.11"`; `dependencies = []`
(`pyproject.toml`), so the base install resolves offline once the wheel is local.

## Plugin marketplace

Publication of the `loomground-plugins` marketplace is pending. Once it is
published:

```
/plugin marketplace add flxk1/loomground-plugins
/plugin install evidence-emitter@loomground
```

## Optional extras

Each extra is declared in `pyproject.toml` under
`[project.optional-dependencies]`.

| Extra | Dependencies | Effect |
|---|---|---|
| `canonical` | `rfc8785>=0.1` | RFC 8785 (JCS) canonicalization. Without it a stdlib sort-keys/compact-separators approximation is used and named in the package as `jcs-stdlib`. |
| `ed25519` | `cryptography>=41` | `Ed25519Signer` / `Ed25519Verifier`. Key material is supplied by the host. |
| `assurance` | `governance-certification`, `oversight-certificate`, `enforcement-posture`, `effect-reconciliation`, `norm-freshness`, `obligation-discharge`, `5d-nd` | The assurance components the package composes. Any subset may be installed; each is probed independently at emit time. |
| `dev` | `pytest>=7`, `rfc8785>=0.1`, `cryptography>=41`, `enforcement-posture` and `effect-reconciliation` at pinned git commits | The test environment. The two pinned components are the ones `tests/fixtures.py` exercises for real; neither is on PyPI, so the pin is a full-SHA git source. |

`.github/workflows/ci.yml` installs `.[dev]` and runs `pytest` on Python 3.11
and 3.14.

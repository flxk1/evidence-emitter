# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 flxk1
"""evidence-emitter — a governance evidence exporter for ctrl-plane agents.

An agent emits a verifiable, offline-checkable package proving what governance it
applied to an action or a piece of work. The package composes whichever
loomground assurance components are installed — governance-certification,
oversight-certificate, enforcement-posture, effect-reconciliation, norm-freshness,
obligation-discharge, and the 5d+nd grounding resolver — into one DSSE-signed
in-toto Statement, and ships an offline verifier. Components are optional and
probed independently: the package degrades to whatever is present and marks the
rest absent. It attests an agent's own governance and depends on no host runtime.
"""
from ._version import __version__
from .components import EvidenceContext
from .package import EvidencePackage, PREDICATE_TYPE, emit
from .signer import DevSigner, Ed25519Signer, Ed25519Verifier, Signer
from .subjects import A2A_DECISION, SCANREPORT, NormalizedSubject, normalize
from .verify import SectionVerdict, VerdictReport, verify

__all__ = [
    "__version__",
    "emit",
    "verify",
    "EvidencePackage",
    "VerdictReport",
    "SectionVerdict",
    "EvidenceContext",
    "Signer",
    "DevSigner",
    "Ed25519Signer",
    "Ed25519Verifier",
    "NormalizedSubject",
    "normalize",
    "A2A_DECISION",
    "SCANREPORT",
    "PREDICATE_TYPE",
]

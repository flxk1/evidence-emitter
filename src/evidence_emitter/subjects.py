"""Normalize an attested subject into a stable, JSON-able body.

The emitter attests the work of other capabilities. Two shapes are recognised
without importing their packages — structurally, by duck-typing — so the emitter
stays decoupled from what it certifies:

* an **a2a-compliance decision/directive**: a control ``Message`` (``verb``,
  ``from_``/``to`` parties, ``authority``) or a ``SteerRuling`` (``decision``,
  ``kind``, ``reason``);
* a **privacy-shield egress decision**: a ``ScanReport`` (``mode``,
  ``destination``, ``all_allowed``, ``documents``).

Each yields a :class:`NormalizedSubject` — a kind, a stable name, an action
class, and a plain-dict body the package digest-binds.
"""
from __future__ import annotations

import dataclasses
from dataclasses import dataclass
from enum import Enum
from typing import Any

A2A_DECISION = "a2a-compliance-decision"
SCANREPORT = "privacy-shield-scanreport"


@dataclass(frozen=True)
class NormalizedSubject:
    kind: str
    name: str
    action_class: str
    body: dict


def _to_plain(value: Any) -> Any:
    """Best-effort JSON-able projection of an object graph.

    Prefers a ``to_dict()`` the source defines; otherwise unpacks dataclasses,
    enums, sets, and mappings. Trailing ``_`` on field names (``from_``) is
    stripped so the body reads as the wire shape.
    """
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Enum):
        return value.value
    if hasattr(value, "to_dict") and callable(value.to_dict):
        return _to_plain(value.to_dict())
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {k.rstrip("_"): _to_plain(v) for k, v in dataclasses.asdict(value).items()}
    if isinstance(value, dict):
        return {str(k).rstrip("_"): _to_plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        seq = sorted(value) if isinstance(value, (set, frozenset)) else value
        return [_to_plain(v) for v in seq]
    return str(value)


def _has(body: dict, *keys: str) -> bool:
    return all(k in body for k in keys)


def _classify(body: dict) -> str | None:
    if _has(body, "verb", "from", "to") or _has(body, "verb", "authority"):
        return A2A_DECISION
    if _has(body, "decision", "kind", "reason"):
        return A2A_DECISION
    if _has(body, "mode", "destination") and ("all_allowed" in body or "documents" in body):
        return SCANREPORT
    return None


def normalize(subject: Any, *, kind: str | None = None) -> NormalizedSubject:
    """Normalize a supported subject. ``kind`` overrides structural detection."""
    body = _to_plain(subject)
    if not isinstance(body, dict):
        raise TypeError("subject must project to a JSON object (dict)")

    resolved = kind or _classify(body)
    if resolved is None:
        raise ValueError(
            "unrecognised subject: expected an a2a-compliance decision/directive "
            "or a privacy-shield ScanReport (pass kind= to override detection)"
        )

    if resolved == A2A_DECISION:
        if "decision" in body:  # SteerRuling
            name = f"a2a:steer:{body.get('kind', 'unknown')}"
            action_class = f"a2a.steer.{body.get('decision', 'unknown')}"
        else:  # Message
            name = f"a2a:{body.get('verb', 'unknown')}:{body.get('id', 'unknown')}"
            action_class = f"a2a.{body.get('verb', 'unknown')}"
    elif resolved == SCANREPORT:
        name = f"privacy-shield:{body.get('mode', 'unknown')}:{body.get('destination', 'unknown')}"
        action_class = "privacy-shield.egress"
    else:  # pragma: no cover - resolved is constrained above
        raise ValueError(f"unsupported subject kind {resolved!r}")

    return NormalizedSubject(kind=resolved, name=name, action_class=action_class, body=body)

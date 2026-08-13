"""On-demand assertion-fidelity audit.

Printed by ``bauble audit``. Complements ``bauble coverage``: coverage answers
"which requirements have assertions?", the audit answers "does each assertion
faithfully cover the requirement it claims to cover?".

Like coverage, the audit is live — it reads the registry and corpus at run
time, so it can never drift and nothing is committed.
"""

from __future__ import annotations

from collections import Counter

from bauble.registry import Registry
from bauble.requirements import Requirement, load_requirements

__all__ = ["audit_text"]

_AUDIT_META = ("preconditions", "stimulus", "expected_observables")


def _metadata_status(registry: Registry, assertion_id: str) -> str:
    """full / partial / none — whether the assertion carries the audit chain."""
    try:
        a = registry.get(assertion_id)
    except KeyError:
        return "missing"
    present = sum(1 for field in _AUDIT_META if getattr(a, field))
    if present == len(_AUDIT_META):
        return "full"
    if present == 0:
        return "none"
    return "partial"


def audit_text(
    registry: Registry,
    requirements: list[Requirement] | None = None,
) -> str:
    """Render the fidelity audit as plain text."""
    if requirements is None:
        requirements = load_requirements()
    lines: list[str] = []

    # Cross-RFC links: requirement covered by an assertion from another RFC.
    lines.append("Cross-RFC coverage links (requirement rfc != assertion rfc):")
    cross: list[tuple[str, int, str, int]] = []
    for req in requirements:
        for cid in req.covered_by:
            try:
                a = registry.get(cid)
            except KeyError:
                continue
            if a.rfc != req.rfc:
                cross.append((req.id, req.rfc, cid, a.rfc))
    if cross:
        for req_id, req_rfc, cid, a_rfc in cross:
            lines.append(f"  {req_id} (rfc {req_rfc}) <- {cid} (rfc {a_rfc})")
    else:
        lines.append("  (none)")

    lines.append("")
    lines.append("Per requirement:")
    meta_counter: Counter[str] = Counter()
    for req in sorted(requirements, key=lambda r: (r.rfc, r.id)):
        statuses = [_metadata_status(registry, cid) for cid in req.covered_by]
        if not req.covered_by:
            meta_counter["uncovered"] += 1
            lines.append(f"  {req.id}  [{req.test_class.value}/{req.severity.value}]  UNCOVERED")
            continue
        worst = "full" if all(s == "full" for s in statuses) else (
            "none" if all(s == "none" for s in statuses) else "partial"
        )
        meta_counter[worst] += 1
        detail = ", ".join(
            f"{cid}[{s}]" for cid, s in zip(req.covered_by, statuses, strict=True)
        )
        lines.append(
            f"  {req.id}  [{req.test_class.value}/{req.severity.value}]  "
            f"audit-chain={worst}  {detail}"
        )

    lines.append("")
    lines.append("Rollup (by covering-assertion metadata):")
    for key in ("full", "partial", "none", "uncovered", "missing"):
        if meta_counter[key]:
            lines.append(f"  {key:<10} {meta_counter[key]}")
    return "\n".join(lines) + "\n"

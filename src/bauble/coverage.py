"""On-demand coverage facts from the assertion registry and requirements corpus.

Rendered by ``bauble coverage``. The registry is the single source of truth for
what the suite covers, so coverage numbers live nowhere in the committed docs:
this command prints them live and can never drift or go stale.

The requirements corpus (one TOML per RFC) makes conformance measurable: a
requirement with no covering assertion is a surfaced gap, not a silent omission.
"""

from __future__ import annotations

import enum
from collections import Counter

from bauble.registry import Registry
from bauble.requirements import Requirement, load_requirements

__all__ = ["CoverageState", "coverage_text", "requirement_state"]


class CoverageState(str, enum.Enum):
    """Per-requirement coverage state.

    COVERED — every obligation (or, without obligations, the requirement's
    own covered_by) has at least one resolving assertion.
    PARTIALLY_COVERED — at least one but not all obligations are covered.
    UNCOVERED — no obligation (and no requirement-level link) is covered.
    """

    COVERED = "covered"
    PARTIALLY_COVERED = "partial"
    UNCOVERED = "uncovered"


def requirement_state(req: Requirement, assertion_ids: set[str]) -> CoverageState:
    """Classify one requirement by its obligations (or covered_by)."""
    if req.obligations:
        covered = [o for o in req.obligations if any(cid in assertion_ids for cid in o.covered_by)]
        if len(covered) == len(req.obligations):
            return CoverageState.COVERED
        if covered:
            return CoverageState.PARTIALLY_COVERED
        return CoverageState.UNCOVERED
    if any(cid in assertion_ids for cid in req.covered_by):
        return CoverageState.COVERED
    return CoverageState.UNCOVERED


def coverage_text(
    registry: Registry,
    requirements: list[Requirement] | None = None,
) -> str:
    """Render raw coverage facts as plain text.

    Facts only — no conformance verdicts. Verdicts require a live server run,
    so they come from ``bauble run --reporter summary``, not from the registry.
    """
    assertions = registry.all()
    assertion_ids = {a.id for a in assertions}
    if requirements is None:
        requirements = load_requirements()

    lines: list[str] = [f"Total assertions: {len(assertions)}"]

    by_class = Counter(a.test_class.value for a in assertions)
    lines.append("By test class: " + ", ".join(f"{k}={by_class[k]}" for k in sorted(by_class)))

    by_severity = Counter(a.severity.value for a in assertions)
    lines.append(
        "By severity: "
        + ", ".join(f"{k}={by_severity[k]}" for k in ("must", "should", "may") if by_severity[k])
    )

    by_layer = Counter(a.layer.value for a in assertions)
    lines.append(
        "By layer: "
        + ", ".join(
            f"{k}={by_layer[k]}" for k in ("wire", "semantic", "capability") if by_layer[k]
        )
    )

    by_profile = Counter(p.value for a in assertions for p in a.profiles)
    lines.append(
        "By profile: "
        + ", ".join(
            f"{k}={by_profile[k]}" for k in ("interop", "core", "extended") if by_profile[k]
        )
    )

    by_category = Counter(a.category.value for a in assertions)
    lines.append("By category: " + ", ".join(f"{k}={by_category[k]}" for k in sorted(by_category)))

    by_rfc = Counter(a.rfc for a in assertions)
    lines.append("")
    lines.append(f"RFCs with assertions: {len(by_rfc)}")
    lines.append("Per RFC:")
    for rfc in sorted(by_rfc):
        lines.append(f"  RFC {rfc:<6} {by_rfc[rfc]}")

    if requirements:
        _render_requirements(lines, requirements, assertion_ids)

    lines.append("")
    lines.append("Conformance verdicts require a server: run `bauble run --reporter summary`.")
    return "\n".join(lines) + "\n"


def _render_requirements(
    lines: list[str],
    requirements: list[Requirement],
    assertion_ids: set[str],
) -> None:
    """Append per-RFC coverage states, the partial detail, and the gaps."""
    by_rfc: dict[int, list[Requirement]] = {}
    for req in requirements:
        by_rfc.setdefault(req.rfc, []).append(req)

    lines.append("")
    lines.append("Requirements coverage (RFC corpus):")
    rollup: Counter[CoverageState] = Counter()
    for rfc in sorted(by_rfc):
        states = Counter(requirement_state(r, assertion_ids) for r in by_rfc[rfc])
        rollup.update(states)
        lines.append(
            f"  RFC {rfc:<6} "
            f"{states[CoverageState.COVERED]} covered / "
            f"{states[CoverageState.PARTIALLY_COVERED]} partial / "
            f"{states[CoverageState.UNCOVERED]} uncovered"
        )
    lines.append(
        f"  total: {rollup[CoverageState.COVERED]} covered / "
        f"{rollup[CoverageState.PARTIALLY_COVERED]} partial / "
        f"{rollup[CoverageState.UNCOVERED]} uncovered"
    )

    partials = [
        r
        for r in requirements
        if requirement_state(r, assertion_ids) is CoverageState.PARTIALLY_COVERED
    ]
    if partials:
        lines.append("")
        lines.append(f"Partially covered requirements ({len(partials)}):")
        for req in sorted(partials, key=lambda r: (r.rfc, r.id)):
            lines.append(f"  {req.id}  RFC {req.rfc} §{req.section}  {req.text}")
            for obligation in req.obligations:
                covered = any(cid in assertion_ids for cid in obligation.covered_by)
                lines.append(
                    f"    {'ok ' if covered else 'gap'} {obligation.id}: {obligation.text}"
                )

    gaps = [
        r for r in requirements if requirement_state(r, assertion_ids) is not CoverageState.COVERED
    ]
    if gaps:
        lines.append("")
        lines.append(f"Not fully covered requirements ({len(gaps)}):")
        for req in gaps:
            lines.append(
                f"  {req.id}  RFC {req.rfc} §{req.section}  "
                f"[{req.test_class.value}/{req.severity.value}]  {req.text}"
            )

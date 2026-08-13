"""On-demand coverage facts from the assertion registry and requirements corpus.

Rendered by ``bauble coverage``. The registry is the single source of truth for
what the suite covers, so coverage numbers live nowhere in the committed docs:
this command prints them live and can never drift or go stale.

The requirements corpus (one TOML per RFC) makes conformance measurable: a
requirement with no covering assertion is a surfaced gap, not a silent omission.
"""

from __future__ import annotations

from collections import Counter

from bauble.registry import Registry
from bauble.requirements import Requirement, load_requirements

__all__ = ["coverage_text"]


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
    """Append per-RFC requirements coverage and the uncovered-requirement gaps."""
    by_rfc: dict[int, list[Requirement]] = {}
    for req in requirements:
        by_rfc.setdefault(req.rfc, []).append(req)

    lines.append("")
    lines.append("Requirements coverage (RFC corpus):")
    for rfc in sorted(by_rfc):
        reqs = by_rfc[rfc]
        covered = sum(1 for r in reqs if any(cid in assertion_ids for cid in r.covered_by))
        lines.append(f"  RFC {rfc:<6} {covered}/{len(reqs)} requirements covered")

    gaps = [r for r in requirements if not any(cid in assertion_ids for cid in r.covered_by)]
    if gaps:
        lines.append("")
        lines.append(f"Uncovered requirements ({len(gaps)}):")
        for req in gaps:
            lines.append(
                f"  {req.id}  RFC {req.rfc} §{req.section}  "
                f"[{req.test_class.value}/{req.severity.value}]  {req.text}"
            )

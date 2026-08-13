"""coverage: registry-derived facts rendered as text."""

from __future__ import annotations

import re

from bauble.coverage import coverage_text
from bauble.model import Severity, TestClass
from bauble.registry import default_registry
from bauble.requirements import Obligation, Requirement, load_requirements
from bauble.suites import discover

discover()  # register every suite's assertions into the default registry


def test_coverage_total_matches_registry() -> None:
    registry = default_registry()
    text = coverage_text(registry)
    total = len(registry.all())
    assert f"Total assertions: {total}" in text


def test_coverage_per_rfc_sums_to_total() -> None:
    registry = default_registry()
    text = coverage_text(registry)
    counts = [int(n) for n in re.findall(r"^  RFC \d+\s+(\d+)$", text, re.MULTILINE)]
    assert sum(counts) == len(registry.all())


def test_coverage_lists_distinct_rfc_count() -> None:
    registry = default_registry()
    text = coverage_text(registry)
    distinct = {a.rfc for a in registry.all()}
    assert f"RFCs with assertions: {len(distinct)}" in text


def test_requirements_corpus_loads_rfc4511() -> None:
    requirements = load_requirements()
    assert requirements, "requirements corpus is empty"
    assert any(r.rfc == 4511 for r in requirements)


def test_coverage_reports_requirements_section() -> None:
    text = coverage_text(default_registry())
    assert "Requirements coverage (RFC corpus):" in text
    assert "RFC 4511 " in text  # the seed RFC has requirements


def test_corpus_covered_by_links_all_resolve() -> None:
    """Every covered_by id in the corpus must name a registered assertion.

    Catches drift: if an assertion id changes, its requirement link breaks.
    """
    registry = default_registry()
    assertion_ids = {a.id for a in registry.all()}
    broken = [
        cid for req in load_requirements() for cid in req.covered_by if cid not in assertion_ids
    ]
    broken += [
        cid
        for req in load_requirements()
        for ob in req.obligations
        for cid in ob.covered_by
        if cid not in assertion_ids
    ]
    assert not broken, f"covered_by references unknown assertions: {broken}"


def test_uncovered_requirements_are_listed() -> None:
    """A requirement whose covered_by is empty must surface under gaps."""
    text = coverage_text(default_registry())
    # 4511:4.1.10:1 (Referral MUST contain >=1 URI) has no covering assertion.
    assert "4511:4.1.10:1" in text
    assert "Not fully covered requirements" in text


def test_partially_covered_requirements_are_listed() -> None:
    """A requirement with partly-covered obligations must show as partial."""
    text = coverage_text(default_registry())
    # 4528:3:3 covers Delete only; Add/Modify/ModifyDN obligations are gaps.
    assert "Partially covered requirements" in text
    assert "4528:3:3" in text
    assert "gap 4528:3:3:add" in text
    assert "ok  4528:3:3:delete" in text


def _req(id_: str, covered_by: list[str], obligations: list[tuple[str, list[str]]]) -> Requirement:
    return Requirement(
        id=id_,
        rfc=4511,
        section="§x",
        severity=Severity.MUST,
        test_class=TestClass.A,
        text="test",
        covered_by=tuple(covered_by),
        obligations=tuple(
            Obligation(id=oid, text="ob", covered_by=tuple(cb)) for oid, cb in obligations
        ),
    )


def test_requirement_state_no_obligations() -> None:
    from bauble.coverage import CoverageState, requirement_state

    ids = {"a1"}
    assert requirement_state(_req("r1", ["a1"], []), ids) is CoverageState.COVERED
    assert requirement_state(_req("r2", ["missing"], []), ids) is CoverageState.UNCOVERED


def test_requirement_state_with_obligations() -> None:
    from bauble.coverage import CoverageState, requirement_state

    ids = {"a1", "a2"}
    full = _req("r1", [], [("o1", ["a1"]), ("o2", ["a2"])])
    assert requirement_state(full, ids) is CoverageState.COVERED
    partial = _req("r2", [], [("o1", ["a1"]), ("o2", ["missing"])])
    assert requirement_state(partial, ids) is CoverageState.PARTIALLY_COVERED
    none_ = _req("r3", [], [("o1", ["missing"]), ("o2", ["nope"])])
    assert requirement_state(none_, ids) is CoverageState.UNCOVERED

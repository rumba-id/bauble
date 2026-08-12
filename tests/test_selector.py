"""Selector: AND-across, OR-within filtering."""

from __future__ import annotations

from bauble.model import Assertion, Category, Profile, Severity, TestClass
from bauble.selector import Selector


def _assertion(
    assertion_id: str,
    *,
    rfc: int = 4511,
    profiles: frozenset[Profile] = frozenset({Profile.BASE}),
    category: Category = Category.PROTOCOL,
    severity: Severity = Severity.MUST,
    test_class: TestClass = TestClass.A,
    section: str = "§4.2",
) -> Assertion:
    return Assertion(
        id=assertion_id,
        rfc=rfc,
        section=section,
        category=category,
        severity=severity,
        test_class=test_class,
        profiles=profiles,
        text=assertion_id,
    )


def test_empty_selector_matches_all() -> None:
    selector = Selector()
    assert selector.matches(_assertion("a"))


def test_or_within_rfc_dimension() -> None:
    selector = Selector(rfcs=frozenset({4511, 4515}))
    assert selector.matches(_assertion("1", rfc=4511))
    assert selector.matches(_assertion("2", rfc=4515))
    assert not selector.matches(_assertion("3", rfc=4512))


def test_and_across_dimensions() -> None:
    selector = Selector(rfcs=frozenset({4511}), profiles=frozenset({Profile.BASE}))
    assert selector.matches(_assertion("1", rfc=4511, profiles=frozenset({Profile.BASE})))
    assert not selector.matches(_assertion("2", rfc=4511, profiles=frozenset({Profile.STANDARD})))
    assert not selector.matches(_assertion("3", rfc=4512, profiles=frozenset({Profile.BASE})))


def test_exclude() -> None:
    selector = Selector(exclude=frozenset({"x"}))
    assert not selector.matches(_assertion("x"))
    assert selector.matches(_assertion("y"))


def test_scenario_filter() -> None:
    selector = Selector(scenarios=frozenset({"bind"}))
    assert selector.matches(_assertion("1", rfc=4511, section="§4.2.1"))
    assert not selector.matches(_assertion("2", rfc=4511, section="§4.5.1"))

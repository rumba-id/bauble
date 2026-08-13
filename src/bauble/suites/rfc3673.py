"""RFC 3673 — All Operational Attributes (the '+' selector)."""

from __future__ import annotations

from bauble.model import Category, Layer, Profile, Result, Severity, Status, TestClass
from bauble.session import SCOPE_BASE_OBJECT, Session
from bauble.suites._base import assertion
from bauble.suites._helpers import TEST_BASE, bind_admin

_CORE = frozenset({Profile.CORE})

# Operational attributes commonly returned for "+"; at least one must appear.
_OPERATIONAL = ("entryUUID", "createTimestamp", "modifyTimestamp", "creatorsName")

_ALICE = f"uid=alice,{TEST_BASE}"


@assertion(
    id="3673.2.1",
    rfc=3673,
    section="§2",
    category=Category.DATA_MODEL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_CORE,
    layer=Layer.SEMANTIC,
    text="Requesting '+' returns all operational attributes.",
    strategy="Search an entry requesting ['+']; at least one operational attribute must be present.",
    preconditions="Admin bound; seed entry uid=alice exists.",
    stimulus="Search uid=alice requesting only '+' (operational attributes).",
    expected_observables="At least one operational attribute present in the result.",
)
def plus_returns_operational(session: Session) -> Result:
    bind_admin(session)
    outcome, entries = session.search(_ALICE, SCOPE_BASE_OBJECT, "(objectClass=*)", ["+"])
    if outcome.result_code != 0 or not entries:
        return Result("3673.2.1", Status.FAIL, detail=f"search failed: {outcome.result_code}")
    attrs = entries[0].attributes
    if not any(name in attrs for name in _OPERATIONAL):
        return Result(
            "3673.2.1",
            Status.FAIL,
            detail=f"no operational attributes returned for '+': keys={sorted(attrs)}",
        )
    return Result("3673.2.1", Status.PASS)


@assertion(
    id="3673.2.2",
    rfc=3673,
    section="§2",
    category=Category.DATA_MODEL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_CORE,
    layer=Layer.SEMANTIC,
    text="Requesting '*' and '+' together returns both user and operational attributes.",
    strategy="Search an entry requesting ['*', '+']; a user attribute (cn) and an operational attribute must both be present.",
    preconditions="Admin bound; seed entry uid=alice exists.",
    stimulus="Search uid=alice requesting both '*' and '+'.",
    expected_observables="Both a user attribute (cn) and an operational attribute present in the result.",
)
def star_plus_returns_both(session: Session) -> Result:
    outcome, entries = session.search(_ALICE, SCOPE_BASE_OBJECT, "(objectClass=*)", ["*", "+"])
    if outcome.result_code != 0 or not entries:
        return Result("3673.2.2", Status.FAIL, detail=f"search failed: {outcome.result_code}")
    attrs = entries[0].attributes
    if "cn" not in attrs:
        return Result(
            "3673.2.2",
            Status.FAIL,
            detail=f"user attribute 'cn' missing: keys={sorted(attrs)}",
        )
    if not any(name in attrs for name in _OPERATIONAL):
        return Result(
            "3673.2.2",
            Status.FAIL,
            detail=f"no operational attributes returned for '* +': keys={sorted(attrs)}",
        )
    return Result("3673.2.2", Status.PASS)

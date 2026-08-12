"""RFC 4511 §4.10 — Compare operation."""

from __future__ import annotations

from bauble.model import Category, Profile, Result, Severity, Status, TestClass
from bauble.session import Session
from bauble.suites._base import assertion

_BASE = frozenset({Profile.BASE})
_ALICE = "uid=alice,ou=people,dc=bauble,dc=test"


@assertion(
    id="4511.4.10.1",
    rfc=4511,
    section="§4.10",
    category=Category.PROTOCOL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_BASE,
    text="Compare a matching value returns compareTrue (6).",
    strategy="Compare uid=alice attribute uid with value alice; expect 6.",
)
def compare_true(session: Session) -> Result:
    outcome = session.compare(_ALICE, "uid", "alice")
    return Result(
        "4511.4.10.1",
        Status.PASS if outcome.result_code == 6 else Status.FAIL,
        detail=None if outcome.result_code == 6 else f"expected 6, got {outcome.result_code}",
    )


@assertion(
    id="4511.4.10.2",
    rfc=4511,
    section="§4.10",
    category=Category.PROTOCOL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_BASE,
    text="Compare a non-matching value returns compareFalse (5).",
    strategy="Compare uid=alice attribute uid with value bob; expect 5.",
)
def compare_false(session: Session) -> Result:
    outcome = session.compare(_ALICE, "uid", "bob")
    return Result(
        "4511.4.10.2",
        Status.PASS if outcome.result_code == 5 else Status.FAIL,
        detail=None if outcome.result_code == 5 else f"expected 5, got {outcome.result_code}",
    )


@assertion(
    id="4511.4.10.3",
    rfc=4511,
    section="§4.10",
    category=Category.PROTOCOL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_BASE,
    text="Compare with a missing attribute returns noSuchAttribute (16).",
    strategy="Compare uid=alice on a non-existent attribute; expect 16.",
)
def compare_missing_attribute(session: Session) -> Result:
    outcome = session.compare(_ALICE, "mail", "x")
    return Result(
        "4511.4.10.3",
        Status.PASS if outcome.result_code == 16 else Status.FAIL,
        detail=None if outcome.result_code == 16 else f"expected 16, got {outcome.result_code}",
    )


@assertion(
    id="4511.4.10.4",
    rfc=4511,
    section="§4.10",
    category=Category.PROTOCOL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_BASE,
    text="Compare a non-existent entry returns noSuchObject (32).",
    strategy="Compare on a DN that does not exist; expect 32.",
)
def compare_no_such_object(session: Session) -> Result:
    outcome = session.compare("uid=nobody,ou=people,dc=bauble,dc=test", "uid", "x")
    return Result(
        "4511.4.10.4",
        Status.PASS if outcome.result_code == 32 else Status.FAIL,
        detail=None if outcome.result_code == 32 else f"expected 32, got {outcome.result_code}",
    )

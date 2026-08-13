"""RFC 4518 — Internationalized String Preparation."""

from __future__ import annotations

from bauble.model import Category, Profile, Result, Severity, Status, TestClass
from bauble.session import SCOPE_WHOLE_SUBTREE, Session
from bauble.suites._base import assertion

_INTEROP = frozenset({Profile.INTEROP})
_ROOT = "dc=bauble,dc=test"


@assertion(
    id="4518.2.1",
    rfc=4518,
    section="§2",
    category=Category.DATA_MODEL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_INTEROP,
    text="A case-insensitive match on uid ignores casing differences.",
    strategy="Search for (uid=ALICE); expect alice is returned (caseIgnoreMatch).",
    preconditions="Seed entry uid=alice exists.",
    stimulus="Subtree search with the filter (uid=ALICE).",
    expected_observables="uid=alice is returned.",
)
def case_insensitive_match(session: Session) -> Result:
    outcome, entries = session.search(_ROOT, SCOPE_WHOLE_SUBTREE, "(uid=ALICE)")
    if outcome.result_code == 0 and len(entries) == 1:
        return Result("4518.2.1", Status.PASS)
    return Result(
        "4518.2.1",
        Status.FAIL,
        detail=f"expected alice matched case-insensitively, got {len(entries)}",
    )


@assertion(
    id="4518.2.2",
    rfc=4518,
    section="§2.6",
    category=Category.DATA_MODEL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_INTEROP,
    text="caseIgnoreMatch treats leading/trailing/multiple consecutive spaces as insignificant.",
    strategy="Search (cn=Alice  Anderson) (extra inner spaces); expect alice matched.",
    preconditions="Seed entry uid=alice exists.",
    stimulus="Subtree search with the filter (uid= alice ) (surrounding spaces).",
    expected_observables="uid=alice is returned (spaces are insignificant).",
)
def case_insensitive_space_handling(session: Session) -> Result:
    outcome, entries = session.search(_ROOT, SCOPE_WHOLE_SUBTREE, "(uid= alice )")
    if outcome.result_code == 0 and any(e.dn.startswith("uid=alice") for e in entries):
        return Result("4518.2.2", Status.PASS)
    return Result(
        "4518.2.2",
        Status.FAIL,
        detail="extra-space assertion did not match alice",
    )

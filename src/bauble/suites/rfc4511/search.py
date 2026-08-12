"""RFC 4511 §4.5 — Search operation."""

from __future__ import annotations

from bauble.model import Category, Profile, Result, Severity, Status, TestClass
from bauble.session import SCOPE_BASE_OBJECT, SCOPE_SINGLE_LEVEL, SCOPE_WHOLE_SUBTREE, Session
from bauble.suites._base import assertion

_BASE = frozenset({Profile.BASE})
_ROOT = "dc=bauble,dc=test"
_PEOPLE = "ou=people,dc=bauble,dc=test"


@assertion(
    id="4511.4.5.1",
    rfc=4511,
    section="§4.5",
    category=Category.PROTOCOL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_BASE,
    text="Base-object search returns the base entry.",
    strategy="Search dc=bauble,dc=test with base scope; expect 1 entry, result 0.",
)
def search_base_scope(session: Session) -> Result:
    outcome, entries = session.search(_ROOT, SCOPE_BASE_OBJECT, "(objectClass=*)")
    if outcome.result_code == 0 and len(entries) == 1:
        return Result("4511.4.5.1", Status.PASS)
    return Result(
        "4511.4.5.1",
        Status.FAIL,
        detail=f"expected 1 entry / code 0, got {len(entries)} / {outcome.result_code}",
    )


@assertion(
    id="4511.4.5.2",
    rfc=4511,
    section="§4.5",
    category=Category.PROTOCOL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_BASE,
    text="Single-level search returns direct children.",
    strategy="Search ou=people with one-level scope; expect at least 2 entries (alice, bob).",
)
def search_one_level(session: Session) -> Result:
    outcome, entries = session.search(_PEOPLE, SCOPE_SINGLE_LEVEL, "(objectClass=*)")
    if outcome.result_code == 0 and len(entries) >= 2:
        return Result("4511.4.5.2", Status.PASS)
    return Result(
        "4511.4.5.2",
        Status.FAIL,
        detail=f"expected >=2 entries / code 0, got {len(entries)} / {outcome.result_code}",
    )


@assertion(
    id="4511.4.5.3",
    rfc=4511,
    section="§4.5",
    category=Category.PROTOCOL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_BASE,
    text="Subtree search with a filter returns matching entries.",
    strategy="Search dc=bauble,dc=test subtree for (uid=alice); expect exactly 1.",
)
def search_subtree_filter(session: Session) -> Result:
    outcome, entries = session.search(_ROOT, SCOPE_WHOLE_SUBTREE, "(uid=alice)")
    if outcome.result_code == 0 and len(entries) == 1:
        return Result("4511.4.5.3", Status.PASS)
    return Result(
        "4511.4.5.3",
        Status.FAIL,
        detail=f"expected 1 entry / code 0, got {len(entries)} / {outcome.result_code}",
    )


@assertion(
    id="4511.4.5.4",
    rfc=4511,
    section="§4.5",
    category=Category.PROTOCOL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_BASE,
    text="Search with a non-existent base returns noSuchObject (32).",
    strategy="Search a DN that does not exist; expect 32.",
)
def search_no_such_object(session: Session) -> Result:
    outcome, _ = session.search("dc=nonexistent", SCOPE_BASE_OBJECT, "(objectClass=*)")
    return Result(
        "4511.4.5.4",
        Status.PASS if outcome.result_code == 32 else Status.FAIL,
        detail=None if outcome.result_code == 32 else f"expected 32, got {outcome.result_code}",
    )


@assertion(
    id="4511.4.5.5",
    rfc=4511,
    section="§4.5",
    category=Category.PROTOCOL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_BASE,
    text="The matchedDN field is set when a search base does not exist (32).",
    strategy="Search a non-existent base; expect 32 with matchedDN.",
)
def search_matched_dn(session: Session) -> Result:
    outcome, _ = session.search("ou=nonexistent,dc=bauble,dc=test", SCOPE_BASE_OBJECT, "(objectClass=*)")
    ok = outcome.result_code == 32 and len(outcome.matched_dn) > 0
    return Result(
        "4511.4.5.5",
        Status.PASS if ok else Status.FAIL,
        detail=None if ok else f"code={outcome.result_code} matchedDN={outcome.matched_dn}",
    )

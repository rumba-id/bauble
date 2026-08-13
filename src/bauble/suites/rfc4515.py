"""RFC 4515 — String Representation of LDAP Search Filters."""

from __future__ import annotations

from bauble.model import Category, Profile, Result, Severity, Status, TestClass
from bauble.session import SCOPE_WHOLE_SUBTREE, Session
from bauble.suites._base import assertion

_INTEROP = frozenset({Profile.INTEROP})
_ROOT = "dc=bauble,dc=test"


@assertion(
    id="4515.3.1",
    rfc=4515,
    section="§3",
    category=Category.DATA_MODEL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_INTEROP,
    text="An AND filter returns entries matching both criteria.",
    strategy="Search with (&(uid=alice)(sn=Anderson)); expect 1 entry.",
)
def and_filter(session: Session) -> Result:
    outcome, entries = session.search(
        _ROOT,
        SCOPE_WHOLE_SUBTREE,
        "(&(uid=alice)(sn=Anderson))",
    )
    if outcome.result_code == 0 and len(entries) == 1:
        return Result("4515.3.1", Status.PASS)
    return Result(
        "4515.3.1",
        Status.FAIL,
        detail=f"expected 1 entry, got {len(entries)} / {outcome.result_code}",
    )


@assertion(
    id="4515.3.2",
    rfc=4515,
    section="§3",
    category=Category.DATA_MODEL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_INTEROP,
    text="An OR filter returns entries matching either criterion.",
    strategy="Search with (|(uid=alice)(uid=bob)); expect 2 entries.",
)
def or_filter(session: Session) -> Result:
    outcome, entries = session.search(
        _ROOT,
        SCOPE_WHOLE_SUBTREE,
        "(|(uid=alice)(uid=bob))",
    )
    if outcome.result_code == 0 and len(entries) == 2:
        return Result("4515.3.2", Status.PASS)
    return Result(
        "4515.3.2",
        Status.FAIL,
        detail=f"expected 2 entries, got {len(entries)} / {outcome.result_code}",
    )


@assertion(
    id="4515.3.3",
    rfc=4515,
    section="§3",
    category=Category.DATA_MODEL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_INTEROP,
    text="A NOT filter excludes matching entries.",
    strategy="Search with (!(uid=alice)); expect alice is NOT in results.",
)
def not_filter(session: Session) -> Result:
    outcome, entries = session.search(
        _ROOT,
        SCOPE_WHOLE_SUBTREE,
        "(!(uid=alice))",
    )
    dns = {e.dn.lower() for e in entries}
    if outcome.result_code == 0 and "uid=alice,ou=people,dc=bauble,dc=test" not in dns:
        return Result("4515.3.3", Status.PASS)
    return Result(
        "4515.3.3", Status.FAIL, detail="alice unexpectedly present in NOT-filter results"
    )


@assertion(
    id="4515.3.4",
    rfc=4515,
    section="§3",
    category=Category.DATA_MODEL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_INTEROP,
    text="An equality filter matches the exact attribute value.",
    strategy="Search with (uid=alice); expect exactly alice.",
)
def equality_filter(session: Session) -> Result:
    outcome, entries = session.search(_ROOT, SCOPE_WHOLE_SUBTREE, "(uid=alice)")
    if outcome.result_code == 0 and len(entries) == 1 and entries[0].dn.startswith("uid=alice"):
        return Result("4515.3.4", Status.PASS)
    return Result("4515.3.4", Status.FAIL, detail=f"expected alice, got {len(entries)} entries")


@assertion(
    id="4515.3.5",
    rfc=4515,
    section="§3",
    category=Category.DATA_MODEL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_INTEROP,
    text="A substring filter with initial component matches leading substrings.",
    strategy="Search with (cn=Alice*); expect Alice Anderson.",
)
def substring_initial(session: Session) -> Result:
    outcome, entries = session.search(_ROOT, SCOPE_WHOLE_SUBTREE, "(cn=Alice*)")
    dns = {e.dn for e in entries}
    if outcome.result_code == 0 and any("uid=alice" in dn for dn in dns):
        return Result("4515.3.5", Status.PASS)
    return Result(
        "4515.3.5", Status.FAIL, detail=f"substring initial failed: {len(entries)} entries"
    )


@assertion(
    id="4515.3.6",
    rfc=4515,
    section="§3",
    category=Category.DATA_MODEL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_INTEROP,
    text="A substring filter with any component matches interior substrings.",
    strategy="Search with (cn=*Anderson*); expect Alice Anderson.",
)
def substring_any(session: Session) -> Result:
    outcome, entries = session.search(_ROOT, SCOPE_WHOLE_SUBTREE, "(cn=*Anderson*)")
    if outcome.result_code == 0 and any(e.dn.startswith("uid=alice") for e in entries):
        return Result("4515.3.6", Status.PASS)
    return Result("4515.3.6", Status.FAIL, detail="substring any failed")


@assertion(
    id="4515.3.7",
    rfc=4515,
    section="§3",
    category=Category.DATA_MODEL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_INTEROP,
    text="A present filter matches entries where the attribute exists.",
    strategy="Search with (cn=*); expect entries with cn present.",
)
def present_filter(session: Session) -> Result:
    outcome, entries = session.search(_ROOT, SCOPE_WHOLE_SUBTREE, "(cn=*)")
    if outcome.result_code == 0 and len(entries) >= 2:
        return Result("4515.3.7", Status.PASS)
    return Result(
        "4515.3.7", Status.FAIL, detail=f"present filter expected >=2, got {len(entries)}"
    )


@assertion(
    id="4515.3.8",
    rfc=4515,
    section="§3",
    category=Category.DATA_MODEL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_INTEROP,
    text="An extensible match with an explicit matching rule applies that rule.",
    strategy="Search (cn:caseIgnoreMatch:=alice anderson); expect alice.",
)
def extensible_match(session: Session) -> Result:
    outcome, entries = session.search(
        _ROOT, SCOPE_WHOLE_SUBTREE, "(cn:caseIgnoreMatch:=alice anderson)"
    )
    if outcome.result_code == 0 and any(e.dn.startswith("uid=alice") for e in entries):
        return Result("4515.3.8", Status.PASS)
    return Result("4515.3.8", Status.FAIL, detail="extensible match failed")

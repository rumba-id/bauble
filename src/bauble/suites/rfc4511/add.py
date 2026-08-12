"""RFC 4511 §4.7 — Add operation."""

from __future__ import annotations

from bauble.model import Category, Profile, Result, Severity, Status, TestClass
from bauble.session import Session
from bauble.suites._base import assertion
from bauble.suites._helpers import bind_admin, cleanup, test_entry_attrs

_INTEROP = frozenset({Profile.INTEROP})


@assertion(
    id="4511.4.7.1",
    rfc=4511,
    section="§4.7",
    category=Category.PROTOCOL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_INTEROP,
    mutates=True,
    text="Add a valid entry returns success.",
    strategy="Add an inetOrgPerson under ou=people; expect 0; clean up.",
)
def add_valid(session: Session) -> Result:
    bind_admin(session)
    dn = "uid=test-add-1,ou=people,dc=bauble,dc=test"
    outcome = session.add(dn, test_entry_attrs("test-add-1"))
    result = Result(
        "4511.4.7.1",
        Status.PASS if outcome.result_code == 0 else Status.FAIL,
        detail=None if outcome.result_code == 0 else f"expected 0, got {outcome.result_code}",
    )
    cleanup(session, dn)
    return result


@assertion(
    id="4511.4.7.2",
    rfc=4511,
    section="§4.7",
    category=Category.PROTOCOL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_INTEROP,
    mutates=True,
    text="Add a duplicate entry returns entryAlreadyExists (68).",
    strategy="Add an entry, then add it again; expect 68; clean up.",
)
def add_duplicate(session: Session) -> Result:
    bind_admin(session)
    dn = "uid=test-add-2,ou=people,dc=bauble,dc=test"
    attrs = test_entry_attrs("test-add-2")
    session.add(dn, attrs)
    outcome = session.add(dn, attrs)
    result = Result(
        "4511.4.7.2",
        Status.PASS if outcome.result_code == 68 else Status.FAIL,
        detail=None if outcome.result_code == 68 else f"expected 68, got {outcome.result_code}",
    )
    cleanup(session, dn)
    return result


@assertion(
    id="4511.4.7.3",
    rfc=4511,
    section="§4.7",
    category=Category.PROTOCOL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_INTEROP,
    mutates=True,
    text="Add with a missing parent returns noSuchObject (32).",
    strategy="Add under a non-existent branch; expect 32.",
)
def add_missing_parent(session: Session) -> Result:
    bind_admin(session)
    dn = "uid=orphan,ou=nonexistent,dc=bauble,dc=test"
    outcome = session.add(dn, test_entry_attrs("orphan"))
    return Result(
        "4511.4.7.3",
        Status.PASS if outcome.result_code == 32 else Status.FAIL,
        detail=None if outcome.result_code == 32 else f"expected 32, got {outcome.result_code}",
    )


@assertion(
    id="4511.4.7.4",
    rfc=4511,
    section="§4.7",
    category=Category.PROTOCOL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_INTEROP,
    mutates=True,
    text="Add violating schema (missing MUST attribute) returns objectClassViolation (65).",
    strategy="Add an inetOrgPerson without the required sn attribute; expect 65.",
)
def add_schema_violation(session: Session) -> Result:
    bind_admin(session)
    dn = "uid=test-add-4,ou=people,dc=bauble,dc=test"
    attrs: dict[str, list[str | bytes]] = {
        "objectClass": ["inetOrgPerson"],
        "cn": ["No Sn"],
        "uid": ["test-add-4"],
    }
    outcome = session.add(dn, attrs)
    result = Result(
        "4511.4.7.4",
        Status.PASS if outcome.result_code == 65 else Status.FAIL,
        detail=None if outcome.result_code == 65 else f"expected 65, got {outcome.result_code}",
    )
    cleanup(session, dn)
    return result


@assertion(
    id="4511.4.7.5",
    rfc=4511,
    section="§4.7",
    category=Category.PROTOCOL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_INTEROP,
    text="The matchedDN field is set when an add fails with noSuchObject (32).",
    strategy="Add under a non-existent parent; expect matchedDN contains the grandparent.",
)
def add_matched_dn(session: Session) -> Result:
    bind_admin(session)
    outcome = session.add(
        "uid=orphan,ou=nonexistent,dc=bauble,dc=test",
        test_entry_attrs("orphan"),
    )
    ok = outcome.result_code == 32 and "dc=bauble,dc=test" in outcome.matched_dn.lower()
    return Result(
        "4511.4.7.5",
        Status.PASS if ok else Status.FAIL,
        detail=None if ok else f"code={outcome.result_code} matchedDN={outcome.matched_dn}",
    )

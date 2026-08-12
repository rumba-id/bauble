"""RFC 4511 §4.8 — Delete operation."""

from __future__ import annotations

from bauble.model import Category, Profile, Result, Severity, Status, TestClass
from bauble.session import Session
from bauble.suites._base import assertion
from bauble.suites._helpers import bind_admin, cleanup, test_entry_attrs

_BASE = frozenset({Profile.BASE})


@assertion(
    id="4511.4.8.1",
    rfc=4511,
    section="§4.8",
    category=Category.PROTOCOL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_BASE,
    mutates=True,
    text="Delete an existing leaf entry returns success.",
    strategy="Add a test entry, then delete it; expect 0.",
)
def delete_leaf(session: Session) -> Result:
    bind_admin(session)
    dn = "uid=test-del-1,ou=people,dc=bauble,dc=test"
    session.add(dn, test_entry_attrs("test-del-1"))
    outcome = session.delete(dn)
    return Result(
        "4511.4.8.1",
        Status.PASS if outcome.result_code == 0 else Status.FAIL,
        detail=None if outcome.result_code == 0 else f"expected 0, got {outcome.result_code}",
    )


@assertion(
    id="4511.4.8.2",
    rfc=4511,
    section="§4.8",
    category=Category.PROTOCOL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_BASE,
    text="Delete a non-existent entry returns noSuchObject (32).",
    strategy="Delete a DN that does not exist; expect 32.",
)
def delete_nonexistent(session: Session) -> Result:
    bind_admin(session)
    outcome = session.delete("uid=nobody,ou=people,dc=bauble,dc=test")
    return Result(
        "4511.4.8.2",
        Status.PASS if outcome.result_code == 32 else Status.FAIL,
        detail=None if outcome.result_code == 32 else f"expected 32, got {outcome.result_code}",
    )


@assertion(
    id="4511.4.8.3",
    rfc=4511,
    section="§4.8",
    category=Category.PROTOCOL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_BASE,
    mutates=True,
    text="Delete an entry with subordinate entries fails.",
    strategy="Add a parent with a child, then try to delete the parent; expect 66.",
)
def delete_with_children(session: Session) -> Result:
    bind_admin(session)
    parent = "ou=test-del-3,ou=people,dc=bauble,dc=test"
    child = "uid=child,ou=test-del-3,ou=people,dc=bauble,dc=test"
    parent_attrs: dict[str, list[str | bytes]] = {
        "objectClass": ["organizationalUnit"],
        "ou": ["test-del-3"],
    }
    session.add(parent, parent_attrs)
    session.add(child, test_entry_attrs("child"))
    outcome = session.delete(parent)
    cleanup(session, child)
    cleanup(session, parent)
    return Result(
        "4511.4.8.3",
        Status.PASS if outcome.result_code == 66 else Status.FAIL,
        detail=None if outcome.result_code == 66 else f"expected 66, got {outcome.result_code}",
    )

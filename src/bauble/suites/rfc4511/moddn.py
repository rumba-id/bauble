"""RFC 4511 §4.9 — Modify DN operation."""

from __future__ import annotations

from bauble.model import Category, Profile, Result, Severity, Status, TestClass
from bauble.session import Session
from bauble.suites._base import assertion
from bauble.suites._helpers import bind_admin, cleanup, test_entry_attrs

_INTEROP = frozenset({Profile.INTEROP})


@assertion(
    id="4511.4.9.1",
    rfc=4511,
    section="§4.9",
    category=Category.PROTOCOL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_INTEROP,
    mutates=True,
    text="ModifyDN (rename RDN) succeeds.",
    strategy="Add a test entry, rename it; expect 0; clean up.",
)
def rename(session: Session) -> Result:
    bind_admin(session)
    dn = "uid=test-moddn-1,ou=people,dc=bauble,dc=test"
    new_dn = "uid=test-moddn-1-renamed,ou=people,dc=bauble,dc=test"
    session.add(dn, test_entry_attrs("test-moddn-1"))
    outcome = session.modify_dn(dn, "uid=test-moddn-1-renamed", delete_old_rdn=True)
    cleanup(session, new_dn)
    return Result(
        "4511.4.9.1",
        Status.PASS if outcome.result_code == 0 else Status.FAIL,
        detail=None if outcome.result_code == 0 else f"expected 0, got {outcome.result_code}",
    )


@assertion(
    id="4511.4.9.2",
    rfc=4511,
    section="§4.9",
    category=Category.PROTOCOL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_INTEROP,
    mutates=True,
    text="ModifyDN to an existing DN returns entryAlreadyExists (68).",
    strategy="Create two entries; rename one to the other's DN; expect 68; clean up.",
)
def rename_to_existing(session: Session) -> Result:
    bind_admin(session)
    target = "uid=target-moddn,ou=people,dc=bauble,dc=test"
    source = "uid=source-moddn,ou=people,dc=bauble,dc=test"
    session.add(target, test_entry_attrs("target-moddn"))
    session.add(source, test_entry_attrs("source-moddn"))
    outcome = session.modify_dn(source, "uid=target-moddn", delete_old_rdn=True)
    cleanup(session, target)
    cleanup(session, source)
    return Result(
        "4511.4.9.2",
        Status.PASS if outcome.result_code == 68 else Status.FAIL,
        detail=None if outcome.result_code == 68 else f"expected 68, got {outcome.result_code}",
    )


@assertion(
    id="4511.4.9.3",
    rfc=4511,
    section="§4.9",
    category=Category.PROTOCOL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_INTEROP,
    mutates=True,
    text="ModifyDN with newSuperior moves an entry to a new parent.",
    strategy="Move an entry from ou=people to dc=bauble,dc=test; expect 0.",
)
def rename_with_new_superior(session: Session) -> Result:
    bind_admin(session)
    dn = "uid=test-move,ou=people,dc=bauble,dc=test"
    new_dn = "uid=test-move,dc=bauble,dc=test"
    session.add(dn, test_entry_attrs("test-move"))
    outcome = session.modify_dn(
        dn,
        "uid=test-move",
        delete_old_rdn=False,
        new_superior="dc=bauble,dc=test",
    )
    cleanup(session, new_dn)
    cleanup(session, dn)
    return Result(
        "4511.4.9.3",
        Status.PASS if outcome.result_code == 0 else Status.FAIL,
        detail=None if outcome.result_code == 0 else f"expected 0, got {outcome.result_code}",
    )

"""RFC 4511 §4.6 — Modify operation."""

from __future__ import annotations

from bauble.model import Category, Profile, Result, Severity, Status, TestClass
from bauble.session import MOD_ADD, MOD_REPLACE, Modification, Session
from bauble.suites._base import assertion
from bauble.suites._helpers import bind_admin, cleanup, test_entry_attrs

_INTEROP = frozenset({Profile.INTEROP})


@assertion(
    id="4511.4.6.1",
    rfc=4511,
    section="§4.6",
    category=Category.PROTOCOL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_INTEROP,
    mutates=True,
    text="Modify (replace) an attribute succeeds.",
    strategy="Add a test entry, replace its cn; expect 0; clean up.",
)
def modify_replace(session: Session) -> Result:
    bind_admin(session)
    dn = "uid=test-mod-1,ou=people,dc=bauble,dc=test"
    session.add(dn, test_entry_attrs("test-mod-1", cn="Original"))
    outcome = session.modify(dn, [Modification(MOD_REPLACE, "cn", ["Modified"])])
    cleanup(session, dn)
    return Result(
        "4511.4.6.1",
        Status.PASS if outcome.result_code == 0 else Status.FAIL,
        detail=None if outcome.result_code == 0 else f"expected 0, got {outcome.result_code}",
    )


@assertion(
    id="4511.4.6.2",
    rfc=4511,
    section="§4.6",
    category=Category.PROTOCOL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_INTEROP,
    mutates=True,
    text="Modify (add value) to an attribute succeeds.",
    strategy="Add a test entry, add a description value; expect 0; clean up.",
)
def modify_add_value(session: Session) -> Result:
    bind_admin(session)
    dn = "uid=test-mod-2,ou=people,dc=bauble,dc=test"
    session.add(dn, test_entry_attrs("test-mod-2"))
    outcome = session.modify(dn, [Modification(MOD_ADD, "description", ["Added"])])
    cleanup(session, dn)
    return Result(
        "4511.4.6.2",
        Status.PASS if outcome.result_code == 0 else Status.FAIL,
        detail=None if outcome.result_code == 0 else f"expected 0, got {outcome.result_code}",
    )


@assertion(
    id="4511.4.6.3",
    rfc=4511,
    section="§4.6",
    category=Category.PROTOCOL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_INTEROP,
    text="Modify a non-existent entry returns noSuchObject (32).",
    strategy="Modify a DN that does not exist; expect 32.",
)
def modify_nonexistent_entry(session: Session) -> Result:
    bind_admin(session)
    outcome = session.modify(
        "uid=nobody,ou=people,dc=bauble,dc=test",
        [Modification(MOD_REPLACE, "cn", ["x"])],
    )
    ok = outcome.result_code == 32
    return Result(
        "4511.4.6.3",
        Status.PASS if ok else Status.FAIL,
        detail=None if ok else f"expected 32, got {outcome.result_code}",
    )

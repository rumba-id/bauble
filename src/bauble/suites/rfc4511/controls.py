"""RFC 4511 §4.1.12 — LDAP Controls."""

from __future__ import annotations

from bauble.model import Category, Layer, Profile, Result, Severity, Status, TestClass
from bauble.session import SCOPE_BASE_OBJECT, Control, Session
from bauble.suites._base import assertion

_INTEROP = frozenset({Profile.INTEROP})


@assertion(
    id="4511.4.1.1",
    rfc=4511,
    section="§4.1.12",
    category=Category.CONTROL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_INTEROP,
    text="An unknown critical control returns unavailableCriticalExtension (12).",
    strategy="Search with a fake OID control marked critical; expect result code 12.",
)
def unknown_critical_control(session: Session) -> Result:
    outcome, _ = session.search(
        "dc=bauble,dc=test",
        SCOPE_BASE_OBJECT,
        "(objectClass=*)",
        controls=(Control(oid="1.2.3.4.5-fake", criticality=True),),
    )
    if outcome.result_code == 12:
        return Result("4511.4.1.1", Status.PASS)
    return Result("4511.4.1.1", Status.FAIL, detail=f"expected 12, got {outcome.result_code}")


@assertion(
    id="4511.4.1.2",
    rfc=4511,
    section="§4.1.12",
    category=Category.CONTROL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_INTEROP,
    text="An unknown non-critical control is ignored and the operation succeeds.",
    strategy="Search with a fake OID control NOT marked critical; expect success.",
    layer=Layer.WIRE,
)
def unknown_non_critical_control(session: Session) -> Result:
    outcome, _ = session.search(
        "dc=bauble,dc=test",
        SCOPE_BASE_OBJECT,
        "(objectClass=*)",
        controls=(Control(oid="1.2.3.4.5-fake", criticality=False),),
    )
    if outcome.result_code == 0:
        return Result("4511.4.1.2", Status.PASS)
    return Result("4511.4.1.2", Status.FAIL, detail=f"expected 0, got {outcome.result_code}")

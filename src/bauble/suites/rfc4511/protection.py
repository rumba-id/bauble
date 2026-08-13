"""RFC 4511 — server protection of operational attributes and objectClass."""

from __future__ import annotations

from bauble.model import Category, Profile, Result, Severity, Status, TestClass
from bauble.session import MOD_DELETE, MOD_REPLACE, Modification, Session
from bauble.suites._base import assertion
from bauble.suites._helpers import bind_admin

_INTEROP = frozenset({Profile.INTEROP})


@assertion(
    id="4511.3.2.1",
    rfc=4511,
    section="§3.2.1",
    category=Category.DATA_MODEL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_INTEROP,
    mutates=True,
    text="The objectClass attribute cannot be removed from an entry.",
    strategy="Try to delete objectClass from an entry via modify; expect an error.",
    preconditions="Admin bound; seed entry uid=alice exists.",
    stimulus="ModifyRequest deleting the objectClass value from uid=alice.",
    expected_observables="ModifyResponse resultCode non-zero (objectClass cannot be removed).",
)
def object_class_cannot_be_removed(session: Session) -> Result:
    bind_admin(session)
    outcome = session.modify(
        "uid=alice,ou=people,dc=bauble,dc=test",
        [Modification(MOD_DELETE, "objectClass", ["inetOrgPerson"])],
    )
    if outcome.result_code != 0:
        return Result("4511.3.2.1", Status.PASS)
    return Result("4511.3.2.1", Status.FAIL, detail=f"expected error, got {outcome.result_code}")


@assertion(
    id="4511.3.2.2",
    rfc=4511,
    section="§3.2.1",
    category=Category.DATA_MODEL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_INTEROP,
    mutates=True,
    text="Operational attributes (createTimestamp) cannot be modified by clients.",
    strategy="Try to modify createTimestamp on an entry; expect an error.",
    preconditions="Admin bound; seed entry uid=alice exists.",
    stimulus="ModifyRequest replacing createTimestamp on uid=alice.",
    expected_observables="ModifyResponse resultCode non-zero (operational attribute is client-read-only).",
)
def operational_attribute_protected(session: Session) -> Result:
    bind_admin(session)
    outcome = session.modify(
        "uid=alice,ou=people,dc=bauble,dc=test",
        [Modification(MOD_REPLACE, "createTimestamp", ["20240101000000Z"])],
    )
    if outcome.result_code != 0:
        return Result("4511.3.2.2", Status.PASS)
    return Result("4511.3.2.2", Status.FAIL, detail=f"expected error, got {outcome.result_code}")

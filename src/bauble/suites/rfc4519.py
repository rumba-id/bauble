"""RFC 4519 — Schema for User Applications."""

from __future__ import annotations

from bauble.model import Category, Profile, Result, Severity, Status, TestClass
from bauble.session import SCOPE_BASE_OBJECT, Session
from bauble.suites._base import assertion

_INTEROP = frozenset({Profile.INTEROP})
_SUBSCHEMA = "cn=Subschema"


def _has_advertised(session: Session, attribute: str, expected: str) -> tuple[bool, str]:
    """Check that ``attribute`` on the subschema contains ``expected``."""
    from bauble.suites._helpers import bind_admin, subschema_dn

    bind_admin(session)
    dn = subschema_dn(session)
    if dn is None:
        return False, "subschemaSubentry not advertised in root DSE"
    outcome, entries = session.search(dn, SCOPE_BASE_OBJECT, "(objectClass=*)", [attribute])
    if outcome.result_code != 0 or not entries:
        return False, f"subschema not found: {outcome.result_code}"
    values = entries[0].attributes.get(attribute, [])
    for value in values:
        if expected in str(value):
            return True, ""
    return False, f"{expected} not found in {attribute}"


@assertion(
    id="4519.2.1",
    rfc=4519,
    section="§2",
    category=Category.SCHEMA,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_INTEROP,
    text="The inetOrgPerson object class is advertised in the subschema.",
    strategy="Search cn=Subschema for objectClasses containing 'inetOrgPerson'.",
)
def inet_org_person_advertised(session: Session) -> Result:
    ok, detail = _has_advertised(session, "objectClasses", "inetOrgPerson")
    return Result("4519.2.1", Status.PASS if ok else Status.FAIL, detail=detail or None)


@assertion(
    id="4519.2.2",
    rfc=4519,
    section="§2",
    category=Category.SCHEMA,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_INTEROP,
    text="The organizationalUnit object class is advertised in the subschema.",
    strategy="Search cn=Subschema for objectClasses containing 'organizationalUnit'.",
)
def organizational_unit_advertised(session: Session) -> Result:
    ok, detail = _has_advertised(session, "objectClasses", "organizationalUnit")
    return Result("4519.2.2", Status.PASS if ok else Status.FAIL, detail=detail or None)


@assertion(
    id="4519.2.3",
    rfc=4519,
    section="§2",
    category=Category.SCHEMA,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_INTEROP,
    text="The dc (domainComponent) attribute type is advertised in the subschema.",
    strategy="Search cn=Subschema for attributeTypes containing 'dc'.",
)
def domain_component_advertised(session: Session) -> Result:
    ok, detail = _has_advertised(session, "attributeTypes", "dc")
    return Result("4519.2.3", Status.PASS if ok else Status.FAIL, detail=detail or None)

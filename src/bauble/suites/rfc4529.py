"""RFC 4529 — Requesting Attributes by Object Class."""

from bauble.model import Category, Profile, Result, Severity, Status, TestClass
from bauble.session import SCOPE_BASE_OBJECT, Session
from bauble.suites._base import assertion
from bauble.suites._helpers import TEST_BASE

_STANDARD = frozenset({Profile.STANDARD})

_OC_AD_LISTS_FEATURE_OID = "1.3.6.1.4.1.4203.1.5.2"


@assertion(
    id="4529.3.1",
    rfc=4529,
    section="§3",
    category=Category.PROTOCOL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_STANDARD,
    text="'@person' in attribute list returns all attributes of the person object class.",
    strategy="Search with '@person', verify cn, sn, objectClass are present. No operational attrs.",
    requires_features=(_OC_AD_LISTS_FEATURE_OID,),
)
def at_objectclass_returns_attrs(session: Session) -> Result:
    dn = f"uid=alice,{TEST_BASE}"
    outcome, entries = session.search(dn, SCOPE_BASE_OBJECT, "(objectClass=*)", ["@person"])
    if outcome.result_code != 0 or not entries:
        return Result("4529.3.1", Status.FAIL, detail="search with @person failed or no entry")
    attrs = entries[0].attributes
    # person class has cn, sn, userPassword, telephoneNumber, seeAlso, description
    # (via inetOrgPerson: also uid, mail, etc. — but @person should only give person attrs)
    # Note: objectClass is always implicitly included per RFC 4512
    for required in ("cn", "sn", "objectClass"):
        if required not in attrs:
            return Result(
                "4529.3.1",
                Status.FAIL,
                detail=f"expected {required!r} in @person response, got {list(attrs.keys())}",
            )
    # entryUUID is operational — should NOT appear in @person
    if "entryUUID" in attrs:
        return Result("4529.3.1", Status.FAIL, detail="@person included operational attribute")
    return Result("4529.3.1", Status.PASS)


@assertion(
    id="4529.3.2",
    rfc=4529,
    section="§3",
    category=Category.PROTOCOL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_STANDARD,
    text="Unrecognized object class OID is treated as unrecognized attribute description.",
    strategy="Search with '@1.2.3.4.5.9999' — no error, just no extra attributes.",
    requires_features=(_OC_AD_LISTS_FEATURE_OID,),
)
def unknown_objectclass_treated_as_unknown_attr(session: Session) -> Result:
    dn = f"uid=alice,{TEST_BASE}"
    outcome, _ = session.search(dn, SCOPE_BASE_OBJECT, "(objectClass=*)", ["@1.2.3.4.5.9999"])
    # Server should not error; treat as unrecognized attribute.
    if outcome.result_code != 0:
        return Result(
            "4529.3.2",
            Status.FAIL,
            detail=f"unrecognized @OID caused error: {outcome.result_code}",
        )
    return Result("4529.3.2", Status.PASS)

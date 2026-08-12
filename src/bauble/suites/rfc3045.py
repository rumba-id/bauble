"""RFC 3045 — Vendor Information in the LDAP root DSE."""

from bauble.model import Category, Profile, Result, Severity, Status, TestClass
from bauble.session import SCOPE_BASE_OBJECT, Session
from bauble.suites._base import assertion

_CORE = frozenset({Profile.CORE})


@assertion(
    id="3045.2.1",
    rfc=3045,
    section="§2.1",
    category=Category.DATA_MODEL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_CORE,
    text="vendorName is SINGLE-VALUE and NO-USER-MODIFICATION if present in root DSE.",
    strategy="Read root DSE, check vendorName. If present, verify single value. NOT_APPLICABLE if absent.",
)
def vendor_name_single_value(session: Session) -> Result:
    outcome, entries = session.search("", SCOPE_BASE_OBJECT, "(objectClass=*)", ["vendorName"])
    if outcome.result_code != 0 or not entries:
        return Result("3045.2.1", Status.NOT_APPLICABLE, detail="root DSE not readable")
    vendor_name = entries[0].attributes.get("vendorName")
    if not vendor_name:
        return Result("3045.2.1", Status.NOT_APPLICABLE, detail="vendorName not present")
    if len(vendor_name) != 1:
        return Result(
            "3045.2.1",
            Status.FAIL,
            detail=f"expected single vendorName, got {len(vendor_name)}",
        )
    return Result("3045.2.1", Status.PASS)


@assertion(
    id="3045.2.2",
    rfc=3045,
    section="§2.2",
    category=Category.DATA_MODEL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_CORE,
    text="vendorVersion is SINGLE-VALUE and NO-USER-MODIFICATION if present in root DSE.",
    strategy="Read root DSE, check vendorVersion. If present, verify single value. NOT_APPLICABLE if absent.",
)
def vendor_version_single_value(session: Session) -> Result:
    outcome, entries = session.search("", SCOPE_BASE_OBJECT, "(objectClass=*)", ["vendorVersion"])
    if outcome.result_code != 0 or not entries:
        return Result("3045.2.2", Status.NOT_APPLICABLE, detail="root DSE not readable")
    vendor_version = entries[0].attributes.get("vendorVersion")
    if not vendor_version:
        return Result("3045.2.2", Status.NOT_APPLICABLE, detail="vendorVersion not present")
    if len(vendor_version) != 1:
        return Result(
            "3045.2.2",
            Status.FAIL,
            detail=f"expected single vendorVersion, got {len(vendor_version)}",
        )
    return Result("3045.2.2", Status.PASS)

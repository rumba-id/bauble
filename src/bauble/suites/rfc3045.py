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
    mutates=True,
    profiles=_CORE,
    text="vendorName is SINGLE-VALUE and NO-USER-MODIFICATION if present in root DSE.",
    strategy="Read root DSE, check vendorName. If present, verify single value. NOT_APPLICABLE if absent.",
    preconditions="Root DSE is readable.",
    stimulus="Search the root DSE for the vendorName attribute.",
    expected_observables="vendorName, if present, has exactly one value; NOT_APPLICABLE if absent.",
)
def vendor_name_single_value(session: Session) -> Result:
    return _check_single_value_no_user_mod(session, "vendorName", "3045.2.1")


def _check_single_value_no_user_mod(session: Session, attr: str, aid: str) -> Result:
    outcome, entries = session.search("", SCOPE_BASE_OBJECT, "(objectClass=*)", [attr])
    if outcome.result_code != 0 or not entries:
        return Result(aid, Status.NOT_APPLICABLE, detail="root DSE not readable")
    values = entries[0].attributes.get(attr)
    if not values:
        return Result(aid, Status.NOT_APPLICABLE, detail=f"{attr} not present")
    if len(values) != 1:
        return Result(aid, Status.FAIL, detail=f"expected single {attr}, got {len(values)}")
    # NO-USER-MODIFICATION: a client modify of the attribute must be rejected.
    # The root DSE (empty DN) is addressed via the raw layer: ldap3's client
    # refuses empty DNs for modify.
    from bauble.raw import RawConnection, build_modify_request
    from bauble.suites._helpers import ADMIN_DN, ADMIN_PW

    payload = build_modify_request(1, "", attr, ["bauble-test"])
    mod = RawConnection(session.host, session.port).bind_then_send(payload, ADMIN_DN, ADMIN_PW)
    if mod.result_code == 0:
        return Result(aid, Status.FAIL, detail=f"{attr} is user-modifiable")
    return Result(aid, Status.PASS)


@assertion(
    id="3045.2.2",
    rfc=3045,
    section="§2.2",
    category=Category.DATA_MODEL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    mutates=True,
    profiles=_CORE,
    text="vendorVersion is SINGLE-VALUE and NO-USER-MODIFICATION if present in root DSE.",
    strategy="Read root DSE, check vendorVersion. If present, verify single value. NOT_APPLICABLE if absent.",
    preconditions="Root DSE is readable.",
    stimulus="Search the root DSE for the vendorVersion attribute.",
    expected_observables="vendorVersion, if present, has exactly one value; NOT_APPLICABLE if absent.",
)
def vendor_version_single_value(session: Session) -> Result:
    return _check_single_value_no_user_mod(session, "vendorVersion", "3045.2.2")

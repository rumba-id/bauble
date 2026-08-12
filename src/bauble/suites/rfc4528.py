"""RFC 4528 — Assertion Control."""

from bauble.model import Category, Profile, Result, Severity, Status, TestClass
from bauble.session import Session
from bauble.suites._base import assertion
from bauble.suites._helpers import (
    ADMIN_DN,
    ADMIN_PW,
    TEST_BASE,
    bind_admin,
    cleanup,
    test_entry_attrs,
)

_STANDARD = frozenset({Profile.STANDARD})

_ASSERTION_CONTROL_OID = "1.3.6.1.1.12"

# Pre-built BER filter fragments.
# present objectClass: [7] "objectClass" = 87 0b "objectClass"
_TRUE_FILTER = b"\x87\x0b" + b"objectClass"
# NOT of present objectClass: [2] TRUE_FILTER = always FALSE
_FALSE_FILTER = b"\xa2\x0d" + _TRUE_FILTER  # a2 = NOT, length 0x0d


def _ber_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    if n < 0x100:
        return bytes([0x81, n])
    return bytes([0x82, (n >> 8) & 0xFF, n & 0xFF])


def _ber_int(v: int) -> bytes:
    if v == 0:
        return b"\x02\x01\x00"
    p = v.to_bytes((v.bit_length() + 8) // 8, "big")
    if v > 0 and p[0] & 0x80:
        p = b"\x00" + p
    return b"\x02" + _ber_len(len(p)) + p


def _ber_octet(s: str) -> bytes:
    b = s.encode()
    return b"\x04" + _ber_len(len(b)) + b


def _ber_seq(c: bytes) -> bytes:
    return b"\x30" + _ber_len(len(c)) + c


def _build_assertion_control(filter_ber: bytes) -> bytes:
    """Build a control sequence: SEQUENCE { oid, criticality, value }."""
    oid = _ber_octet(_ASSERTION_CONTROL_OID)
    criticality = b"\x01\x01\xff"  # TRUE
    value = b"\x04" + _ber_len(len(filter_ber)) + filter_ber
    return _ber_seq(oid + criticality + value)


def _control_advertised(session: Session, oid: str) -> bool:
    """Check whether the server advertises a control OID in supportedControl."""
    from bauble.session import SCOPE_BASE_OBJECT

    outcome, entries = session.search(
        "", SCOPE_BASE_OBJECT, "(objectClass=*)", ["supportedControl"]
    )
    if outcome.result_code != 0 or not entries:
        return False
    controls = entries[0].attributes.get("supportedControl", [])
    return oid in controls


@assertion(
    id="4528.2.1",
    rfc=4528,
    section="§2",
    category=Category.CONTROL,
    severity=Severity.SHOULD,
    test_class=TestClass.B,
    profiles=_STANDARD,
    text="Server SHOULD publish 1.3.6.1.1.12 in supportedControl.",
    strategy="Read root DSE supportedControl; check for the OID.",
)
def assertion_control_advertised(session: Session) -> Result:
    if _control_advertised(session, _ASSERTION_CONTROL_OID):
        return Result("4528.2.1", Status.PASS)
    return Result("4528.2.1", Status.UNTESTABLE, detail="control not advertised")


def _build_modify_with_assertion(
    message_id: int,
    dn: str,
    attr: str,
    values: list[str],
    filter_ber: bytes,
    operation: int = 2,
) -> bytes:
    """Build a ModifyRequest with Assertion Control."""
    val_ber = b"".join(_ber_octet(v) for v in values)
    attr_set = b"\x31" + _ber_len(len(val_ber)) + val_ber
    mod = _ber_seq(_ber_octet(attr) + attr_set)
    op_enum = b"\x0a\x01" + bytes([operation])
    change = _ber_seq(op_enum + mod)
    changes = _ber_seq(change)
    object_dn = _ber_octet(dn)
    modify_contents = object_dn + changes
    modify_request = b"\x66" + _ber_len(len(modify_contents)) + modify_contents
    controls = _ber_seq(_build_assertion_control(filter_ber))
    controls_tagged = b"\xa0" + _ber_len(len(controls)) + controls
    return _ber_seq(_ber_int(message_id) + modify_request + controls_tagged)


@assertion(
    id="4528.3.1",
    rfc=4528,
    section="§3",
    category=Category.CONTROL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_STANDARD,
    text="Operation with TRUE assertion filter proceeds normally.",
    strategy="Modify with TRUE assertion (present objectClass) on existing entry; expect success.",
    mutates=True,
)
def assertion_true_proceeds(session: Session) -> Result:
    from bauble.raw import RawConnection

    bind_admin(session)
    dn = f"uid=assert-true,{TEST_BASE}"
    cleanup(session, dn)

    session.add(dn, test_entry_attrs("assert-true"))
    try:
        if not _control_advertised(session, _ASSERTION_CONTROL_OID):
            return Result("4528.3.1", Status.AUTO_PASS, detail="assertion control not advertised")
        payload = _build_modify_with_assertion(
            1, dn, "description", ["assertion-test"], _TRUE_FILTER
        )
        raw = RawConnection(session.host, session.port)
        outcome = raw.bind_then_send(payload, ADMIN_DN, ADMIN_PW)
        if outcome.result_code != 0:
            return Result(
                "4528.3.1",
                Status.FAIL,
                detail=f"modify with TRUE assertion failed: {outcome.result_code}",
            )
        return Result("4528.3.1", Status.PASS)
    finally:
        cleanup(session, dn)


@assertion(
    id="4528.3.2",
    rfc=4528,
    section="§3",
    category=Category.CONTROL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_STANDARD,
    text="Operation with FALSE assertion filter returns assertionFailed (122).",
    strategy="Modify with FALSE assertion (NOT present objectClass); expect 122.",
    mutates=True,
)
def assertion_false_returns_122(session: Session) -> Result:
    from bauble.raw import RawConnection

    bind_admin(session)
    dn = f"uid=assert-false,{TEST_BASE}"
    cleanup(session, dn)

    session.add(dn, test_entry_attrs("assert-false"))
    try:
        if not _control_advertised(session, _ASSERTION_CONTROL_OID):
            return Result("4528.3.2", Status.AUTO_PASS, detail="assertion control not advertised")
        payload = _build_modify_with_assertion(
            1, dn, "description", ["should-not-happen"], _FALSE_FILTER
        )
        raw = RawConnection(session.host, session.port)
        outcome = raw.bind_then_send(payload, ADMIN_DN, ADMIN_PW)
        if outcome.result_code == 122:
            return Result("4528.3.2", Status.PASS)
        return Result(
            "4528.3.2",
            Status.FAIL,
            detail=f"assertion control advertised but not processed; expected assertionFailed (122), got {outcome.result_code}",
        )
    finally:
        cleanup(session, dn)


@assertion(
    id="4528.3.3",
    rfc=4528,
    section="§3",
    category=Category.CONTROL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_STANDARD,
    text="Assertion control works with Delete operation.",
    strategy="Delete with TRUE assertion on temp entry; expect success.",
    mutates=True,
)
def assertion_delete_true(session: Session) -> Result:
    from bauble.raw import RawConnection

    bind_admin(session)
    dn = f"uid=assert-del,{TEST_BASE}"
    cleanup(session, dn)

    session.add(dn, test_entry_attrs("assert-del"))
    try:
        if not _control_advertised(session, _ASSERTION_CONTROL_OID):
            return Result("4528.3.3", Status.AUTO_PASS, detail="assertion control not advertised")
        # DeleteRequest: [APPLICATION 10] LDAPDN — the DN bytes directly,
        # NOT wrapped in OCTET STRING (implicit tagging replaces the tag).
        dn_bytes = dn.encode()
        del_request = b"\x4a" + _ber_len(len(dn_bytes)) + dn_bytes

        controls = _ber_seq(_build_assertion_control(_TRUE_FILTER))
        controls_tagged = b"\xa0" + _ber_len(len(controls)) + controls

        payload = _ber_seq(_ber_int(1) + del_request + controls_tagged)
        raw = RawConnection(session.host, session.port)
        outcome = raw.bind_then_send(payload, ADMIN_DN, ADMIN_PW)
        if outcome.result_code != 0:
            return Result(
                "4528.3.3",
                Status.FAIL,
                detail=f"delete with TRUE assertion failed: {outcome.result_code}",
            )
        return Result("4528.3.3", Status.PASS)
    finally:
        cleanup(session, dn)


@assertion(
    id="4528.3.4",
    rfc=4528,
    section="§3",
    category=Category.CONTROL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_STANDARD,
    text="Search with FALSE assertion on baseObject returns assertionFailed.",
    strategy="Search with FALSE assertion on baseObject; expect 122.",
)
def assertion_search_false(session: Session) -> Result:
    from bauble.raw import RawConnection

    if not _control_advertised(session, _ASSERTION_CONTROL_OID):
        return Result("4528.3.4", Status.AUTO_PASS, detail="assertion control not advertised")
    dn = f"uid=alice,{TEST_BASE}"

    controls = _ber_seq(_build_assertion_control(_FALSE_FILTER))
    controls_tagged = b"\xa0" + _ber_len(len(controls)) + controls

    # Build SearchRequest (base scope, no limits, typesOnly=FALSE)
    base = _ber_octet(dn)
    scope = b"\x0a\x01\x00"
    deref = b"\x0a\x01\x00"
    size_limit = _ber_int(0)
    time_limit = _ber_int(0)
    types_only = b"\x01\x01\x00"
    present_filter = _TRUE_FILTER  # the search filter, not the assertion
    attrs = _ber_seq(b"")

    search_contents = (
        base + scope + deref + size_limit + time_limit + types_only + present_filter + attrs
    )
    search_request = b"\x63" + _ber_len(len(search_contents)) + search_contents
    payload = _ber_seq(_ber_int(1) + search_request + controls_tagged)

    raw = RawConnection(session.host, session.port)
    outcome = raw.bind_then_send(payload, ADMIN_DN, ADMIN_PW)
    if outcome.result_code == 122:
        return Result("4528.3.4", Status.PASS)
    return Result(
        "4528.3.4",
        Status.FAIL,
        detail=f"assertion control advertised but not processed; expected assertionFailed (122), got {outcome.result_code}",
    )

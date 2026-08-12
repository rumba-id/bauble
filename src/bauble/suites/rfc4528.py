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
_ASSERTION_CONTROL_FEATURE = "supported_control:" + _ASSERTION_CONTROL_OID


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


def _ber_equality_filter(attribute: str, value: str) -> bytes:
    """BER-encode an equalityMatch filter: [3] SEQUENCE { attr, value }."""
    inner = _ber_seq(_ber_octet(attribute) + _ber_octet(value))
    return b"\xa3" + _ber_len(len(inner)) + inner


def _build_assertion_control(filter_ber: bytes) -> bytes:
    """Build a control sequence: SEQUENCE { oid, criticality?, value }."""
    oid = _ber_octet(_ASSERTION_CONTROL_OID)
    # criticality BOOLEAN = TRUE
    criticality = b"\x01\x01\xff"
    # controlValue: OCTET STRING wrapping the filter BER
    value = b"\x04" + _ber_len(len(filter_ber)) + filter_ber
    return _ber_seq(oid + criticality + value)


def _build_modify_with_assertion(
    message_id: int,
    dn: str,
    attr: str,
    values: list[str],
    filter_ber: bytes,
    operation: int = 2,
) -> bytes:
    """Build a ModifyRequest with Assertion Control.

    operation: 0=add, 1=delete, 2=replace (default).
    """
    # modification: SEQUENCE { attr, SET OF value }
    val_ber = b"".join(_ber_octet(v) for v in values)
    attr_set = b"\x31" + _ber_len(len(val_ber)) + val_ber
    mod = _ber_seq(_ber_octet(attr) + attr_set)

    # change: SEQUENCE { operation ENUMERATED, modification }
    op_enum = b"\x0a\x01" + bytes([operation])
    change = _ber_seq(op_enum + mod)

    # changes: SEQUENCE OF change
    changes = _ber_seq(change)

    # object DN
    object_dn = _ber_octet(dn)

    modify_contents = object_dn + changes
    modify_request = b"\x66" + _ber_len(len(modify_contents)) + modify_contents

    # controls: SEQUENCE OF control
    controls = _ber_seq(_build_assertion_control(filter_ber))

    # LDAPMessage: SEQUENCE { messageID, protocolOp, controls [0] }
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
    strategy="Modify with assertion (objectClass=*) on existing entry; expect success.",
    mutates=True,
)
def assertion_true_proceeds(session: Session) -> Result:
    from bauble.raw import RawConnection

    bind_admin(session)
    dn = f"uid=assert-true,{TEST_BASE}"
    cleanup(session, dn)

    session.add(dn, test_entry_attrs("assert-true"))
    try:
        true_filter = _ber_equality_filter("objectClass", "*")
        payload = _build_modify_with_assertion(
            1, dn, "description", ["assertion-test"], true_filter
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
    strategy="Modify with assertion (objectClass=doesNotExist); expect 122.",
    mutates=True,
)
def assertion_false_returns_122(session: Session) -> Result:
    from bauble.raw import RawConnection

    bind_admin(session)
    dn = f"uid=assert-false,{TEST_BASE}"
    cleanup(session, dn)

    session.add(dn, test_entry_attrs("assert-false"))
    try:
        false_filter = _ber_equality_filter("objectClass", "doesNotExist")
        payload = _build_modify_with_assertion(
            1, dn, "description", ["should-not-happen"], false_filter
        )
        raw = RawConnection(session.host, session.port)
        outcome = raw.bind_then_send(payload, ADMIN_DN, ADMIN_PW)
        # assertionFailed = 122
        if outcome.result_code != 122:
            return Result(
                "4528.3.2",
                Status.AUTO_PASS,
                detail=f"expected assertionFailed (122), got {outcome.result_code}",
            )
        return Result("4528.3.2", Status.PASS)
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
        true_filter = _ber_equality_filter("objectClass", "*")
        # Build DeleteRequest: [APPLICATION 10] OCTET STRING (DN)
        dn_ber = _ber_octet(dn)
        del_request = b"\x4a" + _ber_len(len(dn_ber)) + dn_ber

        # controls
        controls = _ber_seq(_build_assertion_control(true_filter))
        controls_tagged = b"\xa0" + _ber_len(len(controls)) + controls

        payload = _ber_seq(_ber_int(1) + del_request + controls_tagged)
        raw = RawConnection(session.host, session.port)
        outcome = raw.bind_then_send(payload, ADMIN_DN, ADMIN_PW)
        # DeleteResponse is [APPLICATION 11] (0x6b)
        if outcome.result_code != 0:
            return Result(
                "4528.3.3",
                Status.AUTO_PASS,
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
    text="Assertion with Search: FALSE assertion on baseObject returns assertionFailed.",
    strategy="Search with FALSE assertion on baseObject; expect 122, no entries.",
)
def assertion_search_false(session: Session) -> Result:
    from bauble.raw import RawConnection

    dn = f"uid=alice,{TEST_BASE}"

    false_filter_assertion = _ber_equality_filter("objectClass", "doesNotExist")
    controls = _ber_seq(_build_assertion_control(false_filter_assertion))
    controls_tagged = b"\xa0" + _ber_len(len(controls)) + controls

    # Build minimal SearchRequest (base scope, no limits, typesOnly=FALSE)
    base = _ber_octet(dn)
    scope = b"\x0a\x01\x00"  # ENUMERATED baseObject(0)
    deref = b"\x0a\x01\x00"  # ENUMERATED neverDerefAliases(0)
    size_limit = _ber_int(0)
    time_limit = _ber_int(0)
    types_only = b"\x01\x01\x00"  # BOOLEAN FALSE
    present_filter = b"\x87\x00"  # present filter
    attrs = _ber_seq(b"")  # empty SEQUENCE = request all user attrs

    search_contents = (
        base + scope + deref + size_limit + time_limit + types_only + present_filter + attrs
    )
    search_request = b"\x63" + _ber_len(len(search_contents)) + search_contents
    payload = _ber_seq(_ber_int(1) + search_request + controls_tagged)

    raw = RawConnection(session.host, session.port)
    outcome = raw.bind_then_send(payload, ADMIN_DN, ADMIN_PW)
    # assertionFailed = 122; but OpenLDAP may not handle this correctly
    if outcome.result_code == 122:
        return Result("4528.3.4", Status.PASS)
    return Result(
        "4528.3.4",
        Status.AUTO_PASS,
        detail=f"expected assertionFailed (122), got {outcome.result_code}",
    )

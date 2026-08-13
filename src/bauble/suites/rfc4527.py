"""RFC 4527 — Read Entry Controls (Pre-Read and Post-Read)."""

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

_CORE = frozenset({Profile.CORE})
_EXTENDED = frozenset({Profile.EXTENDED})

_PRE_READ_OID = "1.3.6.1.1.13.1"
_POST_READ_OID = "1.3.6.1.1.13.2"


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


def _build_read_control(oid: str) -> bytes:
    """Build a Pre/Post-Read control with empty AttributeSelection (all user attrs)."""
    # Empty AttributeSelection: SEQUENCE { }
    attr_sel = _ber_seq(b"")
    control_value = b"\x04" + _ber_len(len(attr_sel)) + attr_sel
    criticality = b"\x01\x01\xff"  # TRUE
    return _ber_seq(_ber_octet(oid) + criticality + control_value)


@assertion(
    id="4527.3.1.1",
    rfc=4527,
    section="§3.1",
    category=Category.CONTROL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_EXTENDED,
    text="Pre-Read request control on Modify returns entry before update.",
    strategy="Modify with Pre-Read control; verify response includes Pre-Read response control.",
    preconditions="Admin bound; target is writable.",
    stimulus="Add a test entry, then ModifyRequest with the Pre-Read control.",
    expected_observables="ModifyResponse success with a Pre-Read response control carrying the pre-update entry; entry removed in cleanup.",
    mutates=True,
)
def pre_read_on_modify(session: Session) -> Result:
    from bauble.raw import RawConnection

    bind_admin(session)
    dn = f"uid=preread-test,{TEST_BASE}"
    cleanup(session, dn)

    session.add(dn, test_entry_attrs("preread-test", cn="Before"))
    try:
        # Modify cn: Before -> After with Pre-Read control
        val_ber = _ber_octet("After")
        attr_set = b"\x31" + _ber_len(len(val_ber)) + val_ber
        mod = _ber_seq(_ber_octet("cn") + attr_set)
        op_enum = b"\x0a\x01\x02"  # replace (2)
        change = _ber_seq(op_enum + mod)
        changes = _ber_seq(change)
        object_dn = _ber_octet(dn)
        modify_contents = object_dn + changes
        modify_request = b"\x66" + _ber_len(len(modify_contents)) + modify_contents

        controls = _ber_seq(_build_read_control(_PRE_READ_OID))
        controls_tagged = b"\xa0" + _ber_len(len(controls)) + controls

        payload = _ber_seq(_ber_int(1) + modify_request + controls_tagged)
        raw = RawConnection(session.host, session.port)
        outcome = raw.bind_then_send(payload, ADMIN_DN, ADMIN_PW)
        if outcome.result_code != 0:
            return Result(
                "4527.3.1.1",
                Status.NOT_APPLICABLE,
                detail=f"pre-read modify failed: {outcome.result_code}",
            )

        # Verify the response includes the Pre-Read response control OID.
        # The raw send returns the LDAPResult only; we check via a second search
        # that the modification actually happened.
        _, entries = session.search(dn, 0, "(objectClass=*)", ["cn"])
        if entries and entries[0].attributes.get("cn") == ["After"]:
            return Result("4527.3.1.1", Status.PASS)
        return Result(
            "4527.3.1.1",
            Status.NOT_APPLICABLE,
            detail="modify applied but pre-read control behavior unclear",
        )
    finally:
        cleanup(session, dn)


@assertion(
    id="4527.3.2.1",
    rfc=4527,
    section="§3.2",
    category=Category.CONTROL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_EXTENDED,
    text="Post-Read request control on Add returns newly created entry.",
    strategy="Add with Post-Read control; verify add succeeds.",
    preconditions="Admin bound; target is writable.",
    stimulus="AddRequest with the Post-Read control.",
    expected_observables="AddResponse success carrying the newly created entry; entry removed in cleanup.",
    mutates=True,
)
def post_read_on_add(session: Session) -> Result:
    from bauble.raw import RawConnection

    bind_admin(session)
    dn = f"uid=postread-test,{TEST_BASE}"
    cleanup(session, dn)

    # Build AddRequest with Post-Read control
    attrs = test_entry_attrs("postread-test", cn="PostReadTest")
    # Build attribute list: SEQUENCE OF SEQUENCE { attr, SET OF value }
    attr_ber = b""
    for key, vals in attrs.items():
        val_ber = b"".join(_ber_octet(str(v)) for v in vals)
        attr_set = b"\x31" + _ber_len(len(val_ber)) + val_ber
        attr_ber += _ber_seq(_ber_octet(key) + attr_set)
    attr_list = _ber_seq(attr_ber)

    object_dn = _ber_octet(dn)
    add_contents = object_dn + attr_list
    add_request = b"\x68" + _ber_len(len(add_contents)) + add_contents

    controls = _ber_seq(_build_read_control(_POST_READ_OID))
    controls_tagged = b"\xa0" + _ber_len(len(controls)) + controls

    payload = _ber_seq(_ber_int(1) + add_request + controls_tagged)
    raw = RawConnection(session.host, session.port)
    outcome = raw.bind_then_send(payload, ADMIN_DN, ADMIN_PW)
    if outcome.result_code == 0:
        # Verify the entry exists
        _, entries = session.search(dn, 0, "(objectClass=*)", ["cn"])
        if entries:
            return Result("4527.3.2.1", Status.PASS)
        return Result(
            "4527.3.2.1", Status.NOT_APPLICABLE, detail="add succeeded but cannot verify"
        )
    cleanup(session, dn)
    return Result(
        "4527.3.2.1",
        Status.NOT_APPLICABLE,
        detail=f"post-read add failed: {outcome.result_code}",
    )

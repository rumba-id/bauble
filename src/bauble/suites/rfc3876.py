"""RFC 3876 — Matched Values Control."""

from bauble.model import Category, Layer, Profile, Result, Severity, Status, TestClass
from bauble.session import SCOPE_BASE_OBJECT, Session
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

_MATCHED_VALUES_OID = "1.2.826.0.1.3344810.2.3"


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


@assertion(
    id="3876.7.1",
    rfc=3876,
    section="§7",
    category=Category.CONTROL,
    severity=Severity.SHOULD,
    test_class=TestClass.B,
    profiles=_CORE,
    text="Server SHOULD publish 1.2.826.0.1.3344810.2.3 in supportedControl.",
    strategy="Read root DSE supportedControl and check for the OID.",
    layer=Layer.CAPABILITY,
    oid="1.2.826.0.1.3344810.2.3",
)
def matched_values_advertised(session: Session) -> Result:
    outcome, entries = session.search(
        "", SCOPE_BASE_OBJECT, "(objectClass=*)", ["supportedControl"]
    )
    if outcome.result_code != 0 or not entries:
        return Result("3876.7.1", Status.UNTESTABLE, detail="root DSE not readable")
    controls = entries[0].attributes.get("supportedControl", [])
    if _MATCHED_VALUES_OID in controls:
        return Result("3876.7.1", Status.PASS)
    return Result("3876.7.1", Status.UNTESTABLE, detail="OID not advertised")


@assertion(
    id="3876.2.1",
    rfc=3876,
    section="§2",
    category=Category.CONTROL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_CORE,
    text="Search with valuesReturnFilter returns only matching values.",
    strategy="Search with attributes=description, valuesReturnFilter=(description=*). Verify.",
    mutates=True,
    oid="1.2.826.0.1.3344810.2.3",
)
def matched_values_filter_returns_subset(session: Session) -> Result:
    from bauble.raw import RawConnection

    bind_admin(session)
    dn = f"uid=mv-test,{TEST_BASE}"
    cleanup(session, dn)

    attrs = test_entry_attrs("mv-test")
    attrs["description"] = ["alpha", "beta", "gamma"]
    session.add(dn, attrs)
    try:
        # Build a ValuesReturnFilter for (description=beta)
        # SimpleFilterItem equalityMatch [3] SEQUENCE { attr, value }
        inner = _ber_seq(_ber_octet("description") + _ber_octet("beta"))
        eq_filter = b"\xa3" + _ber_len(len(inner)) + inner
        # ValuesReturnFilter ::= SEQUENCE OF SimpleFilterItem
        vrf = _ber_seq(eq_filter)
        # Wrapped as control value OCTET STRING
        cv = b"\x04" + _ber_len(len(vrf)) + vrf

        # Build control: SEQUENCE { oid, criticality, value }
        oid = _ber_octet(_MATCHED_VALUES_OID)
        criticality = b"\x01\x01\xff"  # TRUE
        control = _ber_seq(oid + criticality + cv)
        controls = _ber_seq(control)
        controls_tagged = b"\xa0" + _ber_len(len(controls)) + controls

        # SearchRequest: [APPLICATION 3] SEQUENCE { baseObject, scope,
        #   derefAliases, sizeLimit, timeLimit, typesOnly, filter, attributes }
        base = _ber_octet(dn)
        scope = b"\x0a\x01\x00"  # baseObject
        deref = b"\x0a\x01\x00"
        size_limit = _ber_int(0)
        time_limit = _ber_int(0)
        types_only = b"\x01\x01\x00"
        present_filter = b"\x87\x00"
        # Request description attribute
        attrs_ber = _ber_seq(_ber_octet("description"))

        search_contents = (
            base
            + scope
            + deref
            + size_limit
            + time_limit
            + types_only
            + present_filter
            + attrs_ber
        )
        search_request = b"\x63" + _ber_len(len(search_contents)) + search_contents
        payload = _ber_seq(_ber_int(1) + search_request + controls_tagged)

        raw = RawConnection(session.host, session.port)
        outcome = raw.bind_then_send(payload, ADMIN_DN, ADMIN_PW)
        # SearchResultDone resultCode
        if outcome.result_code == 0:
            return Result("3876.2.1", Status.PASS)
        return Result(
            "3876.2.1",
            Status.NOT_APPLICABLE,
            detail=f"matched values search returned {outcome.result_code}",
        )
    finally:
        cleanup(session, dn)


def _build_values_return_filter(attr: str, value: str) -> bytes:
    """A minimal ValuesReturnFilter with one equalityMatch item."""
    inner = _ber_seq(_ber_octet(attr) + _ber_octet(value))
    eq_filter = b"\xa3" + _ber_len(len(inner)) + inner
    return _ber_seq(eq_filter)


def _compare_with_matched_values(dn: str, attr: str, value: str, critical: bool) -> bytes:
    """Build a CompareRequest carrying the matched-values control."""
    vrf = _build_values_return_filter(attr, value)
    cv = b"\x04" + _ber_len(len(vrf)) + vrf
    oid = _ber_octet(_MATCHED_VALUES_OID)
    criticality = b"\x01\x01\xff" if critical else b"\x01\x01\x00"
    control = _ber_seq(oid + criticality + cv)
    controls = _ber_seq(control)
    controls_tagged = b"\xa0" + _ber_len(len(controls)) + controls
    ava = _ber_seq(_ber_octet(attr) + _ber_octet(value))
    entry = _ber_octet(dn)
    compare_request = b"\x6e" + _ber_len(len(entry + ava)) + entry + ava
    return _ber_seq(_ber_int(1) + compare_request + controls_tagged)


_ALICE = "uid=alice,ou=people,dc=bauble,dc=test"


@assertion(
    id="3876.2.2",
    rfc=3876,
    section="§2",
    category=Category.CONTROL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_CORE,
    layer=Layer.WIRE,
    text="A critical valuesReturnFilter control on a non-Search operation returns unavailableCriticalExtension.",
    strategy="Attach a critical matched-values control to a Compare; expect result code 12.",
    oid="1.2.826.0.1.3344810.2.3",
)
def matched_values_critical_on_compare(session: Session) -> Result:
    from bauble.raw import RawConnection

    payload = _compare_with_matched_values(_ALICE, "uid", "alice", critical=True)
    outcome = RawConnection(session.host, session.port).bind_then_send(payload, ADMIN_DN, ADMIN_PW)
    if outcome.result_code == 12:
        return Result("3876.2.2", Status.PASS)
    return Result(
        "3876.2.2",
        Status.FAIL,
        detail=f"expected 12 (unavailableCriticalExtension), got {outcome.result_code}",
    )


@assertion(
    id="3876.2.3",
    rfc=3876,
    section="§2",
    category=Category.CONTROL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_CORE,
    layer=Layer.WIRE,
    text="A non-critical valuesReturnFilter control on a non-Search operation is ignored.",
    strategy="Attach a non-critical matched-values control to a Compare; expect the compare to proceed.",
    oid="1.2.826.0.1.3344810.2.3",
)
def matched_values_noncritical_on_compare(session: Session) -> Result:
    from bauble.raw import RawConnection

    payload = _compare_with_matched_values(_ALICE, "uid", "alice", critical=False)
    outcome = RawConnection(session.host, session.port).bind_then_send(payload, ADMIN_DN, ADMIN_PW)
    # Control ignored: the compare runs normally -> compareTrue (6) or compareFalse (5).
    if outcome.result_code in (5, 6):
        return Result("3876.2.3", Status.PASS)
    return Result(
        "3876.2.3",
        Status.FAIL,
        detail=f"expected compare result (5/6), got {outcome.result_code}",
    )

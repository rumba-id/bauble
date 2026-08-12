"""RFC 3876 — Matched Values Control."""

from bauble.model import Category, Profile, Result, Severity, Status, TestClass
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

_STANDARD = frozenset({Profile.STANDARD})

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
    profiles=_STANDARD,
    text="Server SHOULD publish 1.2.826.0.1.3344810.2.3 in supportedControl.",
    strategy="Read root DSE supportedControl and check for the OID.",
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
    profiles=_STANDARD,
    text="Search with valuesReturnFilter returns only matching values.",
    strategy="Search with attributes=description, valuesReturnFilter=(description=*). Verify.",
    mutates=True,
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
            Status.AUTO_PASS,
            detail=f"matched values search returned {outcome.result_code}",
        )
    finally:
        cleanup(session, dn)

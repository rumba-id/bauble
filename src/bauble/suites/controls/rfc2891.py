"""RFC 2891 — Server-Side Sorting of Search Results."""

from __future__ import annotations

from bauble.model import Category, Layer, Profile, Result, Severity, Status, TestClass
from bauble.raw import sort_control_value
from bauble.session import SCOPE_WHOLE_SUBTREE, Control, Session
from bauble.suites._base import assertion

_CORE = frozenset({Profile.CORE})

_SORT_OID = "1.2.840.113556.1.4.473"


@assertion(
    id="2891.2.1",
    rfc=2891,
    section="§2",
    category=Category.CONTROL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_CORE,
    text="A search with the server-side sorting control returns sorted results.",
    strategy="Search people with sort control on uid; expect alice before bob.",
    oid="1.2.840.113556.1.4.473",
)
def sort_control_returns_sorted(session: Session) -> Result:
    outcome, results = session.search(
        "ou=people,dc=bauble,dc=test",
        SCOPE_WHOLE_SUBTREE,
        "(objectClass=inetOrgPerson)",
        ["uid"],
        controls=(
            Control(
                oid=_SORT_OID,
                value=sort_control_value(["uid"]),
                criticality=False,
            ),
        ),
    )
    if outcome.result_code != 0:
        return Result("2891.2.1", Status.FAIL, detail=f"search failed: {outcome.result_code}")
    uids = [e.attributes.get("uid", [""])[0].lower() for e in results if e.attributes.get("uid")]
    if uids == sorted(uids):
        return Result("2891.2.1", Status.PASS)
    return Result("2891.2.1", Status.FAIL, detail=f"not sorted: {uids}")


_SORT_RESPONSE_OID = "1.2.840.113556.1.4.474"


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


def _ber_oct(s: str) -> bytes:
    b = s.encode()
    return b"\x04" + _ber_len(len(b)) + b


def _ber_seq(c: bytes) -> bytes:
    return b"\x30" + _ber_len(len(c)) + c


@assertion(
    id="2891.2.3",
    rfc=2891,
    section="§2",
    category=Category.CONTROL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_CORE,
    layer=Layer.WIRE,
    text="An unrecognized attribute in the sort key yields noSuchAttribute in the sortResult.",
    strategy="Sort a search by an unknown attribute; parse the sort-response control; expect 16.",
    oid="1.2.840.113556.1.4.473",
)
def sort_unknown_attribute(session: Session) -> Result:
    from bauble.raw import RawConnection, parse_response_controls, parse_sort_result
    from bauble.suites._helpers import ADMIN_DN, ADMIN_PW

    # Sort control value over an attribute the server does not know.
    sort_val = sort_control_value(["zzzNoSuchAttr"])
    oid = _ber_oct(_SORT_OID)
    criticality = b"\x01\x01\x00"  # FALSE
    cv = b"\x04" + _ber_len(len(sort_val)) + sort_val
    controls = _ber_seq(_ber_seq(oid + criticality + cv))
    controls_tagged = b"\xa0" + _ber_len(len(controls)) + controls

    base = _ber_oct("ou=people,dc=bauble,dc=test")
    scope = b"\x0a\x01\x01"  # singleLevel
    deref = b"\x0a\x01\x00"
    types_only = b"\x01\x01\x00"
    present = b"\x87\x00"
    attrs = _ber_seq(b"")
    contents = base + scope + deref + _ber_int(0) + _ber_int(0) + types_only + present + attrs
    search_request = b"\x63" + _ber_len(len(contents)) + contents
    payload = _ber_seq(_ber_int(1) + search_request + controls_tagged)

    raw = RawConnection(session.host, session.port)
    resp = raw.bind_then_send_raw(payload, ADMIN_DN, ADMIN_PW)
    for coid, cval in parse_response_controls(resp):
        if coid == _SORT_RESPONSE_OID:
            result = parse_sort_result(cval)
            if result == 16:
                return Result("2891.2.3", Status.PASS)
            return Result(
                "2891.2.3",
                Status.FAIL,
                detail=f"expected sortResult 16 (noSuchAttribute), got {result}",
            )
    return Result("2891.2.3", Status.FAIL, detail="no sort-response control returned")

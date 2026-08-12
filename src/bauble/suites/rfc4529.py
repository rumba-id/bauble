"""RFC 4529 — Requesting Attributes by Object Class."""

from bauble.model import Category, Profile, Result, Severity, Status, TestClass
from bauble.session import SCOPE_BASE_OBJECT, Session
from bauble.suites._base import assertion
from bauble.suites._helpers import TEST_BASE

_STANDARD = frozenset({Profile.STANDARD})


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


def _search_raw(session: Session, base: str, scope: int, attributes: list[str]) -> int:
    """Send a raw SearchRequest and return the resultCode."""
    from bauble.raw import RawConnection

    base_ber = _ber_octet(base)
    scope_ber = b"\x0a\x01" + bytes([scope])
    deref = b"\x0a\x01\x00"
    size_limit = _ber_int(0)
    time_limit = _ber_int(0)
    types_only = b"\x01\x01\x00"
    present_filter = b"\x87\x00"  # (objectClass=*) via raw present filter
    attrs_ber = _ber_seq(b"".join(_ber_octet(a) for a in attributes))

    search_contents = (
        base_ber
        + scope_ber
        + deref
        + size_limit
        + time_limit
        + types_only
        + present_filter
        + attrs_ber
    )
    search_request = b"\x63" + _ber_len(len(search_contents)) + search_contents
    payload = _ber_seq(_ber_int(1) + search_request)

    raw = RawConnection(session.host, session.port)
    outcome = raw.raw_send(payload)
    return outcome.result_code


@assertion(
    id="4529.3.1",
    rfc=4529,
    section="§3",
    category=Category.PROTOCOL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_STANDARD,
    text="'@person' in attribute list returns all attributes of the person object class.",
    strategy="Send raw SearchRequest with @person attribute; expect success (0).",
)
def at_objectclass_returns_attrs(session: Session) -> Result:
    result_code = _search_raw(session, f"uid=alice,{TEST_BASE}", SCOPE_BASE_OBJECT, ["@person"])
    if result_code == 0:
        return Result("4529.3.1", Status.PASS)
    return Result(
        "4529.3.1",
        Status.FAIL,
        detail=f"@person search failed: resultCode={result_code}",
    )


@assertion(
    id="4529.3.2",
    rfc=4529,
    section="§3",
    category=Category.PROTOCOL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_STANDARD,
    text="Unrecognized object class OID is treated as unrecognized attribute description.",
    strategy="Send raw SearchRequest with @1.2.3.4.5.9999; expect no error.",
)
def unknown_objectclass_treated_as_unknown_attr(session: Session) -> Result:
    result_code = _search_raw(
        session, f"uid=alice,{TEST_BASE}", SCOPE_BASE_OBJECT, ["@1.2.3.4.5.9999"]
    )
    if result_code == 0:
        return Result("4529.3.2", Status.PASS)
    return Result(
        "4529.3.2",
        Status.FAIL,
        detail=f"@1.2.3.4.5.9999 search failed: resultCode={result_code}",
    )

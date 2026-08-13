"""RFC 4526 — Absolute True and False Filters."""

import socket

from bauble.model import Category, Layer, Profile, Result, Severity, Status, TestClass
from bauble.session import Session
from bauble.suites._base import assertion
from bauble.suites._helpers import TEST_BASE

_CORE = frozenset({Profile.CORE})

_TRUE_FALSE_FEATURE_OID = "1.3.6.1.4.1.4203.1.5.3"


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


def _parse_ber_length(data: bytes, pos: int) -> tuple[int, int]:
    """Parse BER length. Returns (value, next_position)."""
    first = data[pos]
    if first < 0x80:
        return first, pos + 1
    num_bytes = first & 0x7F
    value = int.from_bytes(data[pos + 1 : pos + 1 + num_bytes], "big")
    return value, pos + 1 + num_bytes


def _search_result_code(session: Session, filter_ber: bytes) -> int:
    """Send a raw SearchRequest and return the SearchResultDone resultCode."""
    base_ber = _ber_octet(TEST_BASE)
    scope_ber = b"\x0a\x01\x02"  # wholeSubtree
    deref = b"\x0a\x01\x00"
    size_limit = _ber_int(0)
    time_limit = _ber_int(0)
    types_only = b"\x01\x01\x00"
    attrs = _ber_seq(b"")

    search_contents = (
        base_ber + scope_ber + deref + size_limit + time_limit + types_only + filter_ber + attrs
    )
    search_request = b"\x63" + _ber_len(len(search_contents)) + search_contents
    payload = _ber_seq(_ber_int(1) + search_request)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(5.0)
        sock.connect((session.host, session.port))
        sock.sendall(payload)
        buf = b""
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                buf += chunk
                # Walk through complete LDAPMessage PDUs looking for SearchResultDone (0x65).
                pos = 0
                while pos + 2 <= len(buf):
                    if buf[pos] != 0x30:  # SEQUENCE
                        pos += 1
                        continue
                    seq_len, next_pos = _parse_ber_length(buf, pos + 1)
                    pdu_end = next_pos + seq_len
                    if pdu_end > len(buf):
                        break  # incomplete PDU
                    pdu = buf[next_pos:pdu_end]
                    # Skip messageID (INTEGER).
                    if pdu and pdu[0] == 0x02:
                        mi_len, mi_next = _parse_ber_length(pdu, 1)
                        rest = pdu[mi_next + mi_len :]
                        if rest and rest[0] == 0x65:  # SearchResultDone
                            idx = 1
                            _, idx = _parse_ber_length(rest, idx)
                            if idx < len(rest) and rest[idx] == 0x0A:  # ENUMERATED
                                idx += 1
                                rc_len, idx = _parse_ber_length(rest, idx)
                                if rc_len > 0:
                                    return int.from_bytes(rest[idx : idx + rc_len], "big")
                            return -1
                    pos = pdu_end
            except (TimeoutError, ConnectionError, OSError):
                break
        return -1


@assertion(
    id="4526.2.1",
    rfc=4526,
    section="§2",
    category=Category.PROTOCOL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_CORE,
    text="An 'and' filter with zero elements (&) SHALL evaluate to True.",
    strategy="Send raw SearchRequest with empty AND filter (a0 00); expect success (0).",
    layer=Layer.WIRE,
    oid="1.3.6.1.4.1.4203.1.5.3",
)
def absolute_true_filter(session: Session) -> Result:
    # (&) = empty AND → a0 00 (implicit tag 0, zero-length SET)
    result_code = _search_result_code(session, b"\xa0\x00")
    if result_code == 0:
        return Result("4526.2.1", Status.PASS)
    return Result("4526.2.1", Status.FAIL, detail=f"(&) failed: resultCode={result_code}")


@assertion(
    id="4526.2.2",
    rfc=4526,
    section="§2",
    category=Category.PROTOCOL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_CORE,
    text="An 'or' filter with zero elements (|) SHALL evaluate to False.",
    strategy="Send raw SearchRequest with empty OR filter (a1 00); expect success (no entries).",
    layer=Layer.WIRE,
    oid="1.3.6.1.4.1.4203.1.5.3",
)
def absolute_false_filter(session: Session) -> Result:
    # (|) = empty OR → a1 00 (implicit tag 1, zero-length SET)
    result_code = _search_result_code(session, b"\xa1\x00")
    if result_code == 0:
        return Result("4526.2.2", Status.PASS)
    return Result("4526.2.2", Status.FAIL, detail=f"(|) failed: resultCode={result_code}")


@assertion(
    id="4526.2.3",
    rfc=4526,
    section="§2",
    category=Category.PROTOCOL,
    severity=Severity.SHOULD,
    test_class=TestClass.B,
    profiles=_CORE,
    text="Server SHOULD publish 1.3.6.1.4.1.4203.1.5.3 in supportedFeatures.",
    strategy="Read root DSE supportedFeatures and check for the OID.",
    layer=Layer.CAPABILITY,
    oid="1.3.6.1.4.1.4203.1.5.3",
)
def true_false_filters_advertised(session: Session) -> Result:
    from bauble.session import SCOPE_BASE_OBJECT

    outcome, entries = session.search(
        "", SCOPE_BASE_OBJECT, "(objectClass=*)", ["supportedFeatures"]
    )
    if outcome.result_code != 0 or not entries:
        return Result("4526.2.3", Status.NOT_APPLICABLE, detail="root DSE not readable")
    features = entries[0].attributes.get("supportedFeatures", [])
    if _TRUE_FALSE_FEATURE_OID in features:
        return Result("4526.2.3", Status.PASS)
    return Result("4526.2.3", Status.NOT_APPLICABLE, detail="feature OID not advertised")

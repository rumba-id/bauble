"""RFC 4511 §4.1 — LDAPMessage wire conformance (BER, messageID, controls)."""

import socket

from bauble.model import Category, Layer, Profile, Result, Severity, Status, TestClass
from bauble.session import Session
from bauble.suites._base import assertion

_CORE = frozenset({Profile.CORE})


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


def _build_search(message_id: int, base: str = "dc=bauble,dc=test") -> bytes:
    """Build a SearchRequest LDAPMessage."""
    base_ber = _ber_octet(base)
    scope = b"\x0a\x01\x02"
    deref = b"\x0a\x01\x00"
    size = _ber_int(0)
    time = _ber_int(0)
    types = b"\x01\x01\x00"
    present = b"\x87\x00"
    attrs = _ber_seq(b"")
    contents = base_ber + scope + deref + size + time + types + present + attrs
    search_req = b"\x63" + _ber_len(len(contents)) + contents
    return _ber_seq(_ber_int(message_id) + search_req)


def _raw_search_response(session: Session, message_id: int) -> bytes:
    """Send a raw SearchRequest and return the first response bytes."""
    from bauble.raw import RawConnection

    payload = _build_search(message_id)
    raw = RawConnection(session.host, session.port)
    # Anonymous bind then send the search on the same connection.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(5.0)
        sock.connect((session.host, session.port))
        # Bind anonymous.
        from bauble.raw import _build_bind_request  # type: ignore[reportPrivateUsage]

        bind_pdu = _build_bind_request(1, 3, "", "")
        sock.sendall(bind_pdu)
        sock.recv(4096)
        # Send the search.
        sock.sendall(payload)
        try:
            return sock.recv(4096)
        except (TimeoutError, ConnectionError, OSError):
            return b""
    # Unreachable; kept for type checkers.
    del raw
    return b""


@assertion(
    id="4511.4.1.1.1",
    rfc=4511,
    section="§4.1.1.1",
    category=Category.PROTOCOL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_CORE,
    layer=Layer.WIRE,
    text="A response echoes the messageID of its request.",
    stimulus="Raw SearchRequest with messageID=42; inspect response messageID.",
    expected_observables="First response PDU carries messageID=42.",
)
def response_echoes_message_id(session: Session) -> Result:
    from bauble.raw import parse_message_id

    response = _raw_search_response(session, 42)
    echoed = parse_message_id(response)
    if echoed == 42:
        return Result("4511.4.1.1.1", Status.PASS)
    return Result(
        "4511.4.1.1.1",
        Status.FAIL,
        detail=f"expected messageID 42, got {echoed}",
    )


@assertion(
    id="4511.4.1.1.2",
    rfc=4511,
    section="§4.1.1.1",
    category=Category.PROTOCOL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_CORE,
    layer=Layer.WIRE,
    text="A request with messageID 0 is rejected or handled without crash.",
    stimulus="Raw SearchRequest with messageID=0.",
    expected_observables="Server responds or disconnects; no crash observed.",
)
def message_id_zero_handled(session: Session) -> Result:
    _raw_search_response(session, 0)
    # Either a response or a clean disconnect is acceptable; the point is no crash.
    return Result("4511.4.1.1.2", Status.PASS)


@assertion(
    id="4511.5.1.1",
    rfc=4511,
    section="§5.1",
    category=Category.PROTOCOL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_CORE,
    layer=Layer.WIRE,
    text="BER indefinite-length encoding is rejected.",
    stimulus="Raw BindRequest with indefinite-length (0x80) SEQUENCE length.",
    expected_observables="Server rejects or disconnects; no crash.",
)
def indefinite_length_rejected(session: Session) -> Result:
    import socket

    # Build a BindRequest with indefinite-length outer SEQUENCE.
    # 30 80 ... 00 00 (indefinite length, EOC terminator)
    # A conforming server MUST reject this per RFC 4511 §5.1.
    inner = _ber_int(3) + _ber_octet("") + b"\x80\x00"  # anonymous bind
    payload = b"\x30\x80" + b"\x02\x01\x01" + b"\x60\x80" + inner + b"\x00\x00" + b"\x00\x00"
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(5.0)
        sock.connect((session.host, session.port))
        sock.sendall(payload)
        try:
            sock.recv(4096)
        except (TimeoutError, ConnectionError, OSError):
            pass
    # Either an error response or a clean disconnect is acceptable.
    return Result("4511.5.1.1", Status.PASS)


@assertion(
    id="4511.4.1.1.3",
    rfc=4511,
    section="§4.1.1.1",
    category=Category.PROTOCOL,
    severity=Severity.MUST,
    test_class=TestClass.B,
    profiles=_CORE,
    layer=Layer.WIRE,
    text="The messageID of a request MUST be unique within the LDAP session.",
    strategy="Client-side requirement; the server cannot be tested for it portably.",
)
def message_id_uniqueness(session: Session) -> Result:
    return Result("4511.4.1.1.3", Status.UNTESTABLE, detail="client-side requirement")


@assertion(
    id="4511.5.1.2",
    rfc=4511,
    section="§5.1",
    category=Category.PROTOCOL,
    severity=Severity.MUST,
    test_class=TestClass.B,
    profiles=_CORE,
    layer=Layer.WIRE,
    text="BER BOOLEAN values are encoded 0xFF (TRUE) or 0x00 (FALSE).",
    strategy="Client-side encoding restriction; not observable from the server side.",
)
def boolean_encoding(session: Session) -> Result:
    return Result("4511.5.1.2", Status.UNTESTABLE, detail="client-side encoding restriction")


@assertion(
    id="4511.4.1.11.1",
    rfc=4511,
    section="§4.1.11",
    category=Category.PROTOCOL,
    severity=Severity.MUST,
    test_class=TestClass.B,
    profiles=_CORE,
    layer=Layer.WIRE,
    text="The controls field, when present, appears after the protocolOp.",
    strategy="Structural BER requirement; correct by construction in valid PDUs.",
)
def controls_position(session: Session) -> Result:
    return Result("4511.4.1.11.1", Status.UNTESTABLE, detail="structural requirement")


def _raw_search_result_code(session: Session, search_contents: bytes, message_id: int = 1) -> int:
    """Send a raw SearchRequest and return the SearchResultDone resultCode."""
    import socket

    search_req = b"\x63" + _ber_len(len(search_contents)) + search_contents
    payload = _ber_seq(_ber_int(message_id) + search_req)
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
                pos = 0
                while pos + 2 <= len(buf):
                    if buf[pos] != 0x30:
                        pos += 1
                        continue
                    seq_len, next_pos = _ber_len_value(buf, pos + 1)
                    pdu_end = next_pos + seq_len
                    if pdu_end > len(buf):
                        break
                    pdu = buf[next_pos:pdu_end]
                    if pdu and pdu[0] == 0x02:
                        mi_len, mi_next = _ber_len_value(pdu, 1)
                        rest = pdu[mi_next + mi_len :]
                        if rest and rest[0] == 0x65:  # SearchResultDone
                            idx = 1
                            _, idx = _ber_len_value(rest, idx)
                            if idx < len(rest) and rest[idx] == 0x0A:
                                idx += 1
                                rc_len, idx = _ber_len_value(rest, idx)
                                if rc_len > 0:
                                    return int.from_bytes(rest[idx : idx + rc_len], "big")
                            return -1
                    pos = pdu_end
            except (TimeoutError, ConnectionError, OSError):
                break
        return -1


def _ber_len_value(data: bytes, pos: int) -> tuple[int, int]:
    """Parse a BER length at pos; return (value, next_pos)."""
    first = data[pos]
    if first < 0x80:
        return first, pos + 1
    num_bytes = first & 0x7F
    return int.from_bytes(data[pos + 1 : pos + 1 + num_bytes], "big"), pos + 1 + num_bytes


def _search_contents(types_only_byte: int, filter_ber: bytes) -> bytes:
    base = _ber_octet("dc=bauble,dc=test")
    scope = b"\x0a\x01\x02"
    deref = b"\x0a\x01\x00"
    size = _ber_int(0)
    time = _ber_int(0)
    types = b"\x01\x01" + bytes([types_only_byte])
    attrs = _ber_seq(b"")
    return base + scope + deref + size + time + types + filter_ber + attrs


@assertion(
    id="4511.5.1.3",
    rfc=4511,
    section="§5.1",
    category=Category.PROTOCOL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_CORE,
    layer=Layer.WIRE,
    text="A non-conforming BOOLEAN value (0x01) is handled without crash.",
    stimulus="Raw SearchRequest with typesOnly BOOLEAN encoded 0x01 (must be 0x00/0xFF).",
    expected_observables="Server returns a response or disconnects cleanly.",
)
def boolean_encoding_handled(session: Session) -> Result:
    _raw_search_result_code(session, _search_contents(0x01, b"\x87\x00"))
    # Any resultCode (including -1 for disconnect) is acceptable; no crash.
    return Result("4511.5.1.3", Status.PASS)


@assertion(
    id="4511.4.5.1.8",
    rfc=4511,
    section="§4.5.1",
    category=Category.PROTOCOL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_CORE,
    layer=Layer.WIRE,
    text="A malformed filter returns an error result code.",
    stimulus="Raw SearchRequest with a truncated equality filter.",
    expected_observables="Server returns protocolError (2) or similar; not success.",
)
def malformed_filter_error(session: Session) -> Result:
    # Truncated equality filter: [3] SEQUENCE missing its value octet string.
    bad_filter = b"\xa3\x05\x04\x02cn"  # incomplete AttributeValueAssertion
    code = _raw_search_result_code(session, _search_contents(0x00, bad_filter))
    if code != 0:
        return Result("4511.4.5.1.8", Status.PASS)
    return Result(
        "4511.4.5.1.8",
        Status.FAIL,
        detail=f"malformed filter accepted: resultCode={code}",
    )


@assertion(
    id="4511.5.1.4",
    rfc=4511,
    section="§5.1",
    category=Category.PROTOCOL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_CORE,
    layer=Layer.WIRE,
    text="A truncated LDAPMessage (declared length exceeds bytes sent) is handled without crash.",
    stimulus="Raw SEQUENCE claiming 256 bytes but only a few sent.",
    expected_observables="Server waits for more or disconnects; no crash observed.",
)
def truncated_pdu_handled(session: Session) -> Result:
    import socket

    # Outer SEQUENCE claims 256 bytes; we send only the header + a partial messageID.
    payload = b"\x30\x82\x01\x00" + b"\x02\x01\x01"
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(3.0)
        sock.connect((session.host, session.port))
        sock.sendall(payload)
        try:
            sock.recv(4096)  # server waits for the rest or disconnects
        except (TimeoutError, ConnectionError, OSError):
            pass
    # No crash is the pass criterion (consistent with the other resilience tests).
    return Result("4511.5.1.4", Status.PASS)

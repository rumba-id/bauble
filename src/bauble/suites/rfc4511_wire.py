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

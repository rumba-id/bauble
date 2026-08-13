"""Raw wire-level LDAP access for assertions the high-level client cannot send.

The high-level client (ldap3) validates and constructs PDUs, which blocks
several valid-but-edge-case operations (empty-password named bind, unrecognized
protocol version) and all malformed-PDU tests. This module sends and receives
raw BER on a bare socket, bypassing those guards.

No external dependencies beyond the stdlib. The BER construction is hand-built
for the few message types needed; response parsing extracts the fields the
:class:`~bauble.session.Outcome` carries.
"""

from __future__ import annotations

import socket

from bauble.session import Outcome

__all__ = [
    "RawConnection",
    "paged_results_control_value",
    "password_modify_request_value",
    "sort_control_value",
]


# ---------------------------------------------------------------------------
# BER encoding helpers (write side)
# ---------------------------------------------------------------------------


def _encode_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    if length < 0x100:
        return bytes([0x81, length])
    return bytes([0x82, (length >> 8) & 0xFF, length & 0xFF])


def _encode_integer(value: int) -> bytes:
    if value == 0:
        payload = b"\x00"
    else:
        payload = value.to_bytes((value.bit_length() + 8) // 8, "big")
        if value > 0 and payload[0] & 0x80:
            payload = b"\x00" + payload
    return b"\x02" + _encode_length(len(payload)) + payload


def _encode_octet_string(value: str | bytes) -> bytes:
    payload = value.encode("utf-8") if isinstance(value, str) else value
    return b"\x04" + _encode_length(len(payload)) + payload


def _encode_sequence(contents: bytes) -> bytes:
    return b"\x30" + _encode_length(len(contents)) + contents


def _build_bind_request(message_id: int, version: int, dn: str, password: str) -> bytes:
    """Build an LDAPMessage containing a simple-auth BindRequest."""
    auth = b"\x80" + _encode_length(len(password.encode())) + password.encode()
    bind_contents = _encode_integer(version) + _encode_octet_string(dn) + auth
    bind_request = b"\x60" + _encode_length(len(bind_contents)) + bind_contents
    return _encode_sequence(_encode_integer(message_id) + bind_request)


# ---------------------------------------------------------------------------
# BER parsing helpers (read side)
# ---------------------------------------------------------------------------


def _parse_length(data: bytes, pos: int) -> tuple[int, int]:
    """Return (value, next_pos) for a BER length at ``pos``."""
    first = data[pos]
    if first < 0x80:
        return first, pos + 1
    num_bytes = first & 0x7F
    value = int.from_bytes(data[pos + 1 : pos + 1 + num_bytes], "big")
    return value, pos + 1 + num_bytes


def parse_message_id(data: bytes) -> int | None:
    """Extract the messageID (INTEGER) from a raw LDAPMessage, or None.

    RFC 4511 §4.1.1.1: LDAPMessage ::= SEQUENCE { messageID, protocolOp, ... }.
    """
    if len(data) < 2 or data[0] != 0x30:
        return None
    pos = 1
    _, pos = _parse_length(data, pos)
    if pos >= len(data) or data[pos] != 0x02:
        return None
    pos += 1
    int_len, pos = _parse_length(data, pos)
    if pos + int_len > len(data):
        return None
    return int.from_bytes(data[pos : pos + int_len], "big")


def _parse_bind_response(data: bytes) -> Outcome | None:
    """Parse a BindResponse ([APPLICATION 1]) from a raw LDAP message.

    Returns ``None`` if the response is not a valid BindResponse.
    """
    # Skip the outer SEQUENCE tag + length.
    pos = 0
    if pos >= len(data) or data[pos] != 0x30:
        return None
    pos += 1
    _, pos = _parse_length(data, pos)

    # Skip messageID (INTEGER).
    if pos >= len(data) or data[pos] != 0x02:
        return None
    pos += 1
    int_len, pos = _parse_length(data, pos)
    pos += int_len

    # Expect BindResponse [APPLICATION 1] = 0x61.
    if pos >= len(data) or data[pos] != 0x61:
        return None
    pos += 1
    _, pos = _parse_length(data, pos)

    # resultCode (ENUMERATED 0x0a).
    if pos >= len(data) or data[pos] != 0x0A:
        return None
    pos += 1
    code_len, pos = _parse_length(data, pos)
    result_code = int.from_bytes(data[pos : pos + code_len], "big")
    pos += code_len

    # matchedDN (OCTET STRING).
    matched_dn = ""
    if pos < len(data) and data[pos] == 0x04:
        pos += 1
        dn_len, pos = _parse_length(data, pos)
        matched_dn = data[pos : pos + dn_len].decode("utf-8", errors="replace")
        pos += dn_len

    # errorMessage (OCTET STRING).
    message = ""
    if pos < len(data) and data[pos] == 0x04:
        pos += 1
        msg_len, pos = _parse_length(data, pos)
        message = data[pos : pos + msg_len].decode("utf-8", errors="replace")
        pos += msg_len

    # serverSaslCreds ([0] CONTEXT — optional, absent for simple bind).
    server_sasl_creds: bytes | None = None
    if pos < len(data) and data[pos] == 0x80:
        pos += 1
        creds_len, pos = _parse_length(data, pos)
        server_sasl_creds = data[pos : pos + creds_len]
        pos += creds_len

    return Outcome(
        result_code=result_code,
        matched_dn=matched_dn,
        message=message,
        server_sasl_creds=server_sasl_creds,
    )


def paged_results_control_value(page_size: int, cookie: bytes | None = None) -> bytes:
    """BER-encoded value for the Simple Paged Results control (RFC 2696).

    SEQUENCE { size INTEGER, cookie OCTET STRING }
    """
    cookie = cookie or b""
    inner = _encode_integer(page_size) + _encode_octet_string(cookie)
    return _encode_sequence(inner)


def sort_control_value(attributes: list[str]) -> bytes:
    """BER-encoded value for the Server-Side Sorting control (RFC 2891).

    SEQUENCE OF SEQUENCE { attributeType OCTET STRING }
    """
    inner = b"".join(_encode_sequence(_encode_octet_string(attr)) for attr in attributes)
    return _encode_sequence(inner)


def password_modify_request_value(new_password: str, user_dn: str = "") -> bytes:
    """BER-encoded Password Modify request value (RFC 3062).

    SEQUENCE { userIdentity [0] "...", newPasswd [2] "..." }
    If ``user_dn`` is empty the server applies to the bound identity;
    oldPasswd is omitted so the server does not verify it.
    """
    parts = b""
    if user_dn:
        dn_bytes = user_dn.encode()
        parts += b"\x80" + _encode_length(len(dn_bytes)) + dn_bytes
    payload = new_password.encode()
    parts += b"\x82" + _encode_length(len(payload)) + payload
    return _encode_sequence(parts)


def _build_modify_increment(message_id: int, dn: str, attribute: str, increment_by: int) -> bytes:
    """Build an LDAPMessage containing a Modify-Increment request.

    ModifyRequest ::= [APPLICATION 6] SEQUENCE {
        object   LDAPDN,
        changes  SEQUENCE OF change SEQUENCE {
            operation       ENUMERATED { ..., increment (3) },
            modification    AttributeTypeAndValues
        }
    }
    """
    # modification: SEQUENCE { attributeType, SET OF AttributeValue }
    attr_value = _encode_octet_string(str(increment_by))
    attr_set = b"\x31" + _encode_length(len(attr_value)) + attr_value
    mod = _encode_sequence(_encode_octet_string(attribute) + attr_set)

    # change: SEQUENCE { operation ENUMERATED(3), modification }
    op_enum = b"\x0a\x01\x03"  # ENUMERATED, length 1, value 3
    change = _encode_sequence(op_enum + mod)

    # changes: SEQUENCE OF change
    changes = _encode_sequence(change)

    # ModifyRequest: [APPLICATION 6] SEQUENCE { object DN, changes }
    object_dn = _encode_octet_string(dn)
    modify_contents = object_dn + changes
    modify_request = b"\x66" + _encode_length(len(modify_contents)) + modify_contents

    return _encode_sequence(_encode_integer(message_id) + modify_request)


def _parse_ldap_result(data: bytes) -> Outcome | None:
    """Parse a generic LDAPResult from a raw LDAP message.

    Handles ModifyResponse [APPLICATION 7], AddResponse [APPLICATION 9],
    DeleteResponse [APPLICATION 11], etc. — any PDU containing:
    resultCode ENUMERATED, matchedDN OCTET STRING, diagnosticMessage OCTET STRING.
    """
    pos = 0
    # Skip outer SEQUENCE + length.
    if pos >= len(data) or data[pos] != 0x30:
        return None
    pos += 1
    _, pos = _parse_length(data, pos)

    # Skip messageID (INTEGER).
    if pos >= len(data) or data[pos] != 0x02:
        return None
    pos += 1
    int_len, pos = _parse_length(data, pos)
    pos += int_len

    # Expect [APPLICATION 7] = 0x67 (ModifyResponse), etc.
    # We accept any APPLICATION tag >= 0x60.
    if pos >= len(data) or not (0x60 <= data[pos] <= 0x7F):
        return None
    pos += 1
    _, pos = _parse_length(data, pos)

    # resultCode (ENUMERATED 0x0a).
    if pos >= len(data) or data[pos] != 0x0A:
        return None
    pos += 1
    code_len, pos = _parse_length(data, pos)
    result_code = int.from_bytes(data[pos : pos + code_len], "big")
    pos += code_len

    matched_dn = ""
    message = ""
    if pos < len(data) and data[pos] == 0x04:
        pos += 1
        dn_len, pos = _parse_length(data, pos)
        matched_dn = data[pos : pos + dn_len].decode("utf-8", errors="replace")
        pos += dn_len
    if pos < len(data) and data[pos] == 0x04:
        pos += 1
        msg_len, pos = _parse_length(data, pos)
        message = data[pos : pos + msg_len].decode("utf-8", errors="replace")
        pos += msg_len

    return Outcome(result_code=result_code, matched_dn=matched_dn, message=message)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


class RawConnection:
    """A bare TCP socket that sends and receives raw LDAP BER."""

    def __init__(self, host: str, port: int, timeout: float = 5.0) -> None:
        self._host = host
        self._port = port
        self._timeout = timeout

    def _send_and_receive(self, payload: bytes) -> bytes:
        """Send ``payload`` and return the response (empty on disconnect)."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(self._timeout)
            sock.connect((self._host, self._port))
            sock.sendall(payload)
            try:
                return sock.recv(4096)
            except (TimeoutError, ConnectionError, OSError):
                return b""

    def bind(self, version: int, dn: str = "", password: str = "") -> Outcome:
        """Send a raw simple-auth BindRequest with an arbitrary protocol version.

        Returns the parsed :class:`Outcome`, or an Outcome with result_code -1
        if the server disconnected without a valid response.
        """
        payload = _build_bind_request(1, version, dn, password)
        response = self._send_and_receive(payload)
        outcome = _parse_bind_response(response)
        if outcome is None:
            return Outcome(result_code=-1, message="no valid BindResponse")
        return outcome

    def send_malformed(self, payload: bytes) -> bytes | None:
        """Send arbitrary bytes; return the raw response, or ``None`` if the
        server disconnected (expected for malformed PDUs)."""
        response = self._send_and_receive(payload)
        return response if response else None

    def raw_send(self, payload: bytes) -> Outcome:
        """Send a raw LDAP PDU and parse as a generic LDAPResult."""
        response = self._send_and_receive(payload)
        outcome = _parse_ldap_result(response)
        if outcome is None:
            return Outcome(result_code=-1, message="no valid LDAPResult")
        return outcome

    def bind_then_send(self, payload: bytes, dn: str = "", password: str = "") -> Outcome:
        """Bind (simple) then send a PDU on the same connection."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(self._timeout)
            sock.connect((self._host, self._port))
            # Bind first.
            bind_pdu = _build_bind_request(1, 3, dn, password)
            sock.sendall(bind_pdu)
            try:
                bind_resp = sock.recv(4096)
            except (TimeoutError, ConnectionError, OSError):
                return Outcome(result_code=-1, message="bind failed: connection lost")
            bind_outcome = _parse_bind_response(bind_resp)
            if bind_outcome is None or bind_outcome.result_code != 0:
                return Outcome(
                    result_code=bind_outcome.result_code if bind_outcome else -1,
                    message="bind failed",
                )
            # Send the operation PDU.
            sock.sendall(payload)
            try:
                op_resp = sock.recv(4096)
            except (TimeoutError, ConnectionError, OSError):
                return Outcome(result_code=-1, message="operation failed: connection lost")
            outcome = _parse_ldap_result(op_resp)
            if outcome is None:
                return Outcome(result_code=-1, message="no valid LDAPResult")
            return outcome

    def modify_increment(
        self,
        dn: str,
        attribute: str,
        increment_by: int,
        message_id: int = 1,
    ) -> Outcome:
        """Send a Modify-Increment request (RFC 4525).

        Modify operation type 3 increments all values of ``attribute``
        on ``dn`` by ``increment_by``.
        """
        payload = _build_modify_increment(message_id, dn, attribute, increment_by)
        response = self._send_and_receive(payload)
        outcome = _parse_ldap_result(response)
        if outcome is None:
            return Outcome(result_code=-1, message="no valid LDAPResult")
        return outcome

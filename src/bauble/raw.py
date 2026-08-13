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


def build_bind_request_auth(message_id: int, version: int, dn: str, auth_element: bytes) -> bytes:
    """Build a BindRequest with an arbitrary authentication element.

    ``auth_element`` is the raw CHOICE bytes for AuthenticationChoice: simple
    (``\\x80...``), sasl (``\\xa3...``), or an unsupported tag (e.g. ``\\xa5...``).
    """
    bind_contents = _encode_integer(version) + _encode_octet_string(dn) + auth_element
    bind_request = b"\x60" + _encode_length(len(bind_contents)) + bind_contents
    return _encode_sequence(_encode_integer(message_id) + bind_request)


def build_sasl_bind_request(
    message_id: int, version: int, dn: str, mechanism: str, credentials: bytes | None = None
) -> bytes:
    """Build a SASL BindRequest (AuthenticationChoice sasl [3])."""
    mech = _encode_octet_string(mechanism)
    sasl_contents = mech + (_encode_octet_string(credentials) if credentials is not None else b"")
    sasl_seq = b"\x30" + _encode_length(len(sasl_contents)) + sasl_contents
    auth_element = b"\xa3" + _encode_length(len(sasl_seq)) + sasl_seq
    return build_bind_request_auth(message_id, version, dn, auth_element)


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


def password_modify_request_value(
    new_password: str, user_dn: str = "", old_password: str = ""
) -> bytes:
    """BER-encoded Password Modify request value (RFC 3062).

    SEQUENCE { userIdentity [0]?, oldPasswd [1]?, newPasswd [2] }.
    If ``user_dn`` is empty the server applies to the bound identity.
    If ``old_password`` is empty oldPasswd is omitted.
    """
    parts = b""
    if user_dn:
        dn_bytes = user_dn.encode()
        parts += b"\x80" + _encode_length(len(dn_bytes)) + dn_bytes
    if old_password:
        old_bytes = old_password.encode()
        parts += b"\x81" + _encode_length(len(old_bytes)) + old_bytes
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


def _last_complete_message(data: bytes) -> bytes:
    """Return the bytes of the last complete LDAPMessage SEQUENCE in ``data``."""
    last = b""
    pos = 0
    while pos + 2 <= len(data):
        if data[pos] != 0x30:
            pos += 1
            continue
        seq_len, next_pos = _parse_length(data, pos + 1)
        end = next_pos + seq_len
        if end > len(data):
            break
        last = data[pos:end]
        pos = end
    return last


def _controls_of_message(pdu: bytes) -> list[tuple[str, bytes]]:
    """Parse the optional [0] Controls field from one LDAPMessage.

    Each Control is SEQUENCE { controlType OCTET STRING, criticality BOOLEAN?,
    controlValue OCTET STRING? }. criticality is ignored here.
    """
    if len(pdu) < 2 or pdu[0] != 0x30:
        return []
    pos = 1
    _, pos = _parse_length(pdu, pos)  # outer SEQUENCE length
    # messageID (INTEGER 0x02)
    if pos >= len(pdu) or pdu[pos] != 0x02:
        return []
    pos += 1
    mi_len, pos = _parse_length(pdu, pos)
    pos += mi_len
    # protocolOp — skip one definite-length tagged element.
    if pos >= len(pdu):
        return []
    pos += 1
    pop_len, pos = _parse_length(pdu, pos)
    pos += pop_len
    # Optional controls [0] = 0xA0.
    if pos >= len(pdu) or pdu[pos] != 0xA0:
        return []
    pos += 1
    ctrls_len, pos = _parse_length(pdu, pos)
    end = pos + ctrls_len
    controls: list[tuple[str, bytes]] = []
    while pos + 2 <= end:
        if pdu[pos] != 0x30:  # each Control is a SEQUENCE
            break
        pos += 1
        c_len, pos = _parse_length(pdu, pos)
        c_end = pos + c_len
        oid = ""
        value = b""
        seen_oid = False
        while pos + 1 <= c_end and pos + 1 < len(pdu):
            tag = pdu[pos]
            pos += 1
            el_len, pos = _parse_length(pdu, pos)
            el = pdu[pos : pos + el_len]
            pos += el_len
            if tag == 0x04:  # OCTET STRING
                if not seen_oid:
                    oid = el.decode("utf-8", errors="replace")
                    seen_oid = True
                else:
                    value = el
            # 0x01 (criticality BOOLEAN) is ignored.
        if seen_oid:
            controls.append((oid, value))
        pos = c_end
    return controls


def parse_response_controls(data: bytes) -> list[tuple[str, bytes]]:
    """Extract ``(controlType, controlValue)`` pairs from the controls field of
    the last complete LDAPMessage in ``data``. Returns ``[]`` if there are none.

    The controls field is the optional ``[0]`` tag at the end of an
    LDAPMessage, after the messageID and protocolOp.
    """
    last = _last_complete_message(data)
    if not last:
        return []
    return _controls_of_message(last)


def parse_sort_result(control_value: bytes) -> int:
    """Parse the ``sortResult`` ENUMERATED from a sort-response control value.

    ``SortResult ::= SEQUENCE { sortResult ENUMERATED, attributeType [0]? }``.
    ``control_value`` is the OCTET STRING contents (the bytes returned by
    :func:`parse_response_controls`). Returns -1 if unparseable.
    """
    if len(control_value) < 2 or control_value[0] != 0x30:
        return -1
    pos = 1
    _, pos = _parse_length(control_value, pos)
    if pos >= len(control_value) or control_value[pos] != 0x0A:
        return -1
    pos += 1
    n_len, pos = _parse_length(control_value, pos)
    return int.from_bytes(control_value[pos : pos + n_len], "big")


def parse_paged_cookie(control_value: bytes) -> bytes:
    """Parse the cookie from a paged-results response control value.

    ``realSearchControlValue ::= SEQUENCE { size INTEGER, cookie OCTET STRING }``.
    Returns the raw cookie bytes (empty when no more pages remain).
    """
    if len(control_value) < 2 or control_value[0] != 0x30:
        return b""
    pos = 1
    _, pos = _parse_length(control_value, pos)
    if pos >= len(control_value) or control_value[pos] != 0x02:  # size INTEGER
        return b""
    pos += 1
    size_len, pos = _parse_length(control_value, pos)
    pos += size_len
    if pos >= len(control_value) or control_value[pos] != 0x04:  # cookie OCTET STRING
        return b""
    pos += 1
    ck_len, pos = _parse_length(control_value, pos)
    return control_value[pos : pos + ck_len]


def _split_messages(data: bytes) -> list[bytes]:
    """Split raw response bytes into complete LDAPMessage PDUs (definite length)."""
    messages: list[bytes] = []
    pos = 0
    while pos < len(data):
        if data[pos] != 0x30:
            break
        m_len, next_pos = _parse_length(data, pos + 1)
        end = next_pos + m_len
        if end > len(data):
            break
        messages.append(data[pos:end])
        pos = end
    return messages


def parse_search_entries(data: bytes) -> list[dict[str, list[bytes]]]:
    """Extract attribute dicts from SearchResultEntry PDUs in raw response bytes.

    ``SearchResultEntry ::= [APPLICATION 4] SEQUENCE { objectName LDAPDN,
    attributes PartialAttributeList }`` where each attribute is
    ``SEQUENCE { type OCTET STRING, vals SET OF OCTET STRING }``.
    """
    entries: list[dict[str, list[bytes]]] = []
    for msg in _split_messages(data):
        if len(msg) < 2 or msg[0] != 0x30:
            continue
        pos = 1
        _, pos = _parse_length(msg, pos)
        if pos >= len(msg) or msg[pos] != 0x02:  # messageID INTEGER
            continue
        pos += 1
        mi_len, pos = _parse_length(msg, pos)
        pos += mi_len
        if pos >= len(msg) or msg[pos] != 0x64:  # [APPLICATION 4]
            continue
        pos += 1
        entry_len, pos = _parse_length(msg, pos)
        end = pos + entry_len
        # objectName LDAPDN (OCTET STRING)
        if pos >= end or msg[pos] != 0x04:
            continue
        pos += 1
        dn_len, pos = _parse_length(msg, pos)
        pos += dn_len
        # PartialAttributeList (SEQUENCE OF)
        if pos >= end or msg[pos] != 0x30:
            continue
        pos += 1
        attrs_len, pos = _parse_length(msg, pos)
        attrs_end = min(pos + attrs_len, end)
        result: dict[str, list[bytes]] = {}
        while pos + 1 < len(msg) and pos + 1 <= attrs_end:
            if msg[pos] != 0x30:  # each attribute is a SEQUENCE
                break
            pos += 1
            a_len, pos = _parse_length(msg, pos)
            a_end = min(pos + a_len, attrs_end)
            if pos >= a_end or msg[pos] != 0x04:  # type OCTET STRING
                break
            pos += 1
            t_len, pos = _parse_length(msg, pos)
            attr_type = msg[pos : pos + t_len].decode("utf-8", errors="replace")
            pos += t_len
            values: list[bytes] = []
            if pos < a_end and msg[pos] == 0x31:  # vals SET OF
                pos += 1
                set_len, pos = _parse_length(msg, pos)
                set_end = min(pos + set_len, a_end)
                while pos + 1 <= set_end and pos + 1 < len(msg):
                    if msg[pos] != 0x04:
                        break
                    pos += 1
                    v_len, pos = _parse_length(msg, pos)
                    values.append(msg[pos : pos + v_len])
                    pos += v_len
            result[attr_type] = values
            pos = a_end
        entries.append(result)
    return entries


def parse_search_response(data: bytes) -> tuple[int, list[dict[str, list[bytes]]]]:
    """Parse a raw search response stream.

    Returns ``(resultCode, entries)`` where ``resultCode`` comes from the
    SearchResultDone PDU and ``entries`` are the parsed SearchResultEntry
    attribute dicts.
    """
    result_code = -1
    for msg in _split_messages(data):
        outcome = _parse_ldap_result(msg)
        if outcome is not None:
            result_code = outcome.result_code
    return result_code, parse_search_entries(data)


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

    def bind_then_send_raw(self, payload: bytes, dn: str = "", password: str = "") -> bytes:
        """Bind (simple) then send a PDU; return the raw operation-response bytes.

        Reads until the response stream ends (disconnect or read timeout), so a
        full multi-PDU response (e.g. SearchResultEntry* + SearchResultDone) is
        captured for response-control extraction.
        """
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(self._timeout)
            sock.connect((self._host, self._port))
            sock.sendall(_build_bind_request(1, 3, dn, password))
            try:
                sock.recv(4096)  # discard bind response
            except (TimeoutError, ConnectionError, OSError):
                return b""
            sock.sendall(payload)
            buf = b""
            try:
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    buf += chunk
            except (TimeoutError, ConnectionError, OSError):
                pass
            return buf

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

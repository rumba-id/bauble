"""Raw BER wire layer: builders and parsers round-trip correctly."""

from __future__ import annotations

from bauble.raw import (
    build_extensible_match_filter,
    build_search_request,
    paged_results_control_value,
    parse_message_id,
    parse_paged_cookie,
    parse_sort_result,
    password_modify_request_value,
)


def test_parse_message_id_round_trip() -> None:
    payload = build_search_request(42, "dc=bauble,dc=test", ["cn"])
    assert parse_message_id(payload) == 42


def test_parse_message_id_rejects_garbage() -> None:
    assert parse_message_id(b"") is None
    assert parse_message_id(b"\x00\x00") is None


def test_paged_results_cookie_round_trip() -> None:
    value = paged_results_control_value(2, b"cookie-bytes")
    assert parse_paged_cookie(value) == b"cookie-bytes"


def test_paged_results_empty_cookie() -> None:
    value = paged_results_control_value(2)
    assert parse_paged_cookie(value) == b""


def test_parse_sort_result() -> None:
    # SortResult ::= SEQUENCE { sortResult ENUMERATED(16), ... }
    assert parse_sort_result(b"\x30\x03\x0a\x01\x10") == 16


def test_parse_sort_result_rejects_garbage() -> None:
    assert parse_sort_result(b"") == -1
    assert parse_sort_result(b"\x00\x00") == -1


def test_password_modify_request_value_structure() -> None:
    # SEQUENCE { userIdentity [0], oldPasswd [1], newPasswd [2] }
    value = password_modify_request_value("new-pass", "uid=bob", "old-pass")
    assert value[0] == 0x30  # SEQUENCE tag
    assert b"\x80" in value  # userIdentity context tag
    assert b"\x81" in value  # oldPasswd context tag
    assert b"\x82" in value  # newPasswd context tag
    assert b"new-pass" in value


def test_build_extensible_match_filter() -> None:
    filter_ber = build_extensible_match_filter("cn", "caseExactMatch", "alice")
    assert filter_ber[0] == 0xA9  # extensibleMatch [9] tag
    assert b"caseExactMatch" in filter_ber
    assert b"alice" in filter_ber


# ---------------------------------------------------------------------------
# Property-based tests (hypothesis) for BER encoding/decoding primitives
# ---------------------------------------------------------------------------

from hypothesis import HealthCheck, given, settings
from hypothesis.strategies import binary, integers, text

from bauble.raw import (  # pyright: ignore[reportPrivateUsage]
    _encode_integer,
    _encode_length,
    _encode_octet_string,
    _encode_sequence,
    _parse_length,
)


@given(integers(min_value=0, max_value=65535))
@settings(suppress_health_check=[HealthCheck.too_slow])
def test_encode_parse_length_round_trip(length: int) -> None:
    """BER-encoded length round-trips through decode for 0..65535."""
    encoded = _encode_length(length)
    decoded, next_pos = _parse_length(encoded, 0)
    assert decoded == length
    # Verify next_pos matches the encoded length (1 byte short, 2 bytes medium).
    if length < 0x80:
        assert next_pos == 1
    else:
        assert next_pos == (2 if length < 0x100 else 3)


@given(integers(min_value=0, max_value=65535))
def test_encode_length_never_uses_indefinite(length: int) -> None:
    """BER length encoding first byte is never 0x80 (indefinite marker)."""
    encoded = _encode_length(length)
    assert encoded[0] != 0x80


@given(integers(min_value=0, max_value=65535))
def test_encode_length_deterministic(length: int) -> None:
    """Same input always produces the same encoding."""
    a = _encode_length(length)
    b = _encode_length(length)
    assert a == b


@given(integers(min_value=0, max_value=2**31 - 1))
@settings(suppress_health_check=[HealthCheck.too_slow])
def test_encode_parse_integer_round_trip(value: int) -> None:
    """BER-encoded integer round-trips through decode for non-negative range."""
    encoded = _encode_integer(value)
    # Manually decode: skip tag (0x02), parse length, read payload.
    assert encoded[0] == 0x02
    int_len, pos = _parse_length(encoded, 1)
    decoded = int.from_bytes(encoded[pos : pos + int_len], "big")
    assert decoded == value


@given(integers(min_value=0, max_value=2**63 - 1))
def test_encode_integer_never_negative_length(value: int) -> None:
    """Integer encoding always has non-negative length."""
    encoded = _encode_integer(value)
    assert len(encoded) >= 2
    _, length = _parse_length(encoded, 1)
    assert length > 0


@given(binary(min_size=0, max_size=4096))
@settings(suppress_health_check=[HealthCheck.too_slow])
def test_encode_parse_octet_string_round_trip(data: bytes) -> None:
    """BER-encoded OCTET STRING round-trips through decode."""
    encoded = _encode_octet_string(data)
    # Decode: skip tag (0x04), parse length, read payload.
    assert encoded[0] == 0x04
    str_len, pos = _parse_length(encoded, 1)
    decoded = encoded[pos : pos + str_len]
    assert decoded == data


@given(binary(min_size=0, max_size=4096))
def test_encode_octet_string_never_empty_tag(data: bytes) -> None:
    """OCTET STRING encoding always has a valid length byte."""
    encoded = _encode_octet_string(data)
    assert len(encoded) >= 2  # tag + at least one length byte


@given(binary(min_size=0, max_size=4096))
def test_encode_octet_string_never_indefinite(data: bytes) -> None:
    """OCTET STRING length encoding first byte is never 0x80."""
    encoded = _encode_octet_string(data)
    assert encoded[1] != 0x80


@given(text(min_size=0, max_size=1024))
def test_encode_parse_text_as_octet_string_round_trip(s: str) -> None:
    """UTF-8 text round-trips through OCTET STRING encoding."""
    encoded = _encode_octet_string(s)
    assert encoded[0] == 0x04
    str_len, pos = _parse_length(encoded, 1)
    decoded = encoded[pos : pos + str_len].decode("utf-8")
    assert decoded == s


@given(binary(min_size=0, max_size=4096))
@settings(suppress_health_check=[HealthCheck.too_slow])
def test_encode_parse_sequence_round_trip(contents: bytes) -> None:
    """BER-encoded SEQUENCE round-trips through decode."""
    encoded = _encode_sequence(contents)
    # Decode: skip tag (0x30), parse length, read payload.
    assert encoded[0] == 0x30
    seq_len, pos = _parse_length(encoded, 1)
    decoded = encoded[pos : pos + seq_len]
    assert decoded == contents


@given(binary(min_size=0, max_size=4096))
def test_encode_sequence_never_indefinite(contents: bytes) -> None:
    """SEQUENCE length encoding first byte is never 0x80."""
    encoded = _encode_sequence(contents)
    assert encoded[1] != 0x80


@given(integers(min_value=0, max_value=127))
def test_encode_length_short_form(length: int) -> None:
    """Lengths < 0x80 encode as a single byte (short form)."""
    encoded = _encode_length(length)
    assert len(encoded) == 1
    assert encoded[0] == length


@given(integers(min_value=0x80, max_value=0xFF))
def test_encode_length_medium_form(length: int) -> None:
    """Lengths 0x80..0xFF encode as [0x81, byte] (medium form)."""
    encoded = _encode_length(length)
    assert len(encoded) == 2
    assert encoded[0] == 0x81
    assert encoded[1] == length


@given(integers(min_value=0x100, max_value=0xFFFF))
def test_encode_length_long_form(length: int) -> None:
    """Lengths 0x100..0xFFFF encode as [0x82, high, low] (long form)."""
    encoded = _encode_length(length)
    assert len(encoded) == 3
    assert encoded[0] == 0x82
    assert encoded[1] == (length >> 8) & 0xFF
    assert encoded[2] == length & 0xFF


@given(integers(min_value=0, max_value=0xFFFF))
def test_encode_length_boundary_127(length: int) -> None:
    """Length 127 encodes as single byte; 128 starts medium form."""
    assert len(_encode_length(127)) == 1
    assert len(_encode_length(128)) == 2


@given(integers(min_value=0, max_value=0xFFFF))
def test_encode_length_boundary_255(length: int) -> None:
    """Length 255 encodes as medium form; 256 starts long form."""
    assert len(_encode_length(255)) == 2
    assert len(_encode_length(256)) == 3


@given(integers(min_value=0, max_value=0xFFFF))
def test_encode_integer_zero_is_single_byte(value: int) -> None:
    """Integer zero always encodes as [0x02, 0x01, 0x00]."""
    if value == 0:
        encoded = _encode_integer(0)
        assert encoded == b"\x02\x01\x00"


@given(integers(min_value=1, max_value=0x7F))
def test_encode_integer_positive_no_leading_zero(value: int) -> None:
    """Positive integers < 128 never have a leading zero byte."""
    encoded = _encode_integer(value)
    # Payload is just the value byte; no extra 0x00 prefix.
    assert len(encoded) == 3  # tag + length(1) + value(1)


@given(integers(min_value=0, max_value=2**31 - 1))
def test_round_trip_build_and_parse_bind_request(message_id: int) -> None:
    """Build a bind request and verify message ID is preserved."""
    from bauble.raw import _build_bind_request  # pyright: ignore[reportPrivateUsage]

    payload = _build_bind_request(message_id, 3, "dc=test", "secret")
    parsed = parse_message_id(payload)
    assert parsed == message_id

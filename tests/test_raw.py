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

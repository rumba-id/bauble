"""RFC 4511 §4.2 Bind: Class A runner logic against FakeSession."""

from __future__ import annotations

from bauble._fake import FakeSession
from bauble.model import Runner, Status
from bauble.registry import default_registry
from bauble.session import Outcome
from bauble.suites import discover

discover()


def _runner(assertion_id: str) -> Runner:
    runner = default_registry().runner(assertion_id)
    assert runner is not None
    return runner


def test_anonymous_bind_pass() -> None:
    result = _runner("4511.4.2.1")(FakeSession(responder=lambda op, args: Outcome(result_code=0)))
    assert result.status is Status.PASS


def test_anonymous_bind_fail() -> None:
    result = _runner("4511.4.2.1")(FakeSession(responder=lambda op, args: Outcome(result_code=1)))
    assert result.status is Status.FAIL


def test_invalid_credentials_pass() -> None:
    result = _runner("4511.4.2.3")(FakeSession(responder=lambda op, args: Outcome(result_code=49)))
    assert result.status is Status.PASS


def test_invalid_credentials_wrong_code() -> None:
    result = _runner("4511.4.2.3")(FakeSession(responder=lambda op, args: Outcome(result_code=0)))
    assert result.status is Status.FAIL


def test_all_assertions_have_runners() -> None:
    registry = default_registry()
    for aid in (
        "4511.4.2.1",
        "4511.4.2.2",
        "4511.4.2.3",
        "4511.4.2.4",
        "4511.4.2.5",
        "4511.4.2.6",
        "4511.4.2.7",
        "4511.4.2.8",
    ):
        assert registry.runner(aid) is not None, f"{aid} has no runner"


def test_parse_search_entries() -> None:
    from bauble.raw import parse_search_entries

    # Build one SearchResultEntry by hand:
    # [APPLICATION 4] SEQUENCE { dn OCTET, SEQUENCE { SEQUENCE { "cn", SET{ "Alice" } } } }
    def ber_oct(s: str | bytes) -> bytes:
        v = s if isinstance(s, bytes) else s.encode()
        return b"\x04" + bytes([len(v)]) + v

    def ber_set(vals: list[bytes]) -> bytes:
        inner = b"".join(ber_oct(v) for v in vals)
        return b"\x31" + bytes([len(inner)]) + inner

    def ber_seq(c: bytes) -> bytes:
        return b"\x30" + bytes([len(c)]) + c

    attrs = ber_seq(
        ber_seq(ber_oct("cn") + ber_set([b"Alice", b"Bob"]))
        + ber_seq(ber_oct("sn") + ber_set([b"Anderson"]))
    )
    entry = (
        b"\x64"
        + bytes([len(attrs) + len(ber_oct("uid=alice,dc=test"))])
        + ber_oct("uid=alice,dc=test")
        + attrs
    )
    pdu = ber_seq(b"\x02\x01\x01" + entry)
    parsed = parse_search_entries(pdu)
    assert parsed == [{"cn": [b"Alice", b"Bob"], "sn": [b"Anderson"]}]


def test_parse_search_entries_ignores_non_entry_messages() -> None:
    from bauble.raw import parse_search_entries

    # A SearchResultDone PDU (no [APPLICATION 4]) must be ignored.
    done = b"\x30\x05\x02\x01\x01\x6a\x00"
    assert parse_search_entries(done) == []

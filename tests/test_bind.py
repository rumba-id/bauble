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

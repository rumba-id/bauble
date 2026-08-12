"""Runner verdict logic, including the golden broken-fake test."""

from __future__ import annotations

from bauble._fake import FakeSession
from bauble.capability import Capability
from bauble.model import Assertion, Category, Profile, Result, Severity, Status, TestClass
from bauble.registry import Registry
from bauble.runner import run
from bauble.selector import Selector
from bauble.session import Outcome, Session


def _assertion(
    assertion_id: str,
    *,
    test_class: TestClass = TestClass.A,
    requires: tuple[str, ...] = (),
    mutates: bool = False,
    requires_features: tuple[str, ...] = (),
) -> Assertion:
    return Assertion(
        id=assertion_id,
        rfc=1,
        section="§1",
        category=Category.PROTOCOL,
        severity=Severity.MUST,
        test_class=test_class,
        profiles=frozenset({Profile.INTEROP}),
        text=assertion_id,
        requires=requires,
        mutates=mutates,
        requires_features=requires_features,
    )


def _statuses(results: list[Result]) -> dict[str, Status]:
    return {r.assertion_id: r.status for r in results}


def test_pass_and_fail() -> None:
    registry = Registry()
    registry.register(_assertion("1.0.0.1"), runner=lambda s: Result("1.0.0.1", Status.PASS))
    registry.register(
        _assertion("1.0.0.2"), runner=lambda s: Result("1.0.0.2", Status.FAIL, "bad")
    )
    statuses = _statuses(run(Selector(), registry, Capability(), FakeSession()))
    assert statuses["1.0.0.1"] is Status.PASS
    assert statuses["1.0.0.2"] is Status.FAIL


def test_blocked_propagation() -> None:
    registry = Registry()
    registry.register(_assertion("1.0.0.1"), runner=lambda s: Result("1.0.0.1", Status.FAIL))
    registry.register(
        _assertion("1.0.0.2", requires=("1.0.0.1",)),
        runner=lambda s: Result("1.0.0.2", Status.PASS),
    )
    statuses = _statuses(run(Selector(), registry, Capability(), FakeSession()))
    assert statuses["1.0.0.1"] is Status.FAIL
    assert statuses["1.0.0.2"] is Status.BLOCKED


def test_untestable_for_class_b() -> None:
    registry = Registry()
    registry.register(_assertion("1.0.0.1", test_class=TestClass.B))
    statuses = _statuses(run(Selector(), registry, Capability(), FakeSession()))
    assert statuses["1.0.0.1"] is Status.UNTESTABLE


def test_auto_pass_when_not_writable() -> None:
    registry = Registry()
    registry.register(
        _assertion("1.0.0.1", mutates=True),
        runner=lambda s: Result("1.0.0.1", Status.PASS),
    )
    statuses = _statuses(run(Selector(), registry, Capability(writable=False), FakeSession()))
    assert statuses["1.0.0.1"] is Status.NOT_APPLICABLE


def test_auto_pass_when_feature_unsupported() -> None:
    registry = Registry()
    registry.register(
        _assertion("1.0.0.1", requires_features=("alt_server",)),
        runner=lambda s: Result("1.0.0.1", Status.PASS),
    )
    statuses = _statuses(run(Selector(), registry, Capability(alt_server=False), FakeSession()))
    assert statuses["1.0.0.1"] is Status.NOT_APPLICABLE


def test_runner_exception_is_fail() -> None:
    def boom(_session: Session) -> Result:
        raise RuntimeError("kaboom")

    registry = Registry()
    registry.register(_assertion("1.0.0.1"), runner=boom)
    statuses = _statuses(run(Selector(), registry, Capability(), FakeSession()))
    assert statuses["1.0.0.1"] is Status.FAIL


def test_broken_fake_drives_fail_verdict() -> None:
    """Golden test: a fake returning the wrong result code yields FAIL, and a
    healthy fake yields PASS for the same assertion."""

    def bind_succeeds(session: Session) -> Result:
        outcome = session.bind("cn=x", "pw")
        return Result("1.0.0.1", Status.PASS if outcome.result_code == 0 else Status.FAIL)

    registry = Registry()
    registry.register(_assertion("1.0.0.1"), runner=bind_succeeds)

    broken = FakeSession(responder=lambda op, args: Outcome(result_code=49))
    assert _statuses(run(Selector(), registry, Capability(), broken))["1.0.0.1"] is Status.FAIL

    healthy = FakeSession(responder=lambda op, args: Outcome(result_code=0))
    assert _statuses(run(Selector(), registry, Capability(), healthy))["1.0.0.1"] is Status.PASS

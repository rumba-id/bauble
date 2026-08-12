"""Registry: registration, lookup, duplicate guard, and discovery."""

from __future__ import annotations

import pytest

from bauble.model import (
    Assertion,
    Category,
    Profile,
    Result,
    Severity,
    Status,
    TestClass,
)
from bauble.registry import Registry, default_registry


def _assertion(assertion_id: str = "1.0.0.1") -> Assertion:
    return Assertion(
        id=assertion_id,
        rfc=1,
        section="§1",
        category=Category.PROTOCOL,
        severity=Severity.MUST,
        test_class=TestClass.A,
        profiles=frozenset({Profile.BASE}),
        text=assertion_id,
    )


def test_register_and_get() -> None:
    registry = Registry()
    assertion = _assertion()
    registry.register(assertion, runner=lambda s: Result("1.0.0.1", Status.PASS))
    assert "1.0.0.1" in registry
    assert registry.get("1.0.0.1") is assertion
    assert registry.runner("1.0.0.1") is not None
    assert len(registry) == 1


def test_lookup_helpers() -> None:
    registry = Registry()
    registry.register(_assertion("1.0.0.1"))
    assert len(registry.by_rfc(1)) == 1
    assert len(registry.by_profile(Profile.BASE)) == 1
    assert len(registry.by_category(Category.PROTOCOL)) == 1
    assert len(registry.by_profile(Profile.STANDARD)) == 0


def test_duplicate_raises() -> None:
    registry = Registry()
    registry.register(_assertion())
    with pytest.raises(ValueError):
        registry.register(_assertion())


def test_discovery_registers_bind_assertions() -> None:
    from bauble.suites import discover

    discover()
    registry = default_registry()
    assert "4511.4.2.1" in registry
    assert "4511.4.2.8" in registry
    assert len(registry.by_rfc(4511)) == 31

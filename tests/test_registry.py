"""Phase 0: registry, decorator, and discovery wiring."""

from __future__ import annotations

import pytest

from bauble.model import (
    Assertion,
    Category,
    Profile,
    Severity,
    TestClass,
)
from bauble.registry import default_registry
from bauble.suites import discover

# Importing the suites package registers assertions; discover() is idempotent.
discover()


def test_discovery_registers_stub_assertion() -> None:
    registry = default_registry()
    assert "0.0.0.1" in registry
    assertion = registry.get("0.0.0.1")
    assert assertion.rfc == 0
    assert assertion.severity is Severity.MAY
    assert assertion.test_class is TestClass.A
    assert Profile.NONE in assertion.profiles
    assert registry.runner("0.0.0.1") is not None


def test_lookup_helpers_filter_correctly() -> None:
    registry = default_registry()
    assert len(registry.by_rfc(0)) == 1
    assert len(registry.by_profile(Profile.NONE)) == 1
    assert len(registry.by_category(Category.PROTOCOL)) == 1
    assert len(registry.by_profile(Profile.BASE)) == 0


def test_duplicate_registration_raises() -> None:
    registry = default_registry()
    duplicate = Assertion(
        id="0.0.0.1",
        rfc=0,
        section="—",
        category=Category.PROTOCOL,
        severity=Severity.MAY,
        test_class=TestClass.A,
        profiles=frozenset({Profile.NONE}),
        text="duplicate",
    )
    with pytest.raises(ValueError):
        registry.register(duplicate)

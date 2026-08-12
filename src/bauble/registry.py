"""The assertion registry: a flat store of assertions and their runners.

Suite modules register at import time via :func:`bauble.suites._base.assertion`;
:mod:`bauble.suites` discovers and imports them. The registry is queried by id,
RFC, profile, and category. Selection by named scenario arrives with the
``scenarios`` module in Phase 1.
"""

from __future__ import annotations

from bauble.model import Assertion, Category, Profile, Runner

__all__ = ["Registry", "default_registry"]


class Registry:
    """Stores assertions keyed by id, with their optional runner functions."""

    def __init__(self) -> None:
        self._assertions: dict[str, Assertion] = {}
        self._runners: dict[str, Runner] = {}

    def register(self, assertion: Assertion, runner: Runner | None = None) -> None:
        """Add an assertion, optionally with the runner that executes it.

        Raises:
            ValueError: if ``assertion.id`` is already registered.
        """
        if assertion.id in self._assertions:
            raise ValueError(f"duplicate assertion id: {assertion.id}")
        self._assertions[assertion.id] = assertion
        if runner is not None:
            self._runners[assertion.id] = runner

    def get(self, assertion_id: str) -> Assertion:
        """Return the assertion with ``assertion_id``."""
        return self._assertions[assertion_id]

    def runner(self, assertion_id: str) -> Runner | None:
        """Return the runner for ``assertion_id``, or ``None`` if untestable."""
        return self._runners.get(assertion_id)

    def all(self) -> list[Assertion]:
        """All registered assertions."""
        return list(self._assertions.values())

    def by_rfc(self, rfc: int) -> list[Assertion]:
        """Assertions sourced from ``rfc``."""
        return [a for a in self._assertions.values() if a.rfc == rfc]

    def by_profile(self, profile: Profile) -> list[Assertion]:
        """Assertions belonging to ``profile``."""
        return [a for a in self._assertions.values() if profile in a.profiles]

    def by_category(self, category: Category) -> list[Assertion]:
        """Assertions in ``category``."""
        return [a for a in self._assertions.values() if a.category == category]

    def __len__(self) -> int:
        return len(self._assertions)

    def __contains__(self, assertion_id: object) -> bool:
        return assertion_id in self._assertions


_default = Registry()


def default_registry() -> Registry:
    """The global registry suite modules register into at import time."""
    return _default

"""Named scenarios: convenience selections over the registry.

Profiles are not enumerated here. A profile selection derives from each
assertion's ``profiles`` tag, so adding an assertion tagged BASE automatically
includes it in BASE. A scenario is a named filter (e.g. ``bind``) for
cross-cutting groupings.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from bauble.model import Assertion

__all__ = ["SCENARIOS", "Scenario", "get_scenario", "scenario_matches"]


@dataclass(frozen=True)
class Scenario:
    """A named filter over assertions."""

    name: str
    description: str
    matches: Callable[[Assertion], bool]


def _section_is(assertion: Assertion, rfc: int, prefix: str) -> bool:
    return assertion.rfc == rfc and assertion.section.startswith(prefix)


SCENARIOS: dict[str, Scenario] = {
    "bind": Scenario("bind", "RFC 4511 §4.2 Bind", lambda a: _section_is(a, 4511, "§4.2")),
    "search": Scenario("search", "RFC 4511 §4.5 Search", lambda a: _section_is(a, 4511, "§4.5")),
    "self-check": Scenario("self-check", "bauble wiring self-checks", lambda a: a.rfc == 0),
}


def get_scenario(name: str) -> Scenario | None:
    """Return the named scenario, or ``None`` if no such scenario exists."""
    return SCENARIOS.get(name)


def scenario_matches(name: str, assertion: Assertion) -> bool:
    """Whether ``assertion`` belongs to the named scenario."""
    scenario = SCENARIOS.get(name)
    return scenario.matches(assertion) if scenario is not None else False

"""Selection of assertions by profile, RFC, scenario, and other dimensions.

Combine semantics: AND across dimensions, OR within a dimension. ``--rfc
4511,4515`` means RFC 4511 OR 4515; ``--profile base --rfc 4511`` means both
must hold. An empty selector matches every assertion.
"""

from __future__ import annotations

from dataclasses import dataclass

from bauble.model import Assertion, Category, Profile, Severity, TestClass
from bauble.scenarios import scenario_matches

__all__ = ["Selector"]


@dataclass(frozen=True)
class Selector:
    """A multi-dimensional filter over the assertion registry."""

    profiles: frozenset[Profile] = frozenset()
    rfcs: frozenset[int] = frozenset()
    scenarios: frozenset[str] = frozenset()
    assertions: frozenset[str] = frozenset()
    categories: frozenset[Category] = frozenset()
    severities: frozenset[Severity] = frozenset()
    test_classes: frozenset[TestClass] = frozenset()
    exclude: frozenset[str] = frozenset()
    allow_mutation: bool = False

    def matches(self, assertion: Assertion) -> bool:
        """Whether ``assertion`` satisfies this selector."""
        if assertion.id in self.exclude:
            return False
        if self.profiles and not any(p in assertion.profiles for p in self.profiles):
            return False
        if self.rfcs and assertion.rfc not in self.rfcs:
            return False
        if self.assertions and assertion.id not in self.assertions:
            return False
        if self.categories and assertion.category not in self.categories:
            return False
        if self.severities and assertion.severity not in self.severities:
            return False
        if self.test_classes and assertion.test_class not in self.test_classes:
            return False
        return not self.scenarios or any(
            scenario_matches(name, assertion) for name in self.scenarios
        )

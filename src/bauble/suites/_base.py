"""Decorator and helpers for declaring assertions in suite modules."""

from __future__ import annotations

from collections.abc import Callable

from bauble.model import (
    Assertion,
    Category,
    Layer,
    Profile,
    Runner,
    Severity,
    TestClass,
)
from bauble.registry import default_registry

__all__ = ["assertion"]


def assertion(
    *,
    id: str,
    rfc: int,
    section: str,
    category: Category,
    severity: Severity,
    test_class: TestClass,
    profiles: frozenset[Profile],
    text: str,
    layer: Layer = Layer.SEMANTIC,
    oid: str = "",
    strategy: str = "",
    requires: tuple[str, ...] = (),
    mutates: bool = False,
    requires_features: tuple[str, ...] = (),
    preconditions: str = "",
    stimulus: str = "",
    expected_observables: str = "",
) -> Callable[[Runner], Runner]:
    """Register an assertion and its runner in the default registry."""

    def decorator(runner: Runner) -> Runner:
        default_registry().register(
            Assertion(
                id=id,
                rfc=rfc,
                section=section,
                category=category,
                severity=severity,
                test_class=test_class,
                profiles=profiles,
                text=text,
                layer=layer,
                oid=oid,
                strategy=strategy,
                requires=requires,
                mutates=mutates,
                requires_features=requires_features,
                preconditions=preconditions,
                stimulus=stimulus,
                expected_observables=expected_observables,
            ),
            runner=runner,
        )
        return runner

    return decorator

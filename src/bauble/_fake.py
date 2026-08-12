"""A scriptable in-memory Session for tests.

The Phase 1 runner is validated against this fake; the Phase 2 harness swaps
in a real ldap3-backed Session behind the same Protocol.
"""

from __future__ import annotations

from collections.abc import Callable

from bauble.session import Control, Entry, Modification, Outcome

__all__ = ["FakeSession"]

Responder = Callable[[str, dict[str, object]], Outcome]


def _success(_op: str, _args: dict[str, object]) -> Outcome:
    return Outcome(result_code=0)


class FakeSession:
    """In-memory Session whose responses are scriptable.

    ``responder`` maps ``(op_name, args_dict)`` to an :class:`Outcome`. The
    default responder returns success (result code 0). Each call is recorded
    in :attr:`calls` so tests can assert on what was invoked.
    """

    def __init__(self, responder: Responder | None = None) -> None:
        self._responder: Responder = responder or _success
        self.calls: list[tuple[str, dict[str, object]]] = []

    def _respond(self, op: str, **args: object) -> Outcome:
        self.calls.append((op, args))
        return self._responder(op, args)

    def bind(self, dn: str | None, password: str | None) -> Outcome:
        return self._respond("bind", dn=dn, password=password)

    def search(
        self,
        base: str,
        scope: int,
        filter_: str,
        attributes: list[str] | None = None,
        controls: tuple[Control, ...] = (),
    ) -> tuple[Outcome, list[Entry]]:
        outcome = self._respond(
            "search",
            base=base,
            scope=scope,
            filter_=filter_,
            attributes=attributes,
            controls=controls,
        )
        return outcome, []

    def add(self, dn: str, attributes: dict[str, list[str | bytes]]) -> Outcome:
        return self._respond("add", dn=dn, attributes=attributes)

    def modify(self, dn: str, changes: list[Modification]) -> Outcome:
        return self._respond("modify", dn=dn, changes=changes)

    def delete(self, dn: str) -> Outcome:
        return self._respond("delete", dn=dn)

    def compare(self, dn: str, attribute: str, value: str) -> Outcome:
        return self._respond("compare", dn=dn, attribute=attribute, value=value)

    def unbind(self) -> None:
        self._respond("unbind")

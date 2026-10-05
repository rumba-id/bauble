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

    For assertions that need entry data (search result counts, attribute values),
    supply ``entries`` when calling :meth:`search`, or use :meth:`add_entry` to
    pre-populate the fake DIT before the call. Entries are scoped per-session so
    each test gets a clean slate.
    """

    host: str = ""
    port: int = 0

    def __init__(self, responder: Responder | None = None) -> None:
        self._responder: Responder = responder or _success
        self.calls: list[tuple[str, dict[str, object]]] = []
        self._entries: dict[str, dict[str, list[str | bytes]]] = {}

    def add_entry(self, dn: str, attributes: dict[str, list[str | bytes]]) -> None:
        """Insert an entry into the fake DIT.

        The entry is returned by :meth:`search` when it matches the base DN
        and scope. Attribute matching uses simple equality (first value).
        """
        self._entries[dn] = dict(attributes)

    def clear_entries(self) -> None:
        """Remove all entries from the fake DIT."""
        self._entries.clear()

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
        deref_aliases: int = 0,
        entries: list[Entry] | None = None,
    ) -> tuple[Outcome, list[Entry]]:
        outcome = self._respond(
            "search",
            base=base,
            scope=scope,
            filter_=filter_,
            attributes=attributes,
            controls=controls,
        )
        if entries is not None:
            return outcome, entries
        # Fall back to the internal DIT store populated via add_entry().
        matched = self._match_entries(base, scope)
        return outcome, matched

    def _match_entries(self, base: str, scope: int) -> list[Entry]:
        """Return entries from the fake DIT matching ``base`` and ``scope``."""
        results: list[Entry] = []
        for dn, attrs in self._entries.items():
            if scope == 0:
                # Base object: exact match on base DN.
                if dn == base:
                    results.append(Entry(dn=dn, attributes=attrs))
            elif scope == 1:
                # Single-level: direct child of base.
                if self._is_direct_child(base, dn):
                    results.append(Entry(dn=dn, attributes=attrs))
            else:
                # Whole-subtree: base or any descendant.
                if dn == base or self._is_descendant(base, dn):
                    results.append(Entry(dn=dn, attributes=attrs))
        return results

    @staticmethod
    def _is_direct_child(parent: str, child: str) -> bool:
        """True when ``child`` is one RDN below ``parent``."""
        if not parent:
            return False
        child_parts = child.split(",")
        # Must have exactly one more component than the parent.
        if len(child_parts) != len(parent.split(",")) + 1:
            return False
        # The suffix (everything after the first RDN) must match the parent DN.
        child_suffix = ",".join(child_parts[1:])
        return child_suffix == parent

    @staticmethod
    def _is_descendant(ancestor: str, descendant: str) -> bool:
        """True when ``descendant`` is under ``ancestor`` in the DIT."""
        if not ancestor or descendant == ancestor:
            return False
        return descendant.endswith("," + ancestor)

    def add(self, dn: str, attributes: dict[str, list[str | bytes]]) -> Outcome:
        return self._respond("add", dn=dn, attributes=attributes)

    def modify(self, dn: str, changes: list[Modification]) -> Outcome:
        return self._respond("modify", dn=dn, changes=changes)

    def delete(self, dn: str) -> Outcome:
        return self._respond("delete", dn=dn)

    def compare(self, dn: str, attribute: str, value: str) -> Outcome:
        return self._respond("compare", dn=dn, attribute=attribute, value=value)

    def modify_dn(
        self,
        dn: str,
        new_rdn: str,
        delete_old_rdn: bool = True,
        new_superior: str | None = None,
    ) -> Outcome:
        return self._respond(
            "modify_dn",
            dn=dn,
            new_rdn=new_rdn,
            delete_old_rdn=delete_old_rdn,
            new_superior=new_superior,
        )

    def extended(self, request_name: str, request_value: bytes | None = None) -> Outcome:
        return self._respond("extended", request_name=request_name, request_value=request_value)

    def start_tls(self) -> Outcome:
        return self._respond("start_tls")

    def unbind(self) -> None:
        self._respond("unbind")

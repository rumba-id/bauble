"""The :class:`Session` contract: the surface every assertion may call.

Both the in-memory fake (Phase 1) and the ldap3-backed harness (Phase 2)
implement this Protocol, so an assertion is independent of how it reaches the
server under test.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

__all__ = ["Control", "Entry", "Modification", "Outcome", "Session"]

#: LDAP search scopes (RFC 4511 §4.5.1): base, one-level, whole-subtree.
SCOPE_BASE_OBJECT = 0
SCOPE_SINGLE_LEVEL = 1
SCOPE_WHOLE_SUBTREE = 2

#: LDAP modify operations (RFC 4511 §4.6): add, delete, replace.
MOD_ADD = 0
MOD_DELETE = 1
MOD_REPLACE = 2


@dataclass(frozen=True)
class Outcome:
    """The full response envelope of an LDAP operation.

    Carrying the result code, matched DN, referrals, and diagnostic message
    (not just success/failure) is what makes most negative paths testable.
    """

    result_code: int
    matched_dn: str = ""
    referrals: tuple[str, ...] = ()
    message: str = ""
    server_sasl_creds: bytes | None = None


@dataclass(frozen=True)
class Entry:
    """A directory entry returned by search."""

    dn: str
    attributes: dict[str, list[str | bytes]]


@dataclass(frozen=True)
class Control:
    """An LDAP control (RFC 4511 §4.1.12).

    Constructible with any OID and criticality, which lets assertions exercise
    the unknown-critical-control path.
    """

    oid: str
    value: bytes | None = None
    criticality: bool = False


@dataclass(frozen=True)
class Modification:
    """A single change in a modify request (RFC 4511 §4.6)."""

    operation: int
    attribute: str
    values: list[str | bytes]


@runtime_checkable
class Session(Protocol):
    """The operations an assertion may invoke against the server under test."""

    host: str
    port: int

    def bind(self, dn: str | None, password: str | None) -> Outcome: ...

    def search(
        self,
        base: str,
        scope: int,
        filter_: str,
        attributes: list[str] | None = None,
        controls: tuple[Control, ...] = (),
    ) -> tuple[Outcome, list[Entry]]: ...

    def add(self, dn: str, attributes: dict[str, list[str | bytes]]) -> Outcome: ...

    def modify(self, dn: str, changes: list[Modification]) -> Outcome: ...

    def delete(self, dn: str) -> Outcome: ...

    def compare(self, dn: str, attribute: str, value: str) -> Outcome: ...

    def unbind(self) -> None: ...

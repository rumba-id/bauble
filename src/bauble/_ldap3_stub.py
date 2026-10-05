"""Minimal type stub for the subset of ldap3.Connection we use.

ldap3 ships with partial type information but is too large to depend on fully.
This module defines a Protocol describing only the methods and attributes that
LdapSession accesses, so pyright can verify correctness without importing
the full ldap3 package at type-check time.
"""

from __future__ import annotations

from typing import Any, Protocol

# ---------------------------------------------------------------------------
# Constants (ldap3 exports these as module-level attributes)
# ---------------------------------------------------------------------------
# Constants (ldap3 exports these as module-level attributes)
# ---------------------------------------------------------------------------

#: LDAP search scope: baseObject.
LDAP_SCOPE_BASE: str = "BASE"
#: LDAP search scope: singleLevel.
LDAP_SCOPE_SINGLE: str = "LEVEL"
#: LDAP search scope: wholeSubtree.
LDAP_SCOPE_SUBTREE: str = "SUBTREE"

#: Simple bind authentication mechanism (anonymous).
LDAP_AUTH_ANONYMOUS: str = "ANONYMOUS"

#: Modify operation: add value(s).
LDAP_MOD_ADD: str = "MODIFY_ADD"
#: Modify operation: delete value(s).
LDAP_MOD_DELETE: str = "MODIFY_DELETE"
#: Modify operation: replace value(s).
LDAP_MOD_REPLACE: str = "MODIFY_REPLACE"


# ---------------------------------------------------------------------------
# Protocol — the ldap3.Connection surface we use
# ---------------------------------------------------------------------------


class _Ldap3Connection(Protocol):
    """Minimal protocol matching the subset of ldap3.Connection used by bauble."""

    # -- lifecycle ----------------------------------------------------------

    def open(self) -> bool: ...

    def start_tls(self) -> bool: ...

    def unbind(self) -> None: ...

    # -- bind ---------------------------------------------------------------

    #: Current binding identity (set to ``None`` for anonymous re-bind).
    user: str | None

    #: Current binding password.
    password: str | None

    #: Authentication mechanism string.
    authentication: str

    def rebind(
        self,
        user: str | None = ...,
        password: str | None = ...,
        authentication: str = ...,
        controls: list[tuple[str, bool, bytes | None]] | None = ...,
    ) -> bool: ...

    # -- result envelope ----------------------------------------------------

    #: Last operation's result dict (keys: ``"result"``, ``"dn"``,
    #: ``"referrals"``, ``"description"``).
    result: dict[str, Any]

    # -- operations ---------------------------------------------------------

    def search(
        self,
        search_base: str,
        search_filter: str,
        search_scope: int | str = ...,
        attributes: list[str] | None = ...,
        controls: list[tuple[str, bool, bytes | None]] | None = ...,
        dereference_aliases: int = ...,
        paged_size: int = ...,
        paged_cookie: bytes | None = ...,
    ) -> bool: ...

    #: Raw response items from the last :meth:`search` call.
    #: Each item is a dict with keys like ``"type"``, ``"dn"``,
    #: ``"attributes"``, ``"uri"``.
    response: list[dict[str, Any]] | None

    def add(
        self,
        dn: str,
        object_class: list[str | bytes] = ...,
        attributes: dict[str, list[str | bytes]] = ...,
    ) -> bool: ...

    def modify(
        self,
        dn: str,
        changes: dict[str, list[tuple[str, list[str | bytes]]]],
    ) -> bool: ...

    def delete(self, dn: str) -> bool: ...

    def compare(
        self,
        dn: str,
        attribute: str,
        value: str,
    ) -> bool: ...

    def modify_dn(
        self,
        dn: str,
        new_rdn: str,
        delete_old_dn: bool = ...,
        new_superior: str | None = ...,
    ) -> bool: ...

    def extended(self, request_name: str, request_value: bytes | None = ...) -> bool: ...


def get_connection(server: Any) -> _Ldap3Connection:
    """Return an ldap3.Connection typed as our protocol.

    At runtime this is a no-op cast; during type checking pyright uses the
    return annotation to infer types for ``self._connection``.
    """
    from typing import cast

    import ldap3

    conn = ldap3.Connection(server, fast_decoder=True)
    return cast(_Ldap3Connection, conn)  # type: ignore[return-value]


def get_server(host: str, port: int, use_ssl: bool, connect_timeout: float) -> Any:
    """Return an ldap3.Server typed as Any (we never access its members)."""
    import ldap3

    return ldap3.Server(
        host=host,
        port=port,
        use_ssl=use_ssl,
        connect_timeout=connect_timeout,
    )

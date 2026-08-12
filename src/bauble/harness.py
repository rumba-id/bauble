"""ldap3-backed :class:`~bauble.session.Session` implementation.

This is the real Session the runner uses against a server under test (Phase 2),
swapped in behind the same Protocol the Phase 1 fake implements. ldap3 is a
dynamic library with partial type information, so the connection is held as
``Any``; the pure mappers are typed and unit-tested.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import ldap3

from bauble.session import Control, Entry, Modification, Outcome

__all__ = ["LdapSession", "ServerConfig"]

#: bauble scope ints (RFC 4511 §4.5.1) -> ldap3 search-scope constants.
_SCOPE: dict[int, Any] = {
    0: ldap3.BASE,
    1: ldap3.LEVEL,
    2: ldap3.SUBTREE,
}

#: bauble modify-op ints (RFC 4511 §4.6) -> ldap3 modify constants.
_MOD: dict[int, Any] = {
    0: ldap3.MODIFY_ADD,
    1: ldap3.MODIFY_DELETE,
    2: ldap3.MODIFY_REPLACE,
}


@dataclass(frozen=True)
class ServerConfig:
    """How to reach the server under test."""

    host: str
    port: int = 389
    use_ssl: bool = False
    use_start_tls: bool = False
    connect_timeout: float = 5.0


def outcome_from_result(result: Any) -> Outcome:
    """Build an Outcome from an ldap3 result mapping."""
    raw_code = result.get("result", -1)
    code = raw_code if isinstance(raw_code, int) else -1
    return Outcome(
        result_code=code,
        matched_dn=str(result.get("dn", "")),
        referrals=tuple(result.get("referrals") or ()),
        message=str(result.get("description", "")),
    )


def ldap3_changes(
    changes: list[Modification],
) -> dict[str, list[tuple[Any, list[str | bytes]]]]:
    """Convert bauble Modifications to the ldap3 ``changes`` mapping."""
    mapped: dict[str, list[tuple[Any, list[str | bytes]]]] = {}
    for change in changes:
        mapped[change.attribute] = [(_MOD[change.operation], list(change.values))]
    return mapped


class LdapSession:
    """A :class:`~bauble.session.Session` backed by ldap3."""

    def __init__(self, config: ServerConfig) -> None:
        self._config = config
        self.host: str = config.host
        self.port: int = config.port
        self._server: Any = ldap3.Server(
            host=config.host,
            port=config.port,
            use_ssl=config.use_ssl,
            connect_timeout=config.connect_timeout,
        )
        self._connection: Any = ldap3.Connection(self._server, fast_decoder=True)
        self._opened = False

    def _ensure_open(self) -> None:
        if not self._opened:
            self._connection.open()
            if self._config.use_start_tls:
                self._connection.start_tls()
            self._opened = True

    def bind(self, dn: str | None, password: str | None) -> Outcome:
        self._ensure_open()
        self._connection.rebind(user=dn, password=password)
        return outcome_from_result(self._connection.result)

    def search(
        self,
        base: str,
        scope: int,
        filter_: str,
        attributes: list[str] | None = None,
        controls: tuple[Control, ...] = (),
    ) -> tuple[Outcome, list[Entry]]:
        self._ensure_open()
        self._connection.search(
            search_base=base,
            search_filter=filter_,
            search_scope=_SCOPE[scope],
            attributes=attributes or ["*"],
            controls=[(c.oid, c.criticality, c.value) for c in controls],
        )
        raw_response: list[Any] = list(self._connection.response or [])
        entries: list[Entry] = []
        for item in raw_response:
            if item.get("type") != "searchResEntry":
                continue
            raw_attrs: Any = item.get("attributes") or {}
            attribute_map: dict[str, list[str | bytes]] = {
                str(key): list(val) for key, val in raw_attrs.items()
            }
            entries.append(Entry(dn=str(item.get("dn", "")), attributes=attribute_map))
        return outcome_from_result(self._connection.result), entries

    def add(self, dn: str, attributes: dict[str, list[str | bytes]]) -> Outcome:
        self._ensure_open()
        object_classes: list[str | bytes] = []
        for key, value in attributes.items():
            if key.lower() == "objectclass":
                object_classes = list(value)
                break
        clean = {key: value for key, value in attributes.items() if key.lower() != "objectclass"}
        self._connection.add(dn, object_class=object_classes, attributes=clean)
        return outcome_from_result(self._connection.result)

    def modify(self, dn: str, changes: list[Modification]) -> Outcome:
        self._ensure_open()
        self._connection.modify(dn, changes=ldap3_changes(changes))
        return outcome_from_result(self._connection.result)

    def delete(self, dn: str) -> Outcome:
        self._ensure_open()
        self._connection.delete(dn)
        return outcome_from_result(self._connection.result)

    def compare(self, dn: str, attribute: str, value: str) -> Outcome:
        self._ensure_open()
        self._connection.compare(dn, attribute, value)
        return outcome_from_result(self._connection.result)

    def modify_dn(
        self,
        dn: str,
        new_rdn: str,
        delete_old_rdn: bool = True,
        new_superior: str | None = None,
    ) -> Outcome:
        self._ensure_open()
        self._connection.modify_dn(
            dn, new_rdn, delete_old_dn=delete_old_rdn, new_superior=new_superior
        )
        return outcome_from_result(self._connection.result)

    def extended(self, request_name: str, request_value: bytes | None = None) -> Outcome:
        self._ensure_open()
        self._connection.extended(request_name, request_value)
        return outcome_from_result(self._connection.result)

    def unbind(self) -> None:
        if self._opened:
            self._connection.unbind()
            self._opened = False

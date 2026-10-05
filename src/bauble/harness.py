"""ldap3-backed :class:`~bauble.session.Session` implementation.

This is the real Session the runner uses against a server under test (Phase 2),
swapped in behind the same Protocol the Phase 1 fake implements. The ldap3
connection is typed via :mod:`bauble._ldap3_stub` so pyright can verify method
calls and attribute access.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from bauble._ldap3_stub import (  # pyright: ignore[reportPrivateUsage]
    LDAP_AUTH_ANONYMOUS,
    LDAP_MOD_ADD,
    LDAP_MOD_DELETE,
    LDAP_MOD_REPLACE,
    LDAP_SCOPE_BASE,
    LDAP_SCOPE_SINGLE,
    LDAP_SCOPE_SUBTREE,
    _Ldap3Connection,  # pyright: ignore[reportPrivateUsage]
    get_connection,
    get_server,
)
from bauble.session import Control, Entry, Modification, Outcome

__all__ = ["LdapSession", "ServerConfig"]

#: bauble scope ints (RFC 4511 §4.5.1) -> ldap3 search-scope constants.
_SCOPE: dict[int, str] = {
    0: LDAP_SCOPE_BASE,
    1: LDAP_SCOPE_SINGLE,
    2: LDAP_SCOPE_SUBTREE,
}

#: bauble modify-op ints (RFC 4511 §4.6) -> ldap3 modify constants.
_MOD: dict[int, str] = {
    0: LDAP_MOD_ADD,
    1: LDAP_MOD_DELETE,
    2: LDAP_MOD_REPLACE,
}


@dataclass(frozen=True)
class ServerConfig:
    """How to reach the server under test."""

    host: str
    port: int = 389
    use_ssl: bool = False
    use_start_tls: bool = False
    connect_timeout: float = 5.0


def outcome_from_result(result: dict[str, Any]) -> Outcome:
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
) -> dict[str, list[tuple[str, list[str | bytes]]]]:
    """Convert bauble Modifications to the ldap3 ``changes`` mapping."""
    mapped: dict[str, list[tuple[str, list[str | bytes]]]] = {}
    for change in changes:
        mapped[change.attribute] = [(_MOD[change.operation], list(change.values))]
    return mapped


class LdapSession:
    """A :class:`~bauble.session.Session` backed by ldap3."""

    def __init__(self, config: ServerConfig) -> None:
        self._config = config
        self.host: str = config.host
        self.port: int = config.port
        self._server = get_server(
            host=config.host,
            port=config.port,
            use_ssl=config.use_ssl,
            connect_timeout=config.connect_timeout,
        )
        self._connection: _Ldap3Connection = get_connection(self._server)
        self._opened = False

    def _ensure_open(self) -> None:
        if not self._opened:
            self._connection.open()
            if self._config.use_start_tls:
                self._connection.start_tls()
            self._opened = True

    def start_tls(self) -> Outcome:
        """Perform a StartTLS operation and upgrade the connection."""
        self._ensure_open()
        result = self._connection.start_tls()
        if result:
            return Outcome(result_code=0)
        return Outcome(result_code=-1, message="StartTLS failed")

    def bind(self, dn: str | None, password: str | None) -> Outcome:
        self._ensure_open()
        if dn is None:
            # Anonymous (re)bind. ldap3's rebind(user=None) skips its
            # `if user:` guard and silently re-sends the PREVIOUS identity's
            # credentials; clear the state explicitly so an empty BindRequest
            # goes out (bind_operation also rejects ANONYMOUS + leftover name).
            self._connection.user = None
            self._connection.password = None
            self._connection.authentication = LDAP_AUTH_ANONYMOUS
            self._connection.rebind(authentication=LDAP_AUTH_ANONYMOUS)
        else:
            self._connection.rebind(user=dn, password=password)
        return outcome_from_result(self._connection.result)

    def search(
        self,
        base: str,
        scope: int,
        filter_: str,
        attributes: list[str] | None = None,
        controls: tuple[Control, ...] = (),
        deref_aliases: int = 0,
    ) -> tuple[Outcome, list[Entry]]:
        self._ensure_open()
        self._connection.search(
            search_base=base,
            search_filter=filter_,
            search_scope=_SCOPE[scope],
            attributes=attributes or ["*"],
            controls=[(c.oid, c.criticality, c.value) for c in controls],
            dereference_aliases=deref_aliases,
        )
        raw_response: list[dict[str, Any]] = list(self._connection.response or [])
        entries: list[Entry] = []
        referral_uris: list[str] = []
        for item in raw_response:
            if item.get("type") == "searchResRef":
                raw_uri: Any = item.get("uri")
                if isinstance(raw_uri, list):
                    referral_uris.extend(str(u) for u in raw_uri)  # type: ignore[reportUnknownArgumentType, reportUnknownVariableType]
                elif raw_uri:
                    referral_uris.append(str(raw_uri))
                continue
            if item.get("type") != "searchResEntry":
                continue
            raw_attrs: dict[str, Any] = item.get("attributes") or {}
            attribute_map: dict[str, list[str | bytes]] = {}
            for key, val in raw_attrs.items():
                if isinstance(val, (list, tuple)):
                    attribute_map[str(key)] = list(val)  # pyright: ignore[reportUnknownArgumentType]
                else:
                    attribute_map[str(key)] = [val]
            entries.append(Entry(dn=str(item.get("dn", "")), attributes=attribute_map))
        outcome = outcome_from_result(self._connection.result)
        if referral_uris and not outcome.referrals:
            outcome = Outcome(
                result_code=outcome.result_code,
                matched_dn=outcome.matched_dn,
                referrals=tuple(referral_uris),
                message=outcome.message,
            )
        return outcome, entries

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

"""The operator's conformance statement: what the server under test implements.

Drives NOT_APPLICABLE: an assertion gated on a feature the server does not support
is reported as NOT_APPLICABLE rather than FAIL, because the server genuinely does
not implement that feature (and is not non-conformant for its absence).
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from bauble.session import SCOPE_BASE_OBJECT, Session

__all__ = ["Capability", "load_capability", "probe_capability"]


@dataclass(frozen=True)
class Capability:
    """What the server under test implements, as declared by the operator."""

    writable: bool = True
    resettable: bool = False
    alt_server: bool = False
    naming_context: bool = False
    supported_extension: frozenset[str] = frozenset()
    supported_control: frozenset[str] = frozenset()
    supported_features: frozenset[str] = frozenset()
    supported_sasl_mechanisms: frozenset[str] = frozenset()
    # Schema/data-model capabilities that no root-DSE OID expresses.
    # ``alias_entries``: the RFC 4512 alias objectClass exists and
    # dereferencing is implemented.
    alias_entries: bool = False
    # ``referral_entries``: the RFC 3296 referral objectClass exists;
    # subordinate referrals / continuation references are returned.
    referral_entries: bool = False
    # ``person_sn_must``: person carries sn as MUST per RFC 4519 §3.
    # AD-schema directories list sn as MAY (MS-ADSC) and accept
    # person/inetOrgPerson entries without it.
    person_sn_must: bool = True
    extended_operation: str | None = None

    def supports(self, feature: str) -> bool:
        """Whether the server supports a named feature.

        Names: ``writable``, ``resettable``, ``alt_server``,
        ``naming_context``, ``alias_entries``, ``referral_entries``,
        ``person_sn_must``, ``extended_operation`` (any), or OID-scoped
        ``supported_extension:<oid>`` / ``supported_control:<oid>`` /
        ``supported_features:<oid>``, or mechanism-scoped
        ``supported_sasl_mechanisms:<mech>``. A bare OID is treated as a
        feature OID (``requires_features`` on assertions passes bare OIDs).
        Unknown feature names are treated as unsupported.
        """
        match feature:
            case "writable":
                return self.writable
            case "resettable":
                return self.resettable
            case "alt_server":
                return self.alt_server
            case "naming_context":
                return self.naming_context
            case "extended_operation":
                return self.extended_operation is not None
            case "alias_entries":
                return self.alias_entries
            case "referral_entries":
                return self.referral_entries
            case "person_sn_must":
                return self.person_sn_must
            case _:
                if feature.startswith("supported_extension:"):
                    return feature.split(":", 1)[1] in self.supported_extension
                if feature.startswith("supported_control:"):
                    return feature.split(":", 1)[1] in self.supported_control
                if feature.startswith("supported_features:"):
                    return feature.split(":", 1)[1] in self.supported_features
                if feature.startswith("supported_sasl_mechanisms:"):
                    return feature.split(":", 1)[1] in self.supported_sasl_mechanisms
                if _is_oid(feature):
                    return feature in self.supported_features
                return False

    def merged_with(self, probed: Capability) -> Capability:
        """Union a live root-DSE probe into this declared statement.

        Declared scalar gates (``writable``/``resettable`` and the schema
        flags) win; the probed advertisement OIDs and root-DSE booleans are
        unioned in, so a server that advertises a feature is tested for it
        even when the operator's file is silent.
        """
        return Capability(
            writable=self.writable,
            resettable=self.resettable,
            alt_server=self.alt_server or probed.alt_server,
            naming_context=self.naming_context or probed.naming_context,
            supported_extension=self.supported_extension | probed.supported_extension,
            supported_control=self.supported_control | probed.supported_control,
            supported_features=self.supported_features | probed.supported_features,
            supported_sasl_mechanisms=self.supported_sasl_mechanisms
            | probed.supported_sasl_mechanisms,
            alias_entries=self.alias_entries,
            referral_entries=self.referral_entries,
            person_sn_must=self.person_sn_must,
            extended_operation=self.extended_operation,
        )


def _is_oid(value: str) -> bool:
    """True when the string looks like an OID (digits and dots)."""
    return bool(value) and all(part.isdigit() for part in value.split("."))


def load_capability(path: str | Path) -> Capability:
    """Load a capability statement from a TOML file."""
    with Path(path).open("rb") as handle:
        data = tomllib.load(handle)
    return _from_mapping(data)


def _from_mapping(data: dict[str, object]) -> Capability:
    server_raw = data.get("server", {})
    features_raw = data.get("features", {})
    if not isinstance(server_raw, dict) or not isinstance(features_raw, dict):
        raise ValueError(  # noqa: TRY004  malformed config is a value error, not a type error
            "capability TOML must have [server] and [features] tables"
        )
    server = cast(dict[str, object], server_raw)
    features = cast(dict[str, object], features_raw)
    extended = features.get("extended_operation")
    return Capability(
        writable=bool(server.get("writable", True)),
        resettable=bool(server.get("resettable", False)),
        alt_server=bool(features.get("alt_server", False)),
        naming_context=bool(features.get("naming_context", False)),
        supported_extension=frozenset(_str_list(features.get("supported_extension"))),
        supported_control=frozenset(_str_list(features.get("supported_control"))),
        supported_features=frozenset(_str_list(features.get("supported_features"))),
        supported_sasl_mechanisms=frozenset(_str_list(features.get("supported_sasl_mechanisms"))),
        alias_entries=bool(features.get("alias_entries", False)),
        referral_entries=bool(features.get("referral_entries", False)),
        person_sn_must=bool(features.get("person_sn_must", True)),
        extended_operation=extended if isinstance(extended, str) else None,
    )


def _str_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    items = cast(list[object], value)
    return [str(item) for item in items]


def probe_capability(session: Session) -> Capability:
    """Read a server's advertised features from its root DSE.

    The root DSE publishes ``supportedControl``, ``supportedExtension``,
    ``supportedFeatures``, ``supportedSASLMechanisms``, ``namingContexts``,
    and ``altServer`` (RFC 4512 §5.1). Probing turns those live facts into
    a :class:`Capability` so ``--server`` runs do not need a hand-written
    capability file. The returned statement is never ``writable``.

    Servers that deny anonymous root-DSE reads (389 DS, LLDAP) are retried
    under the ``BAUBLE_ADMIN_DN``/``BAUBLE_ADMIN_PW`` credentials. On
    failure an empty :class:`Capability` is returned, so :meth:`merged_with`
    leaves the declared statement unchanged.
    """
    attrs = [
        "supportedControl",
        "supportedExtension",
        "supportedFeatures",
        "supportedSASLMechanisms",
        "namingContexts",
        "altServer",
    ]
    outcome, entries = session.search("", SCOPE_BASE_OBJECT, "(objectClass=*)", attrs)
    if outcome.result_code != 0 or not entries:
        admin_dn = os.environ.get("BAUBLE_ADMIN_DN", "cn=admin,dc=bauble,dc=test")
        admin_pw = os.environ.get("BAUBLE_ADMIN_PW", "bauble-admin")
        session.bind(admin_dn, admin_pw)
        outcome, entries = session.search("", SCOPE_BASE_OBJECT, "(objectClass=*)", attrs)
    if outcome.result_code != 0 or not entries:
        return Capability(writable=False)

    published = entries[0].attributes

    def values(name: str) -> list[str]:
        for key, value in published.items():
            if key.lower() == name.lower():
                return [str(v) for v in value]
        return []

    return Capability(
        writable=False,
        alt_server=bool(values("altServer")),
        naming_context=bool(values("namingContexts")),
        supported_extension=frozenset(values("supportedExtension")),
        supported_control=frozenset(values("supportedControl")),
        supported_features=frozenset(values("supportedFeatures")),
        supported_sasl_mechanisms=frozenset(values("supportedSASLMechanisms")),
    )

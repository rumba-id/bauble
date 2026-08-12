"""The operator's conformance statement: what the server under test implements.

Drives AUTO_PASS: an assertion gated on a feature the server does not support
is reported as AUTO_PASS rather than FAIL, because the server genuinely does
not implement that feature (and is not non-conformant for its absence).
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import cast

__all__ = ["Capability", "load_capability"]


@dataclass(frozen=True)
class Capability:
    """What the server under test implements, as declared by the operator."""

    writable: bool = True
    resettable: bool = False
    alt_server: bool = False
    naming_context: bool = False
    supported_extension: frozenset[str] = frozenset()
    supported_control: frozenset[str] = frozenset()
    extended_operation: str | None = None

    def supports(self, feature: str) -> bool:
        """Whether the server supports a named feature.

        Names: ``writable``, ``resettable``, ``alt_server``,
        ``naming_context``, ``extended_operation`` (any), or OID-scoped
        ``supported_extension:<oid>`` / ``supported_control:<oid>``. Unknown
        feature names are treated as unsupported.
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
            case _:
                if feature.startswith("supported_extension:"):
                    return feature.split(":", 1)[1] in self.supported_extension
                if feature.startswith("supported_control:"):
                    return feature.split(":", 1)[1] in self.supported_control
                return False


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
        extended_operation=extended if isinstance(extended, str) else None,
    )


def _str_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    items = cast(list[object], value)
    return [str(item) for item in items]

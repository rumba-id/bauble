"""Capability: feature support and TOML loading."""

from __future__ import annotations

from pathlib import Path

from bauble.capability import Capability, load_capability


def test_supports_boolean_and_oid_features() -> None:
    cap = Capability(alt_server=False, supported_extension=frozenset({"1.2.3"}))
    assert cap.supports("writable")
    assert not cap.supports("alt_server")
    assert cap.supports("supported_extension:1.2.3")
    assert not cap.supports("supported_extension:9.9.9")
    assert not cap.supports("supported_control:1.2.3")
    assert not cap.supports("unknown_feature")


def test_load_capability(tmp_path: Path) -> None:
    toml = tmp_path / "cap.toml"
    toml.write_text(
        "[server]\nwritable = true\nresettable = true\n"
        "[features]\nalt_server = true\nnaming_context = false\n"
        'supported_extension = ["1.2.3"]\nextended_operation = "1.2.3"\n'
    )
    cap = load_capability(toml)
    assert cap.writable
    assert cap.resettable
    assert cap.alt_server
    assert not cap.naming_context
    assert cap.supports("supported_extension:1.2.3")
    assert cap.extended_operation == "1.2.3"
    assert cap.supports("extended_operation")


def test_supports_features_and_sasl() -> None:
    cap = Capability(
        supported_features=frozenset({"1.3.6.1.1.14"}),
        supported_sasl_mechanisms=frozenset({"EXTERNAL", "PLAIN"}),
    )
    assert cap.supports("supported_features:1.3.6.1.1.14")
    assert not cap.supports("supported_features:9.9.9")
    assert cap.supports("supported_sasl_mechanisms:EXTERNAL")
    assert not cap.supports("supported_sasl_mechanisms:GSSAPI")
    # A bare OID is treated as a feature OID (the requires_features form).
    assert cap.supports("1.3.6.1.1.14")
    assert not cap.supports("9.9.9")


def test_load_features_and_sasl(tmp_path: Path) -> None:
    toml = tmp_path / "cap.toml"
    toml.write_text(
        "[server]\nwritable = true\n"
        "[features]\n"
        'supported_features = ["1.3.6.1.1.14"]\n'
        'supported_sasl_mechanisms = ["EXTERNAL"]\n'
    )
    cap = load_capability(toml)
    assert cap.supports("supported_features:1.3.6.1.1.14")
    assert cap.supports("supported_sasl_mechanisms:EXTERNAL")

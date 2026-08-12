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

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


def test_merged_with_unions_probe() -> None:
    declared = Capability(writable=True, supported_control=frozenset({"1.2.3"}))
    probed = Capability(
        writable=False,
        alt_server=True,
        naming_context=True,
        supported_control=frozenset({"9.9.9"}),
        supported_extension=frozenset({"1.3.6.1.4.1.4203.1.11.3"}),
    )
    merged = declared.merged_with(probed)
    assert merged.writable is True  # declared scalar wins over the probe
    assert merged.alt_server is True
    assert merged.naming_context is True
    assert merged.supported_control == frozenset({"1.2.3", "9.9.9"})
    assert merged.supports("supported_control:1.2.3")
    assert merged.supports("supported_control:9.9.9")
    assert merged.supports("supported_extension:1.3.6.1.4.1.4203.1.11.3")


def test_probe_capability_reads_root_dse() -> None:
    from bauble._fake import FakeSession
    from bauble.capability import probe_capability
    from bauble.session import Control, Entry, Outcome

    class RootDseSession(FakeSession):
        def search(
            self,
            base: str,
            scope: int,
            filter_: str,
            attributes: list[str] | None = None,
            controls: tuple[Control, ...] = (),
            deref_aliases: int = 0,
        ) -> tuple[Outcome, list[Entry]]:
            return Outcome(result_code=0), [
                Entry(
                    "",
                    {
                        "supportedControl": ["1.2.840.113556.1.4.319"],
                        "supportedExtension": ["1.3.6.1.4.1.4203.1.11.3"],
                        "supportedFeatures": ["1.3.6.1.4.1.4203.1.5.1"],
                        "supportedSASLMechanisms": ["EXTERNAL"],
                        "namingContexts": ["dc=bauble,dc=test"],
                        "altServer": ["ldap://alt/"],
                    },
                )
            ]

    cap = probe_capability(RootDseSession())
    assert cap.supports("supported_control:1.2.840.113556.1.4.319")
    assert cap.supports("supported_extension:1.3.6.1.4.1.4203.1.11.3")
    assert cap.supports("supported_features:1.3.6.1.4.1.4203.1.5.1")
    assert cap.supports("supported_sasl_mechanisms:EXTERNAL")
    assert cap.naming_context is True
    assert cap.alt_server is True
    assert cap.writable is False


def test_probe_capability_falls_back_to_empty() -> None:
    from bauble._fake import FakeSession
    from bauble.capability import probe_capability
    from bauble.session import Control, Entry, Outcome

    class DenyingSession(FakeSession):
        def search(
            self,
            base: str,
            scope: int,
            filter_: str,
            attributes: list[str] | None = None,
            controls: tuple[Control, ...] = (),
            deref_aliases: int = 0,
        ) -> tuple[Outcome, list[Entry]]:
            return Outcome(result_code=32), []

        def bind(self, dn: str | None, password: str | None) -> Outcome:
            return Outcome(result_code=49)

    cap = probe_capability(DenyingSession())
    assert cap.writable is False
    assert cap.supported_control == frozenset()
    assert cap.naming_context is False

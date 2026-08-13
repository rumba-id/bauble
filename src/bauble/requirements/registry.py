"""Normative-requirements registry: every MUST/SHOULD/MAY per RFC.

Complements the assertion registry. An assertion *verifies* a requirement; a
requirement with no covering assertion is a surfaced conformance gap, not a
silent omission. Requirements are TOML data (one file per RFC) so the corpus
stays reviewable and diffable. SHALL is normalized to MUST (RFC 2119).
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path

from bauble.model import Severity, TestClass

__all__ = ["Requirement", "load_requirements"]


@dataclass(frozen=True)
class Requirement:
    """One normative statement (MUST/SHOULD/MAY) extracted from an RFC.

    ``covered_by`` lists the assertion ids that verify this requirement. A
    requirement whose ``covered_by`` entries are absent from the assertion
    registry is an uncovered conformance gap.
    """

    id: str
    rfc: int
    section: str
    severity: Severity
    test_class: TestClass
    text: str
    covered_by: tuple[str, ...] = ()


def load_requirements() -> list[Requirement]:
    """Load every ``*.toml`` requirement file packaged alongside this module."""
    requirements: list[Requirement] = []
    for path in sorted(Path(__file__).parent.glob("*.toml")):
        data = tomllib.loads(path.read_text(encoding="utf-8"))
        rfc_raw = data.get("rfc")
        if not isinstance(rfc_raw, int):
            raise TypeError(f"{path}: 'rfc' must be an integer, got {rfc_raw!r}")
        rfc = rfc_raw
        for item in data.get("requirement", []):
            requirements.append(
                Requirement(
                    id=str(item["id"]),
                    rfc=rfc,
                    section=str(item.get("section", "")),
                    severity=Severity(str(item["severity"])),
                    test_class=TestClass(str(item["test_class"])),
                    text=str(item.get("text", "")),
                    covered_by=tuple(str(x) for x in item.get("covered_by", [])),
                )
            )
    return requirements

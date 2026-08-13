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

__all__ = ["Obligation", "Requirement", "load_requirements"]


@dataclass(frozen=True)
class Obligation:
    """One independently-testable normative sub-statement of a requirement.

    Splitting a requirement into obligations is what makes
    PARTIALLY_COVERED meaningful: a requirement whose obligations are only
    partly covered is reported as PARTIALLY_COVERED rather than COVERED,
    so a single exercised clause cannot mask an unexercised one.
    """

    id: str
    text: str
    covered_by: tuple[str, ...] = ()


@dataclass(frozen=True)
class Requirement:
    """One normative statement (MUST/SHOULD/MAY) extracted from an RFC.

    ``covered_by`` lists the assertion ids that verify this requirement. A
    requirement whose ``covered_by`` entries are absent from the assertion
    registry is an uncovered conformance gap.

    ``obligations`` splits the statement into independently-testable parts;
    when present, coverage is computed per obligation.
    """

    id: str
    rfc: int
    section: str
    severity: Severity
    test_class: TestClass
    text: str
    covered_by: tuple[str, ...] = ()
    obligations: tuple[Obligation, ...] = ()
    note: str = ""
    """Free-form note: e.g. an accepted cross-RFC link or why a gap is intrinsic."""


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
                    obligations=tuple(
                        Obligation(
                            id=str(ob["id"]),
                            text=str(ob.get("text", "")),
                            covered_by=tuple(str(x) for x in ob.get("covered_by", [])),
                        )
                        for ob in item.get("obligation", [])
                    ),
                    note=str(item.get("note", "")),
                )
            )
    return requirements

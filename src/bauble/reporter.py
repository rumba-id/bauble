"""Reporters: turn run results into text, journal, summary, and JUnit output.

The journal (JSON lines) is the source of truth and is self-describing: each
record carries the assertion's static metadata denormalized, so a summary can
be derived from a journal without the registry.
"""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Protocol, TextIO, cast

from bauble.model import Result
from bauble.registry import Registry

__all__ = [
    "REPORTERS",
    "JUnitReporter",
    "JournalRecord",
    "JournalReporter",
    "ProfileVerdict",
    "Reporter",
    "SummaryReporter",
    "TextReporter",
    "get_reporter",
    "journal_dumps",
    "journal_loads",
    "profile_verdict",
    "to_records",
]

_CONFORMANT_OK = {"pass", "not_applicable"}


@dataclass(frozen=True)
class JournalRecord:
    """One assertion's result plus its denormalized static metadata."""

    assertion_id: str
    rfc: int
    status: str
    severity: str
    test_class: str
    profiles: tuple[str, ...]
    layer: str = "semantic"
    oid: str = ""
    detail: str | None = None


@dataclass(frozen=True)
class ProfileVerdict:
    """Conformance verdict for one profile."""

    profile: str
    must_a_total: int
    must_a_ok: int
    conformant: bool
    untestable: int


def to_records(results: list[Result], registry: Registry) -> list[JournalRecord]:
    """Enrich Results with their assertions' static metadata."""
    records: list[JournalRecord] = []
    for result in results:
        assertion = registry.get(result.assertion_id)
        records.append(
            JournalRecord(
                assertion_id=result.assertion_id,
                rfc=assertion.rfc,
                status=result.status.value,
                severity=assertion.severity.value,
                test_class=assertion.test_class.value,
                profiles=tuple(p.value for p in sorted(assertion.profiles, key=lambda x: x.value)),
                layer=assertion.layer.value,
                oid=assertion.oid,
                detail=result.detail,
            )
        )
    return records


def journal_dumps(records: list[JournalRecord]) -> str:
    """Serialize records to JSON lines."""
    lines: list[str] = []
    for record in records:
        lines.append(
            json.dumps(
                {
                    "assertion_id": record.assertion_id,
                    "rfc": record.rfc,
                    "status": record.status,
                    "severity": record.severity,
                    "test_class": record.test_class,
                    "profiles": list(record.profiles),
                    "layer": record.layer,
                    "oid": record.oid,
                    "detail": record.detail,
                }
            )
        )
    return "\n".join(lines)


def journal_loads(text: str) -> list[JournalRecord]:
    """Parse JSON lines back into records, skipping malformed lines."""
    records: list[JournalRecord] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            parsed: object = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(parsed, dict):
            continue
        data = cast(dict[str, object], parsed)
        rfc_raw = data.get("rfc", 0)
        rfc = rfc_raw if isinstance(rfc_raw, int) else 0
        detail_raw = data.get("detail")
        detail = detail_raw if isinstance(detail_raw, str) else None
        raw_profiles = data.get("profiles")
        profiles = (
            tuple(str(p) for p in cast(list[object], raw_profiles))
            if isinstance(raw_profiles, list)
            else ()
        )
        records.append(
            JournalRecord(
                assertion_id=str(data.get("assertion_id", "")),
                rfc=rfc,
                status=str(data.get("status", "")),
                severity=str(data.get("severity", "")),
                test_class=str(data.get("test_class", "")),
                profiles=profiles,
                layer=str(data.get("layer", "semantic")),
                oid=str(data.get("oid", "")),
                detail=detail,
            )
        )
    return records


def profile_verdict(records: list[JournalRecord], profile: str) -> ProfileVerdict:
    """Conformance verdict for ``profile``.

    Conformant iff every mandatory-testable (severity MUST, class A) assertion
    in the profile is PASS or NOT_APPLICABLE. SHOULD/MAY and class B/D never fail
    conformance.
    """
    in_profile = [r for r in records if profile in r.profiles]
    must_a = [r for r in in_profile if r.severity == "must" and r.test_class == "A"]
    must_a_ok = sum(1 for r in must_a if r.status in _CONFORMANT_OK)
    untestable = sum(1 for r in in_profile if r.status == "untestable")
    return ProfileVerdict(
        profile=profile,
        must_a_total=len(must_a),
        must_a_ok=must_a_ok,
        conformant=must_a_ok == len(must_a),
        untestable=untestable,
    )


def _profiles_in(records: list[JournalRecord]) -> list[str]:
    seen: set[str] = set()
    for record in records:
        seen.update(record.profiles)
    return sorted(seen)


def _rfcs_in(records: list[JournalRecord]) -> list[int]:
    return sorted({record.rfc for record in records})


class Reporter(Protocol):
    """A reporter renders records to an output stream."""

    name: str

    def render(self, records: list[JournalRecord], out: TextIO) -> None: ...


class JournalReporter:
    """Raw JSON-lines journal — the archival source of truth."""

    name = "journal"

    def render(self, records: list[JournalRecord], out: TextIO) -> None:
        out.write(journal_dumps(records))
        out.write("\n")


class TextReporter:
    """Per-assertion lines plus a compact status summary."""

    name = "text"

    def render(self, records: list[JournalRecord], out: TextIO) -> None:
        for record in records:
            detail = f"  ({record.detail})" if record.detail else ""
            out.write(
                f"{record.assertion_id}  [{record.test_class}/{record.severity}]  "
                f"{record.status}{detail}\n"
            )
        counts: dict[str, int] = {}
        for record in records:
            counts[record.status] = counts.get(record.status, 0) + 1
        summary = ", ".join(f"{k}={v}" for k, v in sorted(counts.items())) or "none"
        out.write(f"summary: {summary}\n")


class SummaryReporter:
    """Human conformance summary: per-RFC, per-profile, overall verdict."""

    name = "summary"

    def render(self, records: list[JournalRecord], out: TextIO) -> None:
        out.write("Per RFC:\n")
        for rfc in _rfcs_in(records):
            rfc_records = [r for r in records if r.rfc == rfc]
            verdicts = [profile_verdict(rfc_records, p) for p in _profiles_in(rfc_records)]
            worst = "CONFORMANT" if all(v.conformant for v in verdicts) else "NON-CONFORMANT"
            totals = "+".join(f"{v.must_a_ok}/{v.must_a_total}" for v in verdicts) or "0/0"
            out.write(f"  RFC {rfc:<6} must(A) {totals:<10} {worst}\n")

        out.write("Per profile:\n")
        overall_conformant = True
        for profile in _profiles_in(records):
            verdict = profile_verdict(records, profile)
            overall_conformant = overall_conformant and verdict.conformant
            label = "CONFORMANT" if verdict.conformant else "NON-CONFORMANT"
            out.write(
                f"  {profile:<10} must(A) {verdict.must_a_ok}/{verdict.must_a_total}  "
                f"untestable={verdict.untestable}  {label}\n"
            )

        overall = "CONFORMANT" if overall_conformant else "NON-CONFORMANT"
        total_untestable = sum(1 for r in records if r.status == "untestable")
        out.write(f"Overall: {overall}\n")
        out.write(f"UNTESTABLE: {total_untestable}\n")

        out.write("Per layer:\n")
        for layer in ("wire", "semantic", "capability"):
            layer_records = [r for r in records if r.layer == layer]
            if not layer_records:
                continue
            must_a = [r for r in layer_records if r.severity == "must" and r.test_class == "A"]
            ok = sum(1 for r in must_a if r.status in ("pass", "not_applicable"))
            fail = sum(1 for r in must_a if r.status == "fail")
            na = sum(1 for r in must_a if r.status == "not_applicable")
            untestable = sum(1 for r in layer_records if r.status == "untestable")
            out.write(
                f"  {layer:<11} must(A) {ok}/{len(must_a)}  "
                f"fail={fail}  na={na}  untestable={untestable}\n"
            )

        # Per-OID capability table.
        oid_records = [r for r in records if r.oid]
        if oid_records:
            out.write("Per capability (OID):\n")
            for oid in sorted({r.oid for r in oid_records}):
                oid_group = [r for r in oid_records if r.oid == oid]
                # Advertised if a capability-layer assertion PASSes, or if a
                # behavioral assertion was exercised (PASS/FAIL implies the
                # feature was advertised and tested).
                advertised = any(
                    (r.layer == "capability" and r.status == "pass")
                    or (r.layer != "capability" and r.status in ("pass", "fail"))
                    for r in oid_group
                )
                fails = [r for r in oid_group if r.status == "fail"]
                if fails:
                    verdict = f"FAIL — {fails[0].detail or 'behavioral test failed'}"
                elif advertised:
                    verdict = "CONFORMANT"
                else:
                    verdict = "not advertised"
                out.write(f"  {oid:<24} {verdict}\n")


class JUnitReporter:
    """JUnit XML for CI integration."""

    name = "junit"

    def render(self, records: list[JournalRecord], out: TextIO) -> None:
        suites = ET.Element("testsuites")
        suite = ET.SubElement(
            suites,
            "testsuite",
            {"name": "bauble", "tests": str(len(records))},
        )
        failures = 0
        skipped = 0
        _skip_statuses = {"skip", "blocked", "untestable", "auto_pass", "not_applicable", "na"}
        for record in records:
            case = ET.SubElement(
                suite,
                "testcase",
                {"name": record.assertion_id, "classname": f"rfc.{record.rfc}"},
            )
            if record.status == "fail":
                failures += 1
                failure = ET.SubElement(case, "failure", {"message": record.detail or ""})
                failure.text = record.detail or ""
            elif record.status in _skip_statuses:
                skipped += 1
                skip = ET.SubElement(case, "skipped")
                skip.text = f"{record.status}: {record.detail or ''}"
        suite.set("failures", str(failures))
        suite.set("skipped", str(skipped))
        ET.indent(suites, space="  ")
        out.write(ET.tostring(suites, encoding="unicode"))
        out.write("\n")


REPORTERS: dict[str, type[Reporter]] = {
    "text": TextReporter,
    "journal": JournalReporter,
    "summary": SummaryReporter,
    "junit": JUnitReporter,
}


def get_reporter(name: str) -> Reporter:
    """Return the named reporter (default: text)."""
    cls = REPORTERS.get(name, TextReporter)
    return cls()

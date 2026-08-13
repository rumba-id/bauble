"""Reporters: verdict rule, journal round-trip, and each output format.

Validated against a stub record set (Phase 3 has no real assertions yet).
"""

from __future__ import annotations

import io
import json
import xml.etree.ElementTree as ET

from bauble.model import Assertion, Category, Profile, Result, Severity, Status, TestClass
from bauble.registry import Registry
from bauble.reporter import (
    JournalRecord,
    JournalReporter,
    JUnitReporter,
    SummaryReporter,
    get_reporter,
    journal_dumps,
    journal_loads,
    profile_verdict,
    to_records,
)

_RECORDS = [
    JournalRecord("4511.4.2.1", 4511, "pass", "must", "A", ("base",)),
    JournalRecord("4511.4.2.2", 4511, "pass", "must", "A", ("base",)),
    JournalRecord("4511.4.2.3", 4511, "fail", "must", "A", ("base",)),
    JournalRecord("4511.4.2.7", 4511, "untestable", "must", "B", ("base",)),
    JournalRecord("4511.4.2.9", 4511, "not_applicable", "must", "A", ("base",)),
    JournalRecord("4512.1.1", 4512, "pass", "should", "A", ("standard",)),
]


def _render(reporter_name: str, records: list[JournalRecord] | None = None) -> str:
    buffer = io.StringIO()
    get_reporter(reporter_name).render(records or _RECORDS, buffer)
    return buffer.getvalue()


def test_journal_round_trip() -> None:
    text = journal_dumps(_RECORDS)
    assert journal_loads(text) == _RECORDS


def test_journal_is_valid_json_lines() -> None:
    output = _render("journal")
    lines = [line for line in output.splitlines() if line.strip()]
    assert len(lines) == len(_RECORDS)
    for line in lines:
        record = json.loads(line)
        assert {"assertion_id", "rfc", "status", "severity", "test_class", "profiles"} <= set(
            record
        )


def test_profile_verdict_conformant_rule() -> None:
    base = profile_verdict(_RECORDS, "base")
    # must+A: 4 total (.1, .2 pass; .3 fail; .9 not_applicable); ok = 3; one FAIL -> not conformant
    assert base.must_a_total == 4
    assert base.must_a_ok == 3
    assert base.conformant is False
    assert base.untestable == 1  # the class-B entry

    standard = profile_verdict(_RECORDS, "standard")
    # no must+A in standard -> vacuously conformant
    assert standard.must_a_total == 0
    assert standard.conformant is True


def test_conformant_when_all_must_a_pass() -> None:
    records = [
        JournalRecord("1.0.0.1", 1, "pass", "must", "A", ("base",)),
        JournalRecord("1.0.0.2", 1, "not_applicable", "must", "A", ("base",)),
        JournalRecord("1.0.0.3", 1, "untestable", "must", "B", ("base",)),
        JournalRecord("1.0.0.4", 1, "fail", "should", "A", ("base",)),
    ]
    verdict = profile_verdict(records, "base")
    assert verdict.must_a_total == 2
    assert verdict.must_a_ok == 2
    assert verdict.conformant is True  # the SHOULD failure is only a warning


def test_summary_reports_non_conformant_for_base() -> None:
    output = _render("summary")
    assert "Per profile:" in output
    assert "Overall: NON-CONFORMANT" in output
    assert "base" in output


def test_text_reporter_lists_assertions_and_summary() -> None:
    output = _render("text")
    assert "4511.4.2.3" in output
    assert "summary:" in output


def test_junit_reporter_counts_failures_and_skips() -> None:
    output = _render("junit")
    root = ET.fromstring(output)
    suite = root.find("testsuite")
    assert suite is not None
    assert suite.get("tests") == str(len(_RECORDS))
    assert suite.get("failures") == "1"
    # fail is a failure; not_applicable + untestable are skipped
    assert suite.get("skipped") == "2"


def test_to_records_enriches_from_registry() -> None:
    registry = Registry()
    registry.register(
        Assertion(
            id="4511.4.2.1",
            rfc=4511,
            section="§4.2",
            category=Category.PROTOCOL,
            severity=Severity.MUST,
            test_class=TestClass.A,
            profiles=frozenset({Profile.INTEROP}),
            text="anonymous bind",
        )
    )
    records = to_records([Result("4511.4.2.1", Status.PASS, detail="ok")], registry)
    assert records == [
        JournalRecord("4511.4.2.1", 4511, "pass", "must", "A", ("interop",), "semantic", "", "ok")
    ]


def test_get_reporter_default_is_text() -> None:
    assert get_reporter("text").name == "text"
    assert get_reporter("nonsense").name == "text"
    assert isinstance(get_reporter("summary"), SummaryReporter)
    assert isinstance(get_reporter("journal"), JournalReporter)
    assert isinstance(get_reporter("junit"), JUnitReporter)

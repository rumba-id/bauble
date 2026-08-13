"""audit: assertion-fidelity audit rendered as text."""

from __future__ import annotations

from bauble.audit import audit_text
from bauble.registry import default_registry
from bauble.suites import discover

discover()  # register every suite's assertions into the default registry


def test_audit_reports_cross_rfc_links() -> None:
    """The 4517:4:6 <-> 5020.2.4 cross-RFC link must be surfaced."""
    text = audit_text(default_registry())
    assert "4517:4:6 (rfc 4517) <- 5020.2.4 (rfc 5020)" in text


def test_audit_rollup_counts_cover_all_requirements() -> None:
    """The rollup buckets (full/partial/none/uncovered) sum to the corpus."""
    import re

    from bauble.requirements import load_requirements

    text = audit_text(default_registry())
    total = sum(int(n[1]) for n in re.findall(r"^  (\w+)\s+(\d+)$", text, re.MULTILINE) if n[0] in ("full", "partial", "none", "uncovered"))
    assert total == len(load_requirements())


def test_audit_flags_uncovered_requirements() -> None:
    """Requirements with no covering assertion must be listed as UNCOVERED."""
    text = audit_text(default_registry())
    assert "UNCOVERED" in text

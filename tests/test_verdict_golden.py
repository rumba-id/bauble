"""Verdict-regression gate: the full core profile must match the golden set.

Each golden file (``ci/golden/<target>.txt``) records the expected
assertion -> status mapping from a known-good full run against that
target. The suite passes only when the live run produces exactly that
verdict set — a new FAIL, a lost PASS, or a classification drift fails
CI. Genuine new findings require an intentional golden update.

Regenerate goldens (only after reviewing the changes) with::

    BAUBLE_LIVE=1 BAUBLE_UPDATE_GOLDEN=1 uv run pytest -q tests/test_verdict_golden.py

Run a single target::

    BAUBLE_LIVE=1 uv run pytest -q tests/test_verdict_golden.py -k lldap
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

_LIVE = bool(os.environ.get("BAUBLE_LIVE")) and shutil.which("podman") is not None
_REASON = "set BAUBLE_LIVE=1 with podman on PATH"
_UPDATE = bool(os.environ.get("BAUBLE_UPDATE_GOLDEN"))

_GOLDEN_DIR = Path(__file__).parent.parent / "ci" / "golden"
_ARTIFACT_DIR = Path(__file__).parent.parent / "ci" / "artifacts"

_TARGETS = ["openldap", "389ds", "opendj", "lldap"]


def _run_full_profile(target: str, out_path: Path) -> None:
    """Run the full core profile against the podman target, journal to out_path."""
    cmd = [
        sys.executable,
        "-m",
        "bauble",
        "run",
        "--profile",
        "core",
        "--target",
        "--target-type",
        target,
        "--reporter",
        "journal",
        "--out",
        str(out_path),
    ]
    subprocess.run(cmd, check=True, capture_output=True, text=True)


def _status_map(journal: Path) -> dict[str, str]:
    """Parse a journal into an ordered assertion_id -> status mapping."""
    import json

    rows = [json.loads(line) for line in journal.read_text().splitlines() if line.strip()]
    return {r["assertion_id"]: r["status"] for r in sorted(rows, key=lambda r: r["assertion_id"])}


def _golden_path(target: str) -> Path:
    return _GOLDEN_DIR / f"{target}.txt"


def _read_golden(target: str) -> dict[str, str]:
    mapping: dict[str, str] = {}
    for line in _golden_path(target).read_text().splitlines():
        if line.startswith("#") or "\t" not in line:
            continue
        assertion_id, status = line.split("\t", 1)
        mapping[assertion_id] = status.strip()
    return mapping


def _write_golden(target: str, mapping: dict[str, str]) -> None:
    lines = [
        f"# bauble core-profile golden — {target}",
        "# generated from a known-good full run; BAUBLE_UPDATE_GOLDEN=1 regenerates.",
    ]
    lines += [f"{aid}\t{mapping[aid]}" for aid in sorted(mapping)]
    _golden_path(target).write_text("\n".join(lines) + "\n", encoding="utf-8")


def _diff(golden: dict[str, str], live: dict[str, str]) -> list[str]:
    changed: list[str] = []
    for aid in sorted(set(golden) | set(live)):
        expected = golden.get(aid)
        actual = live.get(aid)
        if expected != actual:
            changed.append(f"  {aid}: golden={expected!r} live={actual!r}")
    return changed


@pytest.mark.skipif(not _LIVE, reason=_REASON)
@pytest.mark.parametrize("target", _TARGETS)
def test_full_core_profile_matches_golden(target: str) -> None:
    """The full core profile's verdict set must equal the golden file."""
    _ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
    journal = _ARTIFACT_DIR / f"{target}.jsonl"
    _run_full_profile(target, journal)
    live = _status_map(journal)
    if _UPDATE:
        _write_golden(target, live)
        return
    golden = _read_golden(target)
    changed = _diff(golden, live)
    assert not changed, (
        f"verdict drift for target {target!r}:\n"
        + "\n".join(changed)
        + "\nReview; regenerate with BAUBLE_UPDATE_GOLDEN=1 if intentional."
    )

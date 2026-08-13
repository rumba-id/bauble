"""RFC 2696 — Simple Paged Results control."""

from __future__ import annotations

from bauble.model import Category, Profile, Result, Severity, Status, TestClass
from bauble.raw import paged_results_control_value
from bauble.session import SCOPE_WHOLE_SUBTREE, Control, Session
from bauble.suites._base import assertion

_CORE = frozenset({Profile.CORE})

_PAGED_OID = "1.2.840.113556.1.4.319"


@assertion(
    id="2696.2.1",
    rfc=2696,
    section="§2",
    category=Category.CONTROL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_CORE,
    text="A search with the paged-results control (size=2) is accepted.",
    strategy="Search the base DIT with paged-results control, page size 2; expect code 0.",
    oid="1.2.840.113556.1.4.319",
)
def paged_results_accepted(session: Session) -> Result:
    outcome, _ = session.search(
        "dc=bauble,dc=test",
        SCOPE_WHOLE_SUBTREE,
        "(objectClass=*)",
        controls=(
            Control(
                oid=_PAGED_OID,
                value=paged_results_control_value(2),
                criticality=False,
            ),
        ),
    )
    if outcome.result_code == 0:
        return Result("2696.2.1", Status.PASS)
    return Result("2696.2.1", Status.FAIL, detail=f"expected 0, got {outcome.result_code}")

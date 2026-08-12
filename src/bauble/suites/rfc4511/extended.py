"""RFC 4511 §4.12 — Extended operation."""

from __future__ import annotations

from bauble.model import Category, Profile, Result, Severity, Status, TestClass
from bauble.session import Session
from bauble.suites._base import assertion

_INTEROP = frozenset({Profile.INTEROP})


@assertion(
    id="4511.4.12.1",
    rfc=4511,
    section="§4.12",
    category=Category.PROTOCOL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_INTEROP,
    text="An unrecognized extended request returns an error (does not succeed).",
    strategy="Send an extended request with a bogus OID; expect a non-zero result code.",
)
def unrecognized_extended(session: Session) -> Result:
    outcome = session.extended("1.2.3.4.5.6-bogus")
    if outcome.result_code != 0:
        return Result("4511.4.12.1", Status.PASS)
    return Result(
        "4511.4.12.1",
        Status.FAIL,
        detail=f"expected non-zero (unsupported OID), got {outcome.result_code}",
    )

"""RFC 4511 §4.3 — Unbind operation."""

from __future__ import annotations

from bauble.model import Category, Profile, Result, Severity, Status, TestClass
from bauble.session import Session
from bauble.suites._base import assertion

_INTEROP = frozenset({Profile.INTEROP})


@assertion(
    id="4511.4.3.1",
    rfc=4511,
    section="§4.3",
    category=Category.PROTOCOL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_INTEROP,
    text="An unbind request returns without error.",
    strategy="Call unbind on a connected session; expect no exception.",
    preconditions="Session is open.",
    stimulus="UnbindRequest.",
    expected_observables="No response; the session closes without error.",
)
def unbind_returns_without_error(session: Session) -> Result:
    session.unbind()
    return Result("4511.4.3.1", Status.PASS)

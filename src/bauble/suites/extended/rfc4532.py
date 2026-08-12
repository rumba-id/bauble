"""RFC 4532 — Who Am I? extended operation."""

from __future__ import annotations

from bauble.model import Category, Profile, Result, Severity, Status, TestClass
from bauble.session import Session
from bauble.suites._base import assertion

_STANDARD = frozenset({Profile.STANDARD})
_WHOAMI_OID = "1.3.6.1.4.1.4203.1.11.3"
_ALICE = "uid=alice,ou=people,dc=bauble,dc=test"
_ALICE_PW = "alice-secret"


@assertion(
    id="4532.1.1",
    rfc=4532,
    section="§1",
    category=Category.EXTENDED,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_STANDARD,
    text="The Who-Am-I extended operation returns the authenticated identity.",
    strategy="Bind as alice, send Who-Am-I extended op; expect the DN in the response.",
)
def who_am_i(session: Session) -> Result:
    session.bind(_ALICE, _ALICE_PW)
    outcome = session.extended(_WHOAMI_OID)
    if outcome.result_code == 0:
        return Result("4532.1.1", Status.PASS)
    return Result("4532.1.1", Status.FAIL, detail=f"expected 0, got {outcome.result_code}")

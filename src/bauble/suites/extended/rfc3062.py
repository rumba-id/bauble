"""RFC 3062 — Password Modify extended operation."""

from __future__ import annotations

from bauble.model import Category, Profile, Result, Severity, Status, TestClass
from bauble.raw import password_modify_request_value
from bauble.session import Session
from bauble.suites._base import assertion
from bauble.suites._helpers import bind_admin

_CORE = frozenset({Profile.CORE})
_PWMOD_OID = "1.3.6.1.4.1.4203.1.11.1"
_BOB_PW = "bob-secret"
_BOB_DN = "uid=bob,ou=people,dc=bauble,dc=test"


@assertion(
    id="3062.2.1",
    rfc=3062,
    section="§2",
    category=Category.EXTENDED,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_CORE,
    text="The Password Modify extended operation is accepted for a valid user.",
    strategy="Send Password Modify as admin for bob with a new password; expect 0; restore.",
    oid="1.3.6.1.4.1.4203.1.11.1",
)
def password_modify_accepted(session: Session) -> Result:
    bind_admin(session)
    outcome = session.extended(
        _PWMOD_OID, password_modify_request_value("bob-new-secret", _BOB_DN)
    )
    # Restore original password
    session.extended(_PWMOD_OID, password_modify_request_value(_BOB_PW, _BOB_DN))
    if outcome.result_code == 0:
        return Result("3062.2.1", Status.PASS)
    return Result("3062.2.1", Status.FAIL, detail=f"expected 0, got {outcome.result_code}")

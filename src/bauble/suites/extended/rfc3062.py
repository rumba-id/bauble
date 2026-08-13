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


@assertion(
    id="3062.3.3",
    rfc=3062,
    section="§3",
    category=Category.EXTENDED,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_CORE,
    text="An incorrect oldPasswd leaves the password unchanged with a non-success result.",
    strategy="Bind as bob, Password Modify with a wrong oldPasswd; expect non-zero.",
    oid="1.3.6.1.4.1.4203.1.11.1",
)
def password_modify_wrong_old_passwd(session: Session) -> Result:
    session.bind(_BOB_DN, _BOB_PW)
    outcome = session.extended(
        _PWMOD_OID,
        password_modify_request_value("bob-should-not-set", _BOB_DN, old_password="wrong-old"),
    )
    if outcome.result_code != 0:
        return Result("3062.3.3", Status.PASS)
    return Result(
        "3062.3.3",
        Status.FAIL,
        detail="password changed despite a wrong oldPasswd",
    )


@assertion(
    id="3062.3.4",
    rfc=3062,
    section="§3",
    category=Category.EXTENDED,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_CORE,
    text="The Password Modify operation SHALL NOT be used anonymously.",
    strategy="Bind anonymous, then Password Modify for bob; expect non-zero.",
    oid="1.3.6.1.4.1.4203.1.11.1",
)
def password_modify_anonymous_rejected(session: Session) -> Result:
    session.bind(None, None)
    outcome = session.extended(
        _PWMOD_OID, password_modify_request_value("bob-should-not-set", _BOB_DN)
    )
    if outcome.result_code != 0:
        return Result("3062.3.4", Status.PASS)
    return Result(
        "3062.3.4",
        Status.FAIL,
        detail="anonymous password modify succeeded",
    )

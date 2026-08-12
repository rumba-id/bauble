"""RFC 4511 §4.2 — Bind Request and Bind Response.

Eight assertions derived directly from the RFC. Four are testable via the
high-level client (Class A); four are not portably reachable and are recorded
as UNTESTABLE (Class B) with the reason. Credentials come from the Phase 2
base seed (alice/alice-secret, bob/bob-secret).
"""

from __future__ import annotations

from bauble.model import Assertion, Category, Profile, Result, Severity, Status, TestClass
from bauble.registry import default_registry
from bauble.session import Session
from bauble.suites._base import assertion

_ALICE = "uid=alice,ou=people,dc=bauble,dc=test"
_ALICE_PW = "alice-secret"
_BOB = "uid=bob,ou=people,dc=bauble,dc=test"
_BOB_PW = "bob-secret"
_BASE = frozenset({Profile.BASE})


# ---------------------------------------------------------------------------
# Class A — testable via the high-level client
# ---------------------------------------------------------------------------


@assertion(
    id="4511.4.2.1",
    rfc=4511,
    section="§4.2",
    category=Category.PROTOCOL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_BASE,
    text="Anonymous bind (empty DN + empty password) returns success.",
    strategy="Bind with empty DN and empty password; expect result code 0.",
)
def anonymous_bind(session: Session) -> Result:
    outcome = session.bind(None, None)
    if outcome.result_code == 0:
        return Result("4511.4.2.1", Status.PASS)
    return Result("4511.4.2.1", Status.FAIL, detail=f"expected success, got {outcome.result_code}")


@assertion(
    id="4511.4.2.2",
    rfc=4511,
    section="§4.2",
    category=Category.PROTOCOL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_BASE,
    text="Simple bind with valid credentials returns success.",
    strategy="Bind as a known user with the correct password; expect 0.",
)
def simple_bind_valid(session: Session) -> Result:
    outcome = session.bind(_ALICE, _ALICE_PW)
    if outcome.result_code == 0:
        return Result("4511.4.2.2", Status.PASS)
    return Result("4511.4.2.2", Status.FAIL, detail=f"expected success, got {outcome.result_code}")


@assertion(
    id="4511.4.2.3",
    rfc=4511,
    section="§4.2",
    category=Category.PROTOCOL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_BASE,
    text="Simple bind with invalid credentials returns invalidCredentials (49).",
    strategy="Bind as a known user with a wrong password; expect 49.",
)
def simple_bind_invalid(session: Session) -> Result:
    outcome = session.bind(_ALICE, "wrong-password")
    if outcome.result_code == 49:
        return Result("4511.4.2.3", Status.PASS)
    return Result("4511.4.2.3", Status.FAIL, detail=f"expected 49, got {outcome.result_code}")


@assertion(
    id="4511.4.2.6",
    rfc=4511,
    section="§4.2",
    category=Category.PROTOCOL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_BASE,
    text="Re-bind on an already-bound connection succeeds.",
    strategy="Bind as one user, then re-bind as a different user; expect both 0.",
    requires=("4511.4.2.2",),
)
def rebind(session: Session) -> Result:
    first = session.bind(_ALICE, _ALICE_PW)
    if first.result_code != 0:
        return Result("4511.4.2.6", Status.BLOCKED, detail="initial bind failed")
    second = session.bind(_BOB, _BOB_PW)
    if second.result_code == 0:
        return Result("4511.4.2.6", Status.PASS)
    return Result(
        "4511.4.2.6",
        Status.FAIL,
        detail=f"re-bind expected success, got {second.result_code}",
    )


# ---------------------------------------------------------------------------
# Class B — not portably testable via the high-level client
# ---------------------------------------------------------------------------

default_registry().register(
    Assertion(
        id="4511.4.2.5",
        rfc=4511,
        section="§4.2",
        category=Category.PROTOCOL,
        severity=Severity.MUST,
        test_class=TestClass.B,
        profiles=_BASE,
        text="Successful simple-bind response carries no serverSaslCreds.",
        strategy="serverSaslCreds is not exposed by the high-level client.",
    )
)

default_registry().register(
    Assertion(
        id="4511.4.2.4",
        rfc=4511,
        section="§4.2",
        category=Category.PROTOCOL,
        severity=Severity.MUST,
        test_class=TestClass.B,
        profiles=_BASE,
        text="Simple bind with non-empty name and empty password does not authenticate.",
        strategy="The high-level client requires a password for named simple binds.",
    )
)

default_registry().register(
    Assertion(
        id="4511.4.2.7",
        rfc=4511,
        section="§4.2",
        category=Category.PROTOCOL,
        severity=Severity.MUST,
        test_class=TestClass.B,
        profiles=_BASE,
        text="Bind with unrecognized protocol version returns protocolError.",
        strategy="The high-level client sends protocol version 3 only.",
    )
)

default_registry().register(
    Assertion(
        id="4511.4.2.8",
        rfc=4511,
        section="§4.2",
        category=Category.PROTOCOL,
        severity=Severity.MUST,
        test_class=TestClass.B,
        profiles=_BASE,
        text="Malformed BindRequest PDU returns protocolError and disconnect.",
        strategy="The high-level client validates and constructs PDUs; cannot send malformed.",
    )
)

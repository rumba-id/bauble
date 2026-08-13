"""RFC 4511 §4.2 — Bind Request and Bind Response.

Eight assertions derived directly from the RFC. With the raw wire layer,
all eight are testable: four via the high-level client, four via raw BER
on a bare socket. Credentials come from the Phase 2 base seed
(alice/alice-secret, bob/bob-secret).
"""

from __future__ import annotations

from bauble.model import Category, Layer, Profile, Result, Severity, Status, TestClass
from bauble.raw import RawConnection, build_bind_request_auth, build_sasl_bind_request
from bauble.session import Session
from bauble.suites._base import assertion

_ALICE = "uid=alice,ou=people,dc=bauble,dc=test"
_ALICE_PW = "alice-secret"
_BOB = "uid=bob,ou=people,dc=bauble,dc=test"
_BOB_PW = "bob-secret"
_INTEROP = frozenset({Profile.INTEROP})


# ---------------------------------------------------------------------------
# High-level client (ldap3) — Class A
# ---------------------------------------------------------------------------


@assertion(
    id="4511.4.2.1",
    rfc=4511,
    section="§4.2",
    category=Category.PROTOCOL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_INTEROP,
    text="Anonymous bind (empty DN + empty password) returns success.",
    strategy="Bind with empty DN and empty password; expect result code 0.",
    preconditions="Session is fresh or unauthenticated.",
    stimulus="Simple BindRequest with empty name and empty password.",
    expected_observables="BindResponse resultCode success (0).",
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
    profiles=_INTEROP,
    text="Simple bind with valid credentials returns success.",
    strategy="Bind as a known user with the correct password; expect 0.",
    preconditions="Seed entry uid=alice,ou=people,dc=bauble,dc=test exists with password alice-secret.",
    stimulus="Simple BindRequest with DN uid=alice and password alice-secret.",
    expected_observables="BindResponse resultCode success (0).",
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
    profiles=_INTEROP,
    text="Simple bind with invalid credentials returns invalidCredentials (49).",
    strategy="Bind as a known user with a wrong password; expect 49.",
    preconditions="Seed entry uid=alice,ou=people,dc=bauble,dc=test exists with password alice-secret.",
    stimulus="Simple BindRequest with DN uid=alice and an incorrect password.",
    expected_observables="BindResponse resultCode invalidCredentials (49).",
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
    profiles=_INTEROP,
    text="Re-bind on an already-bound connection succeeds.",
    strategy="Bind as one user, then re-bind as a different user; expect both 0.",
    preconditions="Prerequisite 4511.4.2.2 passed; seed alice and bob exist with their passwords.",
    stimulus="Simple BindRequest as alice, then a second Simple BindRequest as bob on the same session.",
    expected_observables="Both BindResponses resultCode success (0).",
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
# Raw wire layer — Class A (previously UNTESTABLE via ldap3)
# ---------------------------------------------------------------------------


@assertion(
    id="4511.4.2.4",
    rfc=4511,
    section="§4.2",
    category=Category.PROTOCOL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_INTEROP,
    text="Simple bind with non-empty name and empty password does not authenticate.",
    strategy="Raw BindRequest with a named DN and empty password; expect non-zero.",
    preconditions="Seed entry uid=alice,ou=people,dc=bauble,dc=test exists and requires a non-empty password.",
    stimulus="Raw simple BindRequest with DN uid=alice and an empty password.",
    expected_observables="BindResponse resultCode non-zero (authentication must not succeed).",
    layer=Layer.WIRE,
)
def empty_password_rejected(session: Session) -> Result:
    raw = RawConnection(session.host, session.port)
    outcome = raw.bind(version=3, dn=_ALICE, password="")
    if outcome.result_code != 0:
        return Result("4511.4.2.4", Status.PASS)
    return Result(
        "4511.4.2.4",
        Status.FAIL,
        detail="expected non-success (server should not authenticate)",
    )


@assertion(
    id="4511.4.2.5",
    rfc=4511,
    section="§4.2",
    category=Category.PROTOCOL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_INTEROP,
    text="Successful simple-bind response carries no serverSaslCreds.",
    strategy="Raw simple-auth bind with valid creds; check serverSaslCreds is absent.",
    preconditions="Prerequisite 4511.4.2.2 passed; valid alice credentials exist.",
    stimulus="Raw simple BindRequest with uid=alice and password alice-secret.",
    expected_observables="BindResponse success (0) with serverSaslCreds absent.",
    requires=("4511.4.2.2",),
    layer=Layer.WIRE,
)
def no_server_sasl_creds(session: Session) -> Result:
    raw = RawConnection(session.host, session.port)
    outcome = raw.bind(version=3, dn=_ALICE, password=_ALICE_PW)
    if outcome.result_code != 0:
        return Result("4511.4.2.5", Status.BLOCKED, detail="bind failed")
    if outcome.server_sasl_creds is None:
        return Result("4511.4.2.5", Status.PASS)
    return Result(
        "4511.4.2.5",
        Status.FAIL,
        detail="serverSaslCreds present in simple-bind response",
    )


@assertion(
    id="4511.4.2.7",
    rfc=4511,
    section="§4.2",
    category=Category.PROTOCOL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_INTEROP,
    text="Bind with unrecognized protocol version returns protocolError.",
    strategy="Raw BindRequest with version 99; expect result code 2.",
    preconditions="Session is fresh.",
    stimulus="Raw BindRequest with protocol version 99.",
    expected_observables="BindResponse resultCode protocolError (2).",
    layer=Layer.WIRE,
)
def bad_protocol_version(session: Session) -> Result:
    raw = RawConnection(session.host, session.port)
    outcome = raw.bind(version=99, dn="", password="")
    if outcome.result_code == 2:
        return Result("4511.4.2.7", Status.PASS)
    return Result(
        "4511.4.2.7", Status.FAIL, detail=f"expected 2 (protocolError), got {outcome.result_code}"
    )


@assertion(
    id="4511.4.2.8",
    rfc=4511,
    section="§4.2",
    category=Category.PROTOCOL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_INTEROP,
    text="Malformed BindRequest PDU returns protocolError and disconnect.",
    strategy="Send garbage bytes; expect the server to disconnect (no response).",
    preconditions="Session is fresh.",
    stimulus="Raw bytes 0xffffffff sent as an LDAPMessage.",
    expected_observables="Server disconnects without a valid response.",
    layer=Layer.WIRE,
)
def malformed_pdu_disconnects(session: Session) -> Result:
    raw = RawConnection(session.host, session.port)
    response = raw.send_malformed(b"\xff\xff\xff\xff")
    if response is None:
        return Result("4511.4.2.8", Status.PASS)
    return Result("4511.4.2.8", Status.FAIL, detail="expected disconnect, got a response")


@assertion(
    id="4511.4.2.9",
    rfc=4511,
    section="§4.2",
    category=Category.PROTOCOL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_INTEROP,
    layer=Layer.WIRE,
    text="A BindRequest with an empty SASL mechanism returns authMethodNotSupported (7).",
    strategy="Raw SASL BindRequest with mechanism=''; expect result code 7.",
    preconditions="Session is fresh.",
    stimulus="Raw SASL BindRequest with the mechanism field set to the empty string.",
    expected_observables="BindResponse resultCode authMethodNotSupported (7).",
)
def empty_sasl_mechanism_rejected(session: Session) -> Result:
    raw = RawConnection(session.host, session.port)
    outcome = raw.raw_send(build_sasl_bind_request(1, 3, "", ""))
    if outcome.result_code == 7:
        return Result("4511.4.2.9", Status.PASS)
    return Result(
        "4511.4.2.9",
        Status.FAIL,
        detail=f"expected 7 (authMethodNotSupported), got {outcome.result_code}",
    )


@assertion(
    id="4511.4.2.10",
    rfc=4511,
    section="§4.2",
    category=Category.PROTOCOL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_INTEROP,
    layer=Layer.WIRE,
    text="A BindRequest with an unsupported authentication choice returns authMethodNotSupported (7).",
    strategy="Raw BindRequest with an unrecognized auth CHOICE tag [5]; expect result code 7.",
    preconditions="Session is fresh.",
    stimulus="Raw BindRequest with an unrecognized AuthenticationChoice tag ([5]).",
    expected_observables="BindResponse resultCode authMethodNotSupported (7).",
)
def unsupported_auth_choice_rejected(session: Session) -> Result:
    raw = RawConnection(session.host, session.port)
    outcome = raw.raw_send(build_bind_request_auth(1, 3, "", b"\xa5\x01\x00"))
    if outcome.result_code == 7:
        return Result("4511.4.2.10", Status.PASS)
    return Result(
        "4511.4.2.10",
        Status.FAIL,
        detail=f"expected 7 (authMethodNotSupported), got {outcome.result_code}",
    )

"""RFC 3909 — LDAP Cancel Operation."""

from __future__ import annotations

from bauble.model import Category, Layer, Profile, Result, Severity, Status, TestClass
from bauble.session import SCOPE_BASE_OBJECT, Session
from bauble.suites._base import assertion
from bauble.suites._helpers import ADMIN_DN, ADMIN_PW

_CORE = frozenset({Profile.CORE})

_CANCEL_OID = "1.3.6.1.1.8"

#: RFC 3909 §2.3 — additional result codes.
_NO_SUCH_OPERATION = 119


@assertion(
    id="3909.3.1",
    rfc=3909,
    section="§3",
    category=Category.EXTENDED,
    severity=Severity.SHOULD,
    test_class=TestClass.A,
    profiles=_CORE,
    layer=Layer.CAPABILITY,
    oid=_CANCEL_OID,
    text="Servers SHOULD advertise 1.3.6.1.1.8 in supportedExtension.",
    strategy="Read the root DSE supportedExtension and check for the cancel OID.",
    preconditions="Root DSE is readable.",
    stimulus="Search the root DSE for supportedExtension.",
    expected_observables="1.3.6.1.1.8 present, or NOT_APPLICABLE if not advertised.",
)
def cancel_advertised(session: Session) -> Result:
    outcome, entries = session.search(
        "", SCOPE_BASE_OBJECT, "(objectClass=*)", ["supportedExtension"]
    )
    if outcome.result_code != 0 or not entries:
        return Result("3909.3.1", Status.NOT_APPLICABLE, detail="root DSE not readable")
    extensions = entries[0].attributes.get("supportedExtension", [])
    if _CANCEL_OID in extensions:
        return Result("3909.3.1", Status.PASS)
    return Result("3909.3.1", Status.NOT_APPLICABLE, detail="cancel OID not advertised")


@assertion(
    id="3909.2.1",
    rfc=3909,
    section="§2",
    category=Category.EXTENDED,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_CORE,
    layer=Layer.WIRE,
    text="A Cancel request naming an operation the server has no knowledge of returns noSuchOperation (119).",
    strategy="Raw Cancel extended request for an unknown messageID; expect resultCode 119.",
    preconditions="Target server is reachable on session.host:session.port.",
    stimulus="Bind, then send a Cancel request whose cancelID is an unissued messageID.",
    expected_observables="The Cancel response carries noSuchOperation (119).",
)
def cancel_unknown_message_id(session: Session) -> Result:
    from bauble.raw import RawConnection, build_cancel_request

    # Cancel is optional: only applicable when the server advertises it.
    advertise, entries = session.search(
        "", SCOPE_BASE_OBJECT, "(objectClass=*)", ["supportedExtension"]
    )
    if advertise.result_code != 0 or not entries:
        return Result("3909.2.1", Status.NOT_APPLICABLE, detail="root DSE not readable")
    if _CANCEL_OID not in entries[0].attributes.get("supportedExtension", []):
        return Result("3909.2.1", Status.NOT_APPLICABLE, detail="cancel not advertised")

    raw = RawConnection(session.host, session.port)
    cancel_outcome = raw.bind_then_send(build_cancel_request(2, 999999), ADMIN_DN, ADMIN_PW)
    if cancel_outcome.result_code == _NO_SUCH_OPERATION:
        return Result("3909.2.1", Status.PASS)
    return Result(
        "3909.2.1",
        Status.FAIL,
        detail=f"expected noSuchOperation (119), got {cancel_outcome.result_code}",
    )

"""RFC 4370 — LDAP Proxied Authorization Control."""

from __future__ import annotations

from bauble.model import Category, Layer, Profile, Result, Severity, Status, TestClass
from bauble.session import SCOPE_BASE_OBJECT, Control, Session
from bauble.suites._base import assertion

_CORE = frozenset({Profile.CORE})

_PROXY_AUTHZ_OID = "2.16.840.1.113730.3.4.18"

#: RFC 4511 resultCode — protocolError.
_PROTOCOL_ERROR = 2


@assertion(
    id="4370.2.1",
    rfc=4370,
    section="§2",
    category=Category.CONTROL,
    severity=Severity.SHOULD,
    test_class=TestClass.A,
    profiles=_CORE,
    layer=Layer.CAPABILITY,
    oid=_PROXY_AUTHZ_OID,
    text="The server advertises the Proxy Authorization Control in supportedControl.",
    strategy="Read the root DSE supportedControl and check for the proxy-authz OID.",
    preconditions="Root DSE is readable.",
    stimulus="Search the root DSE for supportedControl.",
    expected_observables="2.16.840.1.113730.3.4.18 present, or NOT_APPLICABLE if not advertised.",
)
def proxy_authz_advertised(session: Session) -> Result:
    outcome, entries = session.search(
        "", SCOPE_BASE_OBJECT, "(objectClass=*)", ["supportedControl"]
    )
    if outcome.result_code != 0 or not entries:
        return Result("4370.2.1", Status.NOT_APPLICABLE, detail="root DSE not readable")
    controls = entries[0].attributes.get("supportedControl", [])
    if _PROXY_AUTHZ_OID in controls:
        return Result("4370.2.1", Status.PASS)
    return Result("4370.2.1", Status.NOT_APPLICABLE, detail="proxy-authz OID not advertised")


@assertion(
    id="4370.3.1",
    rfc=4370,
    section="§3",
    category=Category.CONTROL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_CORE,
    layer=Layer.WIRE,
    text="A Proxy Authorization Control without criticality TRUE is rejected with protocolError.",
    strategy="Send a search with the proxy-authz control and criticality FALSE; expect protocolError (2).",
    preconditions="Root DSE is readable.",
    stimulus="Search the root DSE with a non-critical proxy-authz control.",
    expected_observables="protocolError (2) resultCode.",
)
def proxy_authz_requires_criticality(session: Session) -> Result:
    from bauble.suites._helpers import bind_admin

    # Proxy authorization is optional: only applicable when advertised.
    advertise, entries = session.search(
        "", SCOPE_BASE_OBJECT, "(objectClass=*)", ["supportedControl"]
    )
    if advertise.result_code != 0 or not entries:
        return Result("4370.3.1", Status.NOT_APPLICABLE, detail="root DSE not readable")
    if _PROXY_AUTHZ_OID not in entries[0].attributes.get("supportedControl", []):
        return Result("4370.3.1", Status.NOT_APPLICABLE, detail="proxy-authz not advertised")

    bind_admin(session)
    outcome, _ = session.search(
        "",
        SCOPE_BASE_OBJECT,
        "(objectClass=*)",
        controls=(
            Control(
                oid=_PROXY_AUTHZ_OID,
                value=b"dn:uid=alice,ou=people,dc=bauble,dc=test",
                criticality=False,
            ),
        ),
    )
    if outcome.result_code == _PROTOCOL_ERROR:
        return Result("4370.3.1", Status.PASS)
    return Result(
        "4370.3.1", Status.FAIL, detail=f"expected protocolError (2), got {outcome.result_code}"
    )

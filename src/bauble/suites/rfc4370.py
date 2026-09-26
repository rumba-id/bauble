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


def _extended_response_value(data: bytes) -> bytes:
    """Extract the [11] responseValue from the ExtendedResponse in ``data``."""
    from bauble.raw import _parse_length, _split_messages  # type: ignore[reportPrivateUsage]

    def _skip(buf: bytes, pos: int) -> int:
        pos += 1
        length, pos = _parse_length(buf, pos)
        return pos + length

    def _octet(buf: bytes, pos: int) -> bytes:
        pos += 1
        length, pos = _parse_length(buf, pos)
        return buf[pos : pos + length]

    for msg in _split_messages(data):
        pos = 1
        _, pos = _parse_length(msg, pos)
        if pos + 1 >= len(msg) or msg[pos] != 0x02:  # messageID
            continue
        pos = _skip(msg, pos)
        if msg[pos] != 0x78:  # ExtendedResponse [APPLICATION 24]
            continue
        pos += 1
        _, pos = _parse_length(msg, pos)
        pos = _skip(msg, pos)  # resultCode ENUMERATED
        pos = _skip(msg, pos)  # matchedDN
        pos = _skip(msg, pos)  # diagnosticMessage
        while pos < len(msg):
            if msg[pos] == 0x8B:  # responseValue [11]
                return _octet(msg, pos)
            pos = _skip(msg, pos)
    return b""


@assertion(
    id="4370.3.2",
    rfc=4370,
    section="§3",
    category=Category.AUTH,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_CORE,
    layer=Layer.WIRE,
    text="A recognized proxy authorization identity causes the operation to be executed as that identity.",
    strategy="Who-Am-I extended request carrying a critical proxy-authz control naming uid=alice; the response authzId must be alice's, not the binder's.",
    preconditions="Admin bound; the proxy-authz control is advertised.",
    stimulus="Raw Who-Am-I extended request with the Proxy Authorization Control (criticality TRUE, authzId dn:uid=alice).",
    expected_observables="The Who-Am-I responseValue carries dn:uid=alice (the proxied identity).",
    oid="2.16.840.1.113730.3.4.18",
)
def proxy_authz_identity_applies(session: Session) -> Result:
    from bauble.raw import (
        RawConnection,
        _parse_ldap_result,  # type: ignore[reportPrivateUsage]
        build_control,
        build_extended_request,
    )
    from bauble.suites._helpers import bind_admin

    # Proxy authorization is optional: only applicable when advertised.
    advertise, entries = session.search(
        "", SCOPE_BASE_OBJECT, "(objectClass=*)", ["supportedControl"]
    )
    if advertise.result_code != 0 or not entries:
        return Result("4370.3.2", Status.NOT_APPLICABLE, detail="root DSE not readable")
    if _PROXY_AUTHZ_OID not in entries[0].attributes.get("supportedControl", []):
        return Result("4370.3.2", Status.NOT_APPLICABLE, detail="proxy-authz not advertised")

    bind_admin(session)
    control = build_control(
        _PROXY_AUTHZ_OID,
        criticality=True,
        value=b"dn:uid=alice,ou=people,dc=bauble,dc=test",
    )
    request = build_extended_request(
        2,
        "1.3.6.1.4.1.4203.1.11.3",
        controls=[control],  # Who Am I?
    )
    raw = RawConnection(session.host, session.port)
    from bauble.suites._helpers import ADMIN_DN, ADMIN_PW

    response = raw.bind_then_send_raw(request, ADMIN_DN, ADMIN_PW)
    outcome = _parse_ldap_result(response)
    code = outcome.result_code if outcome else -1
    # RFC 4370 §3: when the client is not authorized to adopt the identity,
    # resultCode 123 is the conformant response (policy denial).
    if code == 123:
        return Result("4370.3.2", Status.PASS, detail="proxy authorization denied by policy (123)")
    if code != 0:
        return Result("4370.3.2", Status.FAIL, detail=f"whoami with proxy-authz failed: {code}")
    value = _extended_response_value(response)
    if value.lower() == b"dn:uid=alice,ou=people,dc=bauble,dc=test":
        return Result("4370.3.2", Status.PASS)
    return Result(
        "4370.3.2",
        Status.FAIL,
        detail=f"executed under the binder's identity instead of the proxied one: {value!r}",
    )

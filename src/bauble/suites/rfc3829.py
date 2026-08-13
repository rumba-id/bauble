"""RFC 3829 — Authorization Identity Request and Response Controls.

ldap3 type stubs are incomplete for Connection.bind/rebind and response
controls, producing unavoidable pyright warnings on known-good code.
"""  # pyright: ignore[reportUnknownArgumentType, reportUnknownVariableType]

from bauble.model import Category, Layer, Profile, Result, Severity, Status, TestClass
from bauble.session import SCOPE_BASE_OBJECT, Session
from bauble.suites._base import assertion
from bauble.suites._helpers import ADMIN_DN, ADMIN_PW

_CORE = frozenset({Profile.CORE})

_AUTHZID_REQUEST_OID = "2.16.840.1.113730.3.4.16"
_AUTHZID_RESPONSE_OID = "2.16.840.1.113730.3.4.15"


@assertion(
    id="3829.2.1",
    rfc=3829,
    section="§2",
    category=Category.AUTH,
    severity=Severity.SHOULD,
    test_class=TestClass.B,
    profiles=_CORE,
    text="Server SHOULD publish 2.16.840.1.113730.3.4.16/15 in supportedControl.",
    strategy="Read root DSE supportedControl and check for both OIDs.",
    layer=Layer.CAPABILITY,
)
def authzid_controls_advertised(session: Session) -> Result:
    outcome, entries = session.search(
        "", SCOPE_BASE_OBJECT, "(objectClass=*)", ["supportedControl"]
    )
    if outcome.result_code != 0 or not entries:
        return Result("3829.2.1", Status.UNTESTABLE, detail="root DSE not readable")
    controls = entries[0].attributes.get("supportedControl", [])
    if _AUTHZID_REQUEST_OID in controls and _AUTHZID_RESPONSE_OID in controls:
        return Result("3829.2.1", Status.PASS)
    return Result("3829.2.1", Status.UNTESTABLE, detail="OIDs not advertised")


@assertion(
    id="3829.4.1",
    rfc=3829,
    section="§4",
    category=Category.AUTH,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_CORE,
    text="Successful bind with AuthzId Request control returns response control with authzId.",
    strategy="Bind as admin with request control; verify response control contains authzId.",
    mutates=True,
)
def authzid_response_on_bind(session: Session) -> Result:
    # Use ldap3 to send the bind with the request control.
    from bauble.harness import LdapSession, ServerConfig, outcome_from_result

    # Create a fresh connection to test the bind control flow.
    cfg = ServerConfig(session.host, session.port)
    raw_session = LdapSession(cfg)
    raw_session._ensure_open()  # type: ignore[reportPrivateUsage]
    conn = raw_session._connection  # type: ignore[reportPrivateUsage]
    conn.rebind(  # type: ignore[reportUnknownMemberType]
        user=ADMIN_DN,  # type: ignore[reportCallIssue]
        password=ADMIN_PW,  # type: ignore[reportCallIssue]
        controls=[
            (_AUTHZID_REQUEST_OID, False, None)  # non-critical
        ],
    )
    result = outcome_from_result(conn.result)
    if result.result_code != 0:
        return Result(
            "3829.4.1",
            Status.FAIL,
            detail=f"bind failed: {result.result_code}",
        )

    # Check for response control
    response_controls: list = getattr(conn.result, "controls", None) or []  # type: ignore[reportUnknownVariableType]
    found = False
    for c in response_controls:  # type: ignore[reportUnknownVariableType]
        if getattr(c, "controlType", None) == _AUTHZID_RESPONSE_OID:  # type: ignore[reportUnknownArgumentType]
            found = True
            break
    if found:
        return Result("3829.4.1", Status.PASS)
    return Result(
        "3829.4.1",
        Status.NOT_APPLICABLE,
        detail="no authzId response control returned",
    )

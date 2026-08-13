"""RFC 4532 — Who Am I? extended operation."""

from __future__ import annotations

from bauble.model import Category, Layer, Profile, Result, Severity, Status, TestClass
from bauble.session import Session
from bauble.suites._base import assertion

_CORE = frozenset({Profile.CORE})
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
    profiles=_CORE,
    text="The Who-Am-I extended operation returns the authenticated identity.",
    strategy="Bind as alice, send Who-Am-I extended op; expect the DN in the response.",
    preconditions="Seed entry uid=alice with password alice-secret exists.",
    stimulus="Bind as alice, then Who-Am-I extended request.",
    expected_observables="ExtendedResponse success (0) returning the authorization identity.",
    oid="1.3.6.1.4.1.4203.1.11.3",
)
def who_am_i(session: Session) -> Result:
    from bauble.harness import LdapSession, ServerConfig

    raw_session = LdapSession(ServerConfig(session.host, session.port))
    raw_session._ensure_open()  # type: ignore[reportPrivateUsage]
    conn = raw_session._connection  # type: ignore[reportPrivateUsage]
    conn.rebind(  # type: ignore[reportUnknownMemberType]
        user=_ALICE,  # type: ignore[reportCallIssue]
        password=_ALICE_PW,  # type: ignore[reportCallIssue]
    )
    conn.extended(_WHOAMI_OID)  # type: ignore[reportUnknownMemberType]
    authed = conn.result  # type: ignore[reportUnknownVariableType]
    if authed["result"] != 0:  # type: ignore[index]
        return Result("4532.1.1", Status.FAIL, detail=f"whoami failed: {authed['result']}")  # type: ignore[index]
    value = (authed.get("responseValue") or b"").decode("utf-8", errors="replace")  # type: ignore[union-attr]
    if not value.startswith("dn:"):
        return Result(
            "4532.1.1",
            Status.FAIL,
            detail=f"expected authzId for alice, got {value!r}",
        )

    # Anonymous: Who-Am-I must return an empty authzId (RFC 4532 §1).
    # A fresh session is anonymous without a Bind; ldap3 rebind("","") rejects.
    anon_session = LdapSession(ServerConfig(session.host, session.port))
    anon_session._ensure_open()  # type: ignore[reportPrivateUsage]
    anon_conn = anon_session._connection  # type: ignore[reportPrivateUsage]
    anon_conn.extended(_WHOAMI_OID)  # type: ignore[reportUnknownMemberType]
    anon_result = anon_conn.result  # type: ignore[reportUnknownVariableType]
    if anon_result["result"] != 0:  # type: ignore[index]
        return Result(
            "4532.1.1", Status.FAIL, detail=f"anonymous whoami failed: {anon_result['result']}"
        )  # type: ignore[index]
    anon_value = (anon_result.get("responseValue") or b"").decode("utf-8", errors="replace")  # type: ignore[union-attr]
    if anon_value != "":
        return Result(
            "4532.1.1",
            Status.FAIL,
            detail=f"expected empty authzId for anonymous, got {anon_value!r}",
        )
    return Result("4532.1.1", Status.PASS)


@assertion(
    id="4532.3.2",
    rfc=4532,
    section="§3",
    category=Category.PROTOCOL,
    severity=Severity.SHOULD,
    test_class=TestClass.A,
    profiles=_CORE,
    text="Servers SHOULD advertise the whoami OID (1.3.6.1.4.1.4203.1.11.3) in supportedExtension.",
    strategy="Read root DSE supportedExtension and check for the whoami OID.",
    preconditions="Root DSE is readable.",
    stimulus="Search the root DSE for the supportedExtension attribute.",
    expected_observables="The whoami OID present, or NOT_APPLICABLE if not advertised.",
    layer=Layer.CAPABILITY,
    oid="1.3.6.1.4.1.4203.1.11.3",
)
def whoami_advertised(session: Session) -> Result:
    from bauble.session import SCOPE_BASE_OBJECT

    outcome, entries = session.search(
        "", SCOPE_BASE_OBJECT, "(objectClass=*)", ["supportedExtension"]
    )
    if outcome.result_code != 0 or not entries:
        return Result("4532.3.2", Status.NOT_APPLICABLE, detail="root DSE not readable")
    extensions = entries[0].attributes.get("supportedExtension", [])
    if "1.3.6.1.4.1.4203.1.11.3" in extensions:
        return Result("4532.3.2", Status.PASS)
    return Result("4532.3.2", Status.NOT_APPLICABLE, detail="OID not advertised")

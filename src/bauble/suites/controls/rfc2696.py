"""RFC 2696 — Simple Paged Results control."""

from __future__ import annotations

from bauble.model import Category, Layer, Profile, Result, Severity, Status, TestClass
from bauble.raw import paged_results_control_value
from bauble.session import SCOPE_WHOLE_SUBTREE, Control, Session
from bauble.suites._base import assertion

_CORE = frozenset({Profile.CORE})

_PAGED_OID = "1.2.840.113556.1.4.319"


@assertion(
    id="2696.2.1",
    rfc=2696,
    section="§2",
    category=Category.CONTROL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_CORE,
    text="A search with the paged-results control (size=2) is accepted.",
    strategy="Search the base DIT with paged-results control, page size 2; expect code 0.",
    preconditions="Seed base dc=bauble,dc=test has entries to page over.",
    stimulus="SearchRequest over the base with a paged-results control (size=2).",
    expected_observables="SearchResultDone resultCode success (0).",
    oid="1.2.840.113556.1.4.319",
)
def paged_results_accepted(session: Session) -> Result:
    outcome, _ = session.search(
        "dc=bauble,dc=test",
        SCOPE_WHOLE_SUBTREE,
        "(objectClass=*)",
        controls=(
            Control(
                oid=_PAGED_OID,
                value=paged_results_control_value(2),
                criticality=False,
            ),
        ),
    )
    if outcome.result_code == 0:
        return Result("2696.2.1", Status.PASS)
    return Result("2696.2.1", Status.FAIL, detail=f"expected 0, got {outcome.result_code}")


@assertion(
    id="2696.2.2",
    rfc=2696,
    section="§3",
    category=Category.CONTROL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_CORE,
    text="The paged-results cookie is non-empty while pages remain and empty when exhausted.",
    strategy="Page ou=people (size=1); expect a non-empty cookie then an empty one.",
    preconditions="Seed ou=people has at least 2 entries; admin credentials available.",
    stimulus="Paged SearchRequest over ou=people (size=1), iterating with the returned cookie.",
    expected_observables="The first page returns a non-empty cookie; the final page returns an empty cookie.",
    oid="1.2.840.113556.1.4.319",
)
def paged_results_cookie_exhausts(session: Session) -> Result:
    from bauble.harness import LdapSession, ServerConfig
    from bauble.suites._helpers import ADMIN_DN, ADMIN_PW

    cfg = ServerConfig(session.host, session.port)
    raw_session = LdapSession(cfg)
    raw_session._ensure_open()  # type: ignore[reportPrivateUsage]
    conn = raw_session._connection  # type: ignore[reportPrivateUsage]
    conn.rebind(  # type: ignore[reportUnknownMemberType]
        user=ADMIN_DN,  # type: ignore[reportCallIssue]
        password=ADMIN_PW,  # type: ignore[reportCallIssue]
    )

    cookie: bytes | None = None
    saw_nonempty = False
    exhausted = False
    for _ in range(10):
        conn.search(  # type: ignore[reportUnknownMemberType]
            "ou=people,dc=bauble,dc=test",
            "(objectClass=*)",
            search_scope="SUBTREE",
            attributes=["uid"],
            paged_size=1,
            paged_cookie=cookie,
        )
        ctrl = conn.result.get("controls", {}).get(_PAGED_OID)  # type: ignore[reportUnknownMemberType, reportUnknownVariableType]
        if not ctrl:
            return Result("2696.2.2", Status.FAIL, detail="no paged-response control")
        cookie = ctrl["value"]["cookie"]  # type: ignore[reportUnknownVariableType, reportUnknownArgumentType]
        if cookie:
            saw_nonempty = True
        else:
            exhausted = True
            break
    if saw_nonempty and exhausted:
        return Result("2696.2.2", Status.PASS)
    return Result(
        "2696.2.2",
        Status.FAIL,
        detail=f"cookie did not exhaust (saw_nonempty={saw_nonempty}, exhausted={exhausted})",
    )


@assertion(
    id="2696.3.3",
    rfc=2696,
    section="§3",
    category=Category.PROTOCOL,
    severity=Severity.SHOULD,
    test_class=TestClass.A,
    profiles=_CORE,
    text="Servers SHOULD publish 1.2.840.113556.1.4.319 in supportedControl.",
    strategy="Read root DSE supportedControl and check for the paged-results OID.",
    preconditions="Root DSE is readable.",
    stimulus="Search the root DSE for the supportedControl attribute.",
    expected_observables="Paged-results control OID present, or NOT_APPLICABLE if not advertised.",
    layer=Layer.CAPABILITY,
    oid="1.2.840.113556.1.4.319",
)
def paged_control_advertised(session: Session) -> Result:
    from bauble.session import SCOPE_BASE_OBJECT

    outcome, entries = session.search(
        "", SCOPE_BASE_OBJECT, "(objectClass=*)", ["supportedControl"]
    )
    if outcome.result_code != 0 or not entries:
        return Result("2696.3.3", Status.NOT_APPLICABLE, detail="root DSE not readable")
    controls = entries[0].attributes.get("supportedControl", [])
    if "1.2.840.113556.1.4.319" in controls:
        return Result("2696.3.3", Status.PASS)
    return Result("2696.3.3", Status.NOT_APPLICABLE, detail="OID not advertised")

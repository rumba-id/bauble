"""RFC 4513 §4.1 — Authorization State."""

from bauble.model import Category, Profile, Result, Severity, Status, TestClass
from bauble.session import SCOPE_WHOLE_SUBTREE, Session
from bauble.suites._base import assertion
from bauble.suites._helpers import TEST_BASE

_BASE = frozenset({Profile.BASE})


@assertion(
    id="4513.4.1.1",
    rfc=4513,
    section="§4.1",
    category=Category.AUTH,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_BASE,
    text="Upon initial session establishment, the authorization state is anonymous.",
    strategy="Open a fresh unauthenticated session and issue a search; must succeed.",
)
def initial_session_anonymous(session: Session) -> Result:
    # The session is created fresh by the runner — no Bind called yet.
    # An anonymous session should be able to read entries.
    outcome, entries = session.search(TEST_BASE, SCOPE_WHOLE_SUBTREE, "(objectClass=*)")
    if outcome.result_code != 0:
        return Result(
            "4513.4.1.1",
            Status.FAIL,
            detail=f"anonymous search failed: {outcome.result_code}",
        )
    if not entries:
        return Result("4513.4.1.1", Status.FAIL, detail="no entries returned to anonymous client")
    return Result("4513.4.1.1", Status.PASS)


@assertion(
    id="4513.4.1.2",
    rfc=4513,
    section="§4.1",
    category=Category.AUTH,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_BASE,
    text="Any operation before Bind MUST be treated as post-anonymous-Bind.",
    strategy="Issue search, then bind as admin, then search again — both succeed.",
)
def pre_bind_ops_treated_as_anonymous(session: Session) -> Result:
    # First, search before binding (anonymous).
    outcome, _ = session.search(TEST_BASE, SCOPE_WHOLE_SUBTREE, "(objectClass=*)")
    if outcome.result_code != 0:
        return Result(
            "4513.4.1.2",
            Status.FAIL,
            detail=f"pre-bind search failed: {outcome.result_code}",
        )

    # Now bind as admin.
    from bauble.suites._helpers import ADMIN_DN, ADMIN_PW

    bind_result = session.bind(ADMIN_DN, ADMIN_PW)
    if bind_result.result_code != 0:
        return Result(
            "4513.4.1.2",
            Status.FAIL,
            detail=f"admin bind failed: {bind_result.result_code}",
        )

    # Search again after binding — should still work.
    outcome2, _ = session.search(TEST_BASE, SCOPE_WHOLE_SUBTREE, "(objectClass=*)")
    if outcome2.result_code != 0:
        return Result(
            "4513.4.1.2",
            Status.FAIL,
            detail=f"post-bind search failed: {outcome2.result_code}",
        )
    return Result("4513.4.1.2", Status.PASS)

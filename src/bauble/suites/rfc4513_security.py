"""RFC 4513 §3 — StartTLS and Transport Layer Security."""

from bauble.model import Category, Profile, Result, Severity, Status, TestClass
from bauble.session import SCOPE_BASE_OBJECT, SCOPE_WHOLE_SUBTREE, Session
from bauble.suites._base import assertion
from bauble.suites._helpers import ADMIN_DN, ADMIN_PW, TEST_BASE

_SECURITY = frozenset({Profile.EXTENDED})

_STARTTLS_OID = "1.3.6.1.4.1.1466.20037"


def _starttls(session: Session) -> int:
    """Perform StartTLS on the session. Returns resultCode."""
    outcome = session.start_tls()
    return outcome.result_code


@assertion(
    id="4513.3.1.1",
    rfc=4513,
    section="§3.1.1",
    category=Category.TRANSPORT,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_SECURITY,
    text="StartTLS operation succeeds on an unencrypted session.",
    stimulus="StartTLS extended operation on a plain TCP session.",
    preconditions="Open LDAP session with no TLS active.",
    expected_observables="StartTLS response resultCode is success (0).",
)
def starttls_succeeds(session: Session) -> Result:
    result_code = _starttls(session)
    if result_code == 0:
        return Result("4513.3.1.1", Status.PASS)
    return Result(
        "4513.3.1.1",
        Status.FAIL,
        detail=f"StartTLS failed: resultCode={result_code}",
    )


@assertion(
    id="4513.3.1.1-2",
    rfc=4513,
    section="§3.1.1",
    category=Category.TRANSPORT,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_SECURITY,
    text="StartTLS is rejected when TLS is already established.",
    stimulus="StartTLS extended operation after a successful StartTLS.",
    preconditions="TLS already active on the session.",
    expected_observables="Second StartTLS returns operationsError (1).",
)
def starttls_rejected_when_active(session: Session) -> Result:
    first = _starttls(session)
    if first != 0:
        return Result(
            "4513.3.1.1-2",
            Status.NOT_APPLICABLE,
            detail=f"initial StartTLS failed: resultCode={first}",
        )
    second = _starttls(session)
    if second != 0:
        return Result("4513.3.1.1-2", Status.PASS)
    return Result(
        "4513.3.1.1-2",
        Status.FAIL,
        detail=f"second StartTLS should have failed, got {second}",
    )


@assertion(
    id="4513.3.1.5",
    rfc=4513,
    section="§3.1.5",
    category=Category.TRANSPORT,
    severity=Severity.SHOULD,
    test_class=TestClass.A,
    profiles=_SECURITY,
    text="Server capabilities should be refreshed after TLS establishment.",
    stimulus="Read supportedSASLMechanisms before and after StartTLS.",
    preconditions="Open LDAP session with no TLS active.",
    expected_observables=(
        "supportedSASLMechanisms may differ after TLS (e.g. EXTERNAL added). "
        "PASS if they differ, NOT_APPLICABLE if unchanged (SHOULD requirement)."
    ),
)
def capabilities_refreshed_after_tls(session: Session) -> Result:
    # Read before TLS.
    pre, pre_entries = session.search(
        "", SCOPE_BASE_OBJECT, "(objectClass=*)", ["supportedSASLMechanisms"]
    )
    pre_mechs: set[str | bytes] = set()
    if pre_entries and pre.result_code == 0:
        pre_mechs = set(pre_entries[0].attributes.get("supportedSASLMechanisms", []))

    # StartTLS.
    tls_result = _starttls(session)
    if tls_result != 0:
        return Result(
            "4513.3.1.5",
            Status.NOT_APPLICABLE,
            detail=f"StartTLS failed: resultCode={tls_result}",
        )

    # Read after TLS.
    post, post_entries = session.search(
        "", SCOPE_BASE_OBJECT, "(objectClass=*)", ["supportedSASLMechanisms"]
    )
    post_mechs: set[str | bytes] = set()
    if post_entries and post.result_code == 0:
        post_mechs = set(post_entries[0].attributes.get("supportedSASLMechanisms", []))

    if pre_mechs != post_mechs:
        return Result("4513.3.1.5", Status.PASS)
    return Result(
        "4513.3.1.5",
        Status.NOT_APPLICABLE,
        detail="capabilities unchanged after TLS (SHOULD requirement)",
    )


@assertion(
    id="4513.3.2",
    rfc=4513,
    section="§3.2",
    category=Category.TRANSPORT,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_SECURITY,
    text="Authorization state moves to anonymous after TLS establishment.",
    stimulus="Bind as admin, then StartTLS, then search without re-binding.",
    preconditions="Session authenticated as admin.",
    expected_observables="Post-TLS search succeeds (anonymous access).",
)
def authorization_resets_after_tls(session: Session) -> Result:
    # Bind as admin first.
    bind_result = session.bind(ADMIN_DN, ADMIN_PW)
    if bind_result.result_code != 0:
        return Result(
            "4513.3.2",
            Status.FAIL,
            detail=f"admin bind failed: {bind_result.result_code}",
        )

    # StartTLS.
    tls_result = _starttls(session)
    if tls_result != 0:
        return Result(
            "4513.3.2",
            Status.NOT_APPLICABLE,
            detail=f"StartTLS failed: resultCode={tls_result}",
        )

    # Search without re-binding — should succeed as anonymous.
    outcome, entries = session.search(TEST_BASE, SCOPE_WHOLE_SUBTREE, "(objectClass=*)")
    if outcome.result_code == 0 and entries:
        return Result("4513.3.2", Status.PASS)
    return Result(
        "4513.3.2",
        Status.FAIL,
        detail=f"post-TLS anonymous search failed: {outcome.result_code}",
    )


@assertion(
    id="4513.2.2",
    rfc=4513,
    section="§2",
    category=Category.TRANSPORT,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_SECURITY,
    text="Simple bind with name/password works after StartTLS.",
    stimulus="StartTLS, then bind as admin.",
    preconditions="StartTLS active on the session.",
    expected_observables="Bind succeeds (resultCode 0) over TLS.",
)
def simple_bind_over_starttls(session: Session) -> Result:
    tls_result = _starttls(session)
    if tls_result != 0:
        return Result(
            "4513.2.2",
            Status.NOT_APPLICABLE,
            detail=f"StartTLS failed: resultCode={tls_result}",
        )
    bind_result = session.bind(ADMIN_DN, ADMIN_PW)
    if bind_result.result_code == 0:
        return Result("4513.2.2", Status.PASS)
    return Result(
        "4513.2.2",
        Status.FAIL,
        detail=f"bind over TLS failed: {bind_result.result_code}",
    )

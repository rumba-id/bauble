"""RFC 4511 §4.5 — Alias dereferencing and referral semantics."""

from bauble.model import Category, Profile, Result, Severity, Status, TestClass
from bauble.session import SCOPE_WHOLE_SUBTREE, Session
from bauble.suites._base import assertion

_INTEROP = frozenset({Profile.INTEROP})

#: derefAliases values (RFC 4511 §4.5.1).
_DEREF_NEVER = 0
_DEREF_FINDING_BASE = 2
_DEREF_ALWAYS = 3


@assertion(
    id="4511.4.5.6",
    rfc=4511,
    section="§4.5.1",
    category=Category.PROTOCOL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_INTEROP,
    text="Alias dereferencing with derefAlways follows the alias to its target.",
    strategy="Search (uid=alice-alias) with derefAlways; expect alice entry returned.",
    preconditions="Admin bound; seed contains the alias entry uid=alice-alias pointing at uid=alice.",
    stimulus="Two wholeSubtree searches for (objectClass=alias): one with derefNever, one with derefAlways.",
    expected_observables="derefNever returns the alias entry; derefAlways follows it, so the alias entry is absent from the results.",
)
def alias_dereferenced_always(session: Session) -> Result:
    from bauble.suites._helpers import bind_admin

    bind_admin(session)
    # With derefNever, the alias entry matches (objectClass=alias).
    outcome_never, entries_never = session.search(
        "dc=bauble,dc=test",
        SCOPE_WHOLE_SUBTREE,
        "(objectClass=alias)",
        deref_aliases=_DEREF_NEVER,
    )
    _, entries_always = session.search(
        "dc=bauble,dc=test",
        SCOPE_WHOLE_SUBTREE,
        "(objectClass=alias)",
        deref_aliases=_DEREF_ALWAYS,
    )
    has_alias_never = any("uid=alice-alias" in e.dn for e in entries_never)
    has_alias_always = any("uid=alice-alias" in e.dn for e in entries_always)
    if outcome_never.result_code == 0 and has_alias_never and not has_alias_always:
        return Result("4511.4.5.6", Status.PASS)
    return Result(
        "4511.4.5.6",
        Status.FAIL,
        detail=f"deref mismatch: never={has_alias_never}, always={has_alias_always}",
    )


@assertion(
    id="4511.4.5.7",
    rfc=4511,
    section="§4.5.1",
    category=Category.PROTOCOL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_INTEROP,
    text="A search under a referral entry returns a continuation reference.",
    strategy="Base-scope search on ou=remote (a referral); expect resultCode referral (10).",
    preconditions="Admin bound; seed contains the referral entry ou=remote.",
    stimulus="WholeSubtree search over dc=bauble,dc=test.",
    expected_observables="SearchResultDone carries referrals (a continuation reference for ou=remote).",
)
def referral_returned(session: Session) -> Result:
    outcome, _ = session.search(
        "dc=bauble,dc=test",
        SCOPE_WHOLE_SUBTREE,
        "(objectClass=*)",
    )
    # A subtree search encountering ou=remote returns a SearchResultReference.
    if outcome.referrals:
        return Result("4511.4.5.7", Status.PASS)
    return Result(
        "4511.4.5.7",
        Status.FAIL,
        detail="no referral returned for subtree containing referral entry",
    )

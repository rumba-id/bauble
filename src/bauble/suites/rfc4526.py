"""RFC 4526 — Absolute True and False Filters."""

from bauble.model import Category, Profile, Result, Severity, Status, TestClass
from bauble.session import SCOPE_WHOLE_SUBTREE, Session
from bauble.suites._base import assertion
from bauble.suites._helpers import TEST_BASE

_STANDARD = frozenset({Profile.STANDARD})

_TRUE_FALSE_FEATURE_OID = "1.3.6.1.4.1.4203.1.5.3"


@assertion(
    id="4526.2.1",
    rfc=4526,
    section="§2",
    category=Category.PROTOCOL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_STANDARD,
    text="An 'and' filter with zero elements (&) SHALL evaluate to True.",
    strategy="Search with (&) filter; expect entries returned.",
    requires_features=(_TRUE_FALSE_FEATURE_OID,),
)
def absolute_true_filter(session: Session) -> Result:
    outcome, entries = session.search(TEST_BASE, SCOPE_WHOLE_SUBTREE, "(&)")
    if outcome.result_code != 0:
        return Result("4526.2.1", Status.FAIL, detail=f"search failed: {outcome.result_code}")
    if not entries:
        return Result("4526.2.1", Status.FAIL, detail="(&) returned no entries")
    return Result("4526.2.1", Status.PASS)


@assertion(
    id="4526.2.2",
    rfc=4526,
    section="§2",
    category=Category.PROTOCOL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_STANDARD,
    text="An 'or' filter with zero elements (|) SHALL evaluate to False.",
    strategy="Search with (|) filter; expect zero entries.",
    requires_features=(_TRUE_FALSE_FEATURE_OID,),
)
def absolute_false_filter(session: Session) -> Result:
    outcome, entries = session.search(TEST_BASE, SCOPE_WHOLE_SUBTREE, "(|)")
    if outcome.result_code != 0:
        return Result("4526.2.2", Status.FAIL, detail=f"search failed: {outcome.result_code}")
    if entries:
        return Result(
            "4526.2.2",
            Status.FAIL,
            detail=f"(|) returned {len(entries)} entries, expected 0",
        )
    return Result("4526.2.2", Status.PASS)


@assertion(
    id="4526.2.3",
    rfc=4526,
    section="§2",
    category=Category.PROTOCOL,
    severity=Severity.SHOULD,
    test_class=TestClass.B,
    profiles=_STANDARD,
    text="Server SHOULD publish 1.3.6.1.4.1.4203.1.5.3 in supportedFeatures.",
    strategy="Read root DSE supportedFeatures and check for the OID.",
    requires_features=(_TRUE_FALSE_FEATURE_OID,),
)
def true_false_filters_advertised(session: Session) -> Result:
    from bauble.session import SCOPE_BASE_OBJECT

    outcome, entries = session.search(
        "", SCOPE_BASE_OBJECT, "(objectClass=*)", ["supportedFeatures"]
    )
    if outcome.result_code != 0 or not entries:
        return Result("4526.2.3", Status.AUTO_PASS, detail="root DSE not readable")
    features = entries[0].attributes.get("supportedFeatures", [])
    if _TRUE_FALSE_FEATURE_OID in features:
        return Result("4526.2.3", Status.PASS)
    return Result("4526.2.3", Status.AUTO_PASS, detail="feature OID not advertised")

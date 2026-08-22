"""RFC 3687 — LDAP and X.500 Component Matching Rules."""

from __future__ import annotations

from bauble.model import Category, Layer, Profile, Result, Severity, Status, TestClass
from bauble.session import SCOPE_BASE_OBJECT, Session
from bauble.suites._base import assertion
from bauble.suites._helpers import bind_admin

_CORE = frozenset({Profile.CORE})

#: RFC 3687 §5 — componentFilterMatch (the RFC assigns
#: 1.2.36.79672281.1.13.2; 2.5.13.47 is not defined by this RFC).
_COMPONENT_FILTER_MATCH_OID = "1.2.36.79672281.1.13.2"
#: RFC 3687 §3.2.2.1 — rdnMatch.
_RDN_MATCH_OID = "1.2.36.79672281.1.13.3"


def _subschema_matching_rules(session: Session) -> str | None:
    """The subschema's matchingRules values as one string, or None if unreadable."""
    from bauble.suites._helpers import subschema_dn

    dn = subschema_dn(session)
    if dn is None:
        return None
    outcome, entries = session.search(dn, SCOPE_BASE_OBJECT, "(objectClass=*)", ["matchingRules"])
    if outcome.result_code != 0 or not entries:
        return None
    return " ".join(str(r) for r in entries[0].attributes.get("matchingRules", []))


@assertion(
    id="3687.5.1",
    rfc=3687,
    section="§5",
    category=Category.SCHEMA,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_CORE,
    layer=Layer.CAPABILITY,
    oid=_COMPONENT_FILTER_MATCH_OID,
    text="The subschema advertises the componentFilterMatch matching rule.",
    strategy="Read the subschema matchingRules and check for OID 2.5.13.47.",
    preconditions="Admin bound; the subschema subentry is advertised in the root DSE.",
    stimulus="Search the subschema requesting matchingRules.",
    expected_observables="matchingRules contains 2.5.13.47, or NOT_APPLICABLE if not advertised.",
)
def component_filter_match_advertised(session: Session) -> Result:
    bind_admin(session)
    rules = _subschema_matching_rules(session)
    if rules is None:
        return Result("3687.5.1", Status.NOT_APPLICABLE, detail="subschema not readable")
    if _COMPONENT_FILTER_MATCH_OID in rules:
        return Result("3687.5.1", Status.PASS)
    return Result("3687.5.1", Status.NOT_APPLICABLE, detail="componentFilterMatch not advertised")


@assertion(
    id="3687.3.2.2.1",
    rfc=3687,
    section="§3.2.2.1",
    category=Category.SCHEMA,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_CORE,
    layer=Layer.CAPABILITY,
    oid=_RDN_MATCH_OID,
    text="The subschema advertises the rdnMatch matching rule.",
    strategy="Read the subschema matchingRules and check for OID 1.2.36.79672281.1.13.3.",
    preconditions="Admin bound; the subschema subentry is advertised in the root DSE.",
    stimulus="Search the subschema requesting matchingRules.",
    expected_observables="matchingRules contains 1.2.36.79672281.1.13.3, or NOT_APPLICABLE if not advertised.",
)
def rdn_match_advertised(session: Session) -> Result:
    bind_admin(session)
    rules = _subschema_matching_rules(session)
    if rules is None:
        return Result("3687.3.2.2.1", Status.NOT_APPLICABLE, detail="subschema not readable")
    if _RDN_MATCH_OID in rules:
        return Result("3687.3.2.2.1", Status.PASS)
    return Result("3687.3.2.2.1", Status.NOT_APPLICABLE, detail="rdnMatch not advertised")

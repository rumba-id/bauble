"""RFC 4517 — Syntaxes and Matching Rules."""

from __future__ import annotations

from bauble.model import Category, Layer, Profile, Result, Severity, Status, TestClass
from bauble.session import SCOPE_BASE_OBJECT, SCOPE_WHOLE_SUBTREE, Session
from bauble.suites._base import assertion
from bauble.suites._helpers import TEST_BASE

_INTEROP = frozenset({Profile.INTEROP})
_CORE = frozenset({Profile.CORE})
_SUBSCHEMA = "cn=Subschema"


@assertion(
    id="4517.4.1",
    rfc=4517,
    section="§4.1",
    category=Category.DATA_MODEL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_INTEROP,
    text="The subschema advertises ldapSyntaxes.",
    strategy="Search cn=Subschema for ldapSyntaxes; verify it has values.",
    preconditions="Admin bound; the subschema subentry is advertised in the root DSE.",
    stimulus="Search the subschema requesting the ldapSyntaxes attribute.",
    expected_observables="ldapSyntaxes has at least one value.",
)
def ldap_syntaxes_present(session: Session) -> Result:
    from bauble.suites._helpers import bind_admin, subschema_dn

    bind_admin(session)
    dn = subschema_dn(session)
    if dn is None:
        return Result(
            "4517.4.1", Status.FAIL, detail="subschemaSubentry not advertised in root DSE"
        )
    outcome, entries = session.search(dn, SCOPE_BASE_OBJECT, "(objectClass=*)", ["ldapSyntaxes"])
    if outcome.result_code != 0 or not entries:
        return Result(
            "4517.4.1", Status.FAIL, detail=f"subschema not found: {outcome.result_code}"
        )
    attr = entries[0].attributes.get("ldapSyntaxes")
    if attr and len(attr) > 0:
        return Result("4517.4.1", Status.PASS)
    return Result("4517.4.1", Status.FAIL, detail="ldapSyntaxes absent or empty")


@assertion(
    id="4517.4.2",
    rfc=4517,
    section="§4.2",
    category=Category.DATA_MODEL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_INTEROP,
    text="The subschema advertises matchingRules.",
    strategy="Search cn=Subschema for matchingRules; verify it has values.",
    preconditions="Admin bound; the subschema subentry is advertised in the root DSE.",
    stimulus="Search the subschema requesting the matchingRules attribute.",
    expected_observables="matchingRules has at least one value.",
)
def matching_rules_present(session: Session) -> Result:
    from bauble.suites._helpers import bind_admin, subschema_dn

    bind_admin(session)
    dn = subschema_dn(session)
    if dn is None:
        return Result(
            "4517.4.2", Status.FAIL, detail="subschemaSubentry not advertised in root DSE"
        )
    outcome, entries = session.search(dn, SCOPE_BASE_OBJECT, "(objectClass=*)", ["matchingRules"])
    if outcome.result_code != 0 or not entries:
        return Result(
            "4517.4.2", Status.FAIL, detail=f"subschema not found: {outcome.result_code}"
        )
    attr = entries[0].attributes.get("matchingRules")
    if attr and len(attr) > 0:
        return Result("4517.4.2", Status.PASS)
    return Result("4517.4.2", Status.FAIL, detail="matchingRules absent or empty")


@assertion(
    id="4517.4.3",
    rfc=4517,
    section="§4.2",
    category=Category.SCHEMA,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_INTEROP,
    text="caseIgnoreMatch compares attribute values case-insensitively.",
    strategy="Search (cn=ALICE ANDERSON); expect Alice Anderson matches.",
    preconditions="Seed entry uid=alice exists.",
    stimulus="Subtree search with the filter (uid=ALICE) (uppercase).",
    expected_observables="uid=alice is returned (caseIgnore matching).",
)
def case_ignore_match(session: Session) -> Result:
    from bauble.suites._helpers import bind_admin

    bind_admin(session)
    # uid is the same value on both seeds (OpenLDAP and 389 DS), unlike cn.
    outcome, entries = session.search("dc=bauble,dc=test", SCOPE_WHOLE_SUBTREE, "(uid=ALICE)")
    if outcome.result_code == 0 and any(e.dn.startswith("uid=alice") for e in entries):
        return Result("4517.4.3", Status.PASS)
    return Result("4517.4.3", Status.FAIL, detail="caseIgnoreMatch failed")


@assertion(
    id="4517.4.4",
    rfc=4517,
    section="§4.2",
    category=Category.SCHEMA,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_INTEROP,
    text="integerMatch compares attribute values numerically.",
    strategy="Add entry with uidNumber=100, search (uidNumber=0100); expect it returned.",
    preconditions="Admin bound; target is writable; posixAccount schema available.",
    stimulus="Add an entry with uidNumber=100, then subtree search with (uidNumber=0100).",
    expected_observables="The entry is returned (numeric equality: 100 matches 0100); entry removed in cleanup.",
    mutates=True,
)
def integer_match(session: Session) -> Result:
    from bauble.suites._helpers import TEST_BASE, bind_admin, cleanup

    bind_admin(session)
    dn = f"uid=intmatch,{TEST_BASE}"
    cleanup(session, dn)
    attrs: dict[str, list[str | bytes]] = {
        "objectClass": ["inetOrgPerson", "posixAccount"],
        "cn": ["IntMatch"],
        "sn": ["Match"],
        "uid": ["intmatch"],
        "uidNumber": ["100"],
        "gidNumber": ["100"],
        "homeDirectory": ["/home/intmatch"],
    }
    add_outcome = session.add(dn, attrs)
    if add_outcome.result_code != 0:
        return Result(
            "4517.4.4",
            Status.FAIL,
            detail=f"posixAccount add failed: {add_outcome.result_code}",
        )
    try:
        # Numeric equality: the integer value 100 must match the assertion 0100,
        # which a string comparison would reject. (greaterOrEqual needs an
        # ordering rule the 389 DS schema omits on uidNumber — see
        # docs/server-findings.md.)
        outcome, entries = session.search(TEST_BASE, SCOPE_WHOLE_SUBTREE, "(uidNumber=0100)")
        if outcome.result_code == 0 and any(e.dn == dn for e in entries):
            return Result("4517.4.4", Status.PASS)
        return Result("4517.4.4", Status.FAIL, detail="integerMatch equality failed")
    finally:
        cleanup(session, dn)


@assertion(
    id="4517.4.5",
    rfc=4517,
    section="§4.2",
    category=Category.SCHEMA,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_INTEROP,
    text="generalizedTimeMatch compares timestamps chronologically.",
    strategy="Search (modifyTimestamp>=20200101000000Z); expect recently-added entries.",
    preconditions="Seed entries exist with a modifyTimestamp after 2020.",
    stimulus="Subtree search with the filter (modifyTimestamp>=20200101000000Z).",
    expected_observables="At least 2 entries returned.",
)
def generalized_time_match(session: Session) -> Result:
    outcome, entries = session.search(
        "dc=bauble,dc=test",
        SCOPE_WHOLE_SUBTREE,
        "(modifyTimestamp>=20200101000000Z)",
        ["modifyTimestamp"],
    )
    if outcome.result_code == 0 and len(entries) >= 2:
        return Result("4517.4.5", Status.PASS)
    return Result("4517.4.5", Status.FAIL, detail="generalizedTimeMatch failed")


@assertion(
    id="4517.4.6",
    rfc=4517,
    section="§4.2",
    category=Category.SCHEMA,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_INTEROP,
    text="caseExactMatch compares attribute values case-sensitively.",
    strategy="Extensible-match filter with caseExactMatch on uid; upper-case must not match.",
    preconditions="Seed entry uid=alice exists.",
    stimulus="Base-scope search with (uid:caseExactMatch:=alice), then (uid:caseExactMatch:=ALICE).",
    expected_observables="Exact-case matches; a differing-case assertion does not.",
    layer=Layer.WIRE,
)
def case_exact_match(session: Session) -> Result:
    from bauble.raw import RawConnection, build_extensible_match_filter, build_search_request
    from bauble.suites._helpers import ADMIN_DN, ADMIN_PW

    dn = f"uid=alice,{TEST_BASE}"
    # Exact case must match.
    exact = build_search_request(
        1, dn, ["uid"], filter_ber=build_extensible_match_filter("uid", "caseExactMatch", "alice")
    )
    # Differing case must NOT match (case-sensitive rule).
    upper = build_search_request(
        2, dn, ["uid"], filter_ber=build_extensible_match_filter("uid", "caseExactMatch", "ALICE")
    )
    raw = RawConnection(session.host, session.port)
    exact_resp = raw.bind_then_send_raw(exact, ADMIN_DN, ADMIN_PW)
    upper_resp = raw.bind_then_send_raw(upper, ADMIN_DN, ADMIN_PW)
    from bauble.raw import parse_search_entries

    if parse_search_entries(exact_resp) and not parse_search_entries(upper_resp):
        return Result("4517.4.6", Status.PASS)
    return Result(
        "4517.4.6",
        Status.FAIL,
        detail=f"exact={bool(parse_search_entries(exact_resp))} upper={bool(parse_search_entries(upper_resp))}",
    )

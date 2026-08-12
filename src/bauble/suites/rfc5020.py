"""RFC 5020 — entryDN Operational Attribute."""

from bauble.model import Category, Profile, Result, Severity, Status, TestClass
from bauble.session import SCOPE_BASE_OBJECT, SCOPE_WHOLE_SUBTREE, Session
from bauble.suites._base import assertion
from bauble.suites._helpers import TEST_BASE, bind_admin, cleanup, test_entry_attrs

_STANDARD = frozenset({Profile.STANDARD})


@assertion(
    id="5020.2.1",
    rfc=5020,
    section="§2",
    category=Category.DATA_MODEL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_STANDARD,
    text="entryDN is present on entries when '+' (all operational attributes) is requested.",
    strategy="Search with '+' and verify entryDN is present on each entry.",
)
def entry_dn_present(session: Session) -> Result:
    outcome, entries = session.search(TEST_BASE, SCOPE_WHOLE_SUBTREE, "(objectClass=*)", ["+"])
    if outcome.result_code != 0:
        return Result("5020.2.1", Status.FAIL, detail=f"search failed: {outcome.result_code}")
    if not entries:
        return Result("5020.2.1", Status.FAIL, detail="no entries found")
    for entry in entries:
        if "entryDN" not in entry.attributes:
            return Result("5020.2.1", Status.FAIL, detail=f"entryDN missing from {entry.dn}")
    return Result("5020.2.1", Status.PASS)


@assertion(
    id="5020.2.2",
    rfc=5020,
    section="§2",
    category=Category.DATA_MODEL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_STANDARD,
    text="entryDN value equals the entry's actual DN.",
    strategy="Read entryDN for a known entry and compare to its DN.",
)
def entry_dn_equals_dn(session: Session) -> Result:
    dn = f"uid=alice,{TEST_BASE}"
    outcome, entries = session.search(dn, SCOPE_BASE_OBJECT, "(objectClass=*)", ["+", "*"])
    if outcome.result_code != 0 or not entries:
        return Result("5020.2.2", Status.FAIL, detail="search failed")
    entry = entries[0]
    entry_dn_val = entry.attributes.get("entryDN")
    if entry_dn_val is None:
        return Result("5020.2.2", Status.FAIL, detail="entryDN missing")
    if len(entry_dn_val) != 1 or entry_dn_val[0] != dn:
        return Result(
            "5020.2.2",
            Status.FAIL,
            detail=f"expected entryDN={dn!r}, got {entry_dn_val}",
        )
    return Result("5020.2.2", Status.PASS)


@assertion(
    id="5020.2.3",
    rfc=5020,
    section="§2",
    category=Category.DATA_MODEL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_STANDARD,
    text="entryDN is SINGLE-VALUE and NO-USER-MODIFICATION.",
    strategy="Check entryDN has exactly 1 value. Attempt to modify it — must be rejected.",
    mutates=True,
)
def entry_dn_single_value_read_only(session: Session) -> Result:
    bind_admin(session)
    dn = f"uid=edn-test,{TEST_BASE}"
    cleanup(session, dn)

    session.add(dn, test_entry_attrs("edn-test"))
    try:
        outcome, entries = session.search(dn, SCOPE_BASE_OBJECT, "(objectClass=*)", ["*", "+"])
        if outcome.result_code != 0 or not entries:
            return Result("5020.2.3", Status.FAIL, detail="could not read back entry")
        entry = entries[0]
        entry_dn_val = entry.attributes.get("entryDN")
        if entry_dn_val is None:
            return Result("5020.2.3", Status.FAIL, detail="entryDN missing")
        if len(entry_dn_val) != 1:
            return Result(
                "5020.2.3",
                Status.FAIL,
                detail=f"expected single entryDN, got {len(entry_dn_val)}",
            )

        from bauble.session import MOD_REPLACE, Modification

        modify_outcome = session.modify(
            dn,
            [Modification(MOD_REPLACE, "entryDN", ["cn=nope,dc=bauble,dc=test"])],
        )
        if modify_outcome.result_code == 0:
            return Result("5020.2.3", Status.FAIL, detail="entryDN was modifiable")
        return Result("5020.2.3", Status.PASS)
    finally:
        cleanup(session, dn)


@assertion(
    id="5020.2.4",
    rfc=5020,
    section="§2",
    category=Category.DATA_MODEL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_STANDARD,
    text="entryDN supports distinguishedNameMatch equality in search filters.",
    strategy="Search using (entryDN=<dn>) and verify the correct entry is returned.",
)
def entry_dn_searchable(session: Session) -> Result:
    dn = f"uid=alice,{TEST_BASE}"
    outcome, entries = session.search(dn, SCOPE_BASE_OBJECT, f"(entryDN={dn})", ["*"])
    if outcome.result_code != 0:
        return Result("5020.2.4", Status.FAIL, detail=f"search failed: {outcome.result_code}")
    if len(entries) != 1 or entries[0].dn.lower() != dn.lower():
        return Result(
            "5020.2.4",
            Status.FAIL,
            detail=f"expected 1 entry with dn={dn}, got {len(entries)}",
        )
    return Result("5020.2.4", Status.PASS)

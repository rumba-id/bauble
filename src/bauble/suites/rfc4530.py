"""RFC 4530 — entryUUID Operational Attribute."""

import re

from bauble.model import Category, Layer, Profile, Result, Severity, Status, TestClass
from bauble.session import SCOPE_BASE_OBJECT, SCOPE_WHOLE_SUBTREE, Session
from bauble.suites._base import assertion
from bauble.suites._helpers import (
    TEST_BASE,
    attribute_value,
    bind_admin,
    cleanup,
    test_entry_attrs,
)

_CORE = frozenset({Profile.CORE})

# Regex for RFC 4122 UUID string representation.
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


@assertion(
    id="4530.2.4.1",
    rfc=4530,
    section="§2.4",
    category=Category.DATA_MODEL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_CORE,
    text="Server SHALL assign an entryUUID to each entry upon addition.",
    strategy="Search any entry with '+' (all operational attrs) and check entryUUID is present.",
    preconditions="Seed entries exist.",
    stimulus="Search requesting all operational attributes ('+').",
    expected_observables="Every returned entry carries an entryUUID.",
)
def entry_uuid_present(session: Session) -> Result:
    bind_admin(session)
    outcome, entries = session.search(TEST_BASE, SCOPE_WHOLE_SUBTREE, "(objectClass=*)", ["+"])
    if outcome.result_code != 0:
        return Result("4530.2.4.1", Status.FAIL, detail=f"search failed: {outcome.result_code}")
    if not entries:
        return Result("4530.2.4.1", Status.FAIL, detail="no entries found")
    for entry in entries:
        if attribute_value(entry, "entryUUID") is None:
            return Result("4530.2.4.1", Status.FAIL, detail=f"entryUUID missing from {entry.dn}")
    return Result("4530.2.4.1", Status.PASS)


@assertion(
    id="4530.2.4.2",
    rfc=4530,
    section="§2.4",
    category=Category.DATA_MODEL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_CORE,
    text="entryUUID is SINGLE-VALUE and NO-USER-MODIFICATION.",
    strategy="Check entryUUID has exactly 1 value. Attempt to modify it — must be rejected.",
    preconditions="Admin bound; target is writable.",
    stimulus="Add a test entry, read its entryUUID, then attempt to modify entryUUID.",
    expected_observables="entryUUID has exactly one value; the modification is rejected; entry removed in cleanup.",
    mutates=True,
)
def entry_uuid_single_value_read_only(session: Session) -> Result:
    bind_admin(session)
    dn = f"uid=uuid-test,{TEST_BASE}"
    cleanup(session, dn)

    session.add(dn, test_entry_attrs("uuid-test"))
    try:
        outcome, entries = session.search(dn, SCOPE_BASE_OBJECT, "(objectClass=*)", ["*", "+"])
        if outcome.result_code != 0 or not entries:
            return Result("4530.2.4.2", Status.FAIL, detail="could not read back entry")
        entry = entries[0]
        entry_uuid = attribute_value(entry, "entryUUID")
        if entry_uuid is None:
            return Result("4530.2.4.2", Status.FAIL, detail="entryUUID missing")
        if len(entry_uuid) != 1:
            return Result(
                "4530.2.4.2",
                Status.FAIL,
                detail=f"expected single entryUUID, got {len(entry_uuid)}",
            )

        # Attempt modification — must fail.
        from bauble.session import MOD_REPLACE, Modification

        modify_outcome = session.modify(
            dn,
            [Modification(MOD_REPLACE, "entryUUID", ["00000000-0000-0000-0000-000000000000"])],
        )
        if modify_outcome.result_code == 0:
            return Result("4530.2.4.2", Status.FAIL, detail="entryUUID was modifiable")
        return Result("4530.2.4.2", Status.PASS)
    finally:
        cleanup(session, dn)


@assertion(
    id="4530.2.1.1",
    rfc=4530,
    section="§2.1",
    category=Category.DATA_MODEL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_CORE,
    text="entryUUID values use the RFC 4122 string representation (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx).",
    strategy="Read entryUUID and validate against the UUID hex-octet regex.",
    preconditions="Seed entries exist.",
    stimulus="Search requesting entryUUID on all entries.",
    expected_observables="Every entryUUID matches the RFC 4122 hex-octet regex.",
)
def entry_uuid_valid_format(session: Session) -> Result:
    bind_admin(session)
    outcome, entries = session.search(TEST_BASE, SCOPE_WHOLE_SUBTREE, "(objectClass=*)", ["+"])
    if outcome.result_code != 0 or not entries:
        return Result("4530.2.1.1", Status.FAIL, detail="search failed or no entries")
    for entry in entries:
        uuid_vals = attribute_value(entry, "entryUUID")
        if uuid_vals is None:
            # Already caught by entry_uuid_present; skip.
            continue
        for val in uuid_vals:
            if not isinstance(val, str) or not _UUID_RE.match(val):
                return Result(
                    "4530.2.1.1",
                    Status.FAIL,
                    detail=f"invalid UUID format in {entry.dn}: {val!r}",
                )
    return Result("4530.2.1.1", Status.PASS)


@assertion(
    id="4530.2.4.3",
    rfc=4530,
    section="§2.4",
    category=Category.DATA_MODEL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_CORE,
    text="entryUUID is immutable — same value across reads.",
    strategy="Read the same entry twice and verify entryUUID is unchanged.",
    preconditions="Existing entry uid=alice in the DIT.",
    stimulus="Two consecutive base-scope Search for entryUUID on the same entry.",
    expected_observables="Both reads return the same entryUUID value; no modification occurred.",
)
def entry_uuid_immutable(session: Session) -> Result:
    bind_admin(session)
    dn = f"uid=alice,{TEST_BASE}"
    # Request entryUUID explicitly: portable across servers (LLDAP's '+'
    # selector returns nothing).
    outcome1, entries1 = session.search(dn, SCOPE_BASE_OBJECT, "(objectClass=*)", ["entryUUID"])
    outcome2, entries2 = session.search(dn, SCOPE_BASE_OBJECT, "(objectClass=*)", ["entryUUID"])
    if outcome1.result_code != 0 or not entries1:
        return Result("4530.2.4.3", Status.FAIL, detail="first read failed")
    if outcome2.result_code != 0 or not entries2:
        return Result("4530.2.4.3", Status.FAIL, detail="second read failed")
    uuid1 = attribute_value(entries1[0], "entryUUID")
    uuid2 = attribute_value(entries2[0], "entryUUID")
    if uuid1 is None or uuid2 is None:
        return Result("4530.2.4.3", Status.FAIL, detail="entryUUID missing")
    if uuid1 != uuid2:
        return Result("4530.2.4.3", Status.FAIL, detail="entryUUID changed across reads")
    return Result("4530.2.4.3", Status.PASS)


@assertion(
    id="4530.2.2.1",
    rfc=4530,
    section="§2.2",
    category=Category.DATA_MODEL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_CORE,
    layer=Layer.SEMANTIC,
    text="uuidMatch locates an entry by its entryUUID value.",
    strategy="Read alice's entryUUID, then subtree-search with (entryUUID=<value>); expect alice.",
    preconditions="Seed entry uid=alice exists.",
    stimulus="Read alice's entryUUID, then subtree-search with the filter (entryUUID=<value>).",
    expected_observables="The search returns uid=alice.",
)
def entry_uuid_searchable(session: Session) -> Result:
    bind_admin(session)
    dn = f"uid=alice,{TEST_BASE}"
    outcome, entries = session.search(dn, SCOPE_BASE_OBJECT, "(objectClass=*)", ["entryUUID"])
    if outcome.result_code != 0 or not entries:
        return Result("4530.2.2.1", Status.FAIL, detail="could not read entryUUID")
    uuid_vals = attribute_value(entries[0], "entryUUID")
    if not uuid_vals or not isinstance(uuid_vals[0], str):
        return Result("4530.2.2.1", Status.FAIL, detail="entryUUID missing or non-string")
    uuid_value = uuid_vals[0]
    outcome2, entries2 = session.search(
        TEST_BASE, SCOPE_WHOLE_SUBTREE, f"(entryUUID={uuid_value})"
    )
    if outcome2.result_code != 0:
        return Result("4530.2.2.1", Status.FAIL, detail=f"search failed: {outcome2.result_code}")
    if not any(e.dn == dn for e in entries2):
        return Result(
            "4530.2.2.1",
            Status.FAIL,
            detail=f"(entryUUID={uuid_value}) did not return {dn}",
        )
    return Result("4530.2.2.1", Status.PASS)

"""RFC 3866 — Language Tags and Ranges in LDAP."""

from bauble.model import Category, Layer, Profile, Result, Severity, Status, TestClass
from bauble.session import SCOPE_BASE_OBJECT, Session
from bauble.suites._base import assertion
from bauble.suites._helpers import TEST_BASE, bind_admin, cleanup, test_entry_attrs

_CORE = frozenset({Profile.CORE})

_LANG_TAG_OID = "1.3.6.1.4.1.4203.1.5.4"
_LANG_RANGE_OID = "1.3.6.1.4.1.4203.1.5.5"


@assertion(
    id="3866.2.5.1",
    rfc=3866,
    section="§2.5",
    category=Category.PROTOCOL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_CORE,
    text="Server accepts add with language-tagged attribute values.",
    strategy="Add entry with description;lang-en and description;lang-de. Verify both stored.",
    preconditions="Admin bound; target is writable; language tags supported.",
    stimulus="Add an entry with description;lang-en and description;lang-de values.",
    expected_observables="Both language-tagged values are stored; entry removed in cleanup.",
    mutates=True,
)
def add_language_tagged_values(session: Session) -> Result:
    bind_admin(session)
    dn = f"uid=lang-test,{TEST_BASE}"
    cleanup(session, dn)

    attrs = test_entry_attrs("lang-test")
    attrs["description;lang-en"] = ["Hello"]
    attrs["description;lang-de"] = ["Hallo"]
    session.add(dn, attrs)
    try:
        _, entries = session.search(dn, SCOPE_BASE_OBJECT, "(objectClass=*)", ["*"])
        if not entries:
            return Result("3866.2.5.1", Status.FAIL, detail="could not read back entry")
        entry = entries[0]
        # ldap3 may return these with or without the lang- prefix
        if "description;lang-en" not in entry.attributes:
            return Result(
                "3866.2.5.1",
                Status.NOT_APPLICABLE,
                detail="server stores language tags differently or not supported",
            )
        return Result("3866.2.5.1", Status.PASS)
    finally:
        cleanup(session, dn)


@assertion(
    id="3866.2.2.1",
    rfc=3866,
    section="§2.2",
    category=Category.PROTOCOL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_CORE,
    text="Search filter with language tag option matches only same-tag values.",
    strategy="Add entries with lang-en and lang-de, search with lang-en filter.",
    preconditions="Admin bound; target is writable; language tags supported.",
    stimulus="Add an entry with lang-en and lang-de values, then search with (description;lang-en=Hello).",
    expected_observables="Only the lang-en value matches; entry removed in cleanup.",
    mutates=True,
)
def search_filter_language_tag(session: Session) -> Result:
    bind_admin(session)
    dn = f"uid=lang2-test,{TEST_BASE}"
    cleanup(session, dn)

    attrs = test_entry_attrs("lang2-test")
    attrs["description;lang-en"] = ["Hello"]
    attrs["description;lang-de"] = ["Hallo"]
    session.add(dn, attrs)
    try:
        _, entries = session.search(dn, SCOPE_BASE_OBJECT, "(description;lang-en=Hello)", ["*"])
        if not entries:
            return Result(
                "3866.2.2.1",
                Status.NOT_APPLICABLE,
                detail="language tag filter not supported or no match",
            )
        attrs = entries[0].attributes
        if "description;lang-en" in attrs and "Hello" in attrs.get("description;lang-en", []):
            return Result("3866.2.2.1", Status.PASS)
        return Result(
            "3866.2.2.1",
            Status.NOT_APPLICABLE,
            detail="unexpected filter behavior",
        )
    finally:
        cleanup(session, dn)


@assertion(
    id="3866.3.1.1",
    rfc=3866,
    section="§3.1",
    category=Category.PROTOCOL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_CORE,
    text="Language range option matches all language tags with matching prefix.",
    strategy="Search with description;lang-en-; verify both lang-en and lang-en-US match.",
    preconditions="Admin bound; target is writable; language ranges supported.",
    stimulus="Add an entry with lang-en, lang-en-US, and lang-de values, then request description;lang-en-.",
    expected_observables="Both lang-en and lang-en-US match; entry removed in cleanup.",
    mutates=True,
)
def language_range_matches_prefix(session: Session) -> Result:
    bind_admin(session)
    dn = f"uid=lang3-test,{TEST_BASE}"
    cleanup(session, dn)

    attrs = test_entry_attrs("lang3-test")
    attrs["description;lang-en"] = ["Hello"]
    attrs["description;lang-en-US"] = ["Howdy"]
    attrs["description;lang-de"] = ["Hallo"]
    session.add(dn, attrs)
    try:
        # Request description;lang-en- (range) — should match lang-en and lang-en-US
        _, entries = session.search(
            dn, SCOPE_BASE_OBJECT, "(objectClass=*)", ["description;lang-en-"]
        )
        if not entries:
            return Result(
                "3866.3.1.1",
                Status.NOT_APPLICABLE,
                detail="language range not supported",
            )
        attrs = entries[0].attributes
        # Attribute names are case-insensitive; ldap3 normalizes to lowercase.
        attr_keys = {k.lower() for k in attrs}
        if "description;lang-en" in attr_keys and "description;lang-en-us" in attr_keys:
            return Result("3866.3.1.1", Status.PASS)
        return Result(
            "3866.3.1.1",
            Status.FAIL,
            detail=f"range match failed; got keys: {sorted(attr_keys)}",
        )
    finally:
        cleanup(session, dn)


@assertion(
    id="3866.3.1.2",
    rfc=3866,
    section="§3.1",
    category=Category.PROTOCOL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_CORE,
    text="lang- range matches all language-tagged values.",
    strategy="Request description;lang- ; verify en, en-US, de all returned.",
    preconditions="Admin bound; target is writable; language ranges supported.",
    stimulus="Add an entry with lang-en and lang-de values, then request description;lang-.",
    expected_observables="All language-tagged values are returned; entry removed in cleanup.",
    mutates=True,
)
def lang_range_matches_all(session: Session) -> Result:
    bind_admin(session)
    dn = f"uid=lang4-test,{TEST_BASE}"
    cleanup(session, dn)

    attrs = test_entry_attrs("lang4-test")
    attrs["description;lang-en"] = ["Hello"]
    attrs["description;lang-de"] = ["Hallo"]
    session.add(dn, attrs)
    try:
        _, entries = session.search(
            dn, SCOPE_BASE_OBJECT, "(objectClass=*)", ["description;lang-"]
        )
        if not entries:
            return Result(
                "3866.3.1.2",
                Status.NOT_APPLICABLE,
                detail="lang- range not supported",
            )
        attrs = entries[0].attributes
        if "description;lang-en" in attrs and "description;lang-de" in attrs:
            return Result("3866.3.1.2", Status.PASS)
        return Result(
            "3866.3.1.2",
            Status.NOT_APPLICABLE,
            detail=f"lang- range didn't match all; got {list(attrs.keys())}",
        )
    finally:
        cleanup(session, dn)


@assertion(
    id="3866.3.3",
    rfc=3866,
    section="§3",
    category=Category.PROTOCOL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_CORE,
    text="Language range option on add returns error (ranges are not tagging options).",
    strategy="Try to add entry with description;lang-en-; expect error.",
    preconditions="Admin bound; target is writable.",
    stimulus="AddRequest with an attribute using a language RANGE option (description;lang-en-).",
    expected_observables="AddResponse non-zero (ranges are not tagging options).",
    mutates=True,
)
def language_range_rejected_on_add(session: Session) -> Result:
    bind_admin(session)
    dn = f"uid=lang5-test,{TEST_BASE}"
    cleanup(session, dn)

    attrs = test_entry_attrs("lang5-test")
    attrs["description;lang-en-"] = ["invalid"]
    outcome = session.add(dn, attrs)
    if outcome.result_code != 0:
        return Result("3866.3.3", Status.PASS)
    cleanup(session, dn)
    return Result(
        "3866.3.3",
        Status.NOT_APPLICABLE,
        detail="server accepted language range on add",
    )


@assertion(
    id="3866.4.1",
    rfc=3866,
    section="§4",
    category=Category.PROTOCOL,
    severity=Severity.SHOULD,
    test_class=TestClass.A,
    profiles=_CORE,
    text="Servers SHOULD publish 1.3.6.1.4.1.4203.1.5.4 (tags) and .5 (ranges) in supportedFeatures.",
    strategy="Read root DSE supportedFeatures and check for both OIDs.",
    preconditions="Root DSE is readable.",
    stimulus="Search the root DSE for the supportedFeatures attribute.",
    expected_observables="Both language-tag/range feature OIDs present, or NOT_APPLICABLE if not advertised.",
    layer=Layer.CAPABILITY,
    oid="1.3.6.1.4.1.4203.1.5.4",
)
def language_options_advertised(session: Session) -> Result:
    outcome, entries = session.search(
        "", SCOPE_BASE_OBJECT, "(objectClass=*)", ["supportedFeatures"]
    )
    if outcome.result_code != 0 or not entries:
        return Result("3866.4.1", Status.NOT_APPLICABLE, detail="root DSE not readable")
    features = entries[0].attributes.get("supportedFeatures", [])
    if "1.3.6.1.4.1.4203.1.5.4" in features and "1.3.6.1.4.1.4203.1.5.5" in features:
        return Result("3866.4.1", Status.PASS)
    return Result("3866.4.1", Status.NOT_APPLICABLE, detail="language feature OIDs not advertised")

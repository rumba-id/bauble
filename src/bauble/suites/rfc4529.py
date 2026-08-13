"""RFC 4529 — Requesting Attributes by Object Class."""

from bauble.model import Category, Layer, Profile, Result, Severity, Status, TestClass
from bauble.session import SCOPE_BASE_OBJECT, Session
from bauble.suites._base import assertion
from bauble.suites._helpers import TEST_BASE

_CORE = frozenset({Profile.CORE})


def _ber_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    if n < 0x100:
        return bytes([0x81, n])
    return bytes([0x82, (n >> 8) & 0xFF, n & 0xFF])


def _ber_int(v: int) -> bytes:
    if v == 0:
        return b"\x02\x01\x00"
    p = v.to_bytes((v.bit_length() + 8) // 8, "big")
    if v > 0 and p[0] & 0x80:
        p = b"\x00" + p
    return b"\x02" + _ber_len(len(p)) + p


def _ber_octet(s: str) -> bytes:
    b = s.encode()
    return b"\x04" + _ber_len(len(b)) + b


def _ber_seq(c: bytes) -> bytes:
    return b"\x30" + _ber_len(len(c)) + c


def _search_raw(
    session: Session, base: str, scope: int, attributes: list[str]
) -> tuple[int, list[dict[str, list[bytes]]]]:
    """Send a raw SearchRequest; return (resultCode, parsed entry attributes)."""
    from bauble.raw import RawConnection, parse_search_response

    base_ber = _ber_octet(base)
    scope_ber = b"\x0a\x01" + bytes([scope])
    deref = b"\x0a\x01\x00"
    size_limit = _ber_int(0)
    time_limit = _ber_int(0)
    types_only = b"\x01\x01\x00"
    present_filter = b"\x87\x0bobjectClass"  # (objectClass=*) present filter
    attrs_ber = _ber_seq(b"".join(_ber_octet(a) for a in attributes))

    search_contents = (
        base_ber
        + scope_ber
        + deref
        + size_limit
        + time_limit
        + types_only
        + present_filter
        + attrs_ber
    )
    search_request = b"\x63" + _ber_len(len(search_contents)) + search_contents
    payload = _ber_seq(_ber_int(1) + search_request)

    raw = RawConnection(session.host, session.port)
    return parse_search_response(raw.bind_then_send_raw(payload))


@assertion(
    id="4529.3.1",
    rfc=4529,
    section="§3",
    category=Category.PROTOCOL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_CORE,
    text="'@person' in attribute list returns all attributes of the person object class.",
    strategy="Send raw SearchRequest with @person attribute; expect success (0).",
    preconditions="Target server is reachable; seed entry uid=alice exists.",
    stimulus="Raw SearchRequest for uid=alice requesting the @person attribute list.",
    expected_observables="SearchResultDone resultCode success (0).",
    layer=Layer.WIRE,
    oid="1.3.6.1.4.1.4203.1.5.2",
)
def at_objectclass_returns_attrs(session: Session) -> Result:
    result_code, entries = _search_raw(
        session, f"uid=alice,{TEST_BASE}", SCOPE_BASE_OBJECT, ["@person"]
    )
    if result_code != 0:
        return Result(
            "4529.3.1",
            Status.FAIL,
            detail=f"@person search failed: resultCode={result_code}",
        )
    # '@person' must request all MUST/MAY/SUP attributes of the person object
    # class (cn, sn at minimum).
    returned = {k.lower() for e in entries for k in e}
    missing = [a for a in ("cn", "sn") if a not in returned]
    if not missing:
        return Result("4529.3.1", Status.PASS)
    return Result(
        "4529.3.1",
        Status.FAIL,
        detail=f"@person returned no {', '.join(missing)}; got {sorted(returned)}",
    )


@assertion(
    id="4529.3.2",
    rfc=4529,
    section="§3",
    category=Category.PROTOCOL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_CORE,
    text="Unrecognized object class OID is treated as unrecognized attribute description.",
    strategy="Send raw SearchRequest with @1.2.3.4.5.9999; expect no error.",
    preconditions="Target server is reachable; seed entry uid=alice exists.",
    stimulus="Raw SearchRequest for uid=alice requesting an unknown @OID attribute list.",
    expected_observables="SearchResultDone resultCode success (0); no error.",
    layer=Layer.WIRE,
    oid="1.3.6.1.4.1.4203.1.5.2",
)
def unknown_objectclass_treated_as_unknown_attr(session: Session) -> Result:
    result_code, _ = _search_raw(
        session, f"uid=alice,{TEST_BASE}", SCOPE_BASE_OBJECT, ["@1.2.3.4.5.9999"]
    )
    if result_code == 0:
        return Result("4529.3.2", Status.PASS)
    return Result(
        "4529.3.2",
        Status.FAIL,
        detail=f"@1.2.3.4.5.9999 search failed: resultCode={result_code}",
    )


@assertion(
    id="4529.3.3",
    rfc=4529,
    section="§3",
    category=Category.PROTOCOL,
    severity=Severity.SHOULD,
    test_class=TestClass.A,
    profiles=_CORE,
    text="Servers supporting this feature SHOULD publish OID 1.3.6.1.4.1.4203.1.5.2 in supportedFeatures.",
    strategy="Read root DSE supportedFeatures and check for the @objectclass OID.",
    preconditions="Root DSE is readable.",
    stimulus="Search the root DSE for the supportedFeatures attribute.",
    expected_observables="The @objectclass feature OID present, or NOT_APPLICABLE if not advertised.",
    layer=Layer.CAPABILITY,
    oid="1.3.6.1.4.1.4203.1.5.2",
)
def objectclass_feature_advertised(session: Session) -> Result:
    outcome, entries = session.search(
        "", SCOPE_BASE_OBJECT, "(objectClass=*)", ["supportedFeatures"]
    )
    if outcome.result_code != 0 or not entries:
        return Result("4529.3.3", Status.NOT_APPLICABLE, detail="root DSE not readable")
    features = entries[0].attributes.get("supportedFeatures", [])
    if "1.3.6.1.4.1.4203.1.5.2" in features:
        return Result("4529.3.3", Status.PASS)
    return Result("4529.3.3", Status.NOT_APPLICABLE, detail="feature OID not advertised")

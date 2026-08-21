"""RFC 4533 — LDAP Content Synchronization Operation."""

from __future__ import annotations

from bauble.model import Category, Layer, Profile, Result, Severity, Status, TestClass
from bauble.session import SCOPE_BASE_OBJECT, Session
from bauble.suites._base import assertion
from bauble.suites._helpers import ADMIN_DN, ADMIN_PW

_CORE = frozenset({Profile.CORE})

_SYNC_REQUEST_OID = "1.3.6.1.4.1.4203.1.9.1.1"
_SYNC_STATE_OID = "1.3.6.1.4.1.4203.1.9.1.2"
_SYNC_DONE_OID = "1.3.6.1.4.1.4203.1.9.1.3"

#: syncRequestValue ::= SEQUENCE { mode ENUMERATED { refreshOnly (1) } }
_REFRESH_ONLY_VALUE = bytes.fromhex("30030a0101")


@assertion(
    id="4533.2.1",
    rfc=4533,
    section="§2",
    category=Category.CONTROL,
    severity=Severity.SHOULD,
    test_class=TestClass.A,
    profiles=_CORE,
    layer=Layer.CAPABILITY,
    oid=_SYNC_REQUEST_OID,
    text="The server advertises the syncRequest control in supportedControl.",
    strategy="Read the root DSE supportedControl and check for the syncRequest OID.",
    preconditions="Root DSE is readable.",
    stimulus="Search the root DSE for supportedControl.",
    expected_observables="1.3.6.1.4.1.4203.1.9.1.1 present, or NOT_APPLICABLE if not advertised.",
)
def sync_request_advertised(session: Session) -> Result:
    outcome, entries = session.search(
        "", SCOPE_BASE_OBJECT, "(objectClass=*)", ["supportedControl"]
    )
    if outcome.result_code != 0 or not entries:
        return Result("4533.2.1", Status.NOT_APPLICABLE, detail="root DSE not readable")
    controls = entries[0].attributes.get("supportedControl", [])
    if _SYNC_REQUEST_OID in controls:
        return Result("4533.2.1", Status.PASS)
    return Result("4533.2.1", Status.NOT_APPLICABLE, detail="syncRequest OID not advertised")


@assertion(
    id="4533.3.1",
    rfc=4533,
    section="§3",
    category=Category.CONTROL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_CORE,
    layer=Layer.WIRE,
    text="A refreshOnly syncRequest returns a syncDone control carrying a cookie.",
    strategy="Raw refreshOnly syncRequest over the base; verify the syncDone control carries a non-empty cookie.",
    preconditions="Admin bound; the syncprov overlay is loaded.",
    stimulus="Search with the syncRequest control (mode=refreshOnly, no cookie).",
    expected_observables="A syncDone control (1.3.6.1.4.1.4203.1.9.1.3) with a non-empty cookie.",
)
def sync_refresh_only_returns_cookie(session: Session) -> Result:
    # Content sync is optional: only applicable when the server advertises it.
    advertise, entries = session.search(
        "", SCOPE_BASE_OBJECT, "(objectClass=*)", ["supportedControl"]
    )
    if advertise.result_code != 0 or not entries:
        return Result("4533.3.1", Status.NOT_APPLICABLE, detail="root DSE not readable")
    if _SYNC_REQUEST_OID not in entries[0].attributes.get("supportedControl", []):
        return Result("4533.3.1", Status.NOT_APPLICABLE, detail="syncRequest not advertised")
    from bauble.raw import (
        RawConnection,
        build_control,
        build_search_request,
        parse_response_controls,
    )

    control = build_control(_SYNC_REQUEST_OID, criticality=True, value=_REFRESH_ONLY_VALUE)
    request = build_search_request(
        1, "dc=bauble,dc=test", ["uid"], scope=2, controls=[control]
    )
    raw = RawConnection(session.host, session.port)
    response = raw.bind_then_send_raw(request, ADMIN_DN, ADMIN_PW)
    controls = dict(parse_response_controls(response))
    done = controls.get(_SYNC_DONE_OID)
    if done is None:
        return Result("4533.3.1", Status.FAIL, detail="no syncDone control returned")
    # The cookie is an OCTET STRING inside the syncDone value carrying "csn=".
    if b"csn=" not in done:
        return Result("4533.3.1", Status.FAIL, detail=f"syncDone cookie missing: {done!r}")
    return Result("4533.3.1", Status.PASS)


def _sync_cookie(done_value: bytes) -> bytes:
    """Extract the cookie from a syncDoneValue: SEQUENCE { cookie, ... }."""
    from bauble.raw import _parse_length  # type: ignore[reportPrivateUsage]

    pos = 1
    _, pos = _parse_length(done_value, pos)
    if pos >= len(done_value) or done_value[pos] != 0x04:
        return b""
    pos += 1
    length, pos = _parse_length(done_value, pos)
    return done_value[pos : pos + length]


def _sync_state(value: bytes) -> tuple[int, bytes]:
    """Parse a syncStateValue: SEQUENCE { state ENUMERATED, entryUUID }."""
    from bauble.raw import _parse_length  # type: ignore[reportPrivateUsage]

    pos = 1
    _, pos = _parse_length(value, pos)
    if pos + 3 > len(value) or value[pos] != 0x0A:  # ENUMERATED
        return -1, b""
    state = value[pos + 2]
    pos += 3
    if pos >= len(value) or value[pos] != 0x04:
        return state, b""
    pos += 1
    length, pos = _parse_length(value, pos)
    return state, value[pos : pos + length]


@assertion(
    id="4533.3.2",
    rfc=4533,
    section="§3",
    category=Category.CONTROL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_CORE,
    layer=Layer.WIRE,
    text="An incremental syncRequest with a cookie returns only the change, as a syncState control with the new state and entryUUID.",
    strategy="First sync obtains a cookie; add an entry; re-sync with the cookie; the response must carry a syncState (state=add) control and the entryUUID.",
    preconditions="Admin bound; target is writable; the syncprov overlay is loaded.",
    stimulus="refreshOnly sync, add uid=sync-new, refreshOnly sync carrying the cookie.",
    expected_observables="A syncState control (1.3.6.1.4.1.4203.1.9.1.2) with state add (1) and a 16-byte entryUUID; entry removed in cleanup.",
    mutates=True,
)
def sync_incremental_returns_change(session: Session) -> Result:
    from bauble.raw import (
        RawConnection,
        build_add_request,
        build_control,
        build_search_request,
        parse_all_response_controls,
        parse_search_entries,
    )
    from bauble.suites._helpers import ADMIN_DN, ADMIN_PW, TEST_BASE, bind_admin, cleanup

    # Content sync is optional: only applicable when the server advertises it.
    advertise, entries = session.search(
        "", SCOPE_BASE_OBJECT, "(objectClass=*)", ["supportedControl"]
    )
    if advertise.result_code != 0 or not entries:
        return Result("4533.3.2", Status.NOT_APPLICABLE, detail="root DSE not readable")
    if _SYNC_REQUEST_OID not in entries[0].attributes.get("supportedControl", []):
        return Result("4533.3.2", Status.NOT_APPLICABLE, detail="syncRequest not advertised")

    bind_admin(session)
    dn = f"uid=sync-new,{TEST_BASE}"
    cleanup(session, dn)
    raw = RawConnection(session.host, session.port)

    # First sync: obtain the cookie.
    first = build_search_request(
        1,
        "dc=bauble,dc=test",
        ["uid"],
        scope=2,
        controls=[build_control(_SYNC_REQUEST_OID, criticality=True, value=_REFRESH_ONLY_VALUE)],
    )
    first_response = raw.bind_then_send_raw(first, ADMIN_DN, ADMIN_PW)
    from bauble.raw import parse_response_controls

    done = dict(parse_response_controls(first_response)).get(_SYNC_DONE_OID)
    if done is None:
        return Result("4533.3.2", Status.FAIL, detail="first sync returned no syncDone")
    cookie = _sync_cookie(done)
    if not cookie:
        return Result("4533.3.2", Status.FAIL, detail="first syncDone carries no cookie")

    try:
        add = raw.bind_then_send(
            build_add_request(
                2,
                dn,
                {
                    "objectClass": ["inetOrgPerson"],
                    "cn": ["SyncNew"],
                    "sn": ["N"],
                    "uid": ["sync-new"],
                },
            ),
            ADMIN_DN,
            ADMIN_PW,
        )
        if add.result_code != 0:
            return Result(
                "4533.3.2", Status.NOT_APPLICABLE, detail=f"test entry add failed: {add.result_code}"
            )

        # Incremental sync with the cookie.
        inner = bytes.fromhex("0a0101") + b"\x04" + bytes([len(cookie)]) + cookie
        value = b"\x30" + bytes([len(inner)]) + inner
        second = build_search_request(
            3,
            "dc=bauble,dc=test",
            ["uid"],
            scope=2,
            controls=[build_control(_SYNC_REQUEST_OID, criticality=True, value=value)],
        )
        second_response = raw.bind_then_send_raw(second, ADMIN_DN, ADMIN_PW)
        states = [
            v for oid, v in parse_all_response_controls(second_response) if oid == _SYNC_STATE_OID
        ]
        if not states:
            return Result(
                "4533.3.2", Status.FAIL, detail="incremental sync returned no syncState control"
            )
        state, entry_uuid = _sync_state(states[0])
        if state != 1:  # add
            return Result("4533.3.2", Status.FAIL, detail=f"expected state add (1), got {state}")
        if len(entry_uuid) != 16:
            return Result(
                "4533.3.2", Status.FAIL, detail=f"expected 16-byte entryUUID, got {entry_uuid!r}"
            )
        if not any(b"sync-new" in (e.get("uid") or []) for e in parse_search_entries(second_response)):
            return Result(
                "4533.3.2", Status.FAIL, detail="incremental sync did not return the changed entry"
            )
        return Result("4533.3.2", Status.PASS)
    finally:
        cleanup(session, dn)


#: syncRequestValue ::= SEQUENCE { mode ENUMERATED { refreshAndPersist (3) } }
_REFRESH_AND_PERSIST_VALUE = bytes.fromhex("30030a0103")


@assertion(
    id="4533.3.3",
    rfc=4533,
    section="§3",
    category=Category.CONTROL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_CORE,
    layer=Layer.WIRE,
    text="A refreshAndPersist syncRequest streams a subsequent change as a syncState control with the new state and entryUUID.",
    strategy="Open a persistent session, send refreshAndPersist, then add an entry on a second connection; the change arrives as a syncState (state=add) control on the first connection.",
    preconditions="Admin bound; target is writable; the syncprov overlay is loaded.",
    stimulus="refreshAndPersist syncRequest on a RawSession; add uid=sync-persist on a second connection; read the stream.",
    expected_observables="A syncState control (1.3.6.1.4.1.4203.1.9.1.2) with state add (1) and a 16-byte entryUUID; entry removed in cleanup.",
    mutates=True,
)
def sync_persist_streams_change(session: Session) -> Result:
    from bauble.raw import (
        RawSession,
        build_control,
        build_search_request,
        parse_all_response_controls,
    )
    from bauble.suites._helpers import ADMIN_DN, ADMIN_PW, TEST_BASE, cleanup

    advertise, entries = session.search(
        "", SCOPE_BASE_OBJECT, "(objectClass=*)", ["supportedControl"]
    )
    if advertise.result_code != 0 or not entries:
        return Result("4533.3.3", Status.NOT_APPLICABLE, detail="root DSE not readable")
    if _SYNC_REQUEST_OID not in entries[0].attributes.get("supportedControl", []):
        return Result("4533.3.3", Status.NOT_APPLICABLE, detail="syncRequest not advertised")

    dn = f"uid=sync-persist,{TEST_BASE}"
    cleanup(session, dn)
    raw = RawSession(session.host, session.port)
    raw.open()
    try:
        if raw.bind(ADMIN_DN, ADMIN_PW).result_code != 0:
            return Result("4533.3.3", Status.BLOCKED, detail="admin bind failed")
        search = build_search_request(
            raw.next_message_id(),
            "dc=bauble,dc=test",
            ["uid"],
            scope=2,
            controls=[
                build_control(_SYNC_REQUEST_OID, criticality=True, value=_REFRESH_AND_PERSIST_VALUE)
            ],
        )
        raw.send(search)
        raw.recv(0.5)  # drain the initial refresh phase

        # Trigger a change on a second connection.
        from bauble.harness import LdapSession, ServerConfig

        other = LdapSession(ServerConfig(session.host, session.port))
        other.bind(ADMIN_DN, ADMIN_PW)
        if other.add(
            dn,
            {"objectClass": ["inetOrgPerson"], "cn": ["Persist"], "sn": ["P"], "uid": ["sync-persist"]},
        ).result_code != 0:
            return Result("4533.3.3", Status.NOT_APPLICABLE, detail="test entry add failed")

        streamed = raw.recv(2.0)
        states = [
            v for oid, v in parse_all_response_controls(streamed) if oid == _SYNC_STATE_OID
        ]
        if not states:
            return Result("4533.3.3", Status.FAIL, detail="no syncState control streamed")
        state, entry_uuid = _sync_state(states[0])
        if state != 1:  # add
            return Result("4533.3.3", Status.FAIL, detail=f"expected state add (1), got {state}")
        if len(entry_uuid) != 16:
            return Result(
                "4533.3.3", Status.FAIL, detail=f"expected 16-byte entryUUID, got {entry_uuid!r}"
            )
        return Result("4533.3.3", Status.PASS)
    finally:
        raw.close()
        cleanup(session, dn)

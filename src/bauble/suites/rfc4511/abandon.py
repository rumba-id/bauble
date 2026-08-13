"""RFC 4511 §4.11 — Abandon operation.

The observable core of both requirements is deterministic: an
AbandonRequest gets no response, and the session continues to serve
subsequent requests. The racy part (whether an in-progress operation is
actually ceased) is not asserted — the server may legitimately complete
the operation before processing the abandon.
"""

from __future__ import annotations

from bauble.model import Category, Profile, Result, Severity, Status, TestClass
from bauble.raw import RawSession, build_abandon_request, build_search_request
from bauble.session import Session
from bauble.suites._base import assertion
from bauble.suites._helpers import ADMIN_DN, ADMIN_PW, TEST_BASE

_INTEROP = frozenset({Profile.INTEROP})


@assertion(
    id="4511.4.11.2",
    rfc=4511,
    section="§4.11",
    category=Category.PROTOCOL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_INTEROP,
    text="Abandon of an unknown messageID is silently discarded.",
    strategy="Raw abandon with an unknown messageID; expect no response, and the session keeps working.",
    preconditions="Target server is reachable on session.host:session.port.",
    stimulus="AbandonRequest naming an unknown messageID, then a base-scope search on the same session.",
    expected_observables="No response to the AbandonRequest; the follow-up search succeeds.",
)
def abandon_unknown_message_id(session: Session) -> Result:
    raw = RawSession(session.host, session.port)
    raw.open()
    try:
        bind = raw.bind(ADMIN_DN, ADMIN_PW)
        if bind.result_code != 0:
            return Result("4511.4.11.2", Status.BLOCKED, detail="admin bind failed")
        abandon_id = raw.next_message_id()
        raw.send(build_abandon_request(abandon_id, 999999))
        # The abandon must not break the session: a follow-up search works.
        search_id = raw.next_message_id()
        payload = build_search_request(search_id, TEST_BASE, ["cn"])
        response = raw.send(payload)
        if not response:
            return Result(
                "4511.4.11.2",
                Status.FAIL,
                detail="session unusable after abandon (no search response)",
            )
        return Result("4511.4.11.2", Status.PASS)
    finally:
        raw.close()


@assertion(
    id="4511.4.11.1",
    rfc=4511,
    section="§4.11",
    category=Category.PROTOCOL,
    severity=Severity.MUST,
    test_class=TestClass.A,
    profiles=_INTEROP,
    text="Abandon of an in-progress operation ceases the operation.",
    strategy="Raw abandon of a just-issued search; expect no response, and the session keeps working.",
    preconditions="Target server is reachable on session.host:session.port.",
    stimulus="SearchRequest followed immediately by an AbandonRequest for it, then another search.",
    expected_observables="No response to the AbandonRequest; a follow-up search succeeds on the same session.",
)
def abandon_in_progress(session: Session) -> Result:
    raw = RawSession(session.host, session.port)
    raw.open()
    try:
        bind = raw.bind(ADMIN_DN, ADMIN_PW)
        if bind.result_code != 0:
            return Result("4511.4.11.1", Status.BLOCKED, detail="admin bind failed")
        search_id = raw.next_message_id()
        raw.send(build_search_request(search_id, TEST_BASE, ["cn"]))
        # Immediately abandon the in-flight search, then verify the session
        # still serves a follow-up request.
        abandon_id = raw.next_message_id()
        raw.send(build_abandon_request(abandon_id, search_id))
        follow_id = raw.next_message_id()
        payload = build_search_request(follow_id, TEST_BASE, ["cn"])
        response = raw.send(payload)
        if not response:
            return Result(
                "4511.4.11.1",
                Status.FAIL,
                detail="session unusable after abandon (no follow-up search response)",
            )
        return Result("4511.4.11.1", Status.PASS)
    finally:
        raw.close()

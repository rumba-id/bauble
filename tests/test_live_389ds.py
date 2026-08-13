"""Live integration test against the podman 389 Directory Server target.

Skipped unless ``BAUBLE_LIVE=1`` and ``podman`` is on PATH, so the default
gate (``uv run pytest``) never builds a container. Run with::

    BAUBLE_LIVE=1 uv run pytest -q tests/test_live_389ds.py

The 389 DS admin DN is ``cn=Directory Manager`` (override via
``BAUBLE_ADMIN_DN`` / ``BAUBLE_ADMIN_PW``).
"""

from __future__ import annotations

import os
import shutil
from collections.abc import Iterator

import pytest

from bauble.fixtures.directory389 import Directory389Target
from bauble.harness import LdapSession
from bauble.session import MOD_REPLACE, SCOPE_WHOLE_SUBTREE, Modification

_LIVE = bool(os.environ.get("BAUBLE_LIVE")) and shutil.which("podman") is not None
_REASON = "set BAUBLE_LIVE=1 with podman on PATH"

_ADMIN_DN = os.environ.get("BAUBLE_ADMIN_DN", "cn=Directory Manager")
_ADMIN_PW = os.environ.get("BAUBLE_ADMIN_PW", "bauble-admin")
_ALICE = "uid=alice,ou=people,dc=bauble,dc=test"


@pytest.fixture(scope="module")
def target() -> Iterator[Directory389Target]:
    tgt = Directory389Target()
    tgt.build()
    tgt.start()
    yield tgt
    tgt.stop()


@pytest.mark.skipif(not _LIVE, reason=_REASON)
def test_connectivity_smoke(target: Directory389Target) -> None:
    """Bind (anon + admin + named), search, compare, and an add/modify/delete round-trip."""
    session = LdapSession(target.server_config())

    # Anonymous bind is accepted (389 DS may restrict what anonymous can read).
    assert session.bind(None, None).result_code == 0

    # Admin can read the seeded entry.
    session.bind(_ADMIN_DN, _ADMIN_PW)
    outcome, entries = session.search(
        "dc=bauble,dc=test", SCOPE_WHOLE_SUBTREE, "(uid=alice)", ["cn", "uid"]
    )
    assert outcome.result_code == 0
    assert len(entries) == 1
    assert entries[0].attributes["cn"] == ["Alice"]

    # Named bind as the seeded user.
    assert session.bind(_ALICE, "alice-secret").result_code == 0
    assert session.bind(_ALICE, "wrong").result_code == 49

    session.bind(_ADMIN_DN, _ADMIN_PW)
    assert session.compare(_ALICE, "uid", "alice").result_code == 6
    assert session.compare(_ALICE, "uid", "bob").result_code == 5

    dn = "uid=carol,ou=people,dc=bauble,dc=test"
    try:
        assert (
            session.add(
                dn,
                {
                    "objectClass": ["inetOrgPerson"],
                    "cn": ["Carol"],
                    "sn": ["Carson"],
                    "uid": ["carol"],
                    "userPassword": ["x"],
                },
            ).result_code
            == 0
        )
        assert (
            session.modify(dn, [Modification(MOD_REPLACE, "cn", ["Carol Carson"])]).result_code
            == 0
        )
    finally:
        session.delete(dn)

    session.unbind()

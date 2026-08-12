"""Live integration test against the podman OpenLDAP target.

Skipped unless ``BAUBLE_LIVE=1`` and ``podman`` is on PATH, so the default
gate (``uv run pytest``) never builds a container. Run with::

    BAUBLE_LIVE=1 uv run pytest -q tests/test_live.py
"""

from __future__ import annotations

import os
import shutil
from collections.abc import Iterator

import pytest

from bauble.fixtures.container import OpenLDAPTarget
from bauble.harness import LdapSession
from bauble.session import MOD_REPLACE, SCOPE_WHOLE_SUBTREE, Modification

_LIVE = bool(os.environ.get("BAUBLE_LIVE")) and shutil.which("podman") is not None
_REASON = "set BAUBLE_LIVE=1 with podman on PATH"


@pytest.fixture(scope="module")
def target() -> Iterator[OpenLDAPTarget]:
    tgt = OpenLDAPTarget()
    tgt.build()
    tgt.start()
    yield tgt
    tgt.stop()


@pytest.mark.skipif(not _LIVE, reason=_REASON)
def test_connectivity_smoke(target: OpenLDAPTarget) -> None:
    """Bind (anon + named), search, compare, and an add/modify/delete round-trip."""
    session = LdapSession(target.server_config())

    assert session.bind(None, None).result_code == 0

    outcome, entries = session.search(
        "dc=bauble,dc=test", SCOPE_WHOLE_SUBTREE, "(uid=alice)", ["cn", "uid"]
    )
    assert outcome.result_code == 0
    assert len(entries) == 1
    assert entries[0].attributes["cn"] == ["Alice Anderson"]

    assert session.bind("uid=alice,ou=people,dc=bauble,dc=test", "alice-secret").result_code == 0
    assert session.bind("uid=alice,ou=people,dc=bauble,dc=test", "wrong").result_code == 49

    session.bind("cn=admin,dc=bauble,dc=test", "bauble-admin")
    assert (
        session.compare("uid=alice,ou=people,dc=bauble,dc=test", "uid", "alice").result_code == 6
    )
    assert session.compare("uid=alice,ou=people,dc=bauble,dc=test", "uid", "bob").result_code == 5

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


@pytest.mark.skipif(not _LIVE, reason=_REASON)
def test_isolation_reproducible(target: OpenLDAPTarget) -> None:
    """Two runs against the seed return the same DNs (no drift)."""
    session = LdapSession(target.server_config())

    def _dns() -> list[str]:
        session.bind("cn=admin,dc=bauble,dc=test", "bauble-admin")
        _, found = session.search(
            "dc=bauble,dc=test", SCOPE_WHOLE_SUBTREE, "(objectClass=*)", ["objectClass"]
        )
        return sorted(e.dn for e in found)

    first = _dns()
    second = _dns()
    session.unbind()
    assert first == second
    assert "uid=alice,ou=people,dc=bauble,dc=test" in first

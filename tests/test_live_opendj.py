"""Live integration test against the podman OpenDJ target.

Skipped unless ``BAUBLE_LIVE=1`` and ``podman`` is on PATH, so the default
gate (``uv run pytest``) never builds a container. Run with::

    BAUBLE_LIVE=1 uv run pytest -q tests/test_live_opendj.py

OpenDJ's admin DN is ``cn=Directory Manager``.
"""

from __future__ import annotations

import os
import shutil
from collections.abc import Iterator

import pytest

from bauble.fixtures.opendj import OpenDJTarget
from bauble.harness import LdapSession
from bauble.session import SCOPE_WHOLE_SUBTREE

_LIVE = bool(os.environ.get("BAUBLE_LIVE")) and shutil.which("podman") is not None
_REASON = "set BAUBLE_LIVE=1 with podman on PATH"


@pytest.fixture(scope="module")
def target() -> Iterator[OpenDJTarget]:
    tgt = OpenDJTarget()
    tgt.start()
    yield tgt
    tgt.stop()


@pytest.mark.skipif(not _LIVE, reason=_REASON)
def test_connectivity_smoke(target: OpenDJTarget) -> None:
    """Bind, search the seed, and read an entry against OpenDJ."""
    session = LdapSession(target.server_config())
    assert session.bind(target.admin_dn, target.admin_pw).result_code == 0

    outcome, entries = session.search(
        "dc=bauble,dc=test", SCOPE_WHOLE_SUBTREE, "(uid=alice)", ["cn", "uid"]
    )
    assert outcome.result_code == 0
    assert len(entries) == 1
    assert entries[0].attributes["cn"] == ["Alice Anderson"]

    assert session.bind("uid=alice,ou=people,dc=bauble,dc=test", "alice-secret").result_code == 0
    assert session.bind("uid=alice,ou=people,dc=bauble,dc=test", "wrong").result_code == 49

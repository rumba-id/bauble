"""Shared fixtures for test suite."""

from __future__ import annotations

import pytest

from bauble.client import ServerConfig


@pytest.fixture
def server_config():
    """Default server configuration for tests."""
    return ServerConfig(host="localhost", port=389)

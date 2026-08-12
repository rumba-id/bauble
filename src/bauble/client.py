"""LDAP connection management."""

from __future__ import annotations

import ssl
from typing import TYPE_CHECKING

import ldap3

if TYPE_CHECKING:
    from ldap3 import Connection

__all__ = ["ServerConfig", "create_connection"]


class ServerConfig:
    """Configuration for connecting to an LDAP server."""

    def __init__(
        self,
        host: str,
        port: int = 389,
        use_tls: bool = False,
        tls: ssl.SSLContext | None = None,
        connect_timeout: float = 5.0,
    ) -> None:
        self.host = host
        self.port = port
        self.use_tls = use_tls
        self.tls = tls
        self.connect_timeout = connect_timeout

    @property
    def uri(self) -> str:
        """Return the LDAP URI for this configuration."""
        scheme = "ldaps" if self.use_tls else "ldap"
        return f"{scheme}://{self.host}:{self.port}"


def create_connection(config: ServerConfig) -> Connection:
    """Create an ldap3 Connection using the given server configuration."""
    server = ldap3.Server(
        host=config.host,
        port=config.port,
        use_ssl=config.use_tls,
        tls=config.tls,
        connect_timeout=config.connect_timeout,
    )
    conn = ldap3.Connection(
        server=server,
        fast_decoder=True,
    )
    conn.open()
    return conn

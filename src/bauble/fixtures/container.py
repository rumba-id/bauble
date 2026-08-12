"""Lifecycle for the podman OpenLDAP test target.

Wraps the ``podman`` CLI via :mod:`subprocess` (no testcontainers dependency).
Used by the live integration test and by ``bauble run --target``.
"""

from __future__ import annotations

import subprocess
import time
from pathlib import Path

from bauble.harness import ServerConfig

__all__ = ["OpenLDAPTarget"]

_FIXTURES = Path(__file__).resolve().parent
_ADMIN_DN = "cn=admin,dc=bauble,dc=test"
_ADMIN_PW = "bauble-admin"
_DEFAULT_HOST_PORT = 3890


class OpenLDAPTarget:
    """A disposable, containerized OpenLDAP seeded with the bauble base DIT."""

    def __init__(
        self,
        name: str = "bauble-openldap",
        host_port: int = _DEFAULT_HOST_PORT,
        image: str = "bauble-openldap",
    ) -> None:
        self.name = name
        self.host_port = host_port
        self.image = image

    def build(self) -> None:
        """Build the image (idempotent: podman caches layers)."""
        subprocess.run(
            [
                "podman",
                "build",
                "-t",
                self.image,
                "-f",
                str(_FIXTURES / "Containerfile"),
                str(_FIXTURES),
            ],
            check=True,
            capture_output=True,
        )

    def start(self) -> None:
        """Start a fresh container and wait until slapd answers."""
        self.stop()
        subprocess.run(
            [
                "podman",
                "run",
                "-d",
                "--name",
                self.name,
                "-p",
                f"{self.host_port}:389",
                self.image,
            ],
            check=True,
            capture_output=True,
        )
        self._wait_ready()

    def _wait_ready(self, timeout: float = 30.0) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            result = subprocess.run(
                [
                    "podman",
                    "exec",
                    self.name,
                    "ldapwhoami",
                    "-x",
                    "-H",
                    "ldap://127.0.0.1:389",
                    "-D",
                    _ADMIN_DN,
                    "-w",
                    _ADMIN_PW,
                ],
                capture_output=True,
                check=False,
            )
            if result.returncode == 0:
                return
            time.sleep(0.5)
        raise RuntimeError(f"OpenLDAP target {self.name!r} did not become ready")

    def stop(self) -> None:
        """Remove the container (idempotent)."""
        subprocess.run(["podman", "rm", "-f", self.name], capture_output=True, check=False)

    def server_config(
        self,
        *,
        use_ssl: bool = False,
        use_start_tls: bool = False,
    ) -> ServerConfig:
        """A ServerConfig pointing at this target's mapped host port."""
        return ServerConfig(
            host="127.0.0.1",
            port=self.host_port,
            use_ssl=use_ssl,
            use_start_tls=use_start_tls,
        )

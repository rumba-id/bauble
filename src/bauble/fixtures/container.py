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


def _podman(args: list[str], *, check: bool = True) -> subprocess.CompletedProcess[bytes]:
    """Run a podman command; on failure raise with podman's stderr included.

    The callers previously used ``check=True, capture_output=True``, which
    swallowed podman's diagnostics and left CI with only an opaque exit code.
    """
    result = subprocess.run(args, capture_output=True, check=False)
    if check and result.returncode != 0:
        stderr = result.stderr.decode("utf-8", errors="replace").strip()
        cmd = " ".join(args[1:])
        raise RuntimeError(f"podman {cmd} failed ({result.returncode}): {stderr}")
    return result


def _capability_path(name: str) -> Path:
    return Path(__file__).parent / name


class OpenLDAPTarget:
    """A disposable, containerized OpenLDAP seeded with the bauble base DIT."""

    def __init__(
        self,
        name: str = "bauble-openldap",
        host_port: int = _DEFAULT_HOST_PORT,
        image: str = "bauble-openldap",
        ldaps_port: int = 6360,
    ) -> None:
        self.name = name
        self.host_port = host_port
        self.ldaps_port = ldaps_port
        self.image = image
        self.capability_path = _capability_path("capability-openldap.toml")

    def build(self) -> None:
        """Build the image (idempotent: podman caches layers)."""
        _podman(
            [
                "podman",
                "build",
                "-t",
                self.image,
                "-f",
                str(_FIXTURES / "Containerfile"),
                str(_FIXTURES),
            ]
        )

    def is_running(self) -> bool:
        """Whether the container is currently running."""
        result = subprocess.run(
            ["podman", "inspect", "--format", "{{.State.Running}}", self.name],
            capture_output=True,
            check=False,
            text=True,
        )
        return result.returncode == 0 and result.stdout.strip() == "true"

    def ensure_running(self) -> None:
        """Reuse the running container, or build+start if it is not up.

        This is the default isolation model: the base seed is the contract,
        and mutating assertions self-clean, so a long-lived container does
        not drift between runs.  Use :meth:`start` for a forced fresh start.
        """
        if not self.is_running():
            self.build()
            self.start()

    def start(self) -> None:
        """Start a fresh container and wait until slapd answers."""
        self.stop()
        _podman(
            [
                "podman",
                "run",
                "-d",
                "--name",
                self.name,
                "-p",
                f"{self.host_port}:389",
                "-p",
                f"{self.ldaps_port}:636",
                self.image,
            ]
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

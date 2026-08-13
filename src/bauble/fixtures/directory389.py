"""Lifecycle for the podman 389 Directory Server test target."""

from __future__ import annotations

import subprocess
import time
from pathlib import Path

from bauble.harness import ServerConfig

__all__ = ["Directory389Target"]

_FIXTURES = Path(__file__).resolve().parent / "389ds"
_ADMIN_DN = "cn=Directory Manager"
_ADMIN_PW = "bauble-admin"
_DEFAULT_HOST_PORT = 3390
_DEFAULT_SECURE_PORT = 3637


def _podman(args: list[str], *, check: bool = True) -> subprocess.CompletedProcess[bytes]:
    """Run a podman command; on failure raise with podman's stderr included.

    Mirrors ``bauble.fixtures.container._podman`` so both targets surface
    podman's diagnostics instead of an opaque exit code.
    """
    result = subprocess.run(args, capture_output=True, check=False)
    if check and result.returncode != 0:
        stderr = result.stderr.decode("utf-8", errors="replace").strip()
        cmd = " ".join(args[1:])
        raise RuntimeError(f"podman {cmd} failed ({result.returncode}): {stderr}")
    return result


class Directory389Target:
    """A disposable, containerized 389 DS seeded with the bauble base DIT."""

    def __init__(
        self,
        name: str = "bauble-389ds",
        host_port: int = _DEFAULT_HOST_PORT,
        image: str = "bauble-389ds",
    ) -> None:
        self.name = name
        self.host_port = host_port
        self.image = image

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
        """Reuse the running container, or build+start if not up."""
        if not self.is_running():
            self.build()
            self.start()

    def start(self) -> None:
        """Start a fresh container and wait until the DS answers."""
        self.stop()
        _podman(
            [
                "podman",
                "run",
                "-d",
                "--name",
                self.name,
                "-p",
                f"{self.host_port}:3389",
                "-p",
                f"{_DEFAULT_SECURE_PORT}:3636",
                self.image,
            ]
        )
        self._wait_ready()

    def _wait_ready(self, timeout: float = 60.0) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            result = subprocess.run(
                [
                    "podman",
                    "exec",
                    self.name,
                    "ldapsearch",
                    "-x",
                    "-H",
                    "ldap://127.0.0.1:3389",
                    "-D",
                    _ADMIN_DN,
                    "-w",
                    _ADMIN_PW,
                    "-b",
                    "dc=bauble,dc=test",
                    "-s",
                    "base",
                    "(objectClass=*)",
                ],
                capture_output=True,
                check=False,
            )
            if result.returncode == 0:
                return
            time.sleep(1.0)
        raise RuntimeError(f"389 DS target {self.name!r} did not become ready")

    def stop(self) -> None:
        """Remove the container (idempotent)."""
        subprocess.run(["podman", "rm", "-f", self.name], capture_output=True, check=False)

    def server_config(self, *, use_ssl: bool = False, use_start_tls: bool = False) -> ServerConfig:
        """A ServerConfig pointing at this target's mapped host port."""
        return ServerConfig(
            host="127.0.0.1",
            port=self.host_port,
            use_ssl=use_ssl,
            use_start_tls=use_start_tls,
        )

"""Podman fixture for the OpenDJ LDAP server (OpenIdentityPlatform).

OpenDJ is a Java LDAPv3 server (Sun DSEE / OpenDS lineage) — a third,
genuinely different implementation for cross-implementation comparison.
The official image runs ``setup`` on first start from environment
variables; the fixture waits for readiness, then seeds the base DIT from
``seed.ldif`` when the base entry is absent.
"""

from __future__ import annotations

import subprocess
import time
from pathlib import Path

from bauble.harness import ServerConfig

_IMAGE = "docker.io/openidentityplatform/opendj"
_DEFAULT_HOST_PORT = 13890
_DEFAULT_ADMIN_DN = "cn=Directory Manager"
_DEFAULT_ADMIN_PW = "bauble-admin"
_BASE_DN = "dc=bauble,dc=test"


def _podman(
    args: list[str], *, check: bool = True, stdin: bytes | None = None
) -> subprocess.CompletedProcess[bytes]:
    """Run a podman command; on failure raise with podman's stderr included.

    Mirrors ``bauble.fixtures.container._podman`` so every target surfaces
    podman's diagnostics instead of an opaque exit code.
    """
    result = subprocess.run(args, capture_output=True, check=False, input=stdin)
    if check and result.returncode != 0:
        stderr = result.stderr.decode("utf-8", errors="replace").strip()
        cmd = " ".join(args[1:])
        raise RuntimeError(f"podman {cmd} failed ({result.returncode}): {stderr}")
    return result


def _capability_path(name: str) -> Path:
    return Path(__file__).parent / name


class OpenDJTarget:
    """A disposable, containerized OpenDJ seeded with the bauble base DIT."""

    def __init__(
        self,
        name: str = "bauble-opendj",
        host_port: int = _DEFAULT_HOST_PORT,
        image: str = _IMAGE,
        admin_dn: str = _DEFAULT_ADMIN_DN,
        admin_pw: str = _DEFAULT_ADMIN_PW,
    ) -> None:
        self.name = name
        self.host_port = host_port
        self.image = image
        self.admin_dn = admin_dn
        self.admin_pw = admin_pw
        self.capability_path = _capability_path("capability-opendj.toml")

    def build(self) -> None:
        # The official image self-configures on first start; nothing to build.
        return None

    def is_running(self) -> bool:
        result = _podman(
            ["podman", "inspect", "--format", "{{.State.Running}}", self.name],
            check=False,
        )
        return result.returncode == 0 and result.stdout.strip() == b"true"

    def ensure_running(self) -> None:
        if not self.is_running():
            self.start()

    def start(self) -> None:
        self.stop()
        _podman(
            [
                "podman",
                "run",
                "-d",
                "--name",
                self.name,
                "-p",
                f"{self.host_port}:1389",
                "-p",
                "16360:1636",
                "-e",
                f"BASE_DN={_BASE_DN}",
                "-e",
                f"ROOT_USER_DN={self.admin_dn}",
                "-e",
                f"ROOT_PASSWORD={self.admin_pw}",
                self.image,
            ]
        )
        self._wait_ready()
        self._seed()

    def _wait_ready(self, timeout: float = 120.0) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            result = _podman(
                [
                    "podman",
                    "exec",
                    self.name,
                    "/opt/opendj/bin/ldapsearch",
                    "--hostname",
                    "127.0.0.1",
                    "--port",
                    "1389",
                    "--bindDN",
                    self.admin_dn,
                    "--bindPassword",
                    self.admin_pw,
                    "--baseDN",
                    "",
                    "--searchScope",
                    "base",
                    "(objectClass=*)",
                ],
                check=False,
            )
            if result.returncode == 0:
                return
            time.sleep(1.0)
        raise RuntimeError(f"OpenDJ target {self.name!r} did not become ready")

    def _seed(self) -> None:
        """Load the base seed when the base entry is absent (idempotent)."""
        exists = _podman(
            [
                "podman",
                "exec",
                self.name,
                "/opt/opendj/bin/ldapsearch",
                "--hostname",
                "127.0.0.1",
                "--port",
                "1389",
                "--bindDN",
                self.admin_dn,
                "--bindPassword",
                self.admin_pw,
                "--baseDN",
                _BASE_DN,
                "--searchScope",
                "base",
                "(objectClass=*)",
            ],
            check=False,
        )
        if exists.returncode == 0:
            return
        seed = Path(__file__).parent / "seed.ldif"
        _podman(
            [
                "podman",
                "exec",
                "-i",
                self.name,
                "/opt/opendj/bin/ldapmodify",
                "--hostname",
                "127.0.0.1",
                "--port",
                "1389",
                "--bindDN",
                self.admin_dn,
                "--bindPassword",
                self.admin_pw,
            ],
            stdin=seed.read_bytes(),
        )

    def stop(self) -> None:
        subprocess.run(["podman", "rm", "-f", self.name], capture_output=True, check=False)

    def server_config(self, *, use_ssl: bool = False, use_start_tls: bool = False) -> ServerConfig:
        return ServerConfig(
            host="127.0.0.1",
            port=self.host_port,
            use_ssl=use_ssl,
            use_start_tls=use_start_tls,
        )

"""Podman fixture for the LLDAP LDAP server (lldap/lldap).

LLDAP is a Rust identity store exposing an LDAPv3 interface over its own
user database — the minimal end of the conformance spectrum. The LDAP
interface is read-mostly: users are created through LLDAP's own bootstrap
mechanism (GraphQL), not through LDAP add operations. The fixture starts
the container, then runs ``bootstrap.sh`` with the bauble seed users
(alice/bob) declared as user-config JSON files.
"""

from __future__ import annotations

import subprocess
import time
from pathlib import Path

from bauble.harness import ServerConfig

_IMAGE = "docker.io/lldap/lldap"
_DEFAULT_HOST_PORT = 13891
_DEFAULT_ADMIN_DN = "cn=admin,ou=people,dc=bauble,dc=test"
_DEFAULT_ADMIN_PW = "bauble-admin"
_BASE_DN = "dc=bauble,dc=test"
_JWT_SECRET = "bauble-test-jwt-secret-0123456789abcdef"


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


class LLDAPTarget:
    """A disposable, containerized LLDAP seeded with the bauble users."""

    def __init__(
        self,
        name: str = "bauble-lldap",
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
        self.capability_path = _capability_path("capability-lldap.toml")

    def build(self) -> None:
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
                f"{self.host_port}:13890",
                "-p",
                "17171:17170",
                "-e",
                f"LLDAP_JWT_SECRET={_JWT_SECRET}",
                "-e",
                f"LLDAP_LDAP_BASE_DN={_BASE_DN}",
                "-e",
                "LLDAP_LDAP_USER_DN=admin",
                "-e",
                f"LLDAP_LDAP_USER_PASS={self.admin_pw}",
                "-e",
                "LLDAP_LDAP_PORT=13890",
                "-e",
                "LLDAP_HTTP_PORT=17170",
                self.image,
            ]
        )
        self._wait_ready()
        self._seed()

    def _wait_ready(self, timeout: float = 60.0) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            result = _podman(
                [
                    "podman",
                    "exec",
                    self.name,
                    "sh",
                    "-c",
                    "curl -sf http://localhost:17170/health >/dev/null 2>&1 || curl -sf http://localhost:17170/ >/dev/null 2>&1",
                ],
                check=False,
            )
            if result.returncode == 0:
                return
            time.sleep(1.0)
        raise RuntimeError(f"LLDAP target {self.name!r} did not become ready")

    def _seed(self) -> None:
        """Bootstrap the seed users via LLDAP's own mechanism (idempotent)."""
        configs_dir = Path(__file__).parent / "lldap"
        _podman(["podman", "exec", self.name, "mkdir", "-p", "/bootstrap/user-configs"])
        for json_file in sorted(configs_dir.glob("*.json")):
            _podman(["podman", "cp", str(json_file), f"{self.name}:/bootstrap/user-configs/"])
        _podman(
            [
                "podman",
                "exec",
                self.name,
                "sh",
                "-c",
                (
                    "LLDAP_URL=http://localhost:17170 "
                    "LLDAP_ADMIN_USERNAME=admin "
                    f"LLDAP_ADMIN_PASSWORD={self.admin_pw} /app/bootstrap.sh"
                ),
            ]
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

"""Generate short-lived TLS material for localhost conformance servers."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class LoopbackCertificate:
    """Paths to one generated loopback certificate chain."""

    root_der: Path
    private_key_pem: Path
    certificate_pem: Path


def generate_loopback_certificate(directory: Path) -> LoopbackCertificate:
    """Generates a strict CA and localhost leaf certificate."""

    ca_config = directory / "ca.cnf"
    server_config = directory / "server.cnf"
    ca_config.write_text(
        """[req]
distinguished_name = dn
x509_extensions = ca_ext
prompt = no
[dn]
CN = Phantom Conformance Test CA
[ca_ext]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
""",
        encoding="utf-8",
    )
    server_config.write_text(
        """[req]
distinguished_name = dn
prompt = no
[dn]
CN = localhost
[server_ext]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:localhost,IP:127.0.0.1
""",
        encoding="utf-8",
    )
    _run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-sha256",
            "-days",
            "2",
            "-config",
            str(ca_config),
            "-keyout",
            str(directory / "ca.key"),
            "-out",
            str(directory / "ca.pem"),
        ]
    )
    _run(
        [
            "openssl",
            "req",
            "-new",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-sha256",
            "-config",
            str(server_config),
            "-keyout",
            str(directory / "server.key"),
            "-out",
            str(directory / "server.csr"),
        ]
    )
    _run(
        [
            "openssl",
            "x509",
            "-req",
            "-in",
            str(directory / "server.csr"),
            "-CA",
            str(directory / "ca.pem"),
            "-CAkey",
            str(directory / "ca.key"),
            "-CAcreateserial",
            "-days",
            "2",
            "-sha256",
            "-extfile",
            str(server_config),
            "-extensions",
            "server_ext",
            "-out",
            str(directory / "server.pem"),
        ]
    )
    root_der = directory / "ca.der"
    _run(
        [
            "openssl",
            "x509",
            "-in",
            str(directory / "ca.pem"),
            "-outform",
            "DER",
            "-out",
            str(root_der),
        ]
    )
    return LoopbackCertificate(
        root_der=root_der,
        private_key_pem=directory / "server.key",
        certificate_pem=directory / "server.pem",
    )


def _run(command: list[str]) -> None:
    subprocess.run(command, check=True, capture_output=True, text=True)

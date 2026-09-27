"""
CloudFail-Killer - SSL Certificate Checker

Validates SSL/TLS certificates on discovered IPs to check if they match
the target domain. A matching certificate is a strong indicator that
the IP hosts the actual origin server behind Cloudflare.

Techniques:
    1. SSL certificate CN (Common Name) matching
    2. SAN (Subject Alternative Name) matching
    3. Certificate issuer comparison with Cloudflare's certs
    4. Certificate fingerprint comparison
    5. Support for both IPv4 and IPv6

MITRE ATT&CK: T1595.002 (SSL/TLS Inspection)
"""

from __future__ import annotations

import asyncio
import logging
import socket
import ssl
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from cryptography import x509

logger = logging.getLogger(__name__)

# Common Cloudflare issuer organization names
CF_ISSUER_PATTERNS = [
    "cloudflare",
    "let's encrypt",
    "buypass",
    "google trust services",
    "digi cert",
    "sectigo",
    "globalsign",
    "samsung",
]


@dataclass
class SSLInfo:
    """SSL certificate information extracted from an IP:port."""
    ip: str
    port: int
    cn: str | None = None
    san: list[str] = field(default_factory=list)
    issuer_org: str | None = None
    issuer_cn: str | None = None
    serial: str | None = None
    not_before: str | None = None
    not_after: str | None = None
    version: int | None = None
    cipher_name: str | None = None
    cipher_bits: int | None = None
    cert_expired: bool = False
    self_signed: bool = False
    is_cloudflare_cert: bool = False
    ssl_error: str | None = None

    @property
    def is_valid(self) -> bool:
        return self.ssl_error is None and self.cn is not None

    def matches_domain(self, domain: str) -> bool:
        """
        Check if this SSL certificate matches the target domain.

        Matches if CN or any SAN contains the domain.
        """
        if not self.cn:
            return False

        # Normalize domain for comparison
        domain = domain.lower().strip(".")
        patterns = [
            f".{domain}",
            domain,
        ]

        # Check CN
        cn_lower = self.cn.lower()
        if any(p in cn_lower for p in patterns):
            return True

        # Check SANs
        for san in self.san:
            san_lower = san.lower()
            if any(p in san_lower for p in patterns):
                return True
            # Wildcard SAN matching
            if san_lower.startswith("*."):
                san_base = san_lower[2:]
                if san_base == domain or san_base.endswith(f".{domain}") or domain.endswith(f".{san_base}"):
                    return True

        return False

    def to_dict(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "port": self.port,
            "cn": self.cn,
            "san": self.san[:10],  # Limit to prevent oversized output
            "issuer_org": self.issuer_org,
            "issuer_cn": self.issuer_cn,
            "serial": self.serial,
            "not_before": self.not_before,
            "not_after": self.not_after,
            "version": self.version,
            "cipher_name": self.cipher_name,
            "cipher_bits": self.cipher_bits,
            "cert_expired": self.cert_expired,
            "self_signed": self.self_signed,
            "is_cloudflare_cert": self.is_cloudflare_cert,
            "is_valid": self.is_valid,
            "ssl_error": self.ssl_error,
        }


class SSLChecker:
    """
    Async SSL certificate checker for origin IP validation.

    Checks SSL certificates on discovered IPs to determine if they
    are likely to be the origin server (cert matches domain).

    Usage:
        checker = SSLChecker(timeout=10)
        info = await checker.check_ssl("1.2.3.4", 443)
        if info.matches_domain("example.com"):
            print("Likely origin server!")
    """

    def __init__(
        self,
        timeout: float = 10.0,
        max_concurrent: int = 50,
        include_expired: bool = True,
    ) -> None:
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.include_expired = include_expired
        self._semaphore = asyncio.Semaphore(max_concurrent)

    async def check_ssl(self, ip: str, port: int = 443) -> SSLInfo:
        """
        Check SSL certificate for an IP:port combination.

        Args:
            ip: IP address to check
            port: Port number (default 443)

        Returns:
            SSLInfo with certificate details
        """
        info = SSLInfo(ip=ip, port=port)

        async with self._semaphore:
            try:
                # Use asyncio's low-level socket with SSL wrapping
                # This gives us direct access to the peer certificate
                ssl_info = await asyncio.wait_for(
                    self._get_cert_async(ip, port),
                    timeout=self.timeout,
                )
                info.cn = ssl_info.get("subject", {}).get("commonName")
                info.san = ssl_info.get("subjectAltName", [])
                if isinstance(info.san, str):
                    info.san = [info.san]
                info.issuer_org = ssl_info.get("issuer", {}).get("organizationName")
                info.issuer_cn = ssl_info.get("issuer", {}).get("commonName")
                info.serial = str(ssl_info.get("serialNumber", ""))
                info.not_before = ssl_info.get("notBefore", "")
                info.not_after = ssl_info.get("notAfter", "")
                info.version = ssl_info.get("version", 0)

                # Check if it's a Cloudflare certificate
                issuer = (info.issuer_org or "").lower()
                info.is_cloudflare_cert = any(
                    p in issuer for p in CF_ISSUER_PATTERNS
                )

                # Check if certificate is expired (pre-computed in _get_cert_sync)
                info.cert_expired = ssl_info.get("_cert_expired", False)

                # Check self-signed (pre-computed: issuer == subject)
                info.self_signed = ssl_info.get("_self_signed", False)

            except TimeoutError:
                info.ssl_error = f"Timeout after {self.timeout}s"
            except ConnectionRefusedError:
                info.ssl_error = "Connection refused"
            except OSError as e:
                info.ssl_error = f"Connection error: {type(e).__name__}"
            except Exception as e:
                info.ssl_error = f"SSL error: {e}"

        return info

    async def check_ssl_batch(
        self,
        ip_port_pairs: list[tuple[str, int]],
    ) -> list[SSLInfo]:
        """
        Check SSL certificates for multiple IPs concurrently.

        Args:
            ip_port_pairs: List of (ip, port) tuples

        Returns:
            List of SSLInfo results
        """
        tasks = [
            self.check_ssl(ip, port)
            for ip, port in ip_port_pairs
        ]
        return await asyncio.gather(*tasks, return_exceptions=False)

    async def _get_cert_async(self, ip: str, port: int) -> dict:
        """
        Get SSL certificate info using asyncio + ssl.

        Returns a dict with certificate fields similar to ssl.SSLSocket.getpeercert().
        """
        # Create a socket pair in the current thread
        loop = asyncio.get_running_loop()

        # Use loop.run_in_executor to bridge sync ssl operations
        result = await loop.run_in_executor(
            None,
            self._get_cert_sync,
            ip,
            port,
        )
        return result

    @staticmethod
    def _get_cert_sync(ip: str, port: int) -> dict:
        """Synchronous SSL certificate retrieval."""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False  # We connect by IP, not hostname
        ctx.verify_mode = ssl.CERT_NONE  # We want the cert even if invalid

        with (socket.create_connection((ip, port), timeout=10) as sock,
              ctx.wrap_socket(sock, server_hostname=ip) as ssock):
                # Get binary cert
                binary_cert = ssock.getpeercert(binary_form=True)
                # Parse the cert
                from cryptography import x509
                cert = x509.load_der_x509_certificate(binary_cert)

                # Extract SANs
                try:
                    san_ext = cert.extensions.get_extension_for_class(
                        x509.SubjectAlternativeName
                    )
                    san_values = san_ext.value.get_values_for_type(
                        x509.DNSName
                    )
                except x509.ExtensionNotFound:
                    san_values = []

                # Build result dict
                result: dict[str, Any] = {
                    "subject": {
                        "commonName": _get_cn_from_cert(cert),
                    },
                    "issuer": {
                        "organizationName": _get_org_from_issuer(cert),
                        "commonName": _get_cn_from_issuer(cert),
                    },
                    "serialNumber": format(cert.serial_number, "x"),
                    "version": cert.version.value,
                    "notBefore": cert.not_valid_before_utc.isoformat() if cert.not_valid_before_utc else "",
                    "notAfter": cert.not_valid_after_utc.isoformat() if cert.not_valid_after_utc else "",
                    "subjectAltName": san_values,
                    "_cert_expired": cert.not_valid_after_utc < datetime.now(UTC) if cert.not_valid_after_utc else False,
                    "_self_signed": cert.issuer == cert.subject,
                    "_binary_cert": binary_cert,
                }

                return result


def _get_cn_from_cert(cert: Any) -> str:
    """Extract Common Name from cert subject."""
    try:
        cns = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
        return cns[0].value if cns else ""
    except Exception:
        return ""


def _get_org_from_issuer(cert: Any) -> str:
    """Extract Organization from cert issuer."""
    try:
        orgs = cert.issuer.get_attributes_for_oid(x509.oid.NameOID.ORGANIZATION_NAME)
        return orgs[0].value if orgs else ""
    except Exception:
        return ""


def _get_cn_from_issuer(cert: Any) -> str:
    """Extract Common Name from cert issuer."""
    try:
        cns = cert.issuer.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
        return cns[0].value if cns else ""
    except Exception:
        return ""

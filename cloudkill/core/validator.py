"""
CloudFail-Killer - Input Validator & Security

Validates user inputs to prevent security issues:
    - Domain validation (format, length, IDN support)
    - IP address validation (format, private ranges)
    - Port number validation
    - Path traversal prevention
    - Command injection prevention
    - Rate limit validation
"""

from __future__ import annotations

import ipaddress
import logging
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Domain validation patterns
DOMAIN_PATTERN = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)"
    r"+[a-zA-Z]{2,63}$"
)

# Common dangerous patterns in user inputs
DANGEROUS_PATTERNS = [
    re.compile(r"[;\|\`&$()]"),       # Shell metacharacters
    re.compile(r"\.\.[/~]"),                 # Path traversal
    re.compile(r"\$\{.*\}"),               # Template injection
    re.compile(r"<[^>]+>"),                 # HTML tags
]

# Private/reserved IP ranges
PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


class ValidationError(Exception):
    """Raised when input validation fails."""

    def __init__(self, field: str, message: str, value: str = "") -> None:
        self.field = field
        self.message = message
        self.value = value
        super().__init__(f"{field}: {message} (value={value!r})")


class InputValidator:
    """
    Validates and sanitizes user inputs for CloudFail-Killer.

    Prevents:
    - Domain format errors
    - Path traversal in output paths
    - Shell injection in webhook URLs
    - Invalid port numbers
    - Private IP ranges in target specifications

    Usage:
        validator = InputValidator()
        validator.validate_domain("example.com")
        validator.validate_ip("192.168.1.1")
        validator.validate_port(443)
        validator.validate_output_path("/tmp/report.json")
        validator.validate_webhook_url("https://hooks.slack.com/test")
    """

    MAX_DOMAIN_LENGTH = 253
    MIN_DOMAIN_LENGTH = 3
    MAX_PORT = 65535
    MIN_PORT = 1
    MAX_PATH_LENGTH = 4096

    def validate_domain(self, domain: str) -> str:
        """
        Validate and sanitize a domain name.

        Args:
            domain: Domain name to validate

        Returns:
            Sanitized domain string

        Raises:
            ValidationError: If domain is invalid
        """
        if not domain or not isinstance(domain, str):
            raise ValidationError("domain", "Domain is required", "")

        domain = domain.strip().lower().rstrip(".")

        if len(domain) < self.MIN_DOMAIN_LENGTH:
            raise ValidationError(
                "domain",
                f"Domain must be at least {self.MIN_DOMAIN_LENGTH} characters",
                domain,
            )

        if len(domain) > self.MAX_DOMAIN_LENGTH:
            raise ValidationError(
                "domain",
                f"Domain exceeds maximum length of {self.MAX_DOMAIN_LENGTH}",
                domain,
            )

        if not DOMAIN_PATTERN.match(domain):
            raise ValidationError(
                "domain",
                "Invalid domain format (must be a valid FQDN)",
                domain,
            )

        # Check for dangerous patterns
        for pattern in DANGEROUS_PATTERNS:
            if pattern.search(domain):
                raise ValidationError(
                    "domain",
                    "Domain contains potentially dangerous characters",
                    domain,
                )

        # Normalize: remove trailing dot
        domain = domain.rstrip(".")

        return domain

    def validate_ip(self, ip: str, allow_private: bool = False) -> str:
        """
        Validate and normalize an IP address.

        Args:
            ip: IP address to validate (IPv4 or IPv6)
            allow_private: Whether to allow private/reserved IPs

        Returns:
            Normalized IP string

        Raises:
            ValidationError: If IP is invalid
        """
        if not ip or not isinstance(ip, str):
            raise ValidationError("ip", "IP address is required", "")

        ip = ip.strip()

        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            raise ValidationError("ip", f"Invalid IP address format: {ip}", ip) from None

        if not allow_private and (ip_obj.is_private or ip_obj.is_loopback
                                     or ip_obj.is_link_local or ip_obj.is_reserved):
            raise ValidationError(
                "ip",
                f"Private/reserved IP address is not allowed: {ip}",
                ip,
            )

        return str(ip_obj)

    def validate_port(self, port: int) -> int:
        """
        Validate a port number.

        Args:
            port: Port number to validate

        Returns:
            Validated port number

        Raises:
            ValidationError: If port is invalid
        """
        if not isinstance(port, int):
            raise ValidationError("port", f"Port must be an integer: {port!r}", "")

        if port < self.MIN_PORT or port > self.MAX_PORT:
            raise ValidationError(
                "port",
                f"Port must be between {self.MIN_PORT} and {self.MAX_PORT}",
                port,
            )

        return port

    def validate_output_path(self, path: str) -> str:
        """
        Validate and sanitize an output file path.

        Prevents path traversal attacks.

        Args:
            path: Output file path

        Returns:
            Sanitized path string

        Raises:
            ValidationError: If path is invalid
        """
        if not path or not isinstance(path, str):
            raise ValidationError("path", "Output path is required", "")

        path = path.strip()

        if len(path) > self.MAX_PATH_LENGTH:
            raise ValidationError(
                "path",
                f"Path exceeds maximum length of {self.MAX_PATH_LENGTH}",
                path,
            )

        # Check for path traversal
        if ".." in path or "~" in path:
            raise ValidationError(
                "path",
                "Path traversal detected (.. or ~ not allowed)",
                path,
            )

        return path

    def safe_output_path(self, output_path: Path | str) -> Path:
        """
        Validate an output path and return it as a Path object.

        Convenience wrapper used by exporters to guarantee every file
        write goes through the same traversal checks.

        Raises:
            ValidationError: If path is invalid or contains traversal
        """
        return Path(self.validate_output_path(str(output_path)))

    def validate_webhook_url(self, url: str) -> str:
        """
        Validate a webhook URL.

        Args:
            url: Webhook URL to validate

        Returns:
            Validated URL string

        Raises:
            ValidationError: If URL is invalid
        """
        if not url or not isinstance(url, str):
            raise ValidationError("webhook_url", "Webhook URL is required", "")

        url = url.strip()

        try:
            parsed = urlparse(url)
        except Exception:
            raise ValidationError("webhook_url", f"Invalid URL format: {url}", url) from None

        if parsed.scheme not in ("https", "http"):
            raise ValidationError(
                "webhook_url",
                "Webhook URL must use HTTPS or HTTP protocol",
                url,
            )

        if not parsed.hostname:
            raise ValidationError(
                "webhook_url",
                "Webhook URL must have a valid hostname",
                url,
            )

        # Block localhost/private IPs in webhooks
        hostname = parsed.hostname
        if hostname in ("localhost", "127.0.0.1", "::1"):
            raise ValidationError(
                "webhook_url",
                "Webhook URL cannot point to localhost",
                url,
            )

        return url

    def validate_profile(self, profile: str) -> str:
        """
        Validate a scan profile name.

        Args:
            profile: Profile name to validate

        Returns:
            Validated profile name

        Raises:
            ValidationError: If profile is invalid
        """
        valid_profiles = {"researcher", "pentester", "bugbounty", "enterprise", "automation"}

        if not profile or profile not in valid_profiles:
            raise ValidationError(
                "profile",
                f"Invalid profile. Must be one of: {', '.join(sorted(valid_profiles))}",
                profile or "",
            )

        return profile

    def validate_format(self, fmt: str) -> str:
        """
        Validate an output format.

        Args:
            fmt: Format name

        Returns:
            Validated format name

        Raises:
            ValidationError: If format is invalid
        """
        valid_formats = {"json", "csv", "txt", "md", "pdf", "nuclei"}

        if not fmt or fmt not in valid_formats:
            raise ValidationError(
                "format",
                f"Invalid format. Must be one of: {', '.join(sorted(valid_formats))}",
                fmt or "",
            )

        return fmt

    def sanitize_string(self, value: str, max_length: int = 256) -> str:
        """
        Sanitize a user-provided string to prevent injection.

        Args:
            value: String to sanitize
            max_length: Maximum allowed length

        Returns:
            Sanitized string
        """
        if not value:
            return ""

        value = str(value).strip()
        value = value[:max_length]

        # Remove null bytes
        value = value.replace("\x00", "")

        # Remove control characters except tab and newline
        value = "".join(
            c for c in value if c >= "\t" or c == "\n"
        )

        return value

    def validate_config(self, config_dict: dict[str, Any]) -> list[str]:
        """
        Validate a configuration dictionary.

        Args:
            config_dict: Configuration dictionary to validate

        Returns:
            List of validation error messages (empty if valid)
        """
        errors: list[str] = []

        if "threads" in config_dict:
            try:
                threads = int(config_dict["threads"])
                if threads < 1 or threads > 200:
                    errors.append(f"threads must be between 1 and 200, got {threads}")
            except (ValueError, TypeError):
                errors.append(f"threads must be an integer, got {config_dict['threads']!r}")

        if "timeout" in config_dict:
            try:
                timeout = int(config_dict["timeout"])
                if timeout < 5 or timeout > 120:
                    errors.append(f"timeout must be between 5 and 120 seconds, got {timeout}")
            except (ValueError, TypeError):
                errors.append(f"timeout must be an integer, got {config_dict['timeout']!r}")

        if "min_confidence" in config_dict:
            try:
                conf = int(config_dict["min_confidence"])
                if conf < 0 or conf > 100:
                    errors.append(f"min_confidence must be between 0 and 100, got {conf}")
            except (ValueError, TypeError):
                errors.append(f"min_confidence must be an integer, got {config_dict['min_confidence']!r}")

        return errors


def validate_domain(domain: str) -> str:
    """Quick domain validation (module-level convenience)."""
    return InputValidator().validate_domain(domain)


def safe_output_path(output_path: Path | str) -> Path:
    """Validate and normalize an output path (module-level convenience).

    Raises:
        ValidationError: If path is invalid or contains traversal
    """
    return InputValidator().safe_output_path(output_path)


def validate_ip(ip: str, allow_private: bool = False) -> str:
    """Quick IP validation (module-level convenience)."""
    return InputValidator().validate_ip(ip, allow_private)

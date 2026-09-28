"""
CloudFail-Killer — Report Signing (ed25519)

Tamper-evident scan reports. A signed report proves to the client that the
file you delivered is byte-for-byte the file the scan produced — and that it
was produced by the holder of the private key.

Requires the optional ``sign`` extra::

    pip install "cloudkill[sign]"

Usage (library)::

    from cloudkill.signing import ensure_keypair, sign_file, verify_file
    priv, pub = ensure_keypair()              # ~/.cloudkill/keys by default
    sig = sign_file("report.json")            # writes report.json.sig
    assert verify_file("report.json", sig, pub)

Usage (CLI)::

    cloudkill sign report.json
    cloudkill verify report.json --sig report.json.sig --pubkey ~/.cloudkill/keys/default.pub
"""

from __future__ import annotations

import base64
from pathlib import Path
import contextlib

from cloudkill.core.validator import safe_output_path

DEFAULT_KEY_DIR = Path.home() / ".cloudkill" / "keys"
DEFAULT_PRIVATE = DEFAULT_KEY_DIR / "default.key"
DEFAULT_PUBLIC = DEFAULT_KEY_DIR / "default.pub"

try:  # optional dependency — cloudkill[sign]
    from cryptography.exceptions import InvalidSignature  # noqa: F401
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )

    _CRYPTO_OK = True
except ImportError:  # pragma: no cover - environment dependent
    _CRYPTO_OK = False


class SigningError(RuntimeError):
    """Raised when signing/verification cannot proceed."""


def _require_crypto() -> None:
    if not _CRYPTO_OK:
        raise SigningError(
            'cryptography is not installed — report signing requires the '
            "'sign' extra:  pip install \"cloudkill[sign]\""
        )


def ensure_keypair(
    private_path: Path | str | None = None,
    public_path: Path | str | None = None,
) -> tuple[Path, Path]:
    """
    Load the ed25519 keypair, generating it on first use.

    Keys are stored as base64 raw seeds (32 bytes) — simple to back up.

    Returns:
        (private_key_path, public_key_path)
    """
    _require_crypto()
    priv = Path(private_path) if private_path else DEFAULT_PRIVATE
    pub = Path(public_path) if public_path else DEFAULT_PUBLIC
    priv.parent.mkdir(parents=True, exist_ok=True)

    if priv.exists():
        return priv, pub

    key = Ed25519PrivateKey.generate()
    priv.write_bytes(base64.b64encode(
        key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
    ))
    pub.write_bytes(base64.b64encode(
        key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    ))
    with contextlib.suppress(OSError):
        priv.chmod(0o600)
    return priv, pub


def load_private(private_path: Path | str | None = None):
    _require_crypto()
    priv, _ = ensure_keypair(private_path)
    return Ed25519PrivateKey.from_private_bytes(base64.b64decode(priv.read_bytes().strip()))


def sign_file(
    path: Path | str,
    private_path: Path | str | None = None,
) -> Path:
    """
    Sign ``path`` with the ed25519 private key and write ``path + ".sig"``.

    The signature covers the exact file bytes — any later edit (even one
    byte) invalidates it.
    """
    _require_crypto()
    key = load_private(private_path)
    target = safe_output_path(Path(path))
    sig_path = target.with_name(target.name + ".sig")
    sig_path.write_bytes(b"ed25519:" + base64.b64encode(key.sign(target.read_bytes())))
    return sig_path


def verify_file(path: Path | str, signature: Path | str, public_path: Path | str) -> bool:
    """
    Verify ``path`` against ``signature`` using the public key.

    Returns True only when the file is byte-for-byte identical to what was
    signed. Any mismatch returns False.
    """
    _require_crypto()
    try:
        target = Path(path)
        sig_raw = Path(signature).read_bytes()
        if sig_raw.startswith(b"ed25519:"):
            sig_raw = base64.b64decode(sig_raw[len(b"ed25519:"):])
        pub_raw = base64.b64decode(Path(public_path).read_bytes().strip())
        Ed25519PublicKey.from_public_bytes(pub_raw).verify(sig_raw, target.read_bytes())
        return True
    except Exception:
        # Missing files, malformed signature, wrong key, tampered bytes —
        # verification simply fails. It never raises.
        return False

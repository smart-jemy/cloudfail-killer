"""Tests for cloudkill.signing — ed25519 report signing."""

from __future__ import annotations

import pytest

from cloudkill.signing import (
    DEFAULT_PRIVATE,
    DEFAULT_PUBLIC,
    SigningError,
    ensure_keypair,
    sign_file,
    verify_file,
)

crypto = pytest.importorskip("cryptography", reason="sign extra not installed")


@pytest.fixture()
def keys(tmp_path):
    return ensure_keypair(tmp_path / "test.key", tmp_path / "test.pub")


@pytest.fixture()
def signed_report(tmp_path, keys):
    report = tmp_path / "report.json"
    report.write_text('{"scan": "authentic"}')
    # sign with the SAME keypair the fixture verifies against
    sig = sign_file(report, tmp_path / "test.key")
    return report, sig


class TestSigningRoundtrip:
    def test_sign_creates_signature_file(self, signed_report):
        report, sig = signed_report
        assert sig.exists()
        assert sig.read_bytes().startswith(b"ed25519:")

    def test_verify_authentic_report(self, signed_report, tmp_path):
        report, sig = signed_report
        assert verify_file(report, sig, tmp_path / "test.pub") is True

    def test_tampered_report_fails(self, signed_report, tmp_path):
        report, sig = signed_report
        report.write_text('{"scan": "tampered by attacker"}')
        assert verify_file(report, sig, tmp_path / "test.pub") is False

    def test_trailing_newline_breaks_signature(self, signed_report, tmp_path):
        report, sig = signed_report
        report.write_bytes(report.read_bytes() + b"\n")
        assert verify_file(report, sig, tmp_path / "test.pub") is False

    def test_wrong_public_key_fails(self, signed_report, tmp_path):
        report, sig = signed_report
        _, other_pub = ensure_keypair(tmp_path / "other.key", tmp_path / "other.pub")
        assert verify_file(report, sig, other_pub) is False


class TestKeypairManagement:
    def test_keypair_generated_once_and_reused(self, tmp_path):
        priv1, pub1 = ensure_keypair(tmp_path / "k.key", tmp_path / "k.pub")
        priv2, pub2 = ensure_keypair(tmp_path / "k.key", tmp_path / "k.pub")
        assert priv1 == priv2 and pub1 == pub2
        assert priv1.read_bytes() == priv2.read_bytes()

    def test_private_key_permissions_restricted(self, tmp_path):
        priv, _ = ensure_keypair(tmp_path / "k.key", tmp_path / "k.pub")
        import os
        assert os.stat(priv).st_mode & 0o077 == 0


class TestGracefulErrors:
    def test_missing_sig_file_returns_false(self, tmp_path, keys):
        report = tmp_path / "r.json"
        report.write_text("{}")
        assert verify_file(report, tmp_path / "nope.sig", tmp_path / "k.pub") is False

    def test_module_usable_without_crypto_flag(self):
        """The module imports fine even without cryptography — errors only
        when signing is actually attempted."""
        from cloudkill import signing
        assert isinstance(signing._CRYPTO_OK, bool)

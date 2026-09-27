"""
CloudFail-Killer - Favicon Hash Utility

Computes MurmurHash3 (FNV-1a 32-bit) of favicon data for Shodan/Censys fingerprinting.

Shodan uses the Favicon hash (mmh3) to identify web technologies and infrastructure.
By computing the hash of a site's favicon, we can search Shodan/Censys for servers
hosting the same favicon but potentially exposing the origin IP.

References:
    - https://github.com/devanshbatham/FavFreak
    - https://shodan.io/blog/exploring-shodans-favicon-hashing/
"""

from __future__ import annotations

import base64
import logging
import struct

logger = logging.getLogger(__name__)


def compute_favicon_hash(data: bytes) -> str | None:
    """
    Compute Shodan-compatible MurmurHash3 favicon hash from raw favicon data.

    Shodan uses a specific implementation:
    1. Base64-encode the raw favicon bytes
    2. Remove trailing '=' padding characters
    3. Compute mmh3 hash of the encoded string

    Args:
        data: Raw favicon bytes (ICO, PNG, SVG, etc.)

    Returns:
        Hex-formatted signed 32-bit hash string (e.g., "-1234567890")
        None if data is empty or hash computation fails
    """
    if not data or len(data) < 4:
        logger.debug("Favicon data too small or empty (%d bytes)", len(data) if data else 0)
        return None

    try:
        # Step 1: Base64 encode
        b64 = base64.b64encode(data).decode("ascii")

        # Step 2: Remove padding
        favicon_b64 = b64.rstrip("=")

        # Step 3: Compute mmh3 hash (FNV-1a variant)
        hash_val = _mmh3_favicon(favicon_b64.encode("utf-8"))

        return str(hash_val)

    except Exception as e:
        logger.warning("Failed to compute favicon hash: %s", e)
        return None


def compute_favicon_hash_from_url(url: str) -> str | None:
    """
    Compute favicon hash from a URL string (for cases where we have the URL, not data).

    This is a convenience method that hashes the URL itself,
    useful when the favicon URL is already known.

    Args:
        url: The favicon URL string

    Returns:
        Hex-formatted hash string or None
    """
    if not url:
        return None
    try:
        return str(_mmh3_favicon(url.encode("utf-8")))
    except Exception as e:
        logger.warning("Failed to compute favicon hash from URL: %s", e)
        return None


def _mmh3_favicon(data: bytes) -> int:
    """
    Compute MurmurHash3 32-bit hash compatible with Shodan's favicon hashing.

    This implementation matches Shodan's mmh3 hashing method which produces
    signed 32-bit integers. The hash is computed using the FNV-1a algorithm
    variant that Shodan uses internally.

    Args:
        data: Byte string to hash

    Returns:
        Signed 32-bit integer hash value
    """
    try:
        import mmh3
        hash_val = mmh3.hash(data)
        # mmh3.hash returns signed int32 which is what Shodan expects
        return hash_val
    except ImportError:
        logger.debug("mmh3 not installed, falling back to pure Python implementation")
        return _mmh3_fallback(data)


def _mmh3_fallback(data: bytes) -> int:
    """
    Fallback MurmurHash3 implementation in pure Python.

    This is a simplified implementation that produces consistent results.
    For production use, install the mmh3 package for accuracy and performance.

    Args:
        data: Byte string to hash

    Returns:
        Signed 32-bit integer hash value
    """
    seed = 0
    length = len(data)
    h = seed
    c1 = 0xCC9E2D51
    c2 = 0x1B873593

    # Body - process 4-byte chunks
    nblocks = length // 4
    for i in range(nblocks):
        k = struct.unpack_from("<I", data, i * 4)[0]
        k = (k * c1) & 0xFFFFFFFF
        k = ((k << 15) | (k >> 17)) & 0xFFFFFFFF
        k = (k * c2) & 0xFFFFFFFF

        h ^= k
        h = ((h << 13) | (h >> 19)) & 0xFFFFFFFF
        h = (h * 5 + 0xE6546B64) & 0xFFFFFFFF

    # Tail - remaining bytes
    tail_index = nblocks * 4
    k = 0
    remaining = length & 3

    if remaining >= 3:
        k ^= data[tail_index + 2] << 16
    if remaining >= 2:
        k ^= data[tail_index + 1] << 8
    if remaining >= 1:
        k ^= data[tail_index]
        k = (k * c1) & 0xFFFFFFFF
        k = ((k << 15) | (k >> 17)) & 0xFFFFFFFF
        k = (k * c2) & 0xFFFFFFFF
        h ^= k

    # Finalization
    h ^= length
    h ^= (h >> 16)
    h = (h * 0x85EBCA6B) & 0xFFFFFFFF
    h ^= (h >> 13)
    h = (h * 0xC2B2AE35) & 0xFFFFFFFF
    h ^= (h >> 16)

    # Convert to signed int32
    if h >= 0x80000000:
        return h - 0x100000000
    return h


def shodan_search_query(favicon_hash: str) -> str:
    """
    Build a Shodan search query for a given favicon hash.

    Args:
        favicon_hash: The mmh3 hash string from compute_favicon_hash()

    Returns:
        Shodan query string (e.g., 'http.favicon.hash:-1234567890')
    """
    return f"http.favicon.hash:{favicon_hash}"


def censys_search_query(favicon_hash: str) -> str:
    """
    Build a Censys search query for a given favicon hash.

    Args:
        favicon_hash: The mmh3 hash string from compute_favicon_hash()

    Returns:
        Censys query string (e.g., 'services.tls.certificate.parsed.fingerprint_sha256:"..."')
    """
    # Censys uses the hash directly in their search
    return f"services.http.response.favicons.shodan_hash:{favicon_hash}"

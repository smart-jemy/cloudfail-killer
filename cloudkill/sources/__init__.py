"""
CloudFail-Killer - Data Source Plugins

All available data source plugins for origin IP discovery.
Each source collects potential origin IPs from a different data source.

Sources are organized by priority:
    - CRITICAL: Favicon Hash (Shodan/Censys)
    - HIGH: AlienVault OTX, Wayback CDX, SPF/DKIM, crt.sh
    - MEDIUM: AnubisDB, URLScan.io, GitHub Dorking, RapidDNS, SubdomainCenter
    - LOW: HackerTarget (50/day), DNSDumpster (scraping), WhoisXML (500 once)
    - REFERENCE: ACME Check (informational only)

Usage:
    from cloudkill.sources import get_all_sources, get_enabled_sources

    sources = get_all_sources(engine=engine)
    # or
    sources = get_enabled_sources(config=config, engine=engine)
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from cloudkill.sources.base import BaseSource

if TYPE_CHECKING:
    from cloudkill.config import Config
    from cloudkill.core.engine import AsyncEngine

logger = logging.getLogger(__name__)

# Source registry: maps source name to its class
_SOURCE_REGISTRY: dict[str, type[BaseSource]] = {}


def _register_source(cls: type[BaseSource]) -> type[BaseSource]:
    """Decorator to register a source plugin."""
    _SOURCE_REGISTRY[cls.name] = cls
    return cls


# Import and register all source plugins
def _import_sources() -> None:
    """Lazily import and register all source plugins."""
    if _SOURCE_REGISTRY:
        return

    try:
        from cloudkill.sources.crtsh import CRTShSource
        _register_source(CRTShSource)
    except ImportError as e:
        logger.debug("Failed to import CRTShSource: %s", e)

    try:
        from cloudkill.sources.certspotter import CertSpotterSource
        _register_source(CertSpotterSource)
    except ImportError as e:
        logger.debug("Failed to import CertSpotterSource: %s", e)

    try:
        from cloudkill.sources.anubisdb import AnubisDBSource
        _register_source(AnubisDBSource)
    except ImportError as e:
        logger.debug("Failed to import AnubisDBSource: %s", e)

    try:
        from cloudkill.sources.otx import OTXSource
        _register_source(OTXSource)
    except ImportError as e:
        logger.debug("Failed to import OTXSource: %s", e)

    try:
        from cloudkill.sources.wayback import WaybackSource
        _register_source(WaybackSource)
    except ImportError as e:
        logger.debug("Failed to import WaybackSource: %s", e)

    try:
        from cloudkill.sources.urlscan import URLScanSource
        _register_source(URLScanSource)
    except ImportError as e:
        logger.debug("Failed to import URLScanSource: %s", e)

    try:
        from cloudkill.sources.hackertarget import HackerTargetSource
        _register_source(HackerTargetSource)
    except ImportError as e:
        logger.debug("Failed to import HackerTargetSource: %s", e)

    try:
        from cloudkill.sources.dnsdumpster import DNSDumpsterSource
        _register_source(DNSDumpsterSource)
    except ImportError as e:
        logger.debug("Failed to import DNSDumpsterSource: %s", e)

    try:
        from cloudkill.sources.whoisxml import WhoisXMLSource
        _register_source(WhoisXMLSource)
    except ImportError as e:
        logger.debug("Failed to import WhoisXMLSource: %s", e)

    try:
        from cloudkill.sources.github_dork import GitHubDorkSource
        _register_source(GitHubDorkSource)
    except ImportError as e:
        logger.debug("Failed to import GitHubDorkSource: %s", e)

    try:
        from cloudkill.sources.favicon_hash import FaviconHashSource
        _register_source(FaviconHashSource)
    except ImportError as e:
        logger.debug("Failed to import FaviconHashSource: %s", e)

    try:
        from cloudkill.sources.spf_dkim import SPFDKIMSource
        _register_source(SPFDKIMSource)
    except ImportError as e:
        logger.debug("Failed to import SPFDKIMSource: %s", e)

    try:
        from cloudkill.sources.acme_check import ACMECheckSource
        _register_source(ACMECheckSource)
    except ImportError as e:
        logger.debug("Failed to import ACMECheckSource: %s", e)

    try:
        from cloudkill.sources.rapiddns import RapidDNSSource
        _register_source(RapidDNSSource)
    except ImportError as e:
        logger.debug("Failed to import RapidDNSSource: %s", e)

    try:
        from cloudkill.sources.subdomain_center import SubdomainCenterSource
        _register_source(SubdomainCenterSource)
    except ImportError as e:
        logger.debug("Failed to import SubdomainCenterSource: %s", e)

    # External sources via entry points (community plugins — see
    # cloudkill/sources/loader.py for the three-step publishing guide)
    try:
        from cloudkill.sources.loader import load_plugin_sources
        for name, cls in load_plugin_sources().items():
            if name not in _SOURCE_REGISTRY:
                _register_source(cls)
    except Exception as e:
        logger.debug("Plugin source discovery failed: %s", e)


def get_all_sources(
    engine: AsyncEngine | None = None,
    ipv6_preference: bool = False,
    dns_servers: list[str] | None = None,
) -> list[BaseSource]:
    """
    Get all registered source plugins.

    Args:
        engine: AsyncEngine instance for HTTP requests
        ipv6_preference: Whether to prefer IPv6 resolution
    dns_servers: Optional custom DNS servers for resolution

    Returns:
        List of all available source instances
    """
    _import_sources()

    sources: list[BaseSource] = []
    for source_class in _SOURCE_REGISTRY.values():
        try:
            source = source_class(
                engine=engine,
                ipv6_preference=ipv6_preference,
                dns_servers=dns_servers,
            )
            sources.append(source)
        except Exception as e:
            logger.warning("Failed to instantiate source %s: %s", source_class.name, e)

    return sources


def get_enabled_sources(
    config: Config,
    engine: AsyncEngine | None = None,
) -> list[BaseSource]:
    """
    Get only enabled and configured source plugins.

    Respects:
    - default_enabled flag on each source
    - is_configured() check (API keys)
    - Per-source config from config.sources_config

    Args:
        config: Application configuration
        engine: AsyncEngine instance

    Returns:
        List of enabled and configured source instances
    """
    all_sources = get_all_sources(
        engine=engine,
        ipv6_preference=config.ipv6_preference,
        dns_servers=config.dns_servers,
    )

    enabled: list[BaseSource] = []
    for source in all_sources:
        # Check if source is enabled by default
        if not source.default_enabled:
            logger.debug("Source %s not enabled by default", source.name)
            continue

        # Check per-source config override
        source_config = config.sources_config.get(source.name)
        if source_config and not source_config.enabled:
            logger.debug("Source %s disabled in config", source.name)
            continue

        # Check if source has required configuration
        if not source.is_configured():
            logger.debug("Source %s not configured (missing API key?)", source.name)
            continue

        enabled.append(source)

    return enabled


def get_source_info() -> list[dict[str, str]]:
    """
    Get information about all registered sources.

    Returns:
        List of dicts with source metadata
    """
    _import_sources()

    info: list[dict[str, str]] = []
    for cls in _SOURCE_REGISTRY.values():
        info.append({
            "name": cls.name,
            "description": cls.description,
            "requires_api_key": str(cls.requires_api_key),
            "supports_ipv6": str(cls.supports_ipv6),
            "default_enabled": str(cls.default_enabled),
        })
    return info

"""
CloudFail-Killer Configuration Management
Supports multiple profiles and environment variable overrides.
"""

from __future__ import annotations

from enum import Enum
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class ScanProfile(str, Enum):
    """Predefined scan profiles for different use cases."""
    RESEARCHER = "researcher"
    PENTESTER = "pentester"
    BUGBOUNTY = "bugbounty"
    ENTERPRISE = "enterprise"
    AUTOMATION = "automation"


class StealthMode(str, Enum):
    """Stealth/anti-detection modes."""
    NORMAL = "normal"
    STEALTH = "stealth"
    AGGRESSIVE = "aggressive"


class OutputFormat(str, Enum):
    """Supported output formats."""
    JSON = "json"
    CSV = "csv"
    TXT = "txt"
    MARKDOWN = "md"
    PDF = "pdf"
    NUCLEI = "nuclei"


class SourceConfig(BaseSettings):
    """Configuration for individual data sources."""
    enabled: bool = True
    timeout: int = 30
    retries: int = 3
    rate_limit: float = 1.0  # requests per second
    api_key: str | None = None


class ScoringWeights(BaseSettings):
    """Confidence scoring weights per signal type."""
    non_cf_ip: int = 35
    ssl_match: int = 30
    historical: int = 20
    favicon_match: int = 15
    active_probe: int = 20
    js_recon: int = 25
    spf_dkim: int = 15
    asn_match: int = 15
    host_header: int = 10
    internetdb_match: int = 20


class ProxyConfig(BaseSettings):
    """Proxy configuration."""
    url: str | None = None
    username: str | None = None
    password: str | None = None


class WebhookConfig(BaseSettings):
    """Notification webhook configuration."""
    url: str | None = None
    slack_url: str | None = None
    discord_url: str | None = None


class Config(BaseSettings):
    """Main application configuration."""

    model_config = SettingsConfigDict(
        env_prefix="CLOUDKILL_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- Target ---
    domain: str | None = None

    # --- Network ---
    threads: int = Field(default=20, ge=1, le=200)
    timeout: int = Field(default=30, ge=5, le=120)
    proxy: str | None = None
    ipv6_preference: bool = False
    dns_servers: list[str] = Field(default_factory=list)

    # --- Scan Profile ---
    profile: ScanProfile = ScanProfile.RESEARCHER

    # --- Stealth ---
    stealth_mode: StealthMode = StealthMode.NORMAL
    random_delay_min: float = 0.5
    random_delay_max: float = 2.0

    # --- Active Scanning ---
    active: bool = False
    active_ports: list[int] = Field(default_factory=lambda: [80, 443, 8080, 8443])

    # --- Output ---
    output: str | None = None
    output_format: OutputFormat = OutputFormat.JSON
    verbose: bool = False
    quiet: bool = False

    # --- Caching ---
    cache_enabled: bool = True
    cache_dir: Path = Path.home() / ".cache" / "cloudkill"

    # --- Sources ---
    sources_config: dict[str, SourceConfig] = Field(default_factory=dict)

    # --- Scoring ---
    scoring_weights: ScoringWeights = Field(default_factory=ScoringWeights)

    # --- Notifications ---
    webhook: WebhookConfig = Field(default_factory=WebhookConfig)

    # --- Confidence Threshold ---
    min_confidence: int = Field(default=0, ge=0, le=100)

    # --- Enrichment toggles ---
    internetdb_enabled: bool = True

    # --- Batch ---
    domains_file: str | None = None

    @classmethod
    def from_profile(cls, profile: str | ScanProfile, **overrides: Any) -> Config:
        """Create config from a named profile with optional overrides."""
        if isinstance(profile, str):
            profile = ScanProfile(profile)

        # Load profile-specific weights
        profiles_dir = Path(__file__).parent / "profiles" / "profiles.yaml"
        weights = ScoringWeights()

        if profiles_dir.exists():
            all_profiles = yaml.safe_load(profiles_dir.read_text(encoding="utf-8"))
            profile_weights = all_profiles.get(profile.value, {})
            weights = ScoringWeights(**profile_weights)

        config = cls(profile=profile, scoring_weights=weights, **overrides)
        return config

    @property
    def effective_threads(self) -> int:
        """Adjust threads based on stealth mode."""
        if self.stealth_mode == StealthMode.STEALTH:
            return max(5, self.threads // 3)
        elif self.stealth_mode == StealthMode.AGGRESSIVE:
            return self.threads
        return self.threads

    @property
    def all_output_formats(self) -> list[OutputFormat]:
        """Get all requested output formats."""
        formats = [self.output_format]
        # PDF is auto-added for enterprise profile
        if self.profile == ScanProfile.ENTERPRISE:
            formats.append(OutputFormat.PDF)
        return list(set(formats))


@lru_cache(maxsize=1)
def get_config() -> Config:
    """Get cached global config instance."""
    return Config()

"""
CloudFail-Killer - Confidence Scoring Engine

Calculates final confidence scores (0-100) for discovered IPs based on
multiple signals and profile-specific weights.

The scoring engine combines signals from:
    - Non-Cloudflare IP (already filtered, gives base score)
    - SSL certificate match with target domain
    - Historical DNS data presence
    - ASN/hosting provider detection
    - Favicon hash match
    - JS Recon findings
    - SPF/DKIM origin correlation
    - Active probe success
    - Host header response

Each profile (researcher, pentester, bugbounty, enterprise, automation) has
different weight configurations defined in profiles.yaml.

Scoring algorithm:
    1. Start with non-CF IP base score
    2. Add weighted scores for each detected signal
    3. Cap at 100, clamp at 0
    4. Determine status: potential (30-69), confirmed (70+), false_positive (<30)
"""

from __future__ import annotations

import logging

from cloudkill.config import Config
from cloudkill.core.models import EnrichedResult, ResultStatus

logger = logging.getLogger(__name__)

# Minimum confidence thresholds for status classification
STATUS_CONFIRMED_THRESHOLD = 70
STATUS_POTENTIAL_THRESHOLD = 30


class ScoringEngine:
    """
    Confidence scoring engine that evaluates discovered IPs.

    Each IP gets a confidence score from 0-100 based on multiple
    signals, weighted according to the active scan profile.

    Usage:
        engine = ScoringEngine(config)
        engine.score(result)
        engine.score_batch(results)
        engine.determine_status(result)
    """

    def __init__(self, config: Config) -> None:
        self.config = config
        self.weights = config.scoring_weights
        self._target_domain = ""

    def set_target_domain(self, domain: str) -> None:
        """Set the target domain for SSL matching."""
        self._target_domain = domain.lower()

    def score(self, result: EnrichedResult) -> int:
        """
        Calculate the final confidence score for an enriched result.

        Applies profile-specific weights to all detected signals
        and returns a score from 0 to 100.

        Args:
            result: EnrichedResult with all enrichment data populated

        Returns:
            Final confidence score (0-100)
        """
        score = result.confidence  # Start with accumulated score
        domain = self._target_domain

        if not domain:
            domain = ".".join(result.subdomain.split(".")[-2:]) if "." in result.subdomain else result.subdomain

        # --- Signal: Non-Cloudflare IP (already in score from runner) ---
        # Base non-CF score is already added by runner (+40)
        # We now add weighted bonuses for each signal

        # --- Signal: SSL Certificate Match ---
        # Check SSL even if ssl_matches not yet set (enricher may have set CN/SAN but not flag)
        if result.ssl_matches or result.ssl_cn or result.ssl_san:
            ssl_score = self._calculate_ssl_score(result, domain)
            score += ssl_score

        # --- Signal: ASN / Hosting Provider ---
        if result.asn_org:
            asn_score = self._calculate_asn_score(result)
            score += asn_score

        # --- Signal: Historical Data ---
        if result.is_historical:
            hist_score = self.weights.historical
            score += hist_score
            result.confidence_reasons.append(
                f"Historical DNS data found (+{hist_score})"
            )

        # --- Signal: Favicon Hash Match ---
        if result.favicon_match:
            score += self.weights.favicon_match
            result.confidence_reasons.append(
                f"Favicon hash match (+{self.weights.favicon_match})"
            )

        # --- Signal: JS Recon ---
        if result.js_extracted:
            score += self.weights.js_recon
            result.confidence_reasons.append(
                f"JS endpoint extraction (+{self.weights.js_recon})"
            )

        # --- Signal: SPF/DKIM Origin ---
        if result.spf_dkim_origin:
            score += self.weights.spf_dkim
            result.confidence_reasons.append(
                f"SPF/DKIM origin correlation (+{self.weights.spf_dkim})"
            )

        # --- Signal: ACME Misconfiguration ---
        if result.acme_configured:
            score += 8  # Fixed bonus for ACME misconfig
            result.confidence_reasons.append("ACME misconfiguration detected (+8)")

        # --- Signal: Shodan InternetDB hostname match ---
        if result.internetdb_match:
            score += self.weights.internetdb_match
            result.confidence_reasons.append(
                f"InternetDB hostname match (+{self.weights.internetdb_match})"
            )

        # --- Signal: Host Header Match ---
        if result.host_header_match:
            score += self.weights.host_header
            result.confidence_reasons.append(
                f"Host header probe matched (+{self.weights.host_header})"
            )

        # --- Penalty: Self-signed certificate ---
        # Slightly reduce confidence for self-signed certs
        ssl_meta = result.raw_source_result.metadata if result.raw_source_result else {}
        if ssl_meta.get("self_signed"):
            score -= 10
            result.confidence_reasons.append("Self-signed certificate (-10)")

        # --- Clamp to valid range ---
        score = max(0, min(100, score))

        result.confidence = score
        return score

    def score_batch(self, results: list[EnrichedResult]) -> None:
        """Score all results in a batch."""
        for result in results:
            self.score(result)

    def determine_status(self, result: EnrichedResult) -> None:
        """
        Determine the status of an enriched result based on its score.

        - confirmed: confidence >= 70
        - potential: confidence >= 30
        - false_positive: confidence < 30

        Args:
            result: EnrichedResult to classify
        """
        if result.confidence >= STATUS_CONFIRMED_THRESHOLD:
            result.status = ResultStatus.CONFIRMED
        elif result.confidence >= STATUS_POTENTIAL_THRESHOLD:
            result.status = ResultStatus.POTENTIAL
        else:
            result.status = ResultStatus.FALSE_POSITIVE

    def determine_status_batch(self, results: list[EnrichedResult]) -> None:
        """Determine status for all results."""
        for result in results:
            self.determine_status(result)

    def _calculate_ssl_score(self, result: EnrichedResult, domain: str) -> int:
        """
        Calculate SSL-based confidence score.

        Full CN match: full weight
        Partial/SAN match: half weight
        Same issuer as Cloudfront (not CF itself): bonus
        """
        weight = self.weights.ssl_match
        score = 0

        # Full CN match
        cn = result.ssl_cn or ""
        if cn.lower() == domain or cn.lower().endswith(f".{domain}"):
            score = weight
            result.confidence_reasons.append(
                f"SSL CN exact match: {cn} (+{weight})"
            )
        elif cn:
            # Partial match (subdomain matches)
            if domain in cn.lower():
                score = weight // 2
                result.confidence_reasons.append(
                    f"SSL CN partial match: {cn} (+{weight // 2})"
                )

        # SAN match (additional signal)
        if result.ssl_san and not score:
            for san in result.ssl_san[:5]:
                san_lower = san.lower()
                if san_lower == domain or san_lower.endswith(f".{domain}"):
                    score = weight // 2
                    result.confidence_reasons.append(
                        f"SSL SAN match: {san} (+{weight // 2})"
                    )
                    break

        return score

    def _calculate_asn_score(self, result: EnrichedResult) -> int:
        """
        Calculate ASN/hosting-based confidence score.

        - Known hosting provider: full weight
        - Non-Cloudflare ASN: partial weight
        - Same ASN as other results: correlation bonus
        """
        weight = self.weights.asn_match
        score = 0

        if result.hosting_provider:
            # Known hosting providers are more likely origin servers
            score = weight
            result.confidence_reasons.append(
                f"Hosting provider: {result.hosting_provider} (+{weight})"
            )
        elif result.asn_org and "cloudflare" not in result.asn_org.lower():
            # Any identifiable non-CF ASN is a signal
            score = weight // 2
            result.confidence_reasons.append(
                f"Non-CF ASN: {result.asn_org[:40]} (+{weight // 2})"
            )

        return score


class ResultDeduplicator:
    """
    Deduplicate results based on IP address and subdomain.

    Ensures each unique IP appears only once, keeping the result
    with the highest confidence score.
    """

    @staticmethod
    def deduplicate(results: list[EnrichedResult]) -> list[EnrichedResult]:
        """
        Deduplicate results, keeping the highest confidence per IP.

        For each unique IP, the result with:
        1. Highest confidence score
        2. Most recent discovery time
        3. Earliest source alphabetically

        Args:
            results: List of enriched results

        Returns:
            Deduplicated list sorted by confidence
        """
        best: dict[str, EnrichedResult] = {}

        for result in results:
            ip = result.ip
            existing = best.get(ip)

            if existing is None or result.confidence > existing.confidence:
                best[ip] = result
            elif result.confidence == existing.confidence:
                # Tie-break: prefer more enriched data
                new_signals = sum([
                    bool(result.ssl_matches),
                    bool(result.hosting_provider),
                    bool(result.favicon_match),
                    bool(result.js_extracted),
                    bool(result.spf_dkim_origin),
                    bool(result.internetdb_match),
                ])
                old_signals = sum([
                    bool(existing.ssl_matches),
                    bool(existing.hosting_provider),
                    bool(existing.favicon_match),
                    bool(existing.js_extracted),
                    bool(existing.spf_dkim_origin),
                    bool(existing.internetdb_match),
                ])
                if new_signals > old_signals:
                    best[ip] = result

        # Sort by confidence descending
        return sorted(best.values(), key=lambda r: -r.confidence)

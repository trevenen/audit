"""
Hybrid Risk Scoring for Cloud Audit Findings
============================================
Combines detection severity + asset context + third-party threat intelligence
into a unified 0-100 risk score for prioritization.
"""

from dataclasses import dataclass
from typing import Optional, Dict, Any
from enum import Enum


class Severity(Enum):
    CRITICAL = 0
    HIGH = 1
    MEDIUM = 2
    LOW = 3
    INFO = 4


class AssetCriticality(Enum):
    CRITICAL = 4.0  # Production DB, payment processing, auth system
    HIGH = 3.0      # Production app, customer data, internal tools
    MEDIUM = 2.0    # Dev/staging, non-sensitive workloads
    LOW = 1.0       # Sandbox, test accounts, non-critical


class DataSensitivity(Enum):
    PII = 3.0        # Personally identifiable information
    FINANCIAL = 3.0  # Payment data, billing
    PROPRIETARY = 2.0  # Internal business logic, configs
    PUBLIC = 1.0     # Public-facing, non-sensitive


@dataclass
class AssetContext:
    """Context about a resource to determine criticality."""
    is_production: bool = False
    data_sensitivity: DataSensitivity = DataSensitivity.PUBLIC
    has_public_ip: bool = False
    instance_count: int = 1  # How many instances would be affected
    recovery_time_sla: Optional[int] = None  # SLA in minutes; lower = more critical

    @property
    def criticality(self) -> AssetCriticality:
        """Derive criticality from attributes."""
        if self.is_production and self.data_sensitivity in (DataSensitivity.PII, DataSensitivity.FINANCIAL):
            return AssetCriticality.CRITICAL
        if self.is_production:
            return AssetCriticality.HIGH
        if self.data_sensitivity in (DataSensitivity.PII, DataSensitivity.FINANCIAL):
            return AssetCriticality.HIGH
        if self.has_public_ip:
            return AssetCriticality.MEDIUM
        return AssetCriticality.LOW


@dataclass
class ThreatContext:
    """Third-party threat intelligence signals."""
    cvss_score: Optional[float] = None  # 0-10; if available for this finding type
    exploit_available: bool = False  # Is there a public exploit?
    active_exploitation: bool = False  # Is this being exploited in the wild?
    affected_instances: int = 1  # How many resources have this issue?

    @property
    def exploitability_multiplier(self) -> float:
        """Derive exploitability from threat signals."""
        base = 1.0
        if self.cvss_score:
            base = max(base, self.cvss_score / 10.0)  # Normalize CVSS to 0-1
        if self.exploit_available:
            base *= 1.5
        if self.active_exploitation:
            base *= 2.0
        return min(base, 3.0)  # Cap at 3x


class RiskScorer:
    """Calculates hybrid risk scores for cloud audit findings."""

    # Severity weights (higher = more impactful)
    SEVERITY_WEIGHTS = {
        Severity.CRITICAL: 10,
        Severity.HIGH: 7,
        Severity.MEDIUM: 4,
        Severity.LOW: 2,
        Severity.INFO: 1,
    }

    # Scale factors
    CRITICALITY_SCALE = 25  # Max contribution from asset criticality
    EXPLOITABILITY_SCALE = 25  # Max contribution from threat intelligence
    SCALE_SCALE = 15  # Max contribution from instance count / blast radius

    def score(
        self,
        severity: str,
        asset_context: Optional[AssetContext] = None,
        threat_context: Optional[ThreatContext] = None,
    ) -> int:
        """
        Calculate risk score (0-100) for a finding.

        Args:
            severity: One of CRITICAL, HIGH, MEDIUM, LOW, INFO
            asset_context: Optional context about the affected resource
            threat_context: Optional third-party threat intelligence

        Returns:
            Risk score 0-100, where 100 is maximum risk.
        """
        try:
            sev = Severity[severity]
        except KeyError:
            sev = Severity.INFO

        asset_context = asset_context or AssetContext()
        threat_context = threat_context or ThreatContext()

        # Pillar 1: Detection severity (40 points max)
        severity_score = self.SEVERITY_WEIGHTS.get(sev, 1) * 4

        # Pillar 2: Asset criticality (25 points max)
        criticality_score = (
            asset_context.criticality.value / AssetCriticality.CRITICAL.value
        ) * self.CRITICALITY_SCALE

        # Pillar 3: Threat intelligence / exploitability (25 points max)
        exploitability_score = (
            threat_context.exploitability_multiplier / 3.0
        ) * self.EXPLOITABILITY_SCALE

        # Pillar 4: Blast radius / scale (10 points max)
        scale_factor = min(threat_context.affected_instances, 10) / 10.0
        scale_score = scale_factor * self.SCALE_SCALE

        total = severity_score + criticality_score + exploitability_score + scale_score
        return min(int(total), 100)

    def score_with_defaults(
        self,
        severity: str,
        is_production: bool = False,
        has_public_ip: bool = False,
        data_sensitive: bool = False,
    ) -> int:
        """Simplified scoring when you don't have full context."""
        asset = AssetContext(
            is_production=is_production,
            has_public_ip=has_public_ip,
            data_sensitivity=DataSensitivity.PII if data_sensitive else DataSensitivity.PUBLIC,
        )
        return self.score(severity, asset_context=asset)


# Example integrations (stubs for external risk APIs)
class ThreatIntelligence:
    """Placeholder for third-party threat intel lookups."""

    @staticmethod
    def lookup_cvss(cve_id: str) -> Optional[float]:
        """Fetch CVSS score from NVD or similar."""
        # Example: requests.get(f"https://services.nvd.nist.gov/rest/json/cves/1.0/{cve_id}")
        return None

    @staticmethod
    def lookup_exploit_availability(cve_id: str) -> bool:
        """Check if exploit is known (e.g., Shodan, PoC databases)."""
        # Example: requests.get(f"https://exploit-db.com/search?cve={cve_id}")
        return False

    @staticmethod
    def lookup_active_exploitation(ioc: str) -> bool:
        """Check threat feeds for active exploitation."""
        # Example: query Shodan, Censys, AlienVault OTX
        return False

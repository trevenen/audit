#!/usr/bin/env python3
"""
Example: Using Hybrid Risk Scoring with Your Own Findings
==========================================================

This script demonstrates how to use the risk_scorer, asset_classifier,
and threat_intel modules to score custom findings.
"""

import json
from risk_scorer import RiskScorer, AssetContext, DataSensitivity, ThreatContext
from asset_classifier import AwsAssetClassifier
from threat_intel import ThreatIntel, NVDClient


def example_security_group_finding():
    """Score a security group finding with full context."""
    print("\n=== Example 1: Security Group Finding ===\n")

    # The finding
    sg_id = "sg-12345678"
    port = 22
    severity = "CRITICAL"

    # Asset context: this SG is used by production database servers
    asset = AssetContext(
        is_production=True,
        data_sensitivity=DataSensitivity.FINANCIAL,  # Stores payment data
        has_public_ip=True,
        instance_count=5,  # 5 instances use this SG
    )

    # Threat context: SSH is actively exploited
    threat = ThreatContext(
        cvss_score=9.8,  # SSH brute-force CVE
        exploit_available=True,
        active_exploitation=True,  # Always under attack
        affected_instances=5,
    )

    scorer = RiskScorer()
    risk_score = scorer.score(severity, asset, threat)

    print(f"Finding: Port {port} (SSH) open to 0.0.0.0/0 on {sg_id}")
    print(f"  Severity: {severity}")
    print(f"  Asset: Production + Financial Data, {asset.instance_count} instances")
    print(f"  Threat: CVSS 9.8, actively exploited")
    print(f"  → Risk Score: {risk_score}/100 ← URGENT!\n")

    return risk_score


def example_instance_metadata_finding():
    """Score an IMDSv2 finding with tag-based classification."""
    print("=== Example 2: Instance Metadata Finding (with Tag Classification) ===\n")

    # Simulate instance data with tags
    instance = {
        "InstanceId": "i-abcdef01234567890",
        "PublicIpAddress": "203.0.113.42",
        "Tags": [
            {"Key": "Name", "Value": "analytics-dev-01"},
            {"Key": "environment", "Value": "dev"},  # ← DEV tag
            {"Key": "data_classification", "Value": "internal"},
        ],
    }

    # Classify from tags
    is_prod, sensitivity = AwsAssetClassifier.classify_instance(instance)

    # The finding: IMDSv2 not enforced
    severity = "MEDIUM"
    asset = AssetContext(
        is_production=is_prod,  # False (dev tag)
        data_sensitivity=sensitivity,
        has_public_ip=True,
    )

    threat = ThreatContext(
        exploit_available=True,  # SSRF is a known attack
        active_exploitation=True,
    )

    scorer = RiskScorer()
    risk_score = scorer.score(severity, asset, threat)

    print(f"Finding: IMDSv2 not enforced on {instance['InstanceId']}")
    print(f"  Severity: {severity}")
    print(f"  Tags: {instance['Tags']}")
    print(f"  Classified as: {'Production' if is_prod else 'Development'}, {sensitivity.name} data")
    print(f"  → Risk Score: {risk_score}/100 ← Can wait\n")

    return risk_score


def example_with_nvd_lookup():
    """Score a finding using real NVD CVE data."""
    print("=== Example 3: Using Real CVSS from NVD ===\n")

    # Look up a real CVE
    cve_id = "CVE-2024-3156"  # Example, may not exist
    print(f"Looking up {cve_id} in NVD...")

    nvd = NVDClient()  # No API key = slower but works
    cvss = nvd.get_cvss_score(cve_id)

    if cvss:
        print(f"  CVSS Score: {cvss}")

        threat = ThreatContext(
            cvss_score=cvss,
            exploit_available=True,
            active_exploitation=nvd.is_exploited_in_wild(cve_id),
        )

        asset = AssetContext(
            is_production=True,
            data_sensitivity=DataSensitivity.PROPRIETARY,
        )

        scorer = RiskScorer()
        risk_score = scorer.score("HIGH", asset, threat)
        print(f"  → Risk Score: {risk_score}/100\n")
    else:
        print(f"  ⚠ {cve_id} not found (or NVD API unreachable)")
        print("  Try setting NVD_API_KEY env var for faster lookups.\n")


def example_batch_scoring():
    """Score multiple findings and sort by priority."""
    print("=== Example 4: Batch Scoring & Prioritization ===\n")

    findings = [
        {
            "name": "SSH open (prod)",
            "severity": "CRITICAL",
            "is_prod": True,
            "sensitive_data": True,
            "public_ip": True,
            "actively_exploited": True,
        },
        {
            "name": "CloudWatch disabled (dev)",
            "severity": "LOW",
            "is_prod": False,
            "sensitive_data": False,
            "public_ip": False,
            "actively_exploited": False,
        },
        {
            "name": "RDP open (prod non-sensitive)",
            "severity": "HIGH",
            "is_prod": True,
            "sensitive_data": False,
            "public_ip": True,
            "actively_exploited": True,
        },
        {
            "name": "IMDSv2 disabled (prod + PII)",
            "severity": "MEDIUM",
            "is_prod": True,
            "sensitive_data": True,
            "public_ip": True,
            "actively_exploited": True,
        },
    ]

    scored = []
    scorer = RiskScorer()

    for f in findings:
        asset = AssetContext(
            is_production=f["is_prod"],
            data_sensitivity=DataSensitivity.PII if f["sensitive_data"] else DataSensitivity.PUBLIC,
            has_public_ip=f["public_ip"],
        )
        threat = ThreatContext(
            active_exploitation=f["actively_exploited"],
            exploit_available=True if f["actively_exploited"] else False,
        )
        score = scorer.score(f["severity"], asset, threat)
        scored.append({**f, "risk_score": score})

    # Sort by score (highest first)
    scored.sort(key=lambda x: x["risk_score"], reverse=True)

    print("Findings sorted by Risk Score (highest priority first):\n")
    for i, f in enumerate(scored, 1):
        print(f"{i}. [{f['risk_score']:3d}/100] {f['name']:30s} ({f['severity']})")

    print("\nNotice: Even though 'CloudWatch disabled' is LOW severity,")
    print("'IMDSv2 disabled (prod+PII)' ranks higher due to asset context & threat signals.\n")


def main():
    print("\n" + "=" * 70)
    print("HYBRID RISK SCORING EXAMPLES")
    print("=" * 70)

    example_security_group_finding()
    example_instance_metadata_finding()
    example_with_nvd_lookup()
    example_batch_scoring()

    print("=" * 70)
    print("\nFor real audits, run:")
    print("  python3 aws-audit/audit_aws.py --all-regions")
    print("\nReports will be saved to: reports/{account-id}/audit_*.json")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    main()

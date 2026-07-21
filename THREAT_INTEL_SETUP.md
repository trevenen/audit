# Threat Intelligence & Asset Classification Setup

This guide explains how to enable third-party risk scoring, threat intelligence, and asset classification in the audit suite.

## Overview

The audit scripts now support **hybrid risk scoring** that combines:

1. **Detection Severity** — What we found (CRITICAL, HIGH, MEDIUM, LOW)
2. **Asset Context** — Is it production? Does it handle sensitive data?
3. **Threat Intelligence** — Is this actively exploited? What's the CVSS score?
4. **Blast Radius** — How many resources are affected?

All findings are scored **0–100**, with higher scores = higher priority.

## Asset Classification (Tag-based)

By default, the audit looks at AWS tags to classify resources:

### Production Tags

Resources are marked as **production** if they have:
- `environment=prod` or `environment=production`
- `env=prd`
- `workload=critical`
- `tier=live`

(Tags are case-insensitive.)

### Data Sensitivity Tags

Add these tags to mark sensitive data:

- `data_classification=PII` → Personally identifiable data
- `sensitivity=customer` → Customer data
- `pii=true` → PII handling
- `data_classification=financial` → Payment/billing data

### Example: Tag an EC2 Instance

```bash
aws ec2 create-tags --resources i-1234567890abcdef0 \
  --tags Key=environment,Value=production \
         Key=data_classification,Value=PII \
  --region us-east-1
```

An instance tagged with `environment=prod` + `data_classification=PII` will boost the risk score of any findings significantly.

## Threat Intelligence APIs

### 1. NIST NVD (Free, CVE/CVSS Data)

The script includes **free NVD lookups** for CVSS scores.

**Optional: Get a free API key for higher rate limits**

```bash
# Get your free API key from https://nvd.nist.gov/developers/request-an-api-key
export NVD_API_KEY="your-key-here"

# Run the audit with threat intel enabled
python3 aws-audit/audit_aws.py --all-regions
```

Without an API key: ~5 requests/second (usually sufficient).
With an API key: 50 requests/second.

### 2. Shodan (Optional, Requires API Key)

Shodan helps detect actively scanned ports. Get an API key at https://account.shodan.io/ (free tier available).

```bash
export SHODAN_API_KEY="your-key-here"
python3 aws-audit/audit_aws.py --all-regions
```

The script uses Shodan to check if ports (22, 3306, 5432, 8006, etc.) are actively scanned in the wild.

### 3. AlienVault OTX (Optional, Threat Feeds)

Free threat intelligence for IP/domain reputation. Get an API key at https://otx.alienvault.com/.

```bash
export OTX_API_KEY="your-key-here"
```

## Example Risk Scores

Same finding, different contexts:

### Example 1: SSH open to internet (no context)
```
Finding: Port 22 open to 0.0.0.0/0
Severity: CRITICAL (10pts)
Asset Criticality: LOW (1.0 multiplier, non-prod)
Threat Intel: Active exploitation (2.0x multiplier)
Result: Risk Score = 72/100
```

### Example 2: SSH open to internet (production + PII)
```
Finding: Port 22 open to 0.0.0.0/0
Severity: CRITICAL (10pts)
Asset Criticality: CRITICAL (4.0 multiplier, prod + PII)
Threat Intel: Active exploitation (2.0x multiplier)
Result: Risk Score = 95/100  ← Priority this first!
```

### Example 3: IMDSv2 not enforced (dev instance)
```
Finding: IMDSv2 not enforced
Severity: MEDIUM (4pts)
Asset Criticality: LOW (1.0 multiplier, dev env)
Threat Intel: SSRF is exploited (1.5x multiplier)
Result: Risk Score = 32/100  ← Lower priority
```

## Report Output

Reports are now saved to:

```
reports/
├── 123456789012/              # AWS Account ID
│   ├── audit_20240721_120000.json
│   ├── audit_20240721_140000.json
│   └── ...
└── 987654321098/
    └── audit_20240721_153000.json
```

Each JSON report includes `risk_score` for every finding:

```json
{
  "generated_at": "2024-07-21T12:00:00+00:00",
  "account": "123456789012",
  "finding_count": 42,
  "findings": [
    {
      "severity": "CRITICAL",
      "risk_score": 95,
      "category": "Proxmox",
      "resource": "[us-east-1] instance:i-1234567890 (prod-hypervisor)",
      "description": "Possible unauthorized/unmanaged Proxmox VE deployment...",
      "remediation": "Verify this is an approved/sanctioned deployment..."
    }
  ]
}
```

Findings are **sorted by risk_score (descending)**, so highest-priority issues appear first.

## Environment Variables

```bash
# Optional API keys for enhanced threat intelligence
export NVD_API_KEY="your-nvd-key"
export SHODAN_API_KEY="your-shodan-key"
export OTX_API_KEY="your-otx-key"

# Then run the audit
python3 aws-audit/audit_aws.py --all-regions
```

## Customization

### Adjust Tag Names

Edit `asset_classifier.py` to match your tagging scheme:

```python
class AwsAssetClassifier:
    PROD_TAGS = {"environment", "env", "workload", "tier"}
    PROD_VALUES = {"prod", "production", "prd", "live", "critical"}
    
    SENSITIVITY_TAGS = {"data_classification", "sensitivity", "pii"}
    PII_VALUES = {"pii", "personal", "customer", "sensitive"}
    FINANCIAL_VALUES = {"financial", "payment", "billing"}
```

### Adjust Risk Score Weights

Edit `risk_scorer.py` to change how pillars are weighted:

```python
class RiskScorer:
    SEVERITY_WEIGHTS = {
        Severity.CRITICAL: 10,  # Max 40 points
        Severity.HIGH: 7,
        Severity.MEDIUM: 4,
        Severity.LOW: 2,
        Severity.INFO: 1,
    }
    
    CRITICALITY_SCALE = 25  # Asset criticality max points
    EXPLOITABILITY_SCALE = 25  # Threat intel max points
    SCALE_SCALE = 15  # Blast radius max points
```

### Add Custom Threat Intel

Extend `threat_intel.py` to integrate your own threat feeds:

```python
class MyCustomThreatIntel:
    def get_risk(self, finding_type: str) -> dict:
        # Query your internal risk database
        return {"custom_score": 0.8}
```

## Next Steps

1. **Tag your cloud resources** with `environment` and `data_classification` tags
2. **(Optional) Get a free NVD API key** for faster CVSS lookups
3. **Run the audit** with `python3 aws-audit/audit_aws.py --all-regions`
4. **Review the JSON report** in `reports/{account-id}/`
5. **Integrate with your SIEM/dashboard** to query risk scores across all audits

## Troubleshooting

### "Could not lookup {CVE-ID}: ..."

NVD API is rate-limited or unreachable. Check:
- Your internet connection
- NVD API key (if using one)
- Check `https://status.nvd.nist.gov/`

### Findings missing risk_score

Ensure the audit script imported `RiskScorer` correctly. Check for import errors in the output.

### Tags aren't being recognized

1. Verify tags on the resource: `aws ec2 describe-tags --filters "Name=resource-id,Values=i-xxx"`
2. Check `asset_classifier.py` for your tag key/value names
3. Remember: tag matching is **case-insensitive** for keys/values

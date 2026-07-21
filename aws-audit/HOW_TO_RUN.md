# How to Run — AWS Audit

## 1. Prerequisites
- Python 3.8+
- AWS CLI v2 installed and configured (`aws configure` or SSO profile)
- An IAM identity with **read-only** permissions covering:
  - `iam:Get*`, `iam:List*`, `iam:GenerateCredentialReport`
  - `ec2:Describe*`
  - `sts:GetCallerIdentity`

  The AWS managed policy `ReadOnlyAccess` (or a scoped-down variant of it)
  is sufficient.

## 2. Install dependencies
```bash
pip install -r requirements.txt
```

## 3. Authenticate
Use whatever method you already use for the AWS CLI — profile, SSO, or
environment variables:
```bash
aws sso login --profile my-profile
# or
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...   # if using temporary credentials
```

## 4. Run the audit

Single region (uses your profile's default region):
```bash
python3 audit_aws.py --profile my-profile
```

Specific region:
```bash
python3 audit_aws.py --profile my-profile --region us-gov-west-1
```

All enabled regions in the account (recommended for a full sweep):
```bash
python3 audit_aws.py --profile my-profile --all-regions
```

Save a JSON report for tracking/tickets:
```bash
python3 audit_aws.py --profile my-profile --all-regions --output aws-report.json
```

## 5. Interpreting output
- Findings print sorted by severity, with a resource identifier and a
  remediation suggestion.
- `Proxmox` category findings need manual verification — SSH/console into
  the flagged instance (or check with the instance owner) to confirm
  whether Proxmox VE is actually installed and whether it's sanctioned.

## Notes for GovCloud / FedRAMP environments
- Run with a profile pointed at the GovCloud partition
  (`aws configure set region us-gov-west-1 --profile govcloud`); the
  script works unmodified against GovCloud endpoints as long as your
  profile/credentials target that partition.
- Consider running this from a CI pipeline or Lambda on a schedule and
  piping `--output` JSON into your existing POA&M/ticketing workflow.

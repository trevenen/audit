# AWS Security Audit

A read-only Python script that scans an AWS account for common IAM,
networking, security-group, and EC2 misconfigurations, and specifically
looks for signs of **Proxmox VE** running on EC2 instances (a common
unsanctioned/shadow-IT nested-hypervisor finding).

## What it checks

### IAM
- Root account: MFA enabled, recent usage
- Account password policy (complexity, length, max age)
- Per-user: console MFA, access key age (>90 days), unused/never-used keys
- Directly-attached admin-level policies on IAM users (should be on roles/groups)
- Inline policies (harder to audit centrally)
- IAM role trust policies that allow `Principal: "*"` (assumable by anyone)

### Networking / Security Groups
- Security groups allowing **all** protocols/ports from `0.0.0.0/0` or `::/0`
- Sensitive ports (SSH 22, RDP 3389, DB ports, VNC, Redis, Elasticsearch,
  **Proxmox 8006/8007/3128**) open to the entire internet
- Network ACLs with inbound allow-all rules
- Default VPC usage
- Subnets routing to an Internet Gateway (public subnets) — informational

### EC2 Instances
- IMDSv2 enforcement (SSRF/credential-theft mitigation)
- Detailed monitoring enabled
- **Proxmox detection**, using several signals combined:
  - Instance name/tags mentioning proxmox/pve/qemu-server
  - AMI name/description mentioning Proxmox
  - Instance user-data / boot scripts referencing a Proxmox install
  - Security groups exposing port 8006 (Proxmox's default web GUI port)
  - Any hit is flagged **HIGH**, and **CRITICAL** if the instance also has
    a public IP (i.e., an unmanaged hypervisor UI reachable from the internet)

## Output

Findings are printed to the console sorted by severity
(`CRITICAL > HIGH > MEDIUM > LOW > INFO`), and optionally written as JSON
with `--output report.json` for ingestion into a ticketing system or SIEM.

## Scope & limitations

- **Read-only.** The script only calls `Describe*`/`List*`/`Get*` APIs — it
  never modifies anything.
- IAM is global; network/EC2 checks are per-region (use `--all-regions` to
  cover the whole account).
- Proxmox detection is heuristic (tags, AMI metadata, user-data, and open
  port 8006). It flags **candidates for manual review**, not confirmed
  installs — always verify before taking action.
- This is a point-in-time assessment, not continuous monitoring. Pair it
  with AWS Config / Security Hub for ongoing compliance.

See `HOW_TO_RUN.md` for setup and IAM permissions needed.

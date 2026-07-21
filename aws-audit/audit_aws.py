#!/usr/bin/env python3
"""
AWS Security Audit Script
==========================
Audits an AWS account for common IAM, networking, security group, and EC2
misconfigurations, and specifically flags evidence of Proxmox VE installs
running on EC2 instances (unauthorized/shadow hypervisor deployments).

This script is READ-ONLY. It never modifies any AWS resource.

Usage:
    python3 audit_aws.py [--profile PROFILE] [--region REGION] [--all-regions]
                         [--output report.json]

See README.md for what is checked and HOW_TO_RUN.md for setup instructions.
"""

import argparse
import datetime
import json
import sys
from pathlib import Path

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError, ProfileNotFound
except ImportError:
    print("ERROR: boto3 is required. Install with: pip install boto3")
    sys.exit(1)

# Import risk scorer and classifiers from parent directory
sys.path.insert(0, str(Path(__file__).parent.parent))
from risk_scorer import RiskScorer, AssetContext, DataSensitivity, ThreatContext
from asset_classifier import AwsAssetClassifier
from threat_intel import ThreatIntel

# Reports directory
REPORTS_DIR = Path(__file__).parent.parent / "reports"

# Threat intelligence (initialize with API keys from env if available)
import os
THREAT_INTEL = ThreatIntel(
    nvd_api_key=os.getenv("NVD_API_KEY"),
    shodan_api_key=os.getenv("SHODAN_API_KEY"),
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

# Ports that matter for the "sensitive ports open to the world" checks.
SENSITIVE_PORTS = {
    22: "SSH",
    3389: "RDP",
    3306: "MySQL",
    5432: "PostgreSQL",
    1433: "MSSQL",
    27017: "MongoDB",
    5900: "VNC",
    6379: "Redis",
    9200: "Elasticsearch",
    # Proxmox VE default ports
    8006: "Proxmox VE Web GUI",
    8007: "Proxmox Backup Server",
    3128: "Proxmox VE SPICE proxy",
}

PROXMOX_KEYWORDS = [
    "proxmox", "pve", "pmxcfs", "pve-manager", "qemu-server",
]

# Bare metal instance types support nested virtualization (KVM/Proxmox)
# Includes current and recent generations
BARE_METAL_TYPES = {
    # 3rd Gen Xeon (Ice Lake) - c7/m7/r7
    "c7i.metal", "c7i.metal-24xl", "c7i.metal-48xl",
    "m7i.metal", "m7i.metal-48xl",
    "r7i.metal", "r7i.metal-48xl",

    # 2nd Gen Xeon (Cascade Lake) - c6i/m6i/r6i
    "c6i.metal", "c6a.metal",
    "m6i.metal", "m6a.metal",
    "r6i.metal", "r6a.metal",

    # Older generations still in use
    "c5n.metal", "c5zn.metal",
    "m5.metal", "m5zn.metal",
    "r5.metal",

    # Storage optimized
    "i3.metal", "i3en.metal", "i4i.metal",

    # Memory optimized
    "x2.metal", "z1d.metal",

    # GPU instances (can run Proxmox)
    "p3.metal", "p4d.metal",
    "g4dn.metal",

    # Graviton ARM-based (also support nested virt)
    "a1.metal",

    # Older/Legacy (still risky if in use)
    "m5n.metal", "r5n.metal",
}

# Newer bare metal instances warrant extra scrutiny
HIGH_SPEC_BARE_METAL = {
    "c8i.metal", "m8i.metal", "r8i.metal",  # Latest Intel
    "c7i.metal", "m7i.metal", "r7i.metal",  # Current generation
}

# Indicators of nested virtualization setup
NESTED_VIRT_INDICATORS = {
    "/etc/network/interfaces": "Proxmox network config",
    "/run/network/interfaces.d": "Proxmox dynamic network config",
    "/etc/network/cloud-interfaces-template": "Proxmox cloud-init template",
    "vmbr0": "Proxmox virtual bridge (NAT guests)",
    "vmbr1": "Proxmox virtual bridge (routed guests)",
    "dnsmasq": "DHCP server for nested guests",
    "kvm": "KVM hypervisor (nested VMs)",
    "qemu-system": "QEMU process (nested VMs)",
}

# Cloud-init scripts that set up Proxmox
PROXMOX_CLOUD_INIT_URLS = [
    "thenickdude/proxmox-on-ec2",  # This repo
    "raw.githubusercontent.com/thenickdude/proxmox-on-ec2",
]


class Findings:
    def __init__(self):
        self.items = []
        self.scorer = RiskScorer()

    def add(
        self,
        severity,
        category,
        resource,
        description,
        remediation="",
        asset_context=None,
        threat_context=None,
    ):
        risk_score = self.scorer.score(severity, asset_context, threat_context)
        self.items.append({
            "severity": severity,
            "category": category,
            "resource": resource,
            "description": description,
            "remediation": remediation,
            "risk_score": risk_score,
        })

    def sorted(self):
        # Sort by risk_score desc, then severity
        return sorted(
            self.items,
            key=lambda f: (-f.get("risk_score", 0), SEVERITY_ORDER.get(f["severity"], 9)),
        )


def get_session(profile, region):
    try:
        if profile:
            return boto3.Session(profile_name=profile, region_name=region)
        return boto3.Session(region_name=region)
    except ProfileNotFound as e:
        print(f"ERROR: {e}")
        sys.exit(1)


def all_regions(session):
    try:
        ec2 = session.client("ec2")
        resp = ec2.describe_regions(AllRegions=False)
        return [r["RegionName"] for r in resp["Regions"]]
    except ClientError as e:
        print(f"WARNING: could not enumerate regions ({e}); falling back to session region only")
        return [session.region_name]


# ---------------------------------------------------------------------------
# IAM checks (global, not per-region)
# ---------------------------------------------------------------------------

def audit_iam(session, findings: Findings):
    iam = session.client("iam")

    # --- Account password policy ---
    try:
        policy = iam.get_account_password_policy()["PasswordPolicy"]
        if not policy.get("RequireUppercaseCharacters") or not policy.get("RequireLowercaseCharacters") \
           or not policy.get("RequireNumbers") or not policy.get("RequireSymbols"):
            findings.add("MEDIUM", "IAM", "account-password-policy",
                         "Password policy does not require a mix of uppercase, lowercase, numbers, and symbols.",
                         "Tighten the account password policy (IAM > Account Settings).")
        if policy.get("MaxPasswordAge", 9999) > 90:
            findings.add("LOW", "IAM", "account-password-policy",
                         f"Password max age is {policy.get('MaxPasswordAge')} days (>90).",
                         "Set password expiration to 90 days or fewer.")
        if policy.get("MinimumPasswordLength", 0) < 14:
            findings.add("LOW", "IAM", "account-password-policy",
                         f"Minimum password length is {policy.get('MinimumPasswordLength')} (<14).",
                         "Require at least 14 characters.")
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchEntity":
            findings.add("HIGH", "IAM", "account-password-policy",
                         "No account password policy is configured.",
                         "Configure a password policy under IAM > Account Settings.")
        else:
            findings.add("INFO", "IAM", "account-password-policy", f"Could not evaluate: {e}")

    # --- Root account usage / MFA ---
    try:
        summary = iam.get_account_summary()["SummaryMap"]
        if summary.get("AccountMFAEnabled", 0) == 0:
            findings.add("CRITICAL", "IAM", "root-account",
                         "MFA is NOT enabled on the root account.",
                         "Enable MFA (hardware or virtual) on the root account immediately.")
    except ClientError as e:
        findings.add("INFO", "IAM", "root-account", f"Could not evaluate root MFA: {e}")

    # Credential report gives root last-used and per-user key/MFA age in one shot
    try:
        import csv
        import io
        import time
        iam.generate_credential_report()
        report = None
        for _ in range(6):
            try:
                report = iam.get_credential_report()
                break
            except ClientError:
                time.sleep(2)
        if report:
            csv_text = report["Content"].decode("utf-8")
            reader = csv.DictReader(io.StringIO(csv_text))
            now = datetime.datetime.now(datetime.timezone.utc)
            for row in reader:
                user = row["user"]
                if user == "<root_account>":
                    last_used_str = row.get("password_last_used", "N/A")
                    if last_used_str not in ("N/A", "no_information", ""):
                        try:
                            last_used = datetime.datetime.fromisoformat(last_used_str.replace("Z", "+00:00"))
                            days = (now - last_used).days
                            if days < 7:
                                findings.add("HIGH", "IAM", "root-account",
                                             f"Root account was used within the last {days} day(s).",
                                             "Avoid routine use of the root account; use IAM roles/users instead.")
                        except ValueError:
                            pass
                    continue

                # Per-user checks
                if row.get("password_enabled") == "true" and row.get("mfa_active") == "false":
                    findings.add("HIGH", "IAM", f"user:{user}",
                                 "Console password login enabled but MFA is not active.",
                                 "Require MFA for all console users (enforce via IAM policy/SCP).")

                for key_num in ("1", "2"):
                    active = row.get(f"access_key_{key_num}_active")
                    last_rotated = row.get(f"access_key_{key_num}_last_rotated")
                    if active == "true" and last_rotated not in ("N/A", "", None):
                        try:
                            rotated = datetime.datetime.fromisoformat(last_rotated.replace("Z", "+00:00"))
                            age_days = (now - rotated).days
                            if age_days > 90:
                                findings.add("MEDIUM", "IAM", f"user:{user}",
                                             f"Access key #{key_num} is {age_days} days old (not rotated in 90+ days).",
                                             "Rotate access keys at least every 90 days; prefer short-lived roles.")
                        except ValueError:
                            pass

                    last_used_col = f"access_key_{key_num}_last_used_date"
                    if active == "true" and row.get(last_used_col) in ("N/A", "no_information", "", None):
                        findings.add("LOW", "IAM", f"user:{user}",
                                     f"Access key #{key_num} is active but has never been used.",
                                     "Deactivate or delete unused access keys.")
    except Exception as e:
        findings.add("INFO", "IAM", "credential-report", f"Could not fully parse credential report: {e}")

    # --- Directly-attached high-privilege policies on users ---
    try:
        paginator = iam.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page["Users"]:
                uname = user["UserName"]
                attached = iam.list_attached_user_policies(UserName=uname)["AttachedPolicies"]
                for pol in attached:
                    if pol["PolicyName"] in ("AdministratorAccess",) or "Admin" in pol["PolicyName"]:
                        findings.add("HIGH", "IAM", f"user:{uname}",
                                     f"User has administrator-level policy '{pol['PolicyName']}' attached directly.",
                                     "Attach broad permissions to roles/groups, not individual users; apply least privilege.")
                inline = iam.list_user_policies(UserName=uname)["PolicyNames"]
                if inline:
                    findings.add("LOW", "IAM", f"user:{uname}",
                                 f"User has {len(inline)} inline polic(y/ies): {inline}.",
                                 "Prefer managed policies attached to groups/roles for auditability.")
    except ClientError as e:
        findings.add("INFO", "IAM", "users", f"Could not list users: {e}")

    # --- Roles with overly permissive trust policies ---
    try:
        paginator = iam.get_paginator("list_roles")
        for page in paginator.paginate():
            for role in page["Roles"]:
                doc = role["AssumeRolePolicyDocument"]
                stmts = doc.get("Statement", [])
                if not isinstance(stmts, list):
                    stmts = [stmts]
                for stmt in stmts:
                    principal = stmt.get("Principal", {})
                    if principal == "*" or principal.get("AWS") == "*":
                        findings.add("CRITICAL", "IAM", f"role:{role['RoleName']}",
                                     "Role trust policy allows ANY AWS principal (Principal: \"*\") to assume it.",
                                     "Restrict the trust policy to specific account IDs/roles/services.")
    except ClientError as e:
        findings.add("INFO", "IAM", "roles", f"Could not list roles: {e}")


# ---------------------------------------------------------------------------
# Network / Security Group checks (per region)
# ---------------------------------------------------------------------------

def _rule_is_open_to_world(ip_permission):
    for ip_range in ip_permission.get("IpRanges", []):
        if ip_range.get("CidrIp") in ("0.0.0.0/0",):
            return True
    for ip_range in ip_permission.get("Ipv6Ranges", []):
        if ip_range.get("CidrIpv6") in ("::/0",):
            return True
    return False


def audit_security_groups(ec2, region, findings: Findings):
    try:
        paginator = ec2.get_paginator("describe_security_groups")
        for page in paginator.paginate():
            for sg in page["SecurityGroups"]:
                sg_id = sg["GroupId"]
                sg_name = sg.get("GroupName", sg_id)

                # Classify SG by tags
                is_prod, sensitivity = AwsAssetClassifier.classify_sg(sg)

                for perm in sg.get("IpPermissions", []):
                    if not _rule_is_open_to_world(perm):
                        continue
                    from_port = perm.get("FromPort")
                    to_port = perm.get("ToPort")
                    proto = perm.get("IpProtocol")

                    if proto == "-1" or (from_port == 0 and to_port == 65535):
                        asset = AssetContext(
                            is_production=is_prod,
                            data_sensitivity=sensitivity,
                            has_public_ip=True,  # NACL/SG is public
                        )
                        findings.add("CRITICAL", "Network", f"[{region}] sg:{sg_name}({sg_id})",
                                     "Security group allows ALL protocols/ports inbound from 0.0.0.0/0 (or ::/0).",
                                     "Restrict ingress to specific ports/protocols and known source ranges.",
                                     asset_context=asset)
                        continue

                    if from_port is None:
                        continue

                    port_range = range(from_port, (to_port or from_port) + 1)
                    for port, label in SENSITIVE_PORTS.items():
                        if port in port_range:
                            sev = "CRITICAL" if port in (22, 3389, 8006) else "HIGH"

                            # Get threat intel for this port
                            threat = ThreatContext(
                                exploit_available=True,  # Common ports always have exploits
                                active_exploitation=THREAT_INTEL.shodan.is_port_commonly_scanned(port),
                                affected_instances=1,
                            )
                            asset = AssetContext(
                                is_production=is_prod,
                                data_sensitivity=sensitivity,
                                has_public_ip=True,
                            )

                            findings.add(sev, "Network", f"[{region}] sg:{sg_name}({sg_id})",
                                         f"Port {port} ({label}) is open to the entire internet (0.0.0.0/0).",
                                         f"Restrict {label} access to a specific IP range, bastion host, or VPN/SSM.",
                                         asset_context=asset,
                                         threat_context=threat)
    except ClientError as e:
        findings.add("INFO", "Network", f"[{region}] security-groups", f"Could not audit security groups: {e}")


def audit_vpc_network(ec2, region, findings: Findings):
    # Default VPC usage (often overlooked / overly permissive by default)
    try:
        vpcs = ec2.describe_vpcs()["Vpcs"]
        for vpc in vpcs:
            if vpc.get("IsDefault"):
                findings.add("LOW", "Network", f"[{region}] vpc:{vpc['VpcId']}",
                             "Default VPC is present/in use.",
                             "Consider using purpose-built VPCs with deliberate subnet/routing design instead of the default VPC.")
    except ClientError as e:
        findings.add("INFO", "Network", f"[{region}] vpcs", f"Could not list VPCs: {e}")

    # NACLs allowing everything
    try:
        nacls = ec2.describe_network_acls()["NetworkAcls"]
        for nacl in nacls:
            for entry in nacl.get("Entries", []):
                if entry.get("Egress"):
                    continue
                if entry.get("CidrBlock") == "0.0.0.0/0" and entry.get("RuleAction") == "allow" \
                   and entry.get("Protocol") == "-1":
                    findings.add("MEDIUM", "Network", f"[{region}] nacl:{nacl['NetworkAclId']}",
                                 "Network ACL has an inbound ALLOW ALL rule from 0.0.0.0/0.",
                                 "Scope NACL rules down to only the traffic that is actually required.")
    except ClientError as e:
        findings.add("INFO", "Network", f"[{region}] nacls", f"Could not list NACLs: {e}")

    # Public subnets (route to an Internet Gateway)
    try:
        route_tables = ec2.describe_route_tables()["RouteTables"]
        for rt in route_tables:
            for route in rt.get("Routes", []):
                if route.get("DestinationCidrBlock") == "0.0.0.0/0" and str(route.get("GatewayId", "")).startswith("igw-"):
                    assoc_subnets = [a.get("SubnetId") for a in rt.get("Associations", []) if a.get("SubnetId")]
                    if assoc_subnets:
                        findings.add("INFO", "Network", f"[{region}] rtb:{rt['RouteTableId']}",
                                     f"Subnets {assoc_subnets} route 0.0.0.0/0 to an Internet Gateway (public subnet).",
                                     "Confirm only resources that must be internet-facing live in these subnets.")
    except ClientError as e:
        findings.add("INFO", "Network", f"[{region}] route-tables", f"Could not list route tables: {e}")


# ---------------------------------------------------------------------------
# EC2 instance checks, incl. Proxmox detection (per region)
# ---------------------------------------------------------------------------

def _text_mentions_proxmox(text):
    if not text:
        return False
    lowered = text.lower()
    return any(k in lowered for k in PROXMOX_KEYWORDS)


def audit_bare_metal_instances(ec2, region, findings: Findings):
    """Check for bare metal instances that could run Proxmox/nested VMs."""
    try:
        paginator = ec2.get_paginator("describe_instances")
        for page in paginator.paginate():
            for reservation in page["Reservations"]:
                for inst in reservation["Instances"]:
                    inst_id = inst["InstanceId"]
                    inst_type = inst.get("InstanceType", "")
                    state = inst["State"]["Name"]

                    if state == "terminated":
                        continue

                    if inst_type not in BARE_METAL_TYPES:
                        continue

                    # Bare metal instance found
                    name_tag = ""
                    for tag in inst.get("Tags", []):
                        if tag.get("Key") == "Name":
                            name_tag = tag.get("Value", "")
                            break

                    public_ip = inst.get("PublicIpAddress")
                    is_high_spec = inst_type in HIGH_SPEC_BARE_METAL

                    # Classify the instance
                    is_prod, sensitivity = AwsAssetClassifier.classify_instance(inst)

                    # Bare metal is inherently suspicious - you need a good reason for it
                    if is_high_spec:
                        sev = "MEDIUM"  # High-spec bare metal is rarely justified
                        desc = (
                            f"High-specification bare metal instance type '{inst_type}' detected.\n"
                            f"Bare metal instances are expensive and typically used for:\n"
                            f"  • Nested hypervisors (Proxmox, KVM, ESXi)\n"
                            f"  • High-performance workloads (HPC, ML training)\n"
                            f"  • License-tied software\n"
                            f"If used for nested virtualization, this bypasses AWS controls and compliance monitoring."
                        )
                    else:
                        sev = "LOW"
                        desc = (
                            f"Bare metal instance type '{inst_type}' is running.\n"
                            f"Bare metal instances support nested virtualization (e.g., Proxmox/KVM).\n"
                            f"Verify this is for an approved use case (HPC, specialized workload)."
                        )

                    threat = ThreatContext(
                        exploit_available=True,  # Metal instances have higher surface area
                        affected_instances=1,
                    )
                    asset = AssetContext(
                        is_production=is_prod,
                        data_sensitivity=sensitivity,
                        has_public_ip=bool(public_ip),
                    )

                    findings.add(
                        sev,
                        "Infrastructure",
                        f"[{region}] instance:{inst_id} ({name_tag or 'unnamed'})",
                        desc,
                        f"Verify bare metal justification: document approved use case, "
                        f"ensure no unauthorized nested VMs running, and monitor for unusual network activity.",
                        asset_context=asset,
                        threat_context=threat,
                    )

    except ClientError as e:
        findings.add("INFO", "Infrastructure", f"[{region}] bare-metal-check", f"Could not audit bare metal instances: {e}")


def audit_ec2_instances(session, ec2, region, findings: Findings):
    try:
        paginator = ec2.get_paginator("describe_instances")
        for page in paginator.paginate():
            for reservation in page["Reservations"]:
                for inst in reservation["Instances"]:
                    inst_id = inst["InstanceId"]
                    state = inst["State"]["Name"]
                    if state == "terminated":
                        continue

                    name_tag = ""
                    tag_blob = ""
                    for tag in inst.get("Tags", []):
                        tag_blob += f"{tag.get('Key','')}={tag.get('Value','')} "
                        if tag.get("Key") == "Name":
                            name_tag = tag.get("Value", "")

                    public_ip = inst.get("PublicIpAddress")
                    image_id = inst.get("ImageId")

                    # --- Proxmox detection heuristics ---
                    proxmox_hits = []
                    nested_virt_evidence = []

                    # 1. Check instance type for bare metal (required for VMs)
                    inst_type = inst.get("InstanceType", "")
                    is_bare_metal = any(
                        inst_type.endswith(".metal") or inst_type == bm
                        for bm in BARE_METAL_TYPES
                    )
                    is_high_spec_bare_metal = inst_type in HIGH_SPEC_BARE_METAL

                    if is_bare_metal:
                        if is_high_spec_bare_metal:
                            nested_virt_evidence.append(
                                f"HIGH-SPEC bare metal instance type '{inst_type}' ⚠️ (perfect for nested VMs, expensive = likely deliberate)"
                            )
                        else:
                            nested_virt_evidence.append(
                                f"bare metal instance type '{inst_type}' (required for nested VMs with KVM)"
                            )

                    # 2. Check name/tags for Proxmox
                    if _text_mentions_proxmox(name_tag) or _text_mentions_proxmox(tag_blob):
                        proxmox_hits.append("instance name/tags reference Proxmox")

                    # 3. Check AMI for Proxmox
                    try:
                        image = ec2.describe_images(ImageIds=[image_id])["Images"]
                        if image:
                            img = image[0]
                            desc_blob = f"{img.get('Name','')} {img.get('Description','')}"
                            if _text_mentions_proxmox(desc_blob):
                                proxmox_hits.append(f"AMI '{image_id}' name/description references Proxmox")
                    except ClientError:
                        pass

                    # 4. Check user data for Proxmox cloud-init installation
                    try:
                        user_data_attr = ec2.describe_instance_attribute(
                            InstanceId=inst_id, Attribute="userData"
                        )
                        ud = user_data_attr.get("UserData", {}).get("Value")
                        if ud:
                            import base64
                            decoded = base64.b64decode(ud).decode("utf-8", errors="ignore")

                            # Check for Proxmox keywords
                            if _text_mentions_proxmox(decoded):
                                proxmox_hits.append("user-data script references Proxmox install")

                            # Check for specific cloud-init techniques from thenickdude/proxmox-on-ec2
                            for repo_url in PROXMOX_CLOUD_INIT_URLS:
                                if repo_url.lower() in decoded.lower():
                                    nested_virt_evidence.append(
                                        f"cloud-init script from '{repo_url}' (nested Proxmox VE installation)"
                                    )
                                    proxmox_hits.append("detected cloud-init from proxmox-on-ec2 repo")

                            # Check for Proxmox package installation commands
                            if any(x in decoded.lower() for x in ["pve-manager", "proxmox-ve", "apt install proxmox"]):
                                nested_virt_evidence.append("cloud-init explicitly installs Proxmox packages")

                            # Check for network bridge setup (vmbr0 = nested guests)
                            if any(x in decoded.lower() for x in ["vmbr0", "vmbr1", "bridge-ports"]):
                                nested_virt_evidence.append("cloud-init configures virtual bridges (vmbr0/vmbr1) for nested guests")
                    except ClientError:
                        pass

                    # 5. Check security groups for Proxmox ports and network exposure
                    sg_ids = [sg["GroupId"] for sg in inst.get("SecurityGroups", [])]
                    proxmox_ports_open = {}
                    if sg_ids:
                        try:
                            sgs = ec2.describe_security_groups(GroupIds=sg_ids)["SecurityGroups"]
                            for sg in sgs:
                                for perm in sg.get("IpPermissions", []):
                                    from_port = perm.get("FromPort")
                                    to_port = perm.get("ToPort")
                                    proto = perm.get("IpProtocol", "")
                                    if from_port is None:
                                        continue

                                    # Check for Proxmox-specific ports
                                    for port, label in SENSITIVE_PORTS.items():
                                        if port in (8006, 8007, 3128):  # Proxmox ports
                                            if from_port <= port <= (to_port or from_port):
                                                proxmox_ports_open[port] = label
                        except ClientError:
                            pass

                    if proxmox_ports_open:
                        ports_str = ", ".join(
                            f"{p} ({l})" for p, l in proxmox_ports_open.items()
                        )
                        proxmox_hits.append(f"security group exposes Proxmox ports: {ports_str}")

                    if proxmox_hits or nested_virt_evidence:
                        # Determine severity
                        if nested_virt_evidence and public_ip:
                            sev = "CRITICAL"  # Confirmed nested virt + public exposure
                        elif nested_virt_evidence:
                            sev = "CRITICAL"  # Confirmed nested virt even if private
                        elif public_ip:
                            sev = "CRITICAL"  # Proxmox ports exposed to internet
                        else:
                            sev = "HIGH"

                        # Proxmox on production = extremely high risk
                        is_prod, sensitivity = AwsAssetClassifier.classify_instance(inst)
                        threat = ThreatContext(
                            exploit_available=True,  # Proxmox has known vulns
                            active_exploitation=True,  # Actively targeted by attackers
                            affected_instances=1,
                        )
                        asset = AssetContext(
                            is_production=is_prod,
                            data_sensitivity=sensitivity,
                            has_public_ip=public_ip,
                            instance_count=1,
                        )

                        # Build detailed description
                        description_parts = ["Possible unauthorized/unmanaged Proxmox VE deployment detected:"]
                        if nested_virt_evidence:
                            description_parts.append("NESTED VIRTUALIZATION CONFIRMED:")
                            for evidence in nested_virt_evidence:
                                description_parts.append(f"  • {evidence}")
                        if proxmox_hits:
                            description_parts.append("INDICATORS:")
                            for hit in proxmox_hits:
                                description_parts.append(f"  • {hit}")
                        if public_ip:
                            description_parts.append(f"  ⚠ Instance has PUBLIC IP: {public_ip}")

                        description = "\n".join(description_parts)

                        findings.add(sev, "Proxmox", f"[{region}] instance:{inst_id} ({name_tag or 'unnamed'})",
                                     description,
                                     "Verify this is an approved/sanctioned deployment. Nested hypervisors on cloud "
                                     "instances frequently indicate shadow-IT, may violate cloud provider licensing, "
                                     "and can bypass central patching, logging, and network controls. If unauthorized, "
                                     "isolate, audit all nested guests, and remove. If authorized, enforce strict "
                                     "monitoring and security policies on nested workloads.",
                                     asset_context=asset,
                                     threat_context=threat)

                    # --- General instance hygiene checks ---
                    if inst.get("MetadataOptions", {}).get("HttpTokens") != "required":
                        is_prod, sensitivity = AwsAssetClassifier.classify_instance(inst)
                        threat = ThreatContext(
                            exploit_available=True,  # SSRF is a known attack path
                            active_exploitation=True,  # Actively exploited in cloud
                        )
                        asset = AssetContext(
                            is_production=is_prod,
                            data_sensitivity=sensitivity,
                            has_public_ip=public_ip,
                        )
                        findings.add("MEDIUM", "EC2", f"[{region}] instance:{inst_id} ({name_tag or 'unnamed'})",
                                     "Instance Metadata Service v2 (IMDSv2) is NOT enforced (HttpTokens != required).",
                                     "Set IMDSv2 to required to mitigate SSRF-based credential theft.",
                                     asset_context=asset,
                                     threat_context=threat)

                    if inst.get("Monitoring", {}).get("State") != "enabled":
                        is_prod, sensitivity = AwsAssetClassifier.classify_instance(inst)
                        asset = AssetContext(
                            is_production=is_prod,
                            data_sensitivity=sensitivity,
                        )
                        findings.add("LOW", "EC2", f"[{region}] instance:{inst_id} ({name_tag or 'unnamed'})",
                                     "Detailed CloudWatch monitoring is not enabled.",
                                     "Enable detailed monitoring for better visibility into instance behavior.",
                                     asset_context=asset)

    except ClientError as e:
        findings.add("INFO", "EC2", f"[{region}] instances", f"Could not audit EC2 instances: {e}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="AWS IAM / Network / EC2 security audit, incl. Proxmox detection.")
    parser.add_argument("--profile", help="AWS CLI profile name to use", default=None)
    parser.add_argument("--region", help="Single region to scan (default: profile/session default)", default=None)
    parser.add_argument("--all-regions", action="store_true", help="Scan all enabled regions for network/EC2 checks")
    parser.add_argument("--output", help="Write JSON report to this file", default=None)
    args = parser.parse_args()

    session = get_session(args.profile, args.region)

    try:
        sts = session.client("sts")
        ident = sts.get_caller_identity()
        print(f"Authenticated as: {ident['Arn']}  (Account: {ident['Account']})")
    except (ClientError, NoCredentialsError) as e:
        print(f"ERROR: could not authenticate to AWS: {e}")
        sys.exit(1)

    findings = Findings()

    print("\n[1/3] Auditing IAM (global)...")
    audit_iam(session, findings)

    regions = all_regions(session) if args.all_regions else [session.region_name]
    print(f"\n[2/3] Auditing networking & security groups in region(s): {regions}")
    for region in regions:
        ec2 = session.client("ec2", region_name=region)
        audit_security_groups(ec2, region, findings)
        audit_vpc_network(ec2, region, findings)

    print(f"\n[3/3] Auditing EC2 instances (incl. Proxmox detection) in region(s): {regions}")
    for region in regions:
        ec2 = session.client("ec2", region_name=region)
        audit_bare_metal_instances(ec2, region, findings)
        audit_ec2_instances(session, ec2, region, findings)

    report = findings.sorted()

    print("\n" + "=" * 78)
    print(f"AUDIT COMPLETE - {len(report)} finding(s)")
    print("=" * 78)
    for f in report:
        risk_score = f.get("risk_score", "?")
        print(f"\n[{f['severity']}] (Risk: {risk_score}/100) ({f['category']}) {f['resource']}")
        print(f"  {f['description']}")
        if f["remediation"]:
            print(f"  -> {f['remediation']}")

    # Determine output path (user-specified or auto in reports/ by account)
    if args.output:
        output_path = Path(args.output)
    else:
        account_id = ident["Account"]
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        account_dir = REPORTS_DIR / account_id
        account_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d_%H%M%S")
        output_path = account_dir / f"audit_{timestamp}.json"

    with open(output_path, "w") as fh:
        json.dump({
            "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "account": ident["Account"],
            "regions_scanned": regions,
            "finding_count": len(report),
            "findings": report,
        }, fh, indent=2)
    print(f"\nJSON report written to: {output_path}")


if __name__ == "__main__":
    main()

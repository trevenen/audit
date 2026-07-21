#!/usr/bin/env python3
"""
Azure Security Audit Script
=============================
Audits an Azure subscription for common RBAC/IAM, networking (NSG/VNet),
and VM misconfigurations, and specifically flags evidence of Proxmox VE
installs running on Azure VMs (unauthorized/shadow hypervisor deployments).

This script is READ-ONLY. It never modifies any Azure resource.

Usage:
    python3 audit_azure.py --subscription-id SUB_ID [--output report.json]

Auth: uses DefaultAzureCredential (az login, environment vars, managed
identity, etc. — see HOW_TO_RUN.md).

See README.md for what is checked and HOW_TO_RUN.md for setup instructions.
"""

import argparse
import datetime
import json
import sys

try:
    from azure.identity import DefaultAzureCredential
    from azure.mgmt.resource import SubscriptionClient
    from azure.mgmt.network import NetworkManagementClient
    from azure.mgmt.compute import ComputeManagementClient
    from azure.mgmt.authorization import AuthorizationManagementClient
    from azure.core.exceptions import HttpResponseError
except ImportError:
    print("ERROR: Azure SDK packages are required. Install with:")
    print("  pip install azure-identity azure-mgmt-resource azure-mgmt-network "
          "azure-mgmt-compute azure-mgmt-authorization")
    sys.exit(1)


SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

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
    8006: "Proxmox VE Web GUI",
    8007: "Proxmox Backup Server",
    3128: "Proxmox VE SPICE proxy",
}

PROXMOX_KEYWORDS = ["proxmox", "pve", "pmxcfs", "pve-manager", "qemu-server"]

HIGH_PRIV_ROLES = {"owner", "contributor"}


class Findings:
    def __init__(self):
        self.items = []

    def add(self, severity, category, resource, description, remediation=""):
        self.items.append({
            "severity": severity,
            "category": category,
            "resource": resource,
            "description": description,
            "remediation": remediation,
        })

    def sorted(self):
        return sorted(self.items, key=lambda f: SEVERITY_ORDER.get(f["severity"], 9))


def _text_mentions_proxmox(text):
    if not text:
        return False
    return any(k in text.lower() for k in PROXMOX_KEYWORDS)


def _port_in_range(port, range_str):
    """range_str can be '*', a single port '22', or a range '8000-9000'."""
    if range_str is None:
        return False
    range_str = range_str.strip()
    if range_str == "*":
        return True
    if "-" in range_str:
        try:
            lo, hi = range_str.split("-")
            return int(lo) <= port <= int(hi)
        except ValueError:
            return False
    try:
        return int(range_str) == port
    except ValueError:
        return False


def _is_open_source(rule):
    src = (rule.source_address_prefix or "").strip()
    src_list = rule.source_address_prefixes or []
    open_values = {"*", "0.0.0.0/0", "Internet", "Any"}
    if src in open_values:
        return True
    if any(s in open_values for s in src_list):
        return True
    return False


# ---------------------------------------------------------------------------
# RBAC / IAM-equivalent checks
# ---------------------------------------------------------------------------

def audit_rbac(auth_client: AuthorizationManagementClient, subscription_id, findings: Findings):
    scope = f"/subscriptions/{subscription_id}"
    try:
        role_defs = {}
        for rd in auth_client.role_definitions.list(scope):
            role_defs[rd.id] = rd.role_name

        assignments = list(auth_client.role_assignments.list_for_scope(scope))
        for a in assignments:
            role_name = role_defs.get(a.role_definition_id, a.role_definition_id)
            principal_type = getattr(a, "principal_type", "Unknown")
            if role_name and role_name.lower() in HIGH_PRIV_ROLES:
                sev = "HIGH" if principal_type == "User" else "MEDIUM"
                findings.add(sev, "RBAC", f"assignment:{a.name}",
                             f"Principal type '{principal_type}' has been granted the '{role_name}' role "
                             f"at subscription scope.",
                             "Prefer assigning high-privilege roles to groups (with PIM/JIT elevation) "
                             "rather than directly to individual users, and scope to resource "
                             "group/resource level wherever possible instead of the whole subscription.")
    except HttpResponseError as e:
        findings.add("INFO", "RBAC", "role-assignments", f"Could not list role assignments: {e.message}")

    findings.add("INFO", "RBAC", "manual-check-needed",
                 "MFA/Conditional Access enforcement cannot be checked via ARM APIs used here.",
                 "Manually verify Conditional Access policies require MFA for all users "
                 "in Microsoft Entra ID (Azure AD) > Security > Conditional Access.")


# ---------------------------------------------------------------------------
# Network Security Group checks
# ---------------------------------------------------------------------------

def audit_nsgs(net_client: NetworkManagementClient, findings: Findings):
    try:
        for nsg in net_client.network_security_groups.list_all():
            rg = nsg.id.split("/")[4] if nsg.id else "?"
            all_rules = list(nsg.security_rules or []) + list(nsg.default_security_rules or [])
            for rule in all_rules:
                if rule.direction != "Inbound" or rule.access != "Allow":
                    continue
                if not _is_open_source(rule):
                    continue

                dest_ranges = []
                if rule.destination_port_range:
                    dest_ranges.append(rule.destination_port_range)
                if rule.destination_port_ranges:
                    dest_ranges.extend(rule.destination_port_ranges)

                if any(r == "*" for r in dest_ranges):
                    findings.add("CRITICAL", "Network", f"nsg:{nsg.name} (rg:{rg}) rule:{rule.name}",
                                 "NSG rule allows ALL ports inbound from any source (destination port '*').",
                                 "Restrict to specific required ports and known source ranges.")
                    continue

                for port, label in SENSITIVE_PORTS.items():
                    if any(_port_in_range(port, r) for r in dest_ranges):
                        sev = "CRITICAL" if port in (22, 3389, 8006) else "HIGH"
                        findings.add(sev, "Network", f"nsg:{nsg.name} (rg:{rg}) rule:{rule.name}",
                                     f"Port {port} ({label}) is open to any source (Internet/'*').",
                                     f"Restrict {label} to a specific IP range, Bastion, or VPN.")
    except HttpResponseError as e:
        findings.add("INFO", "Network", "nsgs", f"Could not list NSGs: {e.message}")


def audit_networks(net_client: NetworkManagementClient, findings: Findings):
    try:
        for vnet in net_client.virtual_networks.list_all():
            rg = vnet.id.split("/")[4] if vnet.id else "?"
            for subnet in vnet.subnets or []:
                if not subnet.network_security_group:
                    findings.add("MEDIUM", "Network", f"vnet:{vnet.name}/subnet:{subnet.name} (rg:{rg})",
                                 "Subnet has no Network Security Group associated.",
                                 "Associate an NSG with every subnet to enforce explicit traffic rules.")
    except HttpResponseError as e:
        findings.add("INFO", "Network", "vnets", f"Could not list virtual networks: {e.message}")

    try:
        for pip in net_client.public_ip_addresses.list_all():
            rg = pip.id.split("/")[4] if pip.id else "?"
            findings.add("INFO", "Network", f"public-ip:{pip.name} (rg:{rg})",
                         f"Public IP address allocated ({pip.ip_address or 'unassigned'}).",
                         "Confirm this public IP is still required; remove unused public IPs.")
    except HttpResponseError as e:
        findings.add("INFO", "Network", "public-ips", f"Could not list public IPs: {e.message}")


# ---------------------------------------------------------------------------
# VM checks, incl. Proxmox detection
# ---------------------------------------------------------------------------

def audit_vms(compute_client: ComputeManagementClient, net_client: NetworkManagementClient, findings: Findings):
    # Pre-fetch NSGs with an open 8006 rule for quick lookup by NIC/subnet association
    nsg_with_8006 = set()
    try:
        for nsg in net_client.network_security_groups.list_all():
            all_rules = list(nsg.security_rules or []) + list(nsg.default_security_rules or [])
            for rule in all_rules:
                if rule.direction == "Inbound" and rule.access == "Allow" and _is_open_source(rule):
                    ranges = []
                    if rule.destination_port_range:
                        ranges.append(rule.destination_port_range)
                    if rule.destination_port_ranges:
                        ranges.extend(rule.destination_port_ranges)
                    if any(_port_in_range(8006, r) or r == "*" for r in ranges):
                        nsg_with_8006.add(nsg.id)
    except HttpResponseError:
        pass

    try:
        for vm in compute_client.virtual_machines.list_all():
            rg = vm.id.split("/")[4] if vm.id else "?"
            vm_name = vm.name
            tags = vm.tags or {}
            tag_blob = " ".join(f"{k}={v}" for k, v in tags.items())

            proxmox_hits = []
            if _text_mentions_proxmox(vm_name) or _text_mentions_proxmox(tag_blob):
                proxmox_hits.append("VM name/tags reference Proxmox")

            image_ref = vm.storage_profile.image_reference if vm.storage_profile else None
            if image_ref:
                image_blob = " ".join(filter(None, [
                    image_ref.publisher, image_ref.offer, image_ref.sku, image_ref.id,
                ]))
                if _text_mentions_proxmox(image_blob):
                    proxmox_hits.append("VM image reference mentions Proxmox")

            os_profile = vm.os_profile
            if os_profile and os_profile.custom_data:
                try:
                    import base64
                    decoded = base64.b64decode(os_profile.custom_data).decode("utf-8", errors="ignore")
                    if _text_mentions_proxmox(decoded):
                        proxmox_hits.append("VM custom_data/cloud-init references Proxmox install")
                except Exception:
                    pass

            # Check attached NICs -> NSG -> port 8006 exposure
            has_public_ip = False
            proxmox_port_open = False
            if vm.network_profile:
                for nic_ref in vm.network_profile.network_interfaces or []:
                    try:
                        nic_parts = nic_ref.id.split("/")
                        nic_rg, nic_name = nic_parts[4], nic_parts[-1]
                        nic = net_client.network_interfaces.get(nic_rg, nic_name)
                        if nic.network_security_group and nic.network_security_group.id in nsg_with_8006:
                            proxmox_port_open = True
                        for ipconf in nic.ip_configurations or []:
                            if ipconf.public_ip_address:
                                has_public_ip = True
                    except HttpResponseError:
                        continue

            if proxmox_port_open:
                proxmox_hits.append("associated NSG exposes port 8006 (Proxmox VE web GUI default port)")

            if proxmox_hits:
                sev = "CRITICAL" if has_public_ip else "HIGH"
                findings.add(sev, "Proxmox", f"vm:{vm_name} (rg:{rg})",
                             "Possible unauthorized/unmanaged Proxmox VE deployment detected: "
                             + "; ".join(proxmox_hits) + (". VM has a PUBLIC IP." if has_public_ip else "."),
                             "Verify this is an approved/sanctioned deployment. Nested hypervisors on cloud "
                             "VMs are frequently unsanctioned shadow-IT, may violate Azure's nested "
                             "virtualization guidance/licensing terms, and can bypass central patching, "
                             "logging, and network controls. Investigate and remove/isolate if unapproved.")

            # General hygiene
            if vm.storage_profile and vm.storage_profile.os_disk and vm.storage_profile.os_disk.encryption_settings \
               and not vm.storage_profile.os_disk.encryption_settings.enabled:
                findings.add("MEDIUM", "VM", f"vm:{vm_name} (rg:{rg})",
                             "OS disk encryption is explicitly disabled.",
                             "Enable Azure Disk Encryption or confirm platform-managed encryption is active.")

    except HttpResponseError as e:
        findings.add("INFO", "VM", "vms", f"Could not list VMs: {e.message}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Azure RBAC / Network / VM security audit, incl. Proxmox detection.")
    parser.add_argument("--subscription-id", required=True, help="Azure subscription ID to audit")
    parser.add_argument("--output", help="Write JSON report to this file", default=None)
    args = parser.parse_args()

    credential = DefaultAzureCredential()
    sub_id = args.subscription_id

    try:
        sub_client = SubscriptionClient(credential)
        sub = sub_client.subscriptions.get(sub_id)
        print(f"Authenticated. Auditing subscription: {sub.display_name} ({sub_id})")
    except HttpResponseError as e:
        print(f"ERROR: could not access subscription {sub_id}: {e.message}")
        sys.exit(1)

    findings = Findings()

    net_client = NetworkManagementClient(credential, sub_id)
    compute_client = ComputeManagementClient(credential, sub_id)
    auth_client = AuthorizationManagementClient(credential, sub_id)

    print("\n[1/3] Auditing RBAC / role assignments...")
    audit_rbac(auth_client, sub_id, findings)

    print("\n[2/3] Auditing networking & NSGs...")
    audit_nsgs(net_client, findings)
    audit_networks(net_client, findings)

    print("\n[3/3] Auditing VMs (incl. Proxmox detection)...")
    audit_vms(compute_client, net_client, findings)

    report = findings.sorted()

    print("\n" + "=" * 78)
    print(f"AUDIT COMPLETE - {len(report)} finding(s)")
    print("=" * 78)
    for f in report:
        print(f"\n[{f['severity']}] ({f['category']}) {f['resource']}")
        print(f"  {f['description']}")
        if f["remediation"]:
            print(f"  -> {f['remediation']}")

    if args.output:
        with open(args.output, "w") as fh:
            json.dump({
                "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "subscription_id": sub_id,
                "finding_count": len(report),
                "findings": report,
            }, fh, indent=2)
        print(f"\nJSON report written to: {args.output}")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Deep Inspection for Proxmox/Nested Virtualization on EC2
========================================================

Uses AWS Systems Manager (SSM) Agent to inspect instance internals:
- Running processes (qemu, kvm, pve-manager)
- Network configuration (vmbr0, vmbr1 bridges)
- Filesystem evidence (/etc/pve, /var/lib/vz)
- Running virtual machines

Requirements:
- EC2 instance must have SSM Agent running
- Instance must have IAM role with AmazonSSMManagedInstanceCore policy
- SSM access must be enabled for the region
"""

import json
from typing import Optional, Dict, List
from botocore.exceptions import ClientError


class ProxmoxDeepInspector:
    """Deep inspection using AWS Systems Manager."""

    def __init__(self, ssm_client, ec2_client):
        self.ssm = ssm_client
        self.ec2 = ec2_client

    def inspect_instance(self, instance_id: str) -> Dict:
        """
        Perform comprehensive inspection of an instance for Proxmox/nested virtualization.

        Returns dict with:
        - is_proxmox_installed: bool
        - running_vms: list of VM details
        - network_bridges: list of bridge names
        - storage_evidence: list of Proxmox storage paths
        - kvm_enabled: bool
        """
        results = {
            "instance_id": instance_id,
            "accessible": True,
            "errors": [],
            "is_proxmox_installed": False,
            "running_vms": [],
            "network_bridges": [],
            "storage_evidence": [],
            "kvm_processes": [],
        }

        # Check if instance is managed by SSM
        if not self._is_ssm_managed(instance_id):
            results["accessible"] = False
            results["errors"].append("Instance not accessible via Systems Manager (check IAM role and SSM Agent)")
            return results

        # Check for Proxmox packages
        if self._check_proxmox_packages(instance_id):
            results["is_proxmox_installed"] = True

        # List KVM/QEMU processes
        results["kvm_processes"] = self._get_kvm_processes(instance_id)
        if results["kvm_processes"]:
            results["is_proxmox_installed"] = True

        # Check for virtual bridges
        results["network_bridges"] = self._get_network_bridges(instance_id)

        # Check for Proxmox storage paths
        results["storage_evidence"] = self._get_proxmox_storage(instance_id)

        # List running VMs (if Proxmox is installed)
        if results["is_proxmox_installed"]:
            results["running_vms"] = self._get_running_vms(instance_id)

        return results

    def _is_ssm_managed(self, instance_id: str) -> bool:
        """Check if instance is managed by SSM."""
        try:
            response = self.ssm.describe_instance_information(
                Filters=[{"Key": "InstanceIds", "Values": [instance_id]}]
            )
            return len(response.get("InstanceInformationList", [])) > 0
        except ClientError:
            return False

    def _run_command(self, instance_id: str, commands: List[str]) -> Optional[str]:
        """
        Run a command on the instance and return output.

        Args:
            instance_id: EC2 instance ID
            commands: List of shell commands to run

        Returns:
            Command output or None if failed
        """
        try:
            response = self.ssm.send_command(
                InstanceIds=[instance_id],
                DocumentName="AWS-RunShellScript",
                Parameters={"command": commands},
            )
            command_id = response["Command"]["CommandId"]

            # Wait for command to complete (poll)
            import time

            for _ in range(30):  # Up to 30 seconds
                try:
                    cmd_result = self.ssm.get_command_invocation(
                        CommandId=command_id, InstanceId=instance_id
                    )
                    if cmd_result["Status"] in ("Success", "Failed"):
                        return cmd_result.get("StandardOutputContent", "")
                except ClientError:
                    pass
                time.sleep(1)

        except ClientError as e:
            return None

        return None

    def _check_proxmox_packages(self, instance_id: str) -> bool:
        """Check if Proxmox packages are installed."""
        output = self._run_command(
            instance_id,
            ["dpkg -l | grep -i proxmox | head -5"],
        )
        return output and len(output.strip()) > 0

    def _get_kvm_processes(self, instance_id: str) -> List[str]:
        """Get list of running KVM/QEMU processes (which indicate nested VMs)."""
        output = self._run_command(
            instance_id,
            ["ps aux | grep -E '(qemu-system|kvm|pve-manager)' | grep -v grep | head -10"],
        )
        if not output:
            return []

        processes = []
        for line in output.strip().split("\n"):
            if line.strip():
                processes.append(line.strip())
        return processes

    def _get_network_bridges(self, instance_id: str) -> List[str]:
        """List all network bridges (vmbr0, vmbr1 indicate Proxmox setup)."""
        output = self._run_command(
            instance_id,
            ["brctl show 2>/dev/null || ip link show type bridge | grep -o '^[a-z0-9]*'"],
        )
        if not output:
            return []

        bridges = []
        for line in output.strip().split("\n"):
            bridge = line.strip().split()[0] if line.strip() else ""
            if bridge and bridge.startswith("vmbr"):
                bridges.append(bridge)
        return bridges

    def _get_proxmox_storage(self, instance_id: str) -> List[str]:
        """Check for Proxmox storage evidence."""
        output = self._run_command(
            instance_id,
            [
                "ls -la /etc/pve 2>/dev/null | head -3 && "
                "ls -la /var/lib/vz 2>/dev/null | head -3 && "
                "df -h | grep -E '/(vz|pve)' | head -3"
            ],
        )
        if not output:
            return []

        evidence = []
        for line in output.strip().split("\n"):
            if line.strip() and any(x in line for x in ["/pve", "/vz", "proxmox"]):
                evidence.append(line.strip())
        return evidence

    def _get_running_vms(self, instance_id: str) -> List[Dict]:
        """List running VMs (Proxmox resources)."""
        output = self._run_command(
            instance_id,
            ["pvesh get /nodes/$(hostname)/qemu --quiet 2>/dev/null || echo 'N/A'"],
        )
        if not output or output.strip() == "N/A":
            return []

        try:
            vms = json.loads(output)
            return [
                {
                    "vmid": vm.get("vmid"),
                    "name": vm.get("name"),
                    "status": vm.get("status"),
                }
                for vm in vms
            ]
        except json.JSONDecodeError:
            return []


def format_inspection_report(results: Dict) -> str:
    """Format inspection results for display."""
    report = []
    report.append(f"\n{'=' * 70}")
    report.append(f"PROXMOX DEEP INSPECTION: {results['instance_id']}")
    report.append(f"{'=' * 70}\n")

    if not results["accessible"]:
        report.append("❌ NOT ACCESSIBLE via Systems Manager")
        for err in results["errors"]:
            report.append(f"  Error: {err}")
        return "\n".join(report)

    report.append(
        f"✓ Proxmox Installed: {'YES ⚠️' if results['is_proxmox_installed'] else 'NO ✓'}"
    )

    if results["kvm_processes"]:
        report.append(f"\n🔴 RUNNING KVM/QEMU PROCESSES ({len(results['kvm_processes'])}):")
        for proc in results["kvm_processes"][:5]:  # Show first 5
            report.append(f"  {proc[:100]}")
        if len(results["kvm_processes"]) > 5:
            report.append(f"  ... and {len(results['kvm_processes']) - 5} more")

    if results["network_bridges"]:
        report.append(f"\n🌉 NETWORK BRIDGES (for nested guests):")
        for bridge in results["network_bridges"]:
            report.append(f"  {bridge}")

    if results["storage_evidence"]:
        report.append(f"\n💾 PROXMOX STORAGE EVIDENCE:")
        for evidence in results["storage_evidence"][:3]:
            report.append(f"  {evidence[:100]}")

    if results["running_vms"]:
        report.append(f"\n🖥️ RUNNING VIRTUAL MACHINES ({len(results['running_vms'])}):")
        for vm in results["running_vms"]:
            report.append(
                f"  VM {vm['vmid']:4s}: {vm['name']:30s} ({vm['status']})"
            )

    if not results["is_proxmox_installed"]:
        report.append("\n✓ No evidence of Proxmox/nested virtualization detected.")

    report.append(f"\n{'=' * 70}\n")
    return "\n".join(report)


# Example usage
if __name__ == "__main__":
    import boto3
    import sys

    if len(sys.argv) < 2:
        print("Usage: python3 proxmox_deep_inspect.py <instance-id> [region]")
        sys.exit(1)

    instance_id = sys.argv[1]
    region = sys.argv[2] if len(sys.argv) > 2 else "us-east-1"

    ssm = boto3.client("ssm", region_name=region)
    ec2 = boto3.client("ec2", region_name=region)

    inspector = ProxmoxDeepInspector(ssm, ec2)
    results = inspector.inspect_instance(instance_id)

    print(format_inspection_report(results))

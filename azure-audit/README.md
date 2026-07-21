# Azure Security Audit

A read-only Python script that scans an Azure subscription for common
RBAC, networking (NSG/VNet), and VM misconfigurations, and specifically
looks for signs of **Proxmox VE** running on Azure VMs.

## What it checks

### RBAC (Azure's IAM equivalent)
- Owner/Contributor role assignments made directly at subscription scope
  (flags User principals more strongly than Group/ServicePrincipal)
- Reminder that MFA/Conditional Access enforcement must be checked
  separately in Microsoft Entra ID — Azure Resource Manager APIs used
  here cannot read Conditional Access policy directly

### Networking / NSGs
- NSG rules allowing **all ports** inbound from any source
- Sensitive ports (SSH 22, RDP 3389, DB ports, VNC, Redis, Elasticsearch,
  **Proxmox 8006/8007/3128**) open from `*`/`Internet`/`0.0.0.0/0`
- Subnets with no NSG associated
- Inventory of allocated public IP addresses (informational — confirm
  each is still required)

### Virtual Machines
- OS disk encryption explicitly disabled
- **Proxmox detection**, combining several signals:
  - VM name/tags mentioning proxmox/pve/qemu-server
  - VM image reference (publisher/offer/sku) mentioning Proxmox
  - VM custom_data / cloud-init script referencing a Proxmox install
  - Associated NSG exposing port 8006 (Proxmox's default web GUI port)
  - Flagged **HIGH**, and **CRITICAL** if the VM also has a public IP

## Output

Findings print to console sorted by severity
(`CRITICAL > HIGH > MEDIUM > LOW > INFO`), and can be written to JSON with
`--output report.json`.

## Scope & limitations

- **Read-only.** Only `list`/`get` calls against ARM management APIs —
  never modifies anything.
- Covers a single subscription per run; loop the script across
  subscriptions for a tenant-wide sweep.
- MFA/Conditional Access and Microsoft Entra ID sign-in risk checks are
  **not** covered — those require Microsoft Graph API permissions
  (`Policy.Read.All`) which are intentionally out of scope for a
  lightweight, low-privilege audit script. See `HOW_TO_RUN.md` for how to
  extend this if you have Graph access.
- Proxmox detection is heuristic (tags, image metadata, custom-data, open
  port 8006). Treat hits as **candidates for manual review**.

See `HOW_TO_RUN.md` for setup and required role assignment.

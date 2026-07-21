# How to Run — Azure Audit

## 1. Prerequisites
- Python 3.8+
- Azure CLI installed (`az` command available), or another credential
  source supported by `DefaultAzureCredential`
- An identity with the built-in **Reader** role (or a custom read-only
  role) at the subscription scope you want to audit. RBAC listing also
  requires the identity itself to have permission to read role
  assignments — Reader is sufficient for this.

## 2. Install dependencies
```bash
pip install -r requirements.txt
```

## 3. Authenticate

Simplest option — interactive login via Azure CLI:
```bash
az login
az account set --subscription "<subscription-id-or-name>"
```

`DefaultAzureCredential` will pick this up automatically. Alternatively,
for automation/service principals:
```bash
export AZURE_CLIENT_ID=...
export AZURE_CLIENT_SECRET=...
export AZURE_TENANT_ID=...
```

## 4. Run the audit
```bash
python3 audit_azure.py --subscription-id <SUBSCRIPTION_ID>
```

Save a JSON report:
```bash
python3 audit_azure.py --subscription-id <SUBSCRIPTION_ID> --output azure-report.json
```

## 5. Auditing multiple subscriptions

Loop over subscriptions (e.g., in bash):
```bash
for sub in $(az account list --query "[].id" -o tsv); do
  python3 audit_azure.py --subscription-id "$sub" --output "report-$sub.json"
done
```

## 6. Interpreting output
- Findings print sorted by severity with a resource identifier and
  remediation guidance.
- `Proxmox` category findings need manual verification — check with the
  resource owner or connect to the VM to confirm whether Proxmox VE is
  actually installed and whether it's an approved deployment.
- The RBAC section always emits one `INFO` reminder that MFA/Conditional
  Access must be checked separately in Microsoft Entra ID, since that
  data isn't reachable through the ARM read-only permissions this script
  uses.

## Notes for Azure Government / FedRAMP environments
- Point the Azure CLI at the correct cloud before logging in:
```bash
  az cloud set --name AzureUSGovernment
  az login
```
- `DefaultAzureCredential` and the management SDKs used here work
  unmodified against Azure Government endpoints once the CLI/environment
  is scoped to that cloud.

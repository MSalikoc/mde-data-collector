# Microsoft Defender for Endpoint — Data Collector

A read-only PowerShell collector for Microsoft Defender for Endpoint health checks.

It signs in with your own account (device code), reads configuration and posture data through the Microsoft Graph and Defender APIs, and writes **a single JSON file**. Nothing is changed in the tenant, and no report or other artefact is produced.

You hand that JSON file to whoever is performing the health check.

| File | Purpose |
|---|---|
| `New-MdeApp.ps1` | One-time setup: creates the Entra app registration with the read-only permissions |
| `MDE-Collect.ps1` | Collects the data → `mde-data-<tenant>-<date>.json` |
| `Test-Parse.ps1` | Syntax check, useful when troubleshooting |

---

## What it reads

Device inventory and sensor health, antivirus and attack surface reduction configuration, security configuration assessment, vulnerabilities and exposure score, Microsoft Secure Score, alerts and incidents of the last 90 days, custom detection rules, licence inventory, Intune endpoint security policies, privileged role membership and Conditional Access policy state.

## What it does not do

- No write, update or delete calls. Every request is a read.
- No changes to policy, configuration or devices.
- No data is sent anywhere. The JSON is written to the folder you run it from and stays on your machine until you send it.

---

## Step 1 · Prerequisites

**PowerShell 7+.** The "Windows PowerShell 5.1" that ships with Windows (blue icon) cannot run these scripts.

```powershell
winget install --id Microsoft.PowerShell --source winget
```

Open a **new PowerShell 7 window** (black icon, `pwsh`) and check:

```powershell
$PSVersionTable.PSVersion
```

`Major` must be 7 or above.

Unblock the downloaded scripts and allow them to run in this session:

```powershell
Get-ChildItem *.ps1 | Unblock-File
```

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
```

Optional sanity check:

```powershell
.\Test-Parse.ps1
```

### Accounts and roles

| Role | Needed for |
|---|---|
| **Security Reader** | Defender data: alerts, incidents, Secure Score, vulnerabilities, Advanced Hunting |
| **Global Reader** | Licences, directory roles, Conditional Access, Intune policies |
| **Global Administrator** | Step 2 only (app registration and consent), one time |

> If Defender RBAC is enabled, the account must have access to all device groups. Otherwise the inventory and vulnerability figures come back partial.

## Step 2 · App registration (one time)

The collector authenticates as a public client. Create the registration and grant consent with one command:

```powershell
.\New-MdeApp.ps1 -TenantId YOUR-TENANT-ID
```

Replace `YOUR-TENANT-ID` with your tenant GUID or `contoso.onmicrosoft.com`. Do not wrap it in `< >` — in a shell those are redirection operators.

A device code appears; sign in at <https://microsoft.com/devicelogin> with a **Global Administrator** account. The script creates the app, enables public client flows, adds the delegated permissions below, grants admin consent and writes the client ID to `.mde-app.json`.

It is idempotent — running it again reuses the existing registration and fills in anything missing.

### Permissions requested (all delegated, all read-only)

**Microsoft Graph:** `ThreatHunting.Read.All`, `SecurityEvents.Read.All`, `SecurityAlert.Read.All`, `SecurityIncident.Read.All`, `CustomDetection.Read.All`, `DeviceManagementConfiguration.Read.All`, `Directory.Read.All`, `Organization.Read.All`, `Policy.Read.All`, `RoleManagement.Read.Directory`

**WindowsDefenderATP:** `Vulnerability.Read`, `SecurityRecommendation.Read`, `Score.Read`, `Ti.Read`, `Machine.Read`, `AdvancedQuery.Read`

If your organisation prefers to create the registration by hand, do that instead and pass `-ClientId <app-id>` to the collector.

## Step 3 · Collect

```powershell
.\MDE-Collect.ps1 -TenantId YOUR-TENANT-ID
```

Sign in with the **Security Reader + Global Reader** account when the device code appears.

Output: `mde-data-<tenant>-<date>.json` in the current folder. The console prints what was collected and any section that was skipped.

A quick first run to confirm permissions before the full collection:

```powershell
.\MDE-Collect.ps1 -TenantId YOUR-TENANT-ID -GraphOnly -AlertDays 7 -EventDays 7
```

### Parameters

| Parameter | Description |
|---|---|
| `-TenantId` | Tenant GUID or `xxx.onmicrosoft.com` (required) |
| `-ClientId` | App registration ID (read from `.mde-app.json` when omitted) |
| `-OutFile` | Output path (defaults to `mde-data-<tenant>-<date>.json`) |
| `-GraphOnly` | Skip the `api.securitycenter.microsoft.com` calls |
| `-AlertDays 90` / `-EventDays 30` | Telemetry windows |
| `-RawDumpPath .\raw` | Write the raw output of every API and KQL call to disk. Troubleshooting only — it contains device and user names |
| `-Verbose` | Detailed progress |

## Step 4 · Hand over the JSON

Send `mde-data-<tenant>-<date>.json` to the assessor. It is plain text — open it and review the contents before sending if you wish.

---

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `#Requires -Version 7.0` or syntax errors | You are on Windows PowerShell 5.1 → open `pwsh` |
| `... is not digitally signed` | `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force` |
| `no such file or directory: <tenant>` | Remove the `< >` characters — they were placeholders |
| `AADSTS65001` / `invalid_client` | App registration missing or consent not granted → Step 2 |
| Most calls return `403` | The token has no Defender permissions → Step 2. The script lists what is missing before it starts |
| `403` only on securitycenter calls | Continue with `-GraphOnly`; the exposure score will be absent |
| Advanced Hunting returns nothing | `ThreatHunting.Read.All` consent missing, or Defender RBAC is restricting the account |
| Alert collection takes too long | Use `-AlertDays 30` |

## Notes

- Advanced Hunting retains 30 days of data, so longer trends are not available.
- Configuration applied through Group Policy rather than Intune is not visible to the collector.
- Any section that fails is skipped; the failure is recorded in the JSON under `meta.warnings`.

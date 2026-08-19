# Microsoft Defender for Endpoint — Data Collector

A read-only PowerShell collector for Microsoft Defender for Endpoint health checks.

It signs in with your own account (device code), reads configuration and posture data through the Microsoft Graph and Defender APIs, and writes **a single JSON file**. Nothing is changed in the tenant, and no report or other artefact is produced.

You hand that JSON file to whoever is performing the health check.

## The whole thing, in order

Run these in **PowerShell 7** (`pwsh`, black icon). Replace `YOUR-TENANT-ID` with the tenant GUID or
`contoso.onmicrosoft.com` — without the `< >` brackets, which a shell treats as redirection.

```powershell
git clone https://github.com/MSalikoc/mde-data-collector.git
```

```powershell
cd mde-data-collector
```

```powershell
Get-ChildItem *.ps1 | Unblock-File; Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
```

```powershell
.\New-MdeApp.ps1 -TenantId YOUR-TENANT-ID -AppOnly
```

```powershell
.\MDE-Collect.ps1 -TenantId YOUR-TENANT-ID
```

That is the entire collection. Step 4 leaves a single `mde-data-<tenant>-<date>.json` next to the
scripts; send that file and nothing else. The sections below explain each step, the permissions
involved and what to do when one of them fails.

> `-AppOnly` is included above because tenants that enforce device-based Conditional Access need it
> and tenants that do not are unaffected by it. It requires a **Global Administrator** for that one
> command. See [Step 3](#step-3--app-registration-one-time).

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

## Step 1 · Get the files

```powershell
git clone https://github.com/MSalikoc/mde-data-collector.git
```

```powershell
cd mde-data-collector
```

No git on the machine? Download the ZIP from the repository's **Code → Download ZIP** button and
extract it. Windows extracts into a folder that contains *another* folder of the same name, so the
scripts end up one level deeper than expected — `cd` until `dir` actually lists `MDE-Collect.ps1`
before running anything.

```powershell
dir *.ps1
```

You should see `MDE-Collect.ps1`, `New-MdeApp.ps1` and `Test-Parse.ps1`. If the list is empty you are
in the wrong folder, and every command below will fail with *"is not recognized as a name of a cmdlet,
function, script file, or executable program"*.

## Step 2 · Prerequisites

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
| **Global Administrator** | Step 3 only (app registration and consent), one time |

> If Defender RBAC is enabled, the account must have access to all device groups. Otherwise the inventory and vulnerability figures come back partial.

## Step 3 · App registration (one time)

The collector authenticates as a public client. Create the registration and grant consent with one command:

```powershell
.\New-MdeApp.ps1 -TenantId YOUR-TENANT-ID
```

Replace `YOUR-TENANT-ID` with your tenant GUID or `contoso.onmicrosoft.com`. Do not wrap it in `< >` — in a shell those are redirection operators.

A device code appears; sign in at <https://microsoft.com/devicelogin> with a **Global Administrator** account. The script creates the app, enables public client flows, adds the delegated permissions below, grants admin consent and writes the client ID to `.mde-app.json`.

It is idempotent — running it again reuses the existing registration and fills in anything missing.

> **If the tenant enforces device-based Conditional Access, add `-AppOnly` now** rather than waiting for the collection to fail. A device code sign-in cannot satisfy a policy that requires a registered or compliant device, and four of the Defender datasets will fail with `AADSTS50131`. See [app-only mode](#if-exposure-score-recommendations-and-indicators-come-back-empty) below. Adding it costs nothing if the tenant turns out not to need it.

### Permissions requested by the default run (delegated, read-only)

These are what a plain `New-MdeApp.ps1` asks for. `-AppOnly` adds application roles on top; they are listed separately below because one of them is not read-only.

**Microsoft Graph:** `ThreatHunting.Read.All`, `SecurityEvents.Read.All`, `SecurityAlert.Read.All`, `SecurityIncident.Read.All`, `CustomDetection.Read.All`, `DeviceManagementConfiguration.Read.All`, `Directory.Read.All`, `Organization.Read.All`, `Policy.Read.All`, `RoleManagement.Read.Directory`

**WindowsDefenderATP:** `Vulnerability.Read`, `SecurityRecommendation.Read`, `Score.Read`, `Ti.Read`, `Machine.Read`, `AdvancedQuery.Read`

If your organisation prefers to create the registration by hand, do that instead and pass `-ClientId <app-id>` to the collector.

### If exposure score, recommendations and indicators come back empty

Those three come from `api.securitycenter.microsoft.com`. In tenants with a Conditional Access policy that requires a registered or compliant device, a token for that resource cannot be issued to a device code sign-in - the flow has no device state to present, so it fails with `AADSTS50131: Device is not in required device state`. Everything else still collects normally.

Device-state policies apply to user sign-ins, not to application identities. Run the registration once more in app-only mode:

```powershell
.\New-MdeApp.ps1 -TenantId YOUR-TENANT-ID -AppOnly
```

This adds the Defender **application** permissions, grants admin consent for them and creates a client secret, which it writes to `.mde-app.json`. The collector picks it up automatically and uses it for the Defender API only; the rest of the collection still runs as the signed-in user.

| Application permission | Used for |
|---|---|
| `Score.Read.All` | exposure score, configuration score |
| `SecurityRecommendation.Read.All` | security recommendations |
| `SecurityConfiguration.Read.All` | secure configuration assessment |
| `Vulnerability.Read.All` | vulnerable software and CVEs |
| `Machine.Read.All` | device inventory |
| `AdvancedQuery.Read.All` | Advanced Hunting |
| `Ti.ReadWrite.All` | threat indicators |

Watch the console: it prints `N uygulama izni atandi (toplam 7)`. If N is not 7, or a permission is listed as skipped, stop there — consent is incomplete and the data will not arrive.

> **`Ti.ReadWrite.All` is a read-write permission and your security team will see it on the consent screen.** WindowsDefenderATP publishes no read-only *application* role for indicators — the read-only `Ti.Read` exists for delegated access only. The collector never writes; if granting write is unacceptable, remove `Ti.ReadWrite.All` from `$MDE_ROLES` in `New-MdeApp.ps1` and the indicator section stays empty while everything else still collects.

> `.mde-app.json` now contains a credential to the tenant. It is excluded by `.gitignore`. Delete the app registration when the engagement is finished.

### If a section comes back empty rather than failing

An empty result is not the same as a blocked one, and it is the more dangerous of the two: a report that says "no security recommendations" reads as good news. If **Defender RBAC** is enabled, the collecting identity — user or application — must be scoped to all device groups, otherwise the API answers successfully with nothing. The collector now says so when recommendations come back empty. Widen the scope and collect again before accepting a zero.

## Step 4 · Collect

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

## Step 5 · Hand over the JSON

Send `mde-data-<tenant>-<date>.json` to the assessor. It is plain text — open it and review the contents before sending if you wish.

---

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `.\New-MdeApp.ps1 ... is not recognized as a name of a cmdlet` | You are not in the folder that holds the scripts. Run `dir *.ps1` — if it lists nothing, `cd` into the extracted folder (a ZIP download nests a second folder of the same name inside the first). The scripts are **only** in this repository; the health-check repository holds the renderer and no collector |
| `#Requires -Version 7.0` or syntax errors | You are on Windows PowerShell 5.1 → open `pwsh` |
| `... is not digitally signed` | `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force` |
| `no such file or directory: <tenant>` | Remove the `< >` characters — they were placeholders |
| `AADSTS65001` / `invalid_client` | App registration missing or consent not granted → Step 3 |
| Most calls return `403` | The token has no Defender permissions → Step 3. The script lists what is missing before it starts |
| `403` only on securitycenter calls | Continue with `-GraphOnly`; the exposure score will be absent |
| `AADSTS50131: Device is not in required device state` | A Conditional Access policy requires a registered or compliant device, which a device code sign-in can never present. Re-run Step 3 with `-AppOnly` — application identities have no device to evaluate. Being excluded from *a* policy is not enough: another policy may scope the Defender app specifically. To find which one, search the Entra sign-in logs by the Correlation ID printed in the error and read the Conditional Access tab |
| Same error *with* a client secret in place | The secret has expired or consent was never granted for the application permissions → re-run `New-MdeApp.ps1 -AppOnly` |
| Recommendations or indicators return zero rows | Not a permission problem — see [empty rather than failing](#if-a-section-comes-back-empty-rather-than-failing) |
| Advanced Hunting returns nothing | `ThreatHunting.Read.All` consent missing, or Defender RBAC is restricting the account |
| `Giris basarisiz (HTTP ...)` during the app registration | The token endpoint could not be reached three times running — usually a corporate proxy or TLS inspection sitting in front of `login.microsoftonline.com`. The message now carries the underlying network error |
| `Giris basarisiz (invalid_client)` / `(unauthorized_client)` | The tenant does not allow the default bootstrap app (Azure CLI). Register your own public client and pass `-BootstrapClientId <app-id>` |
| Alert collection takes too long | Use `-AlertDays 30` |

## Notes

- Advanced Hunting retains 30 days of data, so longer trends are not available.
- Configuration applied through Group Policy rather than Intune is not visible to the collector.
- Any section that fails is skipped; the failure is recorded in the JSON under `meta.warnings`.

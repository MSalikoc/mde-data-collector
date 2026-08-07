#Requires -Version 7.0
<#
.SYNOPSIS
    ON ADIM: Veri toplama icin gereken Entra app kaydini otomatik olusturur.

.DESCRIPTION
    Elle portal gezmeye gerek kalmadan sunlari yapar:
      1. Public client (device code) app kaydi olusturur
      2. Gerekli delegated izinleri ekler (Microsoft Graph + WindowsDefenderATP)
      3. Admin consent verir (oauth2PermissionGrant)
      4. Client ID'yi .mde-app.json dosyasina yazar

    Idempotent: ayni isimde app varsa yeniden olusturmaz, eksik izinleri tamamlar.

    Calistiran hesap Global Administrator (veya Application Administrator +
    Privileged Role Administrator) olmalidir — consent icin gerekli.

.EXAMPLE
    .\New-MdeApp.ps1 -TenantId contoso.onmicrosoft.com

.EXAMPLE
    .\New-MdeApp.ps1 -TenantId YOUR-TENANT-ID -Name "MDE Data Collector - Contoso"
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$TenantId,
    [string]$Name = 'MDE Health Check Collector',

    # Defender API'si icin uygulama kimligi (client credentials).
    # Cihaz durumu sarti koyan Conditional Access politikalari app-only
    # token'lara uygulanmaz - exposure score / oneriler / indicator'lar
    # ancak bu modda alinabilir.
    [switch]$AppOnly,
    [int]$SecretMonths = 12,

    # Kaydi olusturmak icin kullanilan public client (Azure CLI).
    # Bu adimda yalnizca dizin yazma yetkisi gerekir; sonrasinda kullanilmaz.
    [string]$BootstrapClientId = '04b07795-8ddb-461a-bbee-02f9e1bf7b46',

    [string]$OutFile = './.mde-app.json'
)

$ErrorActionPreference = 'Stop'
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch { }

$GRAPH_APPID = '00000003-0000-0000-c000-000000000000'
$MDE_APPID   = 'fc780465-2017-40d4-a0c5-307022471b92'

# Toplayicinin ihtiyac duydugu delegated izinler
$GRAPH_SCOPES = @(
    'ThreatHunting.Read.All'
    'SecurityEvents.Read.All'
    'SecurityAlert.Read.All'
    'SecurityIncident.Read.All'
    'CustomDetection.Read.All'
    'DeviceManagementConfiguration.Read.All'
    'Directory.Read.All'
    'Organization.Read.All'
    'Policy.Read.All'
    'RoleManagement.Read.Directory'
)
# App-only modda kullanilan Application izinleri (delegated karsiliklarindan farkli)
$MDE_ROLES = @(
    'Vulnerability.Read.All'
    'SecurityRecommendation.Read.All'
    'Score.Read.All'
    'Ti.ReadWrite.All'
    'Machine.Read.All'
    'AdvancedQuery.Read.All'
    'SecurityConfiguration.Read.All'
)
$MDE_SCOPES = @(
    'Vulnerability.Read'
    'SecurityRecommendation.Read'
    'Score.Read'
    'Ti.Read'
    'Machine.Read'
    'AdvancedQuery.Read'
)

function Write-Step {
    param([string]$m)
    Write-Host "  -> $m" -ForegroundColor Cyan
}
function Write-Ok {
    param([string]$m)
    Write-Host "  OK $m" -ForegroundColor Green
}
function Write-Warn {
    param([string]$m)
    Write-Host "  !  $m" -ForegroundColor Yellow
}

# ------------------------------------------------------------------ AUTH --
function Get-GraphToken {
    $body = @{
        client_id = $BootstrapClientId
        scope     = 'https://graph.microsoft.com/.default offline_access'
    }
    $dc = Invoke-RestMethod -Method Post -Body $body `
        -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/devicecode"

    Write-Host ''
    Write-Host '  ------------------------------------------------------------' -ForegroundColor Yellow
    Write-Host "  $($dc.message)" -ForegroundColor Yellow
    Write-Host '  Global Administrator hesabiyla giris yapin.' -ForegroundColor Yellow
    Write-Host '  ------------------------------------------------------------' -ForegroundColor Yellow
    Write-Host ''

    $deadline = (Get-Date).AddSeconds([int]$dc.expires_in)
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Seconds ([int]$dc.interval + 1)
        try {
            $tok = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" -Body @{
                client_id   = $BootstrapClientId
                grant_type  = 'urn:ietf:params:oauth:grant-type:device_code'
                device_code = $dc.device_code
            }
            return $tok.access_token
        }
        catch {
            $err = $null
            try { $err = ($_.ErrorDetails.Message | ConvertFrom-Json).error } catch { }
            if ($err -eq 'authorization_pending') { continue }
            if ($err -eq 'slow_down') { Start-Sleep 5; continue }
            throw "Giris basarisiz: $err"
        }
    }
    throw 'Cihaz kodu zaman asimina ugradi.'
}

function Invoke-Graph {
    param(
        [string]$Uri,
        [string]$Method = 'GET',
        $Body
    )
    $headers = @{ Authorization = "Bearer $script:Token"; 'Content-Type' = 'application/json' }
    $p = @{ Uri = $Uri; Method = $Method; Headers = $headers }
    if ($Body) { $p.Body = ($Body | ConvertTo-Json -Depth 10) }
    return Invoke-RestMethod @p
}

Write-Host ''
Write-Host ' MDE Health Check - Entra app kaydi (on adim)' -ForegroundColor White
Write-Host ' ---------------------------------------------------------' -ForegroundColor DarkGray

$script:Token = Get-GraphToken
Write-Ok 'Oturum acildi'

# ------------------------------------------------- KAYNAK SP + IZIN ID'LERI
Write-Step 'Izin tanimlari okunuyor'

function Get-ResourceSp {
    param([string]$AppId, [string]$Label)
    $sp = (Invoke-Graph -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '$AppId'").value
    if (-not $sp -or $sp.Count -eq 0) {
        Write-Warn "$Label service principal yok, olusturuluyor"
        try {
            $sp = @(Invoke-Graph -Uri 'https://graph.microsoft.com/v1.0/servicePrincipals' -Method POST -Body @{ appId = $AppId })
        }
        catch {
            Write-Warn "$Label service principal olusturulamadi: $($_.Exception.Message)"
            return $null
        }
    }
    return $sp[0]
}

$graphSp = Get-ResourceSp -AppId $GRAPH_APPID -Label 'Microsoft Graph'
$mdeSp   = Get-ResourceSp -AppId $MDE_APPID   -Label 'WindowsDefenderATP'
if (-not $graphSp) { throw 'Microsoft Graph service principal bulunamadi.' }

function Resolve-Scopes {
    param($Sp, [string[]]$Names, [string]$Label)
    $found = @()
    $miss = @()
    foreach ($n in $Names) {
        $s = $Sp.oauth2PermissionScopes | Where-Object { $_.value -eq $n } | Select-Object -First 1
        if ($s) { $found += [pscustomobject]@{ name = $n; id = $s.id } } else { $miss += $n }
    }
    if ($miss.Count -gt 0) { Write-Warn "$Label - bulunamayan izinler atlandi: $($miss -join ', ')" }
    return $found
}

function Resolve-Roles {
    param($Sp, [string[]]$Names, [string]$Label)
    $found = @(); $miss = @()
    foreach ($n in $Names) {
        $r = $Sp.appRoles | Where-Object { $_.value -eq $n } | Select-Object -First 1
        if ($r) { $found += [pscustomobject]@{ name = $n; id = $r.id } } else { $miss += $n }
    }
    if ($miss.Count -gt 0) { Write-Warn "$Label (app-only) - bulunamayan izinler atlandi: $($miss -join ', ')" }
    return $found
}

$graphPerms = Resolve-Scopes -Sp $graphSp -Names $GRAPH_SCOPES -Label 'Microsoft Graph'
$mdePerms = @()
if ($mdeSp) { $mdePerms = Resolve-Scopes -Sp $mdeSp -Names $MDE_SCOPES -Label 'WindowsDefenderATP' }
Write-Ok "Graph: $($graphPerms.Count) izin, Defender: $($mdePerms.Count) izin"

# --------------------------------------------------------------- APP KAYDI
Write-Step "App kaydi: $Name"

$rra = @()
$rra += @{
    resourceAppId  = $GRAPH_APPID
    resourceAccess = @($graphPerms | ForEach-Object { @{ id = $_.id; type = 'Scope' } })
}
$mdeRoles = @()
if ($AppOnly -and $mdeSp) {
    $mdeRoles = Resolve-Roles -Sp $mdeSp -Names $MDE_ROLES -Label 'WindowsDefenderATP'
    Write-Ok "App-only modu: $($mdeRoles.Count) uygulama izni"
}
if ($mdePerms.Count -gt 0 -or $mdeRoles.Count -gt 0) {
    $access = @()
    $access += @($mdePerms  | ForEach-Object { @{ id = $_.id; type = 'Scope' } })
    $access += @($mdeRoles  | ForEach-Object { @{ id = $_.id; type = 'Role' } })
    $rra += @{ resourceAppId = $MDE_APPID; resourceAccess = $access }
}

$escaped = $Name.Replace("'", "''")
$existing = (Invoke-Graph -Uri "https://graph.microsoft.com/v1.0/applications?`$filter=displayName eq '$escaped'").value

if ($existing -and $existing.Count -gt 0) {
    $app = $existing[0]
    Write-Warn "Ayni isimde app zaten var (appId $($app.appId)) - izinler guncelleniyor"
    Invoke-Graph -Uri "https://graph.microsoft.com/v1.0/applications/$($app.id)" -Method PATCH -Body @{
        isFallbackPublicClient = $true
        requiredResourceAccess = $rra
    } | Out-Null
}
else {
    $app = Invoke-Graph -Uri 'https://graph.microsoft.com/v1.0/applications' -Method POST -Body @{
        displayName            = $Name
        signInAudience         = 'AzureADMyOrg'
        isFallbackPublicClient = $true          # public client flows = Yes
        requiredResourceAccess = $rra
        publicClient           = @{ redirectUris = @('http://localhost') }
    }
    Write-Ok "App olusturuldu: $($app.appId)"
}

# ------------------------------------------------------ SERVICE PRINCIPAL -
Write-Step 'Service principal'
$appSp = (Invoke-Graph -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '$($app.appId)'").value
if (-not $appSp -or $appSp.Count -eq 0) {
    $created = $false
    foreach ($try in 1..6) {
        try {
            $appSp = @(Invoke-Graph -Uri 'https://graph.microsoft.com/v1.0/servicePrincipals' -Method POST -Body @{ appId = $app.appId })
            $created = $true
            break
        }
        catch {
            Start-Sleep -Seconds 5   # yeni app'in yayilmasini bekle
        }
    }
    if (-not $created) { throw 'Service principal olusturulamadi (app henuz yayilmamis olabilir, script i yeniden calistirin).' }
}
$spId = $appSp[0].id
Write-Ok "Service principal: $spId"

# -------------------------------------------------------- ADMIN CONSENT ---
Write-Step 'Admin consent veriliyor'

function Grant-Consent {
    param($ResourceSp, $Perms, [string]$Label)
    if (-not $ResourceSp -or $Perms.Count -eq 0) { return }
    $scopeText = ($Perms.name -join ' ')

    $current = (Invoke-Graph -Uri "https://graph.microsoft.com/v1.0/oauth2PermissionGrants?`$filter=clientId eq '$spId' and resourceId eq '$($ResourceSp.id)'").value

    try {
        if ($current -and $current.Count -gt 0) {
            $merged = (($current[0].scope -split ' ') + $Perms.name | Where-Object { $_ } | Sort-Object -Unique) -join ' '
            Invoke-Graph -Uri "https://graph.microsoft.com/v1.0/oauth2PermissionGrants/$($current[0].id)" -Method PATCH -Body @{ scope = $merged } | Out-Null
            Write-Ok "$Label - consent guncellendi"
        }
        else {
            Invoke-Graph -Uri 'https://graph.microsoft.com/v1.0/oauth2PermissionGrants' -Method POST -Body @{
                clientId    = $spId
                consentType = 'AllPrincipals'
                resourceId  = $ResourceSp.id
                scope       = $scopeText
            } | Out-Null
            Write-Ok "$Label - consent verildi"
        }
    }
    catch {
        Write-Warn "$Label - consent verilemedi: $($_.Exception.Message)"
        Write-Warn 'Hesabiniz Global Administrator degilse portaldan "Grant admin consent" butonuna basilmalidir.'
    }
}

# --- app-only: uygulama izinlerine admin consent (appRoleAssignment) ---
function Grant-AppRoles {
    param($ResourceSp, $Roles, [string]$Label)
    if (-not $ResourceSp -or $Roles.Count -eq 0) { return }
    $existing = @()
    try { $existing = (Invoke-Graph -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$spId/appRoleAssignments").value } catch { }
    $added = 0
    foreach ($r in $Roles) {
        if ($existing | Where-Object { $_.appRoleId -eq $r.id -and $_.resourceId -eq $ResourceSp.id }) { continue }
        try {
            Invoke-Graph -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$spId/appRoleAssignments" -Method POST -Body @{
                principalId = $spId
                resourceId  = $ResourceSp.id
                appRoleId   = $r.id
            } | Out-Null
            $added++
        }
        catch { Write-Warn "$Label - $($r.name) atanamadi: $($_.Exception.Message)" }
    }
    Write-Ok "$Label - $added uygulama izni atandi (toplam $($Roles.Count))"
}

Grant-Consent -ResourceSp $graphSp -Perms $graphPerms -Label 'Microsoft Graph'
Grant-Consent -ResourceSp $mdeSp   -Perms $mdePerms   -Label 'WindowsDefenderATP'

if ($AppOnly) {
    Grant-AppRoles -ResourceSp $mdeSp -Roles $mdeRoles -Label 'WindowsDefenderATP'

    Write-Step 'Client secret olusturuluyor'
    $secret = $null
    try {
        $pw = Invoke-Graph -Uri "https://graph.microsoft.com/v1.0/applications/$($app.id)/addPassword" -Method POST -Body @{
            passwordCredential = @{
                displayName   = 'MDE collector'
                endDateTime   = (Get-Date).AddMonths($SecretMonths).ToUniversalTime().ToString('o')
            }
        }
        $secret = $pw.secretText
        Write-Ok "Secret olusturuldu, $SecretMonths ay gecerli"
    }
    catch {
        Write-Warn "Secret olusturulamadi: $($_.Exception.Message)"
    }
}

# ------------------------------------------------------------------ CIKTI -
$result = [ordered]@{
    authMode    = $(if ($AppOnly) { 'appOnly' } else { 'deviceCode' })
    clientId    = $app.appId
    objectId    = $app.id
    displayName = $Name
    tenantId    = $TenantId
    createdUtc  = (Get-Date).ToUniversalTime().ToString('u')
    graphScopes = @($graphPerms.name)
    mdeScopes   = @($mdePerms.name)
    mdeRoles    = @($mdeRoles.name)
    clientSecret = $secret
    secretExpires = $(if ($secret) { (Get-Date).AddMonths($SecretMonths).ToString('yyyy-MM-dd') } else { $null })
}
$result | ConvertTo-Json -Depth 5 | Set-Content -Path $OutFile -Encoding utf8

Write-Host ''
Write-Host '  ============================================================' -ForegroundColor Green
Write-Host "   Client ID: $($app.appId)" -ForegroundColor White
Write-Host "   Written to $OutFile - MDE-Collect.ps1 reads it automatically" -ForegroundColor DarkGray
Write-Host '  ============================================================' -ForegroundColor Green
Write-Host ''
Write-Host '  Simdi calistirin:' -ForegroundColor White
Write-Host "   .\MDE-Collect.ps1 -TenantId $TenantId" -ForegroundColor Gray
Write-Host ''
Write-Host '  Not: consent yeni verildiyse yayilmasi 1-2 dakika surebilir.' -ForegroundColor DarkGray
if ($AppOnly -and $secret) {
    Write-Host ''
    Write-Host '  ! .mde-app.json artik bir client secret iceriyor - musteri tenantina' -ForegroundColor Yellow
    Write-Host '    erisim saglar. Engagement bitince app kaydini silin.' -ForegroundColor Yellow
}
Write-Host ''

return [pscustomobject]$result

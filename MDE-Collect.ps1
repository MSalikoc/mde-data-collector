#Requires -Version 7.0
<#
.SYNOPSIS
    Microsoft Defender for Endpoint health check — read-only data collector.

.DESCRIPTION
    Delegated (device code) authentication. Collects the Defender for Endpoint
    configuration and posture data needed for a health check and writes it to a
    single JSON file. Nothing else is produced and nothing is changed.

    Every call is read-only. No configuration is changed.

.EXAMPLE
    ./MDE-Collect.ps1 -TenantId contoso.onmicrosoft.com -OutFile ./mde-data.json

.EXAMPLE
    # Kendi app kaydınızla (önerilen — pre-authorization sorunlarını ortadan kaldırır)
    ./MDE-Collect.ps1 -TenantId YOUR-TENANT-ID -ClientId <public-client-app-id> -Verbose
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$TenantId,

    # Varsayılan: Azure CLI public client. Çoğu tenant'ta hem Graph hem de
    # api.securitycenter.microsoft.com için pre-authorized'dır. Kendi public
    # client app kaydınız varsa onu verin (redirect URI gerekmez, device code).
    [string]$ClientId = '04b07795-8ddb-461a-bbee-02f9e1bf7b46',

    # Defender API'si icin uygulama kimligi. Verilirse (veya .mde-app.json'da
    # varsa) o kaynak icin kullanici oturumu yerine client credentials kullanilir;
    # cihaz durumu sarti koyan CA politikalari boylece devre disi kalir.
    [string]$ClientSecret,

    # Bos birakilirsa: mde-data-<tenant>-<yyyyMMdd>.json
    [string]$OutFile,

    # Telemetri pencereleri
    [int]$AlertDays = 90,
    [int]$EventDays = 30,

    # MDE (securitycenter) API'sini atla — sadece Graph + Advanced Hunting kullan
    [switch]$GraphOnly,

    # Ham API çıktılarını da ayrı bir klasöre yaz (sorun gidermek için)
    [string]$RawDumpPath,

    # Kurumsal ag: PowerShell sistem proxy'sini her zaman devralmaz
    [string]$Proxy,
    [switch]$ProxyUseDefaultCredentials
)

$ErrorActionPreference = 'Stop'

if ($Proxy) {
    $PSDefaultParameterValues['Invoke-RestMethod:Proxy'] = $Proxy
    $PSDefaultParameterValues['Invoke-WebRequest:Proxy'] = $Proxy
}
if ($ProxyUseDefaultCredentials) {
    $PSDefaultParameterValues['Invoke-RestMethod:ProxyUseDefaultCredentials'] = $true
    $PSDefaultParameterValues['Invoke-WebRequest:ProxyUseDefaultCredentials'] = $true
}

# New-MdeApp.ps1 bir app kaydi olusturduysa ClientId'yi oradan al
if (-not $PSBoundParameters.ContainsKey('ClientId')) {
    $appFile = Join-Path $PSScriptRoot '.mde-app.json'
    if (Test-Path $appFile) {
        try {
            $saved = Get-Content $appFile -Raw -Encoding utf8 | ConvertFrom-Json
            if ($saved.clientId) { $ClientId = $saved.clientId }
            if (-not $ClientSecret -and $saved.clientSecret) { $ClientSecret = $saved.clientSecret }
        } catch { }
    }
}

if (-not $OutFile) {
    $slug = ($TenantId -replace '\.onmicrosoft\.com$', '' -replace '[^\w\-]', '')
    if ($slug.Length -gt 20) { $slug = $slug.Substring(0, 8) }
    $OutFile = "./mde-data-$slug-$(Get-Date -Format yyyyMMdd).json"
}

# Windows konsolunda Türkçe karakterler ve simgeler bozulmasın
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch { }

$script:Tokens = @{}
$script:RefreshToken = $null
$script:Warnings = [System.Collections.Generic.List[string]]::new()
$script:Queries = [System.Collections.Generic.List[object]]::new()

function Write-Step($m) { Write-Host "  → $m" -ForegroundColor Cyan }
function Write-Ok($m)   { Write-Host "  ✓ $m" -ForegroundColor Green }
function Write-Skip($m) { Write-Host "  ! $m" -ForegroundColor Yellow; $script:Warnings.Add($m) }


# Uygulama kimligiyle token al (client credentials).
# Cihaz durumu / MFA gibi kullanici kosullari uygulanmaz.
function Get-AppOnlyToken {
    param([string]$Resource)
    try {
        $r = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" -Body @{
            client_id     = $ClientId
            client_secret = $ClientSecret
            scope         = "$Resource/.default"
            grant_type    = 'client_credentials'
        }
        Write-Verbose "app-only token alindi ($Resource)"
        return $r.access_token
    }
    catch {
        try { $script:LastTokenError = ($_.ErrorDetails.Message | ConvertFrom-Json).error_description } catch { $script:LastTokenError = $_.Exception.Message }
        Write-Skip "App-only token alinamadi: $script:LastTokenError"
        return $null
    }
}

# Bir kaynak icin refresh token ile sessizce token al.
# Once v2 (.default), olmazsa v1 (resource=) denenir: Defender API v1 tabanlidir
# ve bazi tenant'larda v2 .default ile yenilenemez.
function Get-TokenFromRefresh {
    param([string]$Resource)
    $script:LastTokenError = $null

    try {
        $r = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" -Body @{
            client_id     = $ClientId
            grant_type    = 'refresh_token'
            refresh_token = $script:RefreshToken
            scope         = "$Resource/.default offline_access"
        }
        if ($r.refresh_token) { $script:RefreshToken = $r.refresh_token }
        return $r.access_token
    }
    catch {
        try { $script:LastTokenError = ($_.ErrorDetails.Message | ConvertFrom-Json).error_description } catch { $script:LastTokenError = $_.Exception.Message }
        Write-Verbose "v2 refresh basarisiz ($Resource): $script:LastTokenError"
    }

    try {
        $r = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$TenantId/oauth2/token" -Body @{
            client_id     = $ClientId
            grant_type    = 'refresh_token'
            refresh_token = $script:RefreshToken
            resource      = $Resource
        }
        if ($r.refresh_token) { $script:RefreshToken = $r.refresh_token }
        Write-Verbose "v1 refresh basarili ($Resource)"
        return $r.access_token
    }
    catch {
        try { $script:LastTokenError = ($_.ErrorDetails.Message | ConvertFrom-Json).error_description } catch { $script:LastTokenError = $_.Exception.Message }
        Write-Verbose "v1 refresh basarisiz ($Resource): $script:LastTokenError"
    }
    return $null
}

# ---------------------------------------------------------------- AUTH ----
function Get-DeviceCodeToken {
    param([string]$Resource)

    $scope = "$Resource/.default offline_access"

    # Elimizde refresh token varsa yeni cihaz kodu istemeden yenile
    if ($script:RefreshToken) {
        $t = Get-TokenFromRefresh -Resource $Resource
        if ($t) { return $t }
    }

    $dc = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/devicecode" -Body @{
        client_id = $ClientId
        scope     = $scope
    }

    Write-Host ''
    Write-Host '  ┌────────────────────────────────────────────────────────────┐' -ForegroundColor Yellow
    Write-Host "  │ $($dc.message)" -ForegroundColor Yellow
    Write-Host '  └────────────────────────────────────────────────────────────┘' -ForegroundColor Yellow
    Write-Host ''

    $deadline = (Get-Date).AddSeconds([int]$dc.expires_in)
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Seconds ([int]$dc.interval + 1)
        try {
            $tok = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" -Body @{
                client_id   = $ClientId
                grant_type  = 'urn:ietf:params:oauth:grant-type:device_code'
                device_code = $dc.device_code
            }
            if ($tok.refresh_token) { $script:RefreshToken = $tok.refresh_token }
            return $tok.access_token
        } catch {
            $body = $_.ErrorDetails.Message | ConvertFrom-Json -ErrorAction SilentlyContinue
            if ($body.error -eq 'authorization_pending') { continue }
            if ($body.error -eq 'slow_down') { Start-Sleep 5; continue }
            throw "Cihaz kodu akışı başarısız: $($body.error) — $($body.error_description)"
        }
    }
    throw 'Cihaz kodu zaman aşımına uğradı.'
}

function Get-Token {
    param([ValidateSet('graph', 'mde')][string]$Api)
    $res = if ($Api -eq 'graph') { 'https://graph.microsoft.com' } else { 'https://api.securitycenter.microsoft.com' }
    if (-not $script:Tokens.ContainsKey($Api)) {
        if ($Api -eq 'mde') {
            # 1) app-only (client credentials): CA cihaz durumu sartindan etkilenmez
            # 2) kullanici oturumundan yenileme
            # Ikisi de olmazsa bolum atlanir; ikinci cihaz kodu ACILMAZ.
            $t = $null
            if ($ClientSecret) { $t = Get-AppOnlyToken -Resource $res }
            if (-not $t -and $script:RefreshToken) { $t = Get-TokenFromRefresh -Resource $res }
            if (-not $t) {
                # AADSTS50131 = tenant'ta kayitli/bilinen cihaz sarti koşan bir Conditional
                # Access politikasi var. Cihaz kodu akisi bunu HICBIR ZAMAN saglayamaz; token
                # politikanin guvendigi cihaza degil, oturumun acildigi makineye verilir.
                # App-only (client credentials) akisinda ortada cihaz yoktur, sart uygulanmaz.
                if ("$script:LastTokenError" -match 'AADSTS50131|device state') {
                    if (-not $ClientSecret) {
                        throw ("Defender API bir Conditional Access politikasi tarafindan engellendi " +
                               "(AADSTS50131: cihaz kayitli degil). Cihaz kodu ile bu asilamaz. " +
                               "Cozum: once .\New-MdeApp.ps1 -TenantId $TenantId -AppOnly calistirin " +
                               "(Global Administrator gerekir), sonra bu komutu tekrarlayin - " +
                               "olusan .mde-app.json otomatik okunur. " +
                               "Politikayi tespit etmek icin Entra oturum acma gunluklerinde " +
                               "Correlation ID ile arayin. Ham hata: $script:LastTokenError")
                    }
                    throw ("Defender API app-only token'i da reddedildi (AADSTS50131). Client secret " +
                           "suresi dolmus olabilir ya da uygulama izinleri onaylanmamis olabilir - " +
                           ".\New-MdeApp.ps1 -AppOnly komutunu tekrar calistirin. " +
                           "Ham hata: $script:LastTokenError")
                }
                throw "Defender API token alinamadi. Sebep: $script:LastTokenError"
            }
            $script:Tokens[$Api] = $t
        }
        else {
            $script:Tokens[$Api] = Get-DeviceCodeToken -Resource $res
        }
        Test-TokenScope -Api $Api -Token $script:Tokens[$Api]
    }
    return $script:Tokens[$Api]
}

# Token'daki izinleri (scp claim) coz ve eksikleri bastan bildir
function Test-TokenScope {
    param([string]$Api, [string]$Token)

    $required = if ($Api -eq 'graph') {
        @('ThreatHunting.Read.All', 'SecurityEvents.Read.All', 'SecurityAlert.Read.All',
          'SecurityIncident.Read.All', 'CustomDetection.Read.All',
          'DeviceManagementConfiguration.Read.All', 'Directory.Read.All',
          'Organization.Read.All', 'Policy.Read.All', 'RoleManagement.Read.Directory')
    } else {
        if ($ClientSecret) {
            @('Vulnerability.Read.All', 'SecurityRecommendation.Read.All', 'Score.Read.All')
        } else {
            @('Vulnerability.Read', 'SecurityRecommendation.Read', 'Score.Read', 'Ti.Read')
        }
    }

    $scopes = @()
    try {
        $payload = $Token.Split('.')[1].Replace('-', '+').Replace('_', '/')
        switch ($payload.Length % 4) { 2 { $payload += '==' } 3 { $payload += '=' } }
        $claims = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($payload)) | ConvertFrom-Json
        $scopes = @($claims.scp -split ' ' | Where-Object { $_ })
        if (-not $scopes -and $claims.roles) { $scopes = @($claims.roles) }
        if ($claims.upn) { Write-Verbose "Oturum: $($claims.upn)" }
    } catch {
        Write-Verbose 'Token cozulemedi, izin denetimi atlaniyor.'
        return
    }

    $missing = @($required | Where-Object { $_ -notin $scopes })
    if ($missing.Count -eq 0) {
        Write-Ok "$Api token izinleri tam ($($scopes.Count) scope)"
        return
    }

    Write-Host ''
    Write-Host "  ! $Api token'inda gerekli izinler YOK — bu bolumler 403 donecek:" -ForegroundColor Red
    $missing | ForEach-Object { Write-Host "      - $_" -ForegroundColor DarkYellow }
    Write-Host '    Cozum: kendi public client app kaydinizi olusturup -ClientId ile verin.' -ForegroundColor Yellow
    Write-Host '    Steps: see README.md, step 2 (app registration).' -ForegroundColor Yellow
    Write-Host ''
    $script:Warnings.Add("$Api token is missing required permissions: $($missing -join ', ')")
}

# ------------------------------------------------------------ REST CALL ----
function Invoke-Api {
    param(
        [string]$Uri,
        [ValidateSet('graph', 'mde')][string]$Api = 'graph',
        [string]$Method = 'GET',
        $Body,
        [switch]$All,         # @odata.nextLink takibi
        [int]$MaxPages = 200  # sayfalama ust siniri
    )
    $headers = @{ Authorization = "Bearer $(Get-Token -Api $Api)"; 'Content-Type' = 'application/json' }
    $items = [System.Collections.Generic.List[object]]::new()
    $next = $Uri
    $attempt = 0
    $page = 0

    while ($next) {
        try {
            $params = @{ Uri = $next; Method = $Method; Headers = $headers }
            if ($Body) { $params.Body = ($Body | ConvertTo-Json -Depth 10 -Compress) }
            $r = Invoke-RestMethod @params
        } catch {
            $code = $_.Exception.Response.StatusCode.value__
            if ($code -eq 429 -and $attempt -lt 5) {
                $wait = 20
                try {
                    $ra = $_.Exception.Response.Headers.RetryAfter
                    if ($ra.Delta) { $wait = [int]$ra.Delta.TotalSeconds }
                } catch { }
                Write-Verbose "429 — $wait sn bekleniyor"
                Start-Sleep -Seconds $wait; $attempt++; continue
            }
            if ($code -eq 401 -and $attempt -lt 2) {
                $script:Tokens.Remove($Api) | Out-Null
                $headers.Authorization = "Bearer $(Get-Token -Api $Api)"
                $attempt++; continue
            }
            throw
        }
        $attempt = 0

        if ($null -ne $r.value) { $items.AddRange(@($r.value)) } else { return $r }
        $page++
        $next = if ($All -and $page -lt $MaxPages) { $r.'@odata.nextLink' } else { $null }
    }
    return $items
}

function Try-Api {
    param([scriptblock]$Block, [string]$What)
    # PowerShell bos diziyi $null'a cokertir, yani donen deger "cagri dustu" ile
    # "cagri calisti ama sonuc bos"u ayirt etmeye yetmez. Bayrak bunun icin.
    $script:LastApiFailed = $false
    try { & $Block }
    catch {
        $script:LastApiFailed = $true
        Write-Skip "$What alınamadı: $($_.Exception.Message.Split([Environment]::NewLine)[0])"
        $null
    }
}

function Invoke-Hunting {
    param([string]$Query, [string]$What, [switch]$Optional)
    $script:Queries.Add([pscustomobject]@{ purpose = $What; query = ($Query.Trim() -replace '\s*\r?\n\s*', ' ') })
    try {
        $r = Invoke-Api -Api graph -Method POST -Uri 'https://graph.microsoft.com/v1.0/security/runHuntingQuery' -Body @{ Query = $Query }
        if ($RawDumpPath) {
            New-Item -ItemType Directory -Force -Path $RawDumpPath | Out-Null
            $r | ConvertTo-Json -Depth 10 | Set-Content (Join-Path $RawDumpPath "hunt-$What.json")
        }
        return @($r.results)
    } catch {
        $msg = $_.Exception.Message.Split([Environment]::NewLine)[0]
        $code = $null
        try { $code = $_.Exception.Response.StatusCode.value__ } catch { }
        # 400 + opsiyonel tablo = tenant'ta o yetkilendirme yok (Defender Vulnerability
        # Management add-on'u gibi). Bu bir hata degil, kapsam bilgisidir.
        # StatusCode bazi PowerShell/HTTP yigin kombinasyonlarinda cozulemiyor ve tespit
        # sessizce basarisiz oluyordu - o zaman mesaj metnine de bakiyoruz.
        $is400 = ($code -eq 400) -or ($msg -match '\b400\b|Bad Request')
        if ($Optional -and $is400) {
            Write-Host "  · ${What}: bu tenant'ta yetkilendirme yok, atlandi" -ForegroundColor DarkGray
            $script:Warnings.Add("$What is not available in this tenant (the table requires an entitlement that is not licensed) - the related section is left empty rather than reported as a failure.")
        }
        else {
            Write-Skip "Advanced Hunting '$What' başarısız: $msg"
        }
        return @()
    }
}

# ------------------------------------------------------------- HELPERS ----
function Pairs { param($Rows, [string]$Key, [string]$Val)
    @($Rows | ForEach-Object { , @($_.$Key, [int]$_.$Val) })
}
function Pct {
    param($n, $d)
    if ($d -gt 0) { [math]::Round(100 * $n / $d) } else { 0 }
}

$data = [ordered]@{
    meta   = [ordered]@{
        generatedUtc = (Get-Date).ToUniversalTime().ToString('u')
        tenantId     = $TenantId
        alertWindow  = "$AlertDays days"
        eventWindow  = "$EventDays days"
        collector     = 'MDE-Collect.ps1 v1.1'
        schemaVersion = 1
    }
    kpi    = [ordered]@{}
    charts = [ordered]@{}
    tables = [ordered]@{}
    raw    = [ordered]@{}
    manual = @()
}

Write-Host ''
Write-Host 'Microsoft Defender for Endpoint — health check collector' -ForegroundColor White
Write-Host '────────────────────────────────────────────────────────' -ForegroundColor DarkGray

# ============================================================ 1 · TENANT ==
Write-Step 'Tenant bilgisi'
$org = Try-Api { Invoke-Api -Uri 'https://graph.microsoft.com/v1.0/organization' } 'Organization'
if ($org) {
    $data.meta.tenantName = $org[0].displayName
    $data.meta.verifiedDomain = ($org[0].verifiedDomains | Where-Object isDefault).name
    Write-Ok "Tenant: $($data.meta.tenantName)"
}

# =========================================================== 2 · LICENCES ==
Write-Step 'Lisans envanteri'
$skus = Try-Api { Invoke-Api -Uri 'https://graph.microsoft.com/v1.0/subscribedSkus' } 'subscribedSkus'
if ($skus) {
    $map = @{
        'DEFENDER_ENDPOINT_P1'    = 'Defender for Endpoint Plan 1'
        'WIN_DEF_ATP'             = 'Defender for Endpoint Plan 2'
        'MDATP_XPLAT'             = 'Defender for Endpoint Plan 2 (server/xplat)'
        'TVM_Premium_Standalone'  = 'Defender Vulnerability Management add-on'
        'SPE_E5'                  = 'Microsoft 365 E5'
        'IDENTITY_THREAT_PROTECTION' = 'Microsoft 365 E5 Security'
        'SPE_E3'                  = 'Microsoft 365 E3'
    }
    $rows = foreach ($s in $skus) {
        [pscustomobject]@{
            sku       = if ($map.ContainsKey($s.skuPartNumber)) { $map[$s.skuPartNumber] } else { $s.skuPartNumber }
            partNumber= $s.skuPartNumber
            purchased = $s.prepaidUnits.enabled
            assigned  = $s.consumedUnits
            available = [math]::Max(0, $s.prepaidUnits.enabled - $s.consumedUnits)
        }
    }
    $data.tables.licenses = @($rows | Where-Object { $map.ContainsKey($_.partNumber) -or $_.assigned -gt 0 } | Sort-Object -Property assigned -Descending)
    # Once Defender SKU'lari; tenant'ta yoksa en cok atanan 5 SKU'ya dus
    $chartRows = @($data.tables.licenses | Where-Object { $map.ContainsKey($_.partNumber) -and $_.assigned -gt 0 })
    if ($chartRows.Count -eq 0) {
        $chartRows = @($data.tables.licenses | Where-Object { $_.assigned -gt 0 } | Select-Object -First 5)
        if ($chartRows.Count -gt 0) { Write-Skip 'No Defender SKU found - the licence chart was populated from the most-assigned SKUs instead.' }
    }
    $data.charts['License distribution'] = @(
        $chartRows | Select-Object -First 5 | ForEach-Object {
            Write-Output -NoEnumerate @($_.sku, [int]$_.assigned)
        })
    Write-Ok "$($data.tables.licenses.Count) SKU"
}

# ================================================= 3 · DEVICE INVENTORY ===
Write-Step 'Cihaz envanteri ve sensör sağlığı (Advanced Hunting)'
$q = @"
DeviceInfo
| where Timestamp > ago(14d)
| summarize arg_max(Timestamp, *) by DeviceId
| summarize Devices = count() by OSPlatform, OnboardingStatus, SensorHealthState
"@
$inv = Invoke-Hunting -Query $q -What 'device-inventory'

if ($inv.Count) {
    $onb   = ($inv | Where-Object OnboardingStatus -eq 'Onboarded'    | Measure-Object Devices -Sum).Sum
    $canbe = ($inv | Where-Object OnboardingStatus -eq 'Can be onboarded' | Measure-Object Devices -Sum).Sum
    $unsup = ($inv | Where-Object OnboardingStatus -eq 'Unsupported'  | Measure-Object Devices -Sum).Sum
    $total = ($inv | Measure-Object Devices -Sum).Sum

    $data.kpi['Total Endpoints']    = '{0:N0}' -f $total
    $data.kpi['Onboarded Devices']  = '{0:N0}' -f $onb
    $data.kpi['Can Be Onboarded']   = '{0:N0}' -f $canbe
    $data.kpi['Onboarding Rate']    = "$(Pct $onb $total)%"
    $data.kpi['Total in scope']     = '{0:N0}' -f $total
    $data.kpi['Onboarded']          = '{0:N0}' -f $onb
    $data.kpi['Not onboarded']      = '{0:N0}' -f ($total - $onb)
    $data.charts['Endpoint onboarding coverage'] = @(, @('Onboarding %', (Pct $onb $total)))

    # platform kırılımı
    $plat = $inv | Where-Object OnboardingStatus -eq 'Onboarded' | Group-Object OSPlatform |
            ForEach-Object { [pscustomobject]@{ name = $_.Name; devices = ($_.Group | Measure-Object Devices -Sum).Sum } } |
            Sort-Object devices -Descending
    $data.charts['Device breakdown by platform'] = @($plat | Select-Object -First 6 | ForEach-Object { , @($_.name, [int]$_.devices) })

    # sensör sağlığı
    $sh = $inv | Where-Object OnboardingStatus -eq 'Onboarded' | Group-Object SensorHealthState |
          ForEach-Object { [pscustomobject]@{ state = $_.Name; devices = ($_.Group | Measure-Object Devices -Sum).Sum } }
    $data.charts['Sensor health distribution'] = @($sh | ForEach-Object { , @($_.state, [int]$_.devices) })
    $healthy = ($sh | Where-Object state -eq 'Active' | Measure-Object devices -Sum).Sum
    $data.kpi['Sensor health']    = "$(Pct $healthy $onb)%"
    # Ilgili durum hic yoksa Sum null doner — 0 olarak yaz, alan bos kalmasin
    function SumState {
        param($Pattern)
        $v = ($sh | Where-Object { $_.state -match $Pattern } | Measure-Object devices -Sum).Sum
        if ($null -eq $v) { 0 } else { $v }
    }
    $data.kpi['Impaired comms']   = '{0:N0}' -f (SumState 'Impaired')
    $data.kpi['No sensor data']   = '{0:N0}' -f (SumState 'No sensor|Misconfigured')
    $data.kpi['Inactive devices'] = '{0:N0}' -f (SumState '^Inactive$')
    $data.kpi['Inactive &gt; 7 days'] = $data.kpi['Inactive devices']

    Write-Ok "$total cihaz, $onb onboarded (%$(Pct $onb $total))"
}

# OS sürüm bazında envanter tablosu
$q = @"
DeviceInfo
| where Timestamp > ago(14d)
| summarize arg_max(Timestamp, *) by DeviceId
| extend Family = case(
    OSPlatform startswith "Windows11", "Windows 11",
    OSPlatform startswith "Windows10", "Windows 10",
    OSPlatform startswith "WindowsServer2012", "Windows Server 2012 R2",
    OSPlatform startswith "WindowsServer2016" or OSPlatform startswith "WindowsServer2019", "Windows Server 2016 / 2019",
    OSPlatform startswith "WindowsServer", "Windows Server 2022 / 2025",
    OSPlatform startswith "macOS", "macOS",
    OSPlatform startswith "Linux", "Linux servers",
    OSPlatform startswith "iOS", "iOS / iPadOS",
    OSPlatform startswith "Android", "Android",
    OSPlatform)
| summarize Discovered = count(),
            Onboarded = countif(OnboardingStatus == "Onboarded"),
            Inactive  = countif(SensorHealthState == "Inactive")
        by Family
| order by Discovered desc
"@
$fam = Invoke-Hunting -Query $q -What 'device-families'
if ($fam.Count) {
    $data.tables.deviceInventory = @($fam | ForEach-Object {
        [ordered]@{
            platform   = $_.Family
            discovered = [int]$_.Discovered
            onboarded  = [int]$_.Onboarded
            gap        = [int]$_.Discovered - [int]$_.Onboarded
            coverage   = "$(Pct $_.Onboarded $_.Discovered)%"
            inactive   = [int]$_.Inactive
        }
    })
    Write-Ok "$($fam.Count) platform ailesi"
}

# Agent / platform sürüm dağılımı
$q = @"
DeviceInfo
| where Timestamp > ago(7d) and OnboardingStatus == "Onboarded"
| summarize arg_max(Timestamp, *) by DeviceId
| summarize Devices = count() by OSPlatform, SensorHealthState, MachineGroup
| order by Devices desc
| take 50
"@
$data.raw.machineGroups = Invoke-Hunting -Query $q -What 'machine-groups'

# ================================================= 4 · SECURE CONFIG (AV/ASR)
Write-Step 'Güvenlik yapılandırma değerlendirmesi (AV / ASR / baseline)'
$q = @"
DeviceTvmSecureConfigurationAssessment
| where IsApplicable == 1
| summarize Compliant = countif(IsCompliant == 1), Applicable = count()
        by ConfigurationId, ConfigurationCategory, ConfigurationSubcategory
| extend CompliancePct = round(100.0 * Compliant / Applicable, 1)
| order by ConfigurationCategory asc, CompliancePct asc
"@
$cfg = Invoke-Hunting -Query $q -What 'secure-config'
if ($cfg.Count) {
    $kb = Invoke-Hunting -Query 'DeviceTvmSecureConfigurationAssessmentKB | project ConfigurationId, ConfigurationName, ConfigurationCategory, ConfigurationImpact, RiskDescription' -What 'secure-config-kb'
    $names = @{}
    foreach ($k in $kb) { $names[$k.ConfigurationId] = $k.ConfigurationName }

    $data.tables.secureConfiguration = @($cfg | ForEach-Object {
        [pscustomobject][ordered]@{
            id          = $_.ConfigurationId
            name        = if ($names.ContainsKey($_.ConfigurationId)) { $names[$_.ConfigurationId] } else { $_.ConfigurationId }
            category    = $_.ConfigurationCategory
            subcategory = $_.ConfigurationSubcategory
            compliant   = [int]$_.Compliant
            applicable  = [int]$_.Applicable
            compliance  = [double]$_.CompliancePct
        }
    })

    # kategori bazında uyum → baseline grafiği
    $byCat = $data.tables.secureConfiguration | Group-Object category | ForEach-Object {
        [pscustomobject]@{
            cat = $_.Name
            pct = [math]::Round(($_.Group | Measure-Object compliance -Average).Average)
        }
    }
    $data.charts['Compliance by baseline profile (%)'] = @($byCat | ForEach-Object { , @($_.cat, [int]$_.pct) })
    $overall = [math]::Round(($data.tables.secureConfiguration | Measure-Object compliance -Average).Average)
    $data.charts['Overall configuration compliance'] = @(, @('Compliance %', $overall))

    # tekil AV kontrolleri KPI'ya
    # NOT: isim regex'i yanlis satiri yakalayabiliyor (ornegin 'tamper' -> LDAP
    # "tampering" satiri). Microsoft'un sabit scid kimlikleri kullanilir.
    function CfgPctById([string]$Scid) {
        $r = $data.tables.secureConfiguration | Where-Object { $_.id -eq $Scid } | Select-Object -First 1
        if ($r) { "$([math]::Round($r.compliance))%" } else { $null }
    }
    foreach ($p in @(
        @{ k = 'Real-time protection on'; id = 'scid-2012' },
        @{ k = 'Cloud protection on';     id = 'scid-2016' },
        @{ k = 'Tamper protection on';    id = 'scid-2003' })) {
        $v = CfgPctById $p.id
        if ($v) { $data.kpi[$p.k] = $v }
    }
    Write-Ok "$($cfg.Count) yapılandırma kontrolü, ortalama uyum %$overall"
}

# ASR kural durumu — audit/block olay sayıları
Write-Step "ASR olayları (son $EventDays gün)"
$q = @"
DeviceEvents
| where Timestamp > ago(${EventDays}d)
| where ActionType startswith "Asr"
| summarize Events = count(), Devices = dcount(DeviceId) by ActionType
| order by Events desc
"@
$asr = Invoke-Hunting -Query $q -What 'asr-events'
if ($asr.Count) {
    $data.tables.asrEvents = @($asr | ForEach-Object {
        $mode = if ($_.ActionType -match 'Audited$') { 'Audit' } elseif ($_.ActionType -match 'Blocked$') { 'Block' } else { 'Other' }
        [pscustomobject][ordered]@{
            rule    = ($_.ActionType -replace '^Asr', '' -replace '(Audited|Blocked)$', '')
            mode    = $mode
            events  = [int]$_.Events
            devices = [int]$_.Devices
        }
    })
    # NOT: satirlar [ordered] hashtable; Select-Object -ExpandProperty hashtable'da
    # calismaz ("Property rule cannot be found"). Uye erisimi ForEach-Object ile yapilir.
    $blockRules = @($data.tables.asrEvents | Where-Object { $_.mode -eq 'Block' } |
                    ForEach-Object { $_.rule } | Select-Object -Unique)
    $auditRules = @($data.tables.asrEvents | Where-Object { $_.mode -eq 'Audit' } |
                    ForEach-Object { $_.rule } | Select-Object -Unique |
                    Where-Object { $_ -notin $blockRules })
    $data.kpi['Rules in block mode'] = $blockRules.Count
    $data.kpi['Rules in audit mode'] = $auditRules.Count
    $data.charts['ASR rule mode distribution'] = @(
        @('Block', $blockRules.Count),
        @('Audit', $auditRules.Count),
        @('Warn', 0),
        @('Not configured', [math]::Max(0, 20 - $blockRules.Count - $auditRules.Count)))
    $data.charts['Top audited attack vectors (30 days)'] = @(
        $data.tables.asrEvents | Where-Object { $_.mode -eq 'Audit' } | Sort-Object { $_.events } -Descending |
        Select-Object -First 5 | ForEach-Object { , @($_.rule, [int]$_.events) })
    Write-Ok "$($data.tables.asrEvents.Count) ASR olay tipi — block: $($blockRules.Count), audit: $($auditRules.Count)"
    $script:Warnings.Add('ASR: rules that generate no events are invisible in telemetry - verify rule modes against the Intune policy export.')
}

# ================================================== 5 · VULNERABILITIES ===
Write-Step 'Zafiyet yönetimi (TVM)'
$q = @"
DeviceTvmSoftwareVulnerabilities
| summarize Devices = dcount(DeviceId) by CveId, VulnerabilitySeverityLevel
| summarize Cves = dcount(CveId), Instances = sum(Devices) by VulnerabilitySeverityLevel
"@
$vuln = Invoke-Hunting -Query $q -What 'vuln-severity'
if ($vuln.Count) {
    $order = 'Critical', 'High', 'Medium', 'Low'
    $data.charts['Vulnerabilities by severity'] = @(
        $order | ForEach-Object {
            $s = $_
            $row = $vuln | Where-Object { $_.VulnerabilitySeverityLevel -eq $s }
            $n = [int]($row.Instances | Select-Object -First 1)
            Write-Output -NoEnumerate @($s, $n)
        })
    $data.kpi['Total vulnerabilities'] = '{0:N0}' -f (($vuln | Measure-Object Instances -Sum).Sum)
    $data.kpi['Critical CVEs'] = '{0:N0}' -f ([int](($vuln | Where-Object VulnerabilitySeverityLevel -eq 'Critical').Cves))
    Write-Ok "$($data.kpi['Total vulnerabilities']) zafiyet örneği"
}

$q = @"
DeviceTvmSoftwareVulnerabilities
| summarize Devices = dcount(DeviceId), Cves = dcount(CveId) by SoftwareName, SoftwareVendor
| order by Devices desc
| take 10
"@
$topsw = Invoke-Hunting -Query $q -What 'top-vuln-software'
if ($topsw.Count) {
    $data.tables.topVulnerableSoftware = @($topsw | ForEach-Object {
        [ordered]@{ product = $_.SoftwareName; vendor = $_.SoftwareVendor; devices = [int]$_.Devices; cves = [int]$_.Cves }
    })
}

$q = @"
DeviceTvmSoftwareInventory
| summarize Products = dcount(strcat(SoftwareVendor, SoftwareName))
"@
$sw = Invoke-Hunting -Query $q -What 'software-count'
if ($sw.Count) { $data.kpi['Software products'] = '{0:N0}' -f [int]$sw[0].Products }

# --- TVM ek yuzeyler: firmware, tarayici eklentileri, sertifikalar ---
# Bunlar Advanced Hunting'den gelir; bloke olan Defender API'sine ihtiyac duymaz.
$q = @"
DeviceTvmHardwareFirmware
| where ComponentType in ("Firmware", "Bios")
| summarize Devices = dcount(DeviceId) by ComponentManufacturer
| order by Devices desc
| take 6
"@
$fw = Invoke-Hunting -Query $q -What 'firmware' -Optional
if ($fw.Count) {
    $data.charts['Firmware / hardware advisories by manufacturer'] = @($fw | ForEach-Object {
        Write-Output -NoEnumerate @($_.ComponentManufacturer, [int]$_.Devices)
    })
    Write-Ok "$($fw.Count) firmware ureticisi"
}

$q = @"
DeviceTvmBrowserExtensions
| summarize Extensions = dcount(ExtensionId), Devices = dcount(DeviceId)
"@
$be = Invoke-Hunting -Query $q -What 'browser-extensions' -Optional
if ($be.Count) { $data.kpi['Browser extensions'] = "$([int]$be[0].Extensions)" }

$q = @"
DeviceTvmCertificateInfo
| where ExpirationDate < now(+90d)
| summarize Certificates = dcount(Thumbprint)
"@
$ci = Invoke-Hunting -Query $q -What 'certificates' -Optional
if ($ci.Count) { $data.kpi['Certificates expiring 90d'] = "$([int]$ci[0].Certificates)" }

# ==================================================== 6 · SECURE SCORE ====
Write-Step 'Microsoft Secure Score'
$ss = Try-Api { Invoke-Api -Uri 'https://graph.microsoft.com/v1.0/security/secureScores?$top=1' } 'Secure Score'
if ($ss) {
    $cur = $ss[0]
    $pct = Pct $cur.currentScore $cur.maxScore
    $data.kpi['Secure score for devices'] = "$pct%"
    $data.charts['Microsoft Secure Score (devices)'] = @(, @('Secure Score %', $pct))
    $data.meta.secureScore = "$([math]::Round($cur.currentScore,1)) / $([math]::Round($cur.maxScore,1))"

    $byCat = $cur.controlScores | Group-Object controlCategory | ForEach-Object {
        [pscustomobject]@{
            cat      = $_.Name
            achieved = [math]::Round((($_.Group | Measure-Object score -Sum).Sum), 1)
        }
    }
    $data.charts['Secure Score breakdown by category (points achieved vs. opportunity)'] =
        @($byCat | ForEach-Object { , @($_.cat, [double]$_.achieved, 0) })

    # "Score impact" kazanilabilecek puandir, mevcut puan degil. controlScores yalnizca
    # mevcut puani tasir (bu listede tanimi geregi ~0), tavan degeri ayri uctan gelir.
    # Alinamazsa impact bos kalir - uydurmaktansa bos birakiyoruz.
    $maxByControl = @{}
    $profiles = Try-Api { Invoke-Api -All -Uri 'https://graph.microsoft.com/v1.0/security/secureScoreControlProfiles' } 'secure score control profiles'
    foreach ($p in @($profiles)) {
        foreach ($k in @($p.id, $p.controlName)) {
            if ($k -and -not $maxByControl.ContainsKey($k)) { $maxByControl[$k] = [double]$p.maxScore }
        }
    }
    $data.tables.secureScoreActions = @($cur.controlScores | Where-Object { $_.score -lt 1 } |
        Sort-Object score | Select-Object -First 10 | ForEach-Object {
            $max = $null
            foreach ($k in @($_.controlName, $_.controlCategory)) {
                if ($k -and $maxByControl.ContainsKey($k)) { $max = $maxByControl[$k]; break }
            }
            $impact = if ($null -ne $max) { [math]::Round($max - [double]$_.score, 1) } else { $null }
            [ordered]@{
                action = $_.controlName; category = $_.controlCategory
                score = $_.score; impact = $impact; state = $_.implementationStatus
            }
        })
    if ($maxByControl.Count -eq 0) {
        Write-Skip 'Secure score control profiles were not readable, so the score impact column stays empty.'
    }
    Write-Ok "Secure Score: $($data.meta.secureScore) (%$pct)"
}

# ================================================ 7 · ALERTS / INCIDENTS ==
Write-Step "Uyarılar ve olaylar (son $AlertDays gün)"
$since = (Get-Date).AddDays(-$AlertDays).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$alerts = Try-Api {
    Invoke-Api -All -Uri ("https://graph.microsoft.com/v1.0/security/alerts_v2?`$filter=createdDateTime%20ge%20$since&`$top=1000")
} 'alerts_v2'

if ($alerts) {
    $mde = @($alerts | Where-Object { $_.serviceSource -eq 'microsoftDefenderForEndpoint' })
    if (-not $mde.Count) { $mde = @($alerts) }

    $data.kpi['Total alerts (90d)'] = '{0:N0}' -f $mde.Count
    $data.kpi['Resolved']           = '{0:N0}' -f (@($mde | Where-Object status -eq 'resolved').Count)
    $data.kpi['Open / in progress'] = '{0:N0}' -f (@($mde | Where-Object { $_.status -in 'new', 'inProgress' }).Count)

    $sev = 'high', 'medium', 'low', 'informational'
    $data.charts['Alert severity breakdown'] = @(
        $sev | ForEach-Object {
            $s = $_
            $label = (Get-Culture).TextInfo.ToTitleCase($s)
            $n = @($mde | Where-Object { $_.severity -eq $s }).Count
            Write-Output -NoEnumerate @($label, $n)
        })
    $data.charts['Alert status breakdown'] = @(
        @('Resolved',    @($mde | Where-Object status -eq 'resolved').Count),
        @('In progress', @($mde | Where-Object status -eq 'inProgress').Count),
        @('New',         @($mde | Where-Object status -eq 'new').Count))

    # yanlis pozitif orani (classification alani)
    $fp = @($mde | Where-Object { $_.classification -eq 'falsePositive' }).Count
    $cls = @($mde | Where-Object { $_.classification -and $_.classification -ne 'unknown' }).Count
    if ($cls -gt 0) {
        $data.charts['False positive rate'] = @(, @('FP rate %', [math]::Round(100 * $fp / $cls)))
        $data.kpi['False positive rate'] = "$([math]::Round(100 * $fp / $cls))%"
    }

    # MITRE taktikleri — alert.category taktiğe karşılık gelir (CredentialAccess, LateralMovement…)
    $tactics = @{}
    foreach ($a in $mde) {
        $t = if ($a.category) { $a.category } elseif ($a.mitreTechniques) { @($a.mitreTechniques)[0] } else { $null }
        if ($t) { $tactics[$t] = 1 + ($tactics[$t] ?? 0) }
    }
    if ($tactics.Count) {
        $data.charts['Alerts by detection category (MITRE tactic)'] =
            @($tactics.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 9 |
              ForEach-Object { , @($_.Key, [int]$_.Value) })
    }

    # MTTD / MTTR
    $resolved = @($mde | Where-Object { $_.status -eq 'resolved' -and $_.resolvedDateTime })
    if ($resolved.Count) {
        $mttr = ($resolved | ForEach-Object { ([datetime]$_.resolvedDateTime - [datetime]$_.createdDateTime).TotalHours } |
                 Measure-Object -Average).Average
        $data.kpi['MTTR'] = "$([math]::Round($mttr,1)) hours"
        $data.tables.socKpi = @(
            [ordered]@{ metric = 'Mean time to respond (MTTR)'; observed = "$([math]::Round($mttr,1)) hours" }
        )
    }
    $lag = @($mde | Where-Object { $_.firstActivityDateTime } | ForEach-Object {
        ([datetime]$_.createdDateTime - [datetime]$_.firstActivityDateTime).TotalMinutes } |
        Where-Object { $_ -ge 0 -and $_ -lt 10080 })
    if ($lag.Count) {
        $mttd = ($lag | Measure-Object -Average).Average
        if ($data.tables.socKpi) { $data.tables.socKpi += [ordered]@{ metric = 'Mean time to detect (MTTD)'; observed = "$([math]::Round($mttd)) minutes" } }
    }
    Write-Ok "$($mde.Count) uyarı"
}

$inc = Try-Api {
    # NOT: incidents ucnda $top=200 ve createdDateTime filtresi 400 dondurur.
    # Sayfalama ile cekip tarihi istemci tarafinda suzuyoruz.
    Invoke-Api -All -MaxPages 10 -Uri 'https://graph.microsoft.com/v1.0/security/incidents?$top=50'
} 'incidents'
if ($inc) {
    $sinceDt = (Get-Date).AddDays(-$AlertDays)
    $inc = @($inc | Where-Object { $_.createdDateTime -and [datetime]$_.createdDateTime -ge $sinceDt })
}

# uyari + olay hacmi ayni aylik eksende
if ($alerts -and $mde) {
    $am = @($mde | Group-Object { ([datetime]$_.createdDateTime).ToString('yyyy-MM') } | Sort-Object Name)
    if ($am.Count) {
        $im = @{}
        if ($inc) { foreach ($g in @($inc | Group-Object { ([datetime]$_.createdDateTime).ToString('yyyy-MM') })) { $im[$g.Name] = $g.Count } }
        $data.charts['Alert volume trend'] = @($am | ForEach-Object {
            $k = $_.Name
            Write-Output -NoEnumerate @($k, $_.Count, $(if ($im.ContainsKey($k)) { $im[$k] } else { 0 }))
        })
    }
}
if ($inc) {
    $data.kpi['Incidents (90d)'] = '{0:N0}' -f @($inc).Count
    $byMonth = @($inc) | Group-Object { ([datetime]$_.createdDateTime).ToString('yyyy-MM') } | Sort-Object Name
    $data.charts['Incident volume by month'] = @($byMonth | ForEach-Object { , @($_.Name, $_.Count) })
    Write-Ok "$(@($inc).Count) olay"
}

# ============================================ 8 · CUSTOM DETECTION RULES ==
Write-Step 'Özel tespit kuralları'
$rules = Try-Api { Invoke-Api -All -Uri 'https://graph.microsoft.com/beta/security/rules/detectionRules' } 'detectionRules'
if ($rules) {
    $data.tables.customDetections = @($rules | ForEach-Object {
        [ordered]@{
            name      = $_.displayName
            frequency = $_.schedule.period
            severity  = $_.detectionAction.alertTemplate.severity
            enabled   = $_.isEnabled
            actions   = @($_.detectionAction.responseActions.'@odata.type' | ForEach-Object { ($_ -split '\.')[-1] }) -join ', '
        }
    })
    Write-Ok "$(@($rules).Count) özel tespit kuralı"
}

# ================================================= 9 · MALWARE / WEB ======
Write-Step 'Kötü amaçlı yazılım ve web koruma olayları'
$q = @"
AlertInfo
| where Timestamp > ago(${EventDays}d) and ServiceSource == "Microsoft Defender for Endpoint"
| summarize Alerts = count() by Category
| order by Alerts desc
| take 8
"@
$cat = Invoke-Hunting -Query $q -What 'alert-categories'
if ($cat.Count) {
    $data.charts['Malware detections by category (last 30 days)'] = @($cat | Select-Object -First 6 | ForEach-Object { , @($_.Category, [int]$_.Alerts) })
}

$q = @"
AlertInfo
| where Timestamp > ago(${AlertDays}d)
| summarize Alerts = count() by DetectionSource
| order by Alerts desc
"@
$ds = Invoke-Hunting -Query $q -What 'detection-source'
if ($ds.Count) {
    $data.charts['Detection source'] = @($ds | Select-Object -First 6 | ForEach-Object {
        Write-Output -NoEnumerate @($_.DetectionSource, [int]$_.Alerts)
    })
    Write-Ok "$($ds.Count) tespit kaynagi"
}

# --- AV platform / motor / imza surumleri (best-effort: tablo her tenant'ta olmayabilir)
$q = @"
DeviceTvmInfoGathering
| where Timestamp > ago(7d)
| summarize arg_max(Timestamp, *) by DeviceId
| extend AvPlatform = tostring(AdditionalFields.AvPlatformVersion),
         AvEngine   = tostring(AdditionalFields.AvEngineVersion),
         AvSig      = tostring(AdditionalFields.AvSignatureVersion)
| where isnotempty(AvPlatform) or isnotempty(AvEngine) or isnotempty(AvSig)
| summarize Devices = count() by AvPlatform, AvEngine, AvSig
| order by Devices desc
"@
$ver = Invoke-Hunting -Query $q -What 'av-versions' -Optional
if ($ver.Count) {
    function VerRow {
        param([string]$Field, [string]$Label)
        $groups = $ver | Group-Object $Field | Where-Object { $_.Name } |
                  ForEach-Object { [pscustomobject]@{ v = $_.Name; n = ($_.Group | Measure-Object Devices -Sum).Sum } }
        if (-not $groups) { return $null }
        $sorted = @($groups | Sort-Object { [version]($_.v -replace '[^0-9.]','0') } -Descending -ErrorAction SilentlyContinue)
        if (-not $sorted) { $sorted = @($groups | Sort-Object n -Descending) }
        $latest = $sorted[0]
        $behind = ($groups | Where-Object { $_.v -ne $latest.v } | Measure-Object n -Sum).Sum
        [pscustomobject]@{
            component = $Label
            current   = ($groups | Sort-Object n -Descending | Select-Object -First 1).v
            latest    = $latest.v
            behind    = [int]$behind
        }
    }
    $rows = @(VerRow 'AvPlatform' 'Defender AV platform version'; VerRow 'AvEngine' 'Antimalware engine version'; VerRow 'AvSig' 'Security intelligence (signature) version') |
            Where-Object { $_ }
    if ($rows.Count) {
        $data.tables.agentVersions = @($rows)
        Write-Ok "$($rows.Count) surum bileseni"
    }
}

$q = @"
DeviceEvents
| where Timestamp > ago(${EventDays}d)
| where ActionType in ("SmartScreenUrlWarning","SmartScreenAppWarning","ExploitGuardNetworkProtectionBlocked","ExploitGuardNetworkProtectionAudited","NetworkProtectionUserBypassEvent")
| summarize Events = count(), Devices = dcount(DeviceId) by ActionType
| order by Events desc
"@
$web = Invoke-Hunting -Query $q -What 'web-protection'
if ($web.Count) {
    $data.tables.webProtection = @($web | ForEach-Object { [ordered]@{ action = $_.ActionType; events = [int]$_.Events; devices = [int]$_.Devices } })
    $data.kpi['Malicious URLs blocked'] = '{0:N0}' -f (($web | Where-Object ActionType -match 'Blocked|Warning' | Measure-Object Events -Sum).Sum)
}

# ==================================== 10 · INTUNE POLICY / EXCLUSIONS =====
Write-Step 'Intune endpoint security politikalari ve AV exclusion listesi'
$pol = Try-Api { Invoke-Api -All -Uri 'https://graph.microsoft.com/beta/deviceManagement/configurationPolicies?$expand=assignments' } 'configurationPolicies'
if ($pol) {
    $data.tables.intunePolicies = @($pol | ForEach-Object {
        [ordered]@{
            name        = $_.name
            template    = $_.templateReference.templateDisplayName
            platform    = $_.platforms
            assignments = @($_.assignments).Count
        }
    })
    Write-Ok "$(@($pol).Count) yapılandırma politikası"

    # AV exclusion'lari ve ASR kural modlarini politika ayarlarindan cikar
    $exclusions = [System.Collections.Generic.List[object]]::new()
    $asrModes = @{}   # kural id -> mod

    function Get-AsrMode {
        param([string]$Value)
        $v = $Value.ToLower()
        if ($v -match '_(block|blocked)$' -or $v -match '_1$') { return 'Block' }
        if ($v -match '_(audit|auditmode)$' -or $v -match '_2$') { return 'Audit' }
        if ($v -match '_(warn)$' -or $v -match '_6$') { return 'Warn' }
        if ($v -match '_(off|disable|disabled|notconfigured)$' -or $v -match '_0$') { return 'Disabled' }
        return $null
    }

    $polScope = @($pol | Where-Object {
        $_.templateReference.templateDisplayName -match 'Antivirus|Defender|Attack Surface' -or
        $_.name -match 'Antivirus|Defender|ASR|Attack Surface'
    })

    foreach ($p in $polScope) {
        $settings = Try-Api { Invoke-Api -All -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies('$($p.id)')/settings" } "policy settings $($p.name)"
        foreach ($s in @($settings)) {
            $json = $s | ConvertTo-Json -Depth 20

            if ($json -match 'excluded(path|extension|process)') {
                foreach ($m in [regex]::Matches($json, '"value"\s*:\s*"([^"]{3,})"')) {
                    # Intune degerleri sik sik bastaki/sondaki bosluklarla geliyor. Trim
                    # sart: "^\w:\\?$" gibi capali desenler tek bir bosluk yuzunden
                    # eslesmiyor ve surucu koku exclusion'lari fark edilmeden geciyordu.
                    $v = $m.Groups[1].Value.Trim()
                    if ($v -and $v -match '\\|\.\w{2,4}$') { $exclusions.Add([pscustomobject][ordered]@{ policy = $p.name; value = $v }) }
                }
            }

            # ASR kural modlari: ayar id'si kural adini, secilen deger modu tasir
            if ($json -match 'attacksurfacereduction|asr_rules|block(office|executable|credential|persistence|process|untrusted|webshell|win32|javascript|adobe)') {
                foreach ($m in [regex]::Matches($json, '"value"\s*:\s*"([^"]*defender[^"]*)"')) {
                    $v = $m.Groups[1].Value
                    $mode = Get-AsrMode -Value $v
                    if ($mode) {
                        $ruleId = ($v -replace '_(block|blocked|audit|auditmode|warn|off|disable|disabled|notconfigured|\d)$', '')
                        $asrModes[$ruleId] = $mode
                    }
                }
            }
        }
    }

    # Telemetride olay uretmeyen kurallar gorunmez; Intune yapilandirmasi daha guvenilir
    if ($asrModes.Count -gt 0) {
        $data.tables.asrRules = @($asrModes.GetEnumerator() | Sort-Object Name | ForEach-Object {
            [ordered]@{ rule = ($_.Key -split '_')[-1]; settingId = $_.Key; mode = $_.Value }
        })
        $blk = @($asrModes.Values | Where-Object { $_ -eq 'Block' }).Count
        $aud = @($asrModes.Values | Where-Object { $_ -eq 'Audit' }).Count
        $wrn = @($asrModes.Values | Where-Object { $_ -eq 'Warn' }).Count
        $off = [math]::Max(0, 20 - $blk - $aud - $wrn)

        $data.kpi['Rules in block mode'] = $blk
        $data.kpi['Rules in audit mode'] = $aud
        $data.kpi['Not configured'] = $off
        $data.charts['ASR rule mode distribution'] = @(
            @('Block', $blk),
            @('Audit', $aud),
            @('Warn', $wrn),
            @('Not configured', $off))
        Write-Ok "ASR modlari Intune'dan alindi: $blk block, $aud audit, $wrn warn"
        $script:Warnings.Add("ASR rule modes were derived from Intune policies ($($asrModes.Count) rules); rules managed through Group Policy are not visible.")
    }
    if ($exclusions.Count) {
        $data.tables.avExclusions = @($exclusions | Sort-Object value -Unique)
        # Neden riskli oldugunu da yaz - "412 yuksek riskli" demek tek basina
        # danismanin isine yaramiyor, hangi turden oldugunu gormesi gerekiyor.
        foreach ($e in $data.tables.avExclusions) {
            $r = switch -Regex ($e.value) {
                '^\w:\\?$'                   { 'Entire drive'; break }
                '^\.\w{1,6}$'                { 'Extension only - applies everywhere'; break }
                '\*'                         { 'Wildcard'; break }
                'AppData|\\Temp\\|\\Temp$'   { 'User-writable path'; break }
                '\\Users\\'                  { 'User profile path'; break }
                'ProgramData'                { 'ProgramData - commonly user-writable'; break }
                'HarddiskVolume'             { 'Raw device / shadow copy path'; break }
                default                      { '' }
            }
            $e | Add-Member -NotePropertyName risk -NotePropertyValue $r -Force
        }
        $risky = @($data.tables.avExclusions | Where-Object { $_.risk })
        $data.kpi['Exclusion count'] = $data.tables.avExclusions.Count
        $data.kpi['High-risk exclusions'] = $risky.Count
        Write-Ok "$($data.tables.avExclusions.Count) exclusion ($($risky.Count) yüksek riskli)"
    }
}

# =================================== 11 · RBAC / PIM / CONDITIONAL ACCESS =
Write-Step 'RBAC, PIM ve Conditional Access'
$roles = Try-Api { Invoke-Api -All -Uri 'https://graph.microsoft.com/v1.0/directoryRoles' } 'directoryRoles'
if ($roles) {
    $watch = 'Global Administrator', 'Security Administrator', 'Security Operator', 'Security Reader', 'Privileged Role Administrator'
    $data.tables.privilegedRoles = @(foreach ($r in @($roles | Where-Object { $_.displayName -in $watch })) {
        $m = Try-Api { Invoke-Api -All -Uri "https://graph.microsoft.com/v1.0/directoryRoles/$($r.id)/members" } "members of $($r.displayName)"
        [ordered]@{ role = $r.displayName; members = @($m).Count }
    })
    Write-Ok "$($data.tables.privilegedRoles.Count) ayrıcalıklı rol"
}
$pim = Try-Api { Invoke-Api -All -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleInstances?$top=200' } 'PIM eligibility'
$data.meta.pimEligibleAssignments = @($pim).Count

$ca = Try-Api { Invoke-Api -All -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies' } 'Conditional Access policies'
if ($ca) {
    $deviceAware = @($ca | Where-Object {
        $_.state -eq 'enabled' -and (
            ($_.grantControls.builtInControls -contains 'compliantDevice') -or
            ($_.grantControls.builtInControls -contains 'domainJoinedDevice'))
    })
    $data.tables.conditionalAccess = @([ordered]@{
        totalPolicies       = @($ca).Count
        enabledPolicies     = @($ca | Where-Object state -eq 'enabled').Count
        deviceComplianceCA  = $deviceAware.Count
        deviceRiskUsed      = ($deviceAware.Count -gt 0)
    })
    Write-Ok "$(@($ca).Count) CA politikası, $($deviceAware.Count) tanesi cihaz uyumu talep ediyor"
}

# ======================================== 12 · MDE-ONLY API (opsiyonel) ===
if (-not $GraphOnly) {
    Write-Step 'MDE API: exposure score, oneriler, indicator listesi'
    $exp = Try-Api { Invoke-Api -Api mde -Uri 'https://api.securitycenter.microsoft.com/api/exposureScore' } 'exposureScore'
    if ($exp) {
        $data.kpi['Exposure Score'] = [math]::Round($exp.score)
        $data.kpi['Exposure score'] = [math]::Round($exp.score)
        Write-Ok "Exposure score: $([math]::Round($exp.score))"
    }
    $cs = Try-Api { Invoke-Api -Api mde -Uri 'https://api.securitycenter.microsoft.com/api/configurationScore' } 'configurationScore'
    if ($cs) { $data.meta.configurationScore = [math]::Round($cs.score) }

    $rec = Try-Api { Invoke-Api -Api mde -Uri 'https://api.securitycenter.microsoft.com/api/recommendations' } 'recommendations'
    if ($rec) {
        $data.tables.securityRecommendations = @($rec | Where-Object { $_.status -ne 'Completed' } |
            Sort-Object -Property @{Expression = { $_.publicExploit }; Descending = $true },
                                  @{Expression = { $_.exposedMachinesCount }; Descending = $true } |
            Select-Object -First 15 | ForEach-Object {
                [ordered]@{
                    recommendation = $_.recommendationName
                    category       = $_.recommendationCategory
                    exposedDevices = $_.exposedMachinesCount
                    severity       = $_.severityScore
                    publicExploit  = $_.publicExploit
                    remediation    = $_.remediationType
                }
            })
        Write-Ok "$(@($rec).Count) güvenlik önerisi"
    }
    # Cagri basarili ama sonuc bos: Defender RBAC acikken kimlik hicbir cihaz grubuna
    # kapsanmamis olabilir. API 403 degil BOS doner ve rapor bunu "sifir bulgu" diye
    # yazar - izinsizlikten cok daha sinsi bir hata. Ayirt edemedigimizi soyluyoruz.
    elseif (-not $script:LastApiFailed) {
        Write-Skip 'Security recommendations came back empty rather than failing. If Defender RBAC is enabled, the collecting identity may not be scoped to any device group - widen the scope and re-run before the report states there are none.'
    }
    $ind = Try-Api { Invoke-Api -Api mde -Uri 'https://api.securitycenter.microsoft.com/api/indicators' } 'indicators'
    if ($ind) {
        $data.tables.indicators = @(@($ind) | Group-Object indicatorType | ForEach-Object {
            [ordered]@{ type = $_.Name; count = $_.Count; withoutExpiry = @($_.Group | Where-Object { -not $_.expirationTime }).Count }
        })
        Write-Ok "$(@($ind).Count) indicator"
    }
}

# ============================================ 13 · BULGU TASLAKLARI =======
# Toplanan veriden esik degerlere gore taslak bulgu uretir. Severity/owner/tarih
# danisman tarafindan gozden gecirilmelidir — bunlar oneri, karar degil.
Write-Step 'Bulgu taslaklari uretiliyor'

function NumOf {
    param([string]$Key)
    $v = $data.kpi[$Key]
    if ($null -eq $v) { return $null }
    $t = ([string]$v) -replace '[^\d\.\-]', ''
    if ($t -eq '') { return $null }
    try { return [double]$t } catch { return $null }
}

$findings = [System.Collections.Generic.List[object]]::new()
function Add-Finding {
    param([string]$Text, [string]$Domain, [string]$Severity)
    $findings.Add([ordered]@{
        id       = ''
        finding  = $Text
        domain   = $Domain
        severity = $Severity
        effort   = ''
        owner    = ''
        due      = ''
        status   = 'Open'
    })
}

$rate = NumOf 'Onboarding Rate'
$gap  = NumOf 'Not onboarded'
if ($null -ne $rate -and $rate -lt 95 -and $gap -gt 0) {
    Add-Finding "$([int]$gap) in-scope devices are running without a Defender for Endpoint sensor (coverage $([int]$rate)%)" 'Deployment' 'High'
}
foreach ($k in 'Impaired comms', 'No sensor data') {
    $n = NumOf $k
    if ($n -gt 0) { Add-Finding "$([int]$n) devices appear onboarded but produce no telemetry ($k)" 'Deployment' 'High' }
}
$tp = NumOf 'Tamper protection on'
if ($null -ne $tp -and $tp -lt 100) { Add-Finding "Tamper protection is enabled on only $([int]$tp)% of devices" 'Protection' $(if ($tp -lt 50) { 'Critical' } else { 'High' }) }
$rt = NumOf 'Real-time protection on'
if ($null -ne $rt -and $rt -lt 100) { Add-Finding "Real-time protection is enabled on $([int]$rt)% of devices; the remainder are unprotected" 'Protection' 'Critical' }
$cp = NumOf 'Cloud protection on'
if ($null -ne $cp -and $cp -lt 100) { Add-Finding "Cloud-delivered protection is enabled on $([int]$cp)% of devices" 'Protection' 'High' }

$blk = NumOf 'Rules in block mode'
$aud = NumOf 'Rules in audit mode'
if ($null -ne $blk -and $blk -lt 8) {
    Add-Finding "Only $([int]$blk) attack surface reduction rules are enforced in block mode$(if ($aud -gt 0) { "; $([int]$aud) remain in audit mode and permit the technique they detect" })" 'ASR' 'High'
}
if ($data.tables.avExclusions -and $data.kpi['High-risk exclusions'] -gt 0) {
    # Tur dokumu olmadan "413 yuksek riskli exclusion" cumlesi bir ise yaramiyor
    $byRisk = @($data.tables.avExclusions | Where-Object { $_.risk } | Group-Object risk |
                Sort-Object Count -Descending | ForEach-Object { "$($_.Count) $($_.Name.ToLower())" })
    $sev = if ($data.tables.avExclusions | Where-Object { $_.risk -eq 'Entire drive' }) { 'Critical' } else { 'High' }
    Add-Finding ("$($data.kpi['High-risk exclusions']) high-risk antivirus exclusions - " +
                 ($byRisk -join ', ')) 'Protection' $sev
}

$crit = NumOf 'Critical CVEs'
if ($crit -gt 0) { Add-Finding "$([int]$crit) critical CVEs are open across the estate" 'TVM' $(if ($crit -ge 20) { 'Critical' } else { 'High' }) }
$exp = NumOf 'Exposure Score'
if ($exp -gt 30) { Add-Finding "Exposure score is $([int]$exp), above the recommended threshold of 30" 'TVM' 'Medium' }
$ss = NumOf 'Secure score for devices'
if ($null -ne $ss -and $ss -lt 70) { Add-Finding "Microsoft Secure Score for devices is $([int]$ss)%, indicating material configuration gaps" 'Governance' 'Medium' }

if ($data.tables.secureConfiguration) {
    $avgCfg = [math]::Round((@($data.tables.secureConfiguration) | Measure-Object compliance -Average).Average)
    if ($avgCfg -lt 60) { Add-Finding "Average security configuration compliance is $avgCfg%, indicating the security baseline is not applied" 'Governance' 'High' }
}
if ($data.tables.conditionalAccess -and -not $data.tables.conditionalAccess[0].deviceRiskUsed) {
    Add-Finding 'Device compliance and risk signals are not used by any Conditional Access policy' 'Integration' 'High'
}
$ga = @($data.tables.privilegedRoles | Where-Object { $_.role -eq 'Global Administrator' }).members
if ($ga -gt 5) { Add-Finding "$ga standing Global Administrator accounts exist outside Privileged Identity Management" 'Governance' 'High' }
if ($null -ne $data.tables.customDetections -and @($data.tables.customDetections).Count -eq 0) {
    Add-Finding 'No custom detection rules are defined' 'EDR' 'Low'
}
$open = NumOf 'Open / in progress'
if ($open -gt 0) { Add-Finding "$([int]$open) alerts remain open or in progress" 'EDR' 'Medium' }

if ($findings.Count -gt 0) {
    $i = 1
    foreach ($f in $findings) { $f.id = 'F-{0:D2}' -f $i; $i++ }
    $data.tables.findings = @($findings)

    $sevOrder = 'Critical', 'High', 'Medium', 'Low'
    $data.charts['Findings by severity'] = @(
        $sevOrder | ForEach-Object {
            $sv = $_
            Write-Output -NoEnumerate @($sv, @($findings | Where-Object { $_.severity -eq $sv }).Count)
        })
    $data.charts['Findings by domain'] = @(
        $findings | Group-Object domain | Sort-Object Count -Descending | ForEach-Object {
            Write-Output -NoEnumerate @($_.Name, $_.Count)
        })
    $data.kpi['Critical Findings'] = @($findings | Where-Object { $_.severity -eq 'Critical' }).Count
    $data.kpi['Critical'] = @($findings | Where-Object { $_.severity -eq 'Critical' }).Count
    $data.kpi['High']     = @($findings | Where-Object { $_.severity -eq 'High' }).Count
    $data.kpi['Medium']   = @($findings | Where-Object { $_.severity -eq 'Medium' }).Count
    $data.kpi['Low']      = @($findings | Where-Object { $_.severity -eq 'Low' }).Count

    Write-Ok "$($findings.Count) taslak bulgu uretildi"
    $script:Warnings.Add("$($findings.Count) findings were generated automatically from threshold rules - review severity, owner and target dates.")
}

# ================================================= 14 · MANUEL ALANLAR ====
$data.manual = @(
    'Executive summary, risk statement and all narrative text'
    'Findings register: severity decision, effort, owner and target dates'
    'Maturity scoring (current vs target) and gap analysis'
    'Remediation roadmap (30 / 90 / 365 days) and priority matrix'
    'Threat Analytics usage (no API - check in the portal)'
    'Proxy / TLS bypass verification (client analyzer output)'
    'SOC operating model, shift cover, playbooks and exercise maturity'
    'Exclusion justifications and approval process'
    'Live response / RBAC practice in operation (who can do what)'
    'Sentinel connector health and ingestion volume (Azure ARM + Usage table)'
)
$data.meta.warnings = @($script:Warnings)
$data.tables.queries = @($script:Queries)

# ======================================================== ÇIKTI ==========
$data | ConvertTo-Json -Depth 12 | Set-Content -Path $OutFile -Encoding utf8
Write-Host ''
Write-Host "  JSON yazıldı: $OutFile" -ForegroundColor White
Write-Host "  KPI: $($data.kpi.Count) · grafik: $($data.charts.Count) · tablo: $($data.tables.Count)" -ForegroundColor DarkGray
if ($script:Warnings.Count) {
    Write-Host ''
    Write-Host '  Uyarılar:' -ForegroundColor Yellow
    $script:Warnings | ForEach-Object { Write-Host "   - $_" -ForegroundColor DarkYellow }
}

# Toplu 403 → izin sorunu; net yonlendirme ver
$forbidden = @($script:Warnings | Where-Object { $_ -match '403|Forbidden|eksik izin' })
if ($forbidden.Count -ge 3) {
    Write-Host ''
    Write-Host '  ┌──────────────────────────────────────────────────────────────┐' -ForegroundColor Red
    Write-Host '  │ Cagrilarin cogu 403 dondu: token gerekli izinlere sahip degil │' -ForegroundColor Red
    Write-Host '  └──────────────────────────────────────────────────────────────┘' -ForegroundColor Red
    Write-Host '  Varsayilan ClientId (Azure CLI) Defender/guvenlik izinlerine yetkili degildir.' -ForegroundColor Yellow
    Write-Host '  Kendi public client app kaydinizi olusturun:' -ForegroundColor Yellow
    Write-Host '    1. entra.microsoft.com > App registrations > New registration (Single tenant)' -ForegroundColor Gray
    Write-Host '    2. Authentication > Allow public client flows: Yes' -ForegroundColor Gray
    Write-Host '    3. API permissions > Delegated > README.md listesi > Grant admin consent' -ForegroundColor Gray
    Write-Host '    4. Yeniden calistirin: -ClientId <yeni app id>' -ForegroundColor Gray
}
Write-Host ''
Write-Host ''
Write-Host '  The JSON file above is the only output. Nothing was changed in the tenant.' -ForegroundColor White
Write-Host '  Send it to the assessor who requested the health check.' -ForegroundColor DarkGray
Write-Host ''

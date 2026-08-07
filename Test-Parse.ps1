#Requires -Version 7.0
<#
.SYNOPSIS
    Klasördeki .ps1 dosyalarını parse eder, sözdizimi hatalarının tam yerini yazar.
.DESCRIPTION
    Hiçbir şey çalıştırmaz — sadece PowerShell'in kendi parser'ını kullanır.
    Sorun giderirken önce bunu çalıştırın.
.EXAMPLE
    .\Test-Parse.ps1
#>
[CmdletBinding()]
param(
    [string]$Path = $PSScriptRoot
)

try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch { }

Write-Host ''
Write-Host " Sozdizimi kontrolu: $Path" -ForegroundColor White
Write-Host ' ---------------------------------------------------------' -ForegroundColor DarkGray

$bad = 0
foreach ($file in (Get-ChildItem -Path $Path -Filter '*.ps1' | Sort-Object Name)) {

    $tokens = $null
    $errors = $null
    $null = [System.Management.Automation.Language.Parser]::ParseFile(
        $file.FullName, [ref]$tokens, [ref]$errors)

    if ($errors -and $errors.Count -gt 0) {
        $bad++
        Write-Host ''
        Write-Host " HATA  $($file.Name)  ($($errors.Count) adet)" -ForegroundColor Red
        foreach ($er in $errors) {
            $ln = $er.Extent.StartLineNumber
            $col = $er.Extent.StartColumnNumber
            Write-Host ("   satir {0}, sutun {1}: {2}" -f $ln, $col, $er.Message) -ForegroundColor Yellow

            # hatalı satırı ve komşularını göster
            $lines = Get-Content -Path $file.FullName
            for ($i = [math]::Max(1, $ln - 2); $i -le [math]::Min($lines.Count, $ln + 2); $i++) {
                $mark = if ($i -eq $ln) { '>>' } else { '  ' }
                $color = if ($i -eq $ln) { 'White' } else { 'DarkGray' }
                Write-Host ("   {0} {1,5}: {2}" -f $mark, $i, $lines[$i - 1]) -ForegroundColor $color
            }
        }
    }
    else {
        Write-Host " OK    $($file.Name)" -ForegroundColor Green
    }

    # Akilli tirnak uyarisi: PowerShell U+2018/2019/201C/201D karakterlerini de
    # string sinirlayicisi sayar; Turkce kesme isareti olarak kullanilirsa
    # string'i erken kapatir ve tum dosyanin tirnak eslesmesi kayar.
    # NOT: karakterler kod noktasiyla yaziliyor — bu dosyanin kendisi de
    # akilli tirnak icermesin diye (aksi halde kendi kendini bozar).
    $raw = Get-Content -Path $file.FullName -Raw
    $smartChars = @([char]0x2018, [char]0x2019, [char]0x201C, [char]0x201D)
    $smartCount = @($raw.ToCharArray() | Where-Object { $smartChars -contains $_ }).Count
    if ($smartCount -gt 0) {
        Write-Host "       ! $smartCount adet akilli tirnak var - duz tirnakla degistirin" -ForegroundColor Yellow
        Write-Host '         (PowerShell bunlari string sinirlayicisi sayar)' -ForegroundColor DarkYellow
    }
}

Write-Host ''
if ($bad -eq 0) {
    Write-Host ' Tum dosyalar sozdizimi acisindan temiz.' -ForegroundColor Green
} else {
    Write-Host " $bad dosyada sozdizimi hatasi var (yukarida)." -ForegroundColor Red
}
Write-Host " PowerShell surumu: $($PSVersionTable.PSVersion)" -ForegroundColor DarkGray
Write-Host ''

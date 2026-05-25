# cleanup.ps1
#
# Removes Quilr Sentinel Endpoint Agent leftovers:
#   1. The Programs & Features (appwiz.cpl) entry/entries for the MSI product(s)
#      - proper removal via `msiexec /x {ProductCode}` (also runs the agent
#        uninstaller through the MSI's deferred CA)
#      - force-removes the ARP registry key if an entry is orphaned (failed /
#        partial install that msiexec can no longer uninstall)
#   2. The WinDivert kernel driver (WinDivert / WinDivert14) if still attached
#
# Run elevated (Administrator). It self-checks and aborts if not.
#
# Usage:
#   .\cleanup.ps1                 # remove all "Quilr Sentinel Endpoint Agent*" products + driver
#   .\cleanup.ps1 -DryRun         # show what would happen, change nothing
#   .\cleanup.ps1 -Force          # also force-remove ARP reg keys even if msiexec succeeded/declined
#   .\cleanup.ps1 -KeepDriver     # leave the WinDivert driver in place
#   .\cleanup.ps1 -NameLike '*Quilr Sentinel*'   # override the product-name match

[CmdletBinding()]
param(
    [string]$NameLike = '*Quilr Sentinel Endpoint Agent*',
    [switch]$Force,
    [switch]$KeepDriver,
    [switch]$DryRun
)

$ErrorActionPreference = 'Continue'
Set-StrictMode -Version Latest

function Write-Step { param($m) Write-Host "[>] $m" -ForegroundColor Cyan }
function Write-Ok   { param($m) Write-Host "[+] $m" -ForegroundColor Green }
function Write-Warn2 { param($m) Write-Host "[!] $m" -ForegroundColor Yellow }
function Write-Err2 { param($m) Write-Host "[x] $m" -ForegroundColor Red }
function Write-Dry  { param($m) Write-Host "[dry-run] $m" -ForegroundColor DarkGray }

# --- Elevation check --------------------------------------------------------
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
           ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Err2 "This script must run as Administrator. Re-launch from an elevated prompt."
    exit 1
}

Write-Host ""
Write-Host "Quilr Sentinel cleanup  (NameLike='$NameLike'  DryRun=$DryRun  Force=$Force  KeepDriver=$KeepDriver)"
Write-Host "============================================================================"

# ── 1. Find ARP / appwiz.cpl entries ────────────────────────────────────────
$arpRoots = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
)

$entries = New-Object System.Collections.Generic.List[object]
foreach ($root in $arpRoots) {
    if (-not (Test-Path $root)) { continue }
    Get-ChildItem $root -ErrorAction SilentlyContinue | ForEach-Object {
        $p = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
        if ($p -and $p.PSObject.Properties.Name -contains 'DisplayName' -and $p.DisplayName -like $NameLike) {
            $dv = ''; if ($p.PSObject.Properties.Name -contains 'DisplayVersion') { $dv = $p.DisplayVersion }
            $us = ''; if ($p.PSObject.Properties.Name -contains 'UninstallString') { $us = $p.UninstallString }
            $isMsi = (($p.PSObject.Properties.Name -contains 'WindowsInstaller') -and ($p.WindowsInstaller -eq 1)) `
                     -or ($_.PSChildName -match '^\{[0-9A-Fa-f-]{36}\}$')
            $entries.Add([pscustomobject]@{
                DisplayName     = $p.DisplayName
                DisplayVersion  = $dv
                KeyName         = $_.PSChildName          # ProductCode for MSI entries
                RegPath         = $_.PSPath
                UninstallString = $us
                IsMsi           = $isMsi
            }) | Out-Null
        }
    }
}

if ($entries.Count -eq 0) {
    Write-Ok "No appwiz.cpl entries matching '$NameLike' found."
} else {
    Write-Step "Found $($entries.Count) matching appwiz.cpl entr$(if($entries.Count -eq 1){'y'}else{'ies'}):"
    $entries | ForEach-Object { Write-Host ("    {0}  v{1}  [{2}]" -f $_.DisplayName, $_.DisplayVersion, $_.KeyName) }
}

# ── 2. Remove each entry ─────────────────────────────────────────────────────
foreach ($e in $entries) {
    Write-Host ""
    Write-Step "Removing: $($e.DisplayName) [$($e.KeyName)]"

    $removedByMsi = $false
    if ($e.IsMsi -and $e.KeyName -match '^\{[0-9A-Fa-f-]{36}\}$') {
        # Proper uninstall via msiexec (also runs the MSI's uninstall CA -> agent uninstaller)
        if ($DryRun) {
            Write-Dry "msiexec /x $($e.KeyName) /qn /norestart"
        } else {
            Write-Step "  msiexec /x $($e.KeyName) /qn /norestart"
            $log = Join-Path $env:TEMP ("sentinel-cleanup-{0}.log" -f ($e.KeyName -replace '[{}]',''))
            $p = Start-Process -FilePath 'msiexec.exe' `
                    -ArgumentList @('/x', $e.KeyName, '/qn', '/norestart', '/l*v', $log) `
                    -Wait -PassThru -WindowStyle Hidden
            # 0 = ok, 3010 = ok+reboot, 1605 = product not installed (already gone)
            if ($p.ExitCode -in @(0, 3010, 1605)) {
                Write-Ok "  msiexec exit $($p.ExitCode) -- removed"
                $removedByMsi = $true
            } else {
                Write-Warn2 "  msiexec exit $($p.ExitCode) -- will force-remove the ARP key (log: $log)"
            }
        }
    } else {
        Write-Warn2 "  Not an MSI entry (or no ProductCode) -- will force-remove the ARP key."
    }

    # Force-remove the ARP registry key if it still exists (orphaned), or if -Force
    $stillThere = Test-Path $e.RegPath
    if (($Force -or -not $removedByMsi) -and $stillThere) {
        if ($DryRun) {
            Write-Dry "Remove-Item $($e.RegPath) -Recurse"
        } else {
            try {
                Remove-Item -Path $e.RegPath -Recurse -Force -ErrorAction Stop
                Write-Ok "  Force-removed ARP registry key."
            } catch {
                Write-Err2 "  Failed to remove ARP key: $($_.Exception.Message)"
            }
        }
    }
}

# ── 3. Remove the WinDivert driver if attached ───────────────────────────────
if ($KeepDriver) {
    Write-Host ""
    Write-Warn2 "Skipping driver removal (-KeepDriver)."
} else {
    Write-Host ""
    Write-Step "Checking for WinDivert kernel driver..."
    $driverNames = @('WinDivert', 'WinDivert14')
    $found = $false
    foreach ($drv in $driverNames) {
        $svc = Get-Service -Name $drv -ErrorAction SilentlyContinue
        # Get-Service may not list kernel drivers reliably; also probe sc.exe query.
        $scQuery = & sc.exe query $drv 2>&1
        $exists = ($svc -ne $null) -or ($LASTEXITCODE -eq 0)
        if (-not $exists) { continue }
        $found = $true
        $state = if ($svc) { $svc.Status } else { '(driver)' }
        Write-Step "  WinDivert driver '$drv' present (state=$state)"
        if ($DryRun) {
            Write-Dry "sc.exe stop $drv ; sc.exe delete $drv"
            continue
        }
        & sc.exe stop $drv   2>&1 | Out-Null   # 0 ok, 1062 not started, 1060 absent
        Start-Sleep -Milliseconds 800
        & sc.exe delete $drv 2>&1 | Out-Null   # 0 ok, 1060 absent
        Start-Sleep -Milliseconds 500
        $after = & sc.exe query $drv 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Ok "  Driver '$drv' removed."
        } else {
            Write-Warn2 "  Driver '$drv' still present -- a handle may be open. Check: fltmc instances ; reboot may be required."
        }
    }
    if (-not $found) { Write-Ok "  No WinDivert driver attached." }

    # Stray driver file (best-effort): the agent install dir's WinDivert64.sys
    $sysFile = 'C:\Program Files\Sentinel\WinDivert64.sys'
    if ((Test-Path $sysFile) -and -not $DryRun) {
        try { Remove-Item $sysFile -Force -ErrorAction Stop; Write-Ok "  Removed $sysFile" }
        catch { Write-Warn2 "  Could not remove $sysFile (in use?): $($_.Exception.Message)" }
    }
}

Write-Host ""
Write-Host "============================================================================"
Write-Ok "Cleanup complete.$(if($DryRun){' (dry-run -- nothing changed)'})"
Write-Host "Verify appwiz.cpl is clear:  Get-CimInstance Win32_Product -Filter \"Name like '%Quilr Sentinel%'\""

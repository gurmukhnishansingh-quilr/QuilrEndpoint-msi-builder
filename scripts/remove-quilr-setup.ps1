# remove-quilr-setup.ps1
# Removes the 3 "Quilr Setup" WiX Burn-bundle entries (QuilrInstaller.exe) from
# Programs & Features. Must run elevated (Administrator). Logs to out\remove-quilr-setup.log.
#
#   Right-click -> Run with PowerShell (as admin), or:
#   Start-Process powershell -Verb RunAs -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File','<this>'

$ErrorActionPreference = 'Continue'
$log = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\out\remove-quilr-setup.log'))
$logDir = Split-Path $log
if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
Set-Content -Path $log -Value "" -ErrorAction SilentlyContinue
function W($m){ $line = "{0}  {1}" -f (Get-Date -Format 'HH:mm:ss'), $m; Write-Host $line; Add-Content -Path $log -Value $line }

$pr = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    W "ERROR: not elevated. Re-run this script as Administrator."
    exit 5
}

$guids = '{13A70429-52AE-4C70-931C-C8F04CDF1F9F}',
         '{420A0AE4-4C88-4EB6-B088-6559FEEAE674}',
         '{75CC4A37-640C-460E-BE46-40FD3F998E0F}'

W "=== Remove 'Quilr Setup' bundles (elevated as $($pr.Identity.Name)) ==="

W "[1] Killing stuck QuilrInstaller processes..."
Get-Process QuilrInstaller -ErrorAction SilentlyContinue | ForEach-Object {
    try { $_.Kill(); W "    killed PID $($_.Id)" }
    catch { W "    kill PID $($_.Id) failed: $($_.Exception.Message)" }
}
Start-Sleep -Seconds 2

W "[2] Uninstalling each bundle (sequential, quiet)..."
foreach ($g in $guids) {
    $exe = "C:\ProgramData\Package Cache\$g\QuilrInstaller.exe"
    if (-not (Test-Path -LiteralPath $exe)) { W "    skip (cached exe missing): $g"; continue }
    W "    uninstalling $g ..."
    try {
        $p = Start-Process -FilePath $exe -ArgumentList '/uninstall','/quiet','/norestart' -PassThru -ErrorAction Stop
        $p.WaitForExit()
        $deadline = (Get-Date).AddSeconds(150)
        while ((Get-Process QuilrInstaller -ErrorAction SilentlyContinue) -and (Get-Date) -lt $deadline) { Start-Sleep -Seconds 2 }
        W "      exit=$($p.ExitCode)  (0=ok, 3010=ok+reboot, 2=another instance/blocked)"
    } catch { W "      ERROR: $($_.Exception.Message)" }
}

W "[3] Verify uninstall..."
$leftAfterUninstall = @()
foreach ($g in $guids) {
    $k = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\$g"
    if (Test-Path $k) { W "    STILL PRESENT: $g"; $leftAfterUninstall += $g } else { W "    removed: $g" }
}

# [4] Fallback purge. The bundle uninstall fails with 0x80070002 (cached bundle
#     is missing its attached payloads) and the inner QuilrMsi is already Absent --
#     these are ORPHANED bundle registrations. Remove the registration directly:
#     the ARP/Uninstall key, the Burn dependency provider key, and the Package Cache.
if ($leftAfterUninstall.Count -gt 0) {
    W "[4] Bundle uninstall could not complete (orphaned registration). Purging directly..."
    $regRoots = @(
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
    )
    $depRoots = @(
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Installer\Dependencies',
        'HKLM:\SOFTWARE\Classes\Installer\Dependencies'
    )
    foreach ($g in $leftAfterUninstall) {
        foreach ($rr in $regRoots) {
            $k = Join-Path $rr $g
            if (Test-Path $k) { try { Remove-Item $k -Recurse -Force -ErrorAction Stop; W "    deleted ARP key: $k" } catch { W "    WARN del $k : $($_.Exception.Message)" } }
        }
        foreach ($dr in $depRoots) {
            $k = Join-Path $dr $g
            if (Test-Path $k) { try { Remove-Item $k -Recurse -Force -ErrorAction Stop; W "    deleted dependency key: $k" } catch { W "    WARN del $k : $($_.Exception.Message)" } }
        }
        $cache = "C:\ProgramData\Package Cache\$g"
        if (Test-Path $cache) {
            try { Remove-Item $cache -Recurse -Force -ErrorAction Stop; W "    deleted Package Cache: $cache" }
            catch {
                # Package Cache is ACL'd to TrustedInstaller; take ownership then retry.
                try {
                    & takeown.exe /F $cache /R /D Y | Out-Null
                    & icacls.exe $cache /grant "*S-1-5-32-544:F" /T /C | Out-Null
                    Remove-Item $cache -Recurse -Force -ErrorAction Stop
                    W "    deleted Package Cache (after takeown): $cache"
                } catch { W "    WARN: could not delete $cache : $($_.Exception.Message)" }
            }
        }
    }
}

W "[5] Final verify..."
$anyLeft = $false
foreach ($g in $guids) {
    $k = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\$g"
    if (Test-Path $k) { W "    STILL PRESENT: $g"; $anyLeft = $true } else { W "    gone: $g" }
}
if ($anyLeft) { W "RESULT: some entries still present -- see warnings above." }
else { W "RESULT: all 3 'Quilr Setup' entries removed from appwiz.cpl." }
W "done. (log: $log)"

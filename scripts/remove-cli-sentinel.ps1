# remove-cli-sentinel.ps1
# Surgically remove a CLI-installed (non-MSI) Sentinel agent: the SentinelAgent
# service + C:\Program Files\Sentinel + C:\ProgramData\Sentinel + %LOCALAPPDATA%\.sentinel.
# Deliberately does NOT touch WinDivert, shared Quilr CA certs, env vars, or network
# adapters, so a running QuilrAI install is left undisturbed. Run as Administrator.

$ErrorActionPreference = 'Continue'
$log = 'C:\Quilr\msi-installer-endpoint\out\remove-cli-sentinel.log'
try { Set-Content -Path $log -Value '' -ErrorAction SilentlyContinue } catch {}
function W($m){ $l = "{0}  {1}" -f (Get-Date -Format 'HH:mm:ss'), $m; Write-Host $l; Add-Content -Path $log -Value $l -ErrorAction SilentlyContinue }

$pr = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { W "ERROR: not elevated."; exit 5 }

W "=== Surgical CLI-Sentinel removal (QuilrAI left intact) ==="

# 1. Service
if (Get-Service -Name SentinelAgent -ErrorAction SilentlyContinue) {
    W "Stopping + deleting SentinelAgent service..."
    cmd /c "sc.exe stop SentinelAgent"   2>&1 | Out-Null
    Start-Sleep -Seconds 2
    cmd /c "sc.exe delete SentinelAgent" 2>&1 | Out-Null
    Start-Sleep -Seconds 1
    if (Get-Service -Name SentinelAgent -ErrorAction SilentlyContinue) { W "  WARN: SentinelAgent still present after delete." } else { W "  SentinelAgent deleted." }
} else { W "SentinelAgent service not present." }

# 2. Kill sentinel* processes (no-op if none)
foreach ($p in 'sentinel','sentinel-proxy','sentinel-diagnostics','sentinel-monitor-v2','sentinel-hook-client','sentinel-claude-hook-client') {
    cmd /c "taskkill /F /IM $p.exe 2>nul" | Out-Null
}
Start-Sleep -Seconds 1

# 3. Remove Sentinel dirs (reboot-delete for anything locked, e.g. WinDivert64.sys;
#    we do NOT unload the shared WinDivert driver since QuilrAI is using it).
Add-Type -Namespace Q -Name Fs -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError=true, CharSet=System.Runtime.InteropServices.CharSet.Unicode)]
public static extern bool MoveFileEx(string lpExistingFileName, string lpNewFileName, int dwFlags);
'@ -ErrorAction SilentlyContinue
$reboot = $false
$dirs = @('C:\Program Files\Sentinel', 'C:\ProgramData\Sentinel', (Join-Path $env:LOCALAPPDATA '.sentinel'))
foreach ($d in $dirs) {
    if (-not (Test-Path -LiteralPath $d)) { W "absent: $d"; continue }
    try { Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction Stop; W "removed: $d" }
    catch {
        W "locked residue in $d -- scheduling reboot-delete for locked items"
        Get-ChildItem -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue |
            Sort-Object { $_.FullName.Length } -Descending | ForEach-Object {
                try { Remove-Item -LiteralPath $_.FullName -Force -Recurse -ErrorAction Stop }
                catch { if ([Q.Fs]::MoveFileEx($_.FullName, [NullString]::Value, 4)) { $reboot = $true; W "  reboot-delete: $($_.FullName)" } }
            }
        try { Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction Stop; W "removed (2nd pass): $d" }
        catch { if ([Q.Fs]::MoveFileEx($d, [NullString]::Value, 4)) { $reboot = $true; W "  reboot-delete dir: $d" } }
    }
}

# 4. Sentinel-specific env vars (User+Machine) -- leave shared QUILR_*/NODE_* alone.
foreach ($v in 'SENTINEL_TEMPLATE_DIR','SENTINEL_INSTALLATION_PATH','SENTINEL_OVERRIDE_EMAIL','SENTINEL_UNIFIED_DLP_POLICY') {
    foreach ($scope in 'Machine','User') { try { [Environment]::SetEnvironmentVariable($v, $null, $scope) } catch {} }
}

W ("done. reboot needed for locked residue: {0}" -f $reboot)

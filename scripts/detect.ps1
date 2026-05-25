# detect.ps1
#
# Detects whether the Quilr Sentinel Endpoint Agent package is installed.
# Designed to double as an Intune / SCCM "detection script":
#   - if detected: writes one line to STDOUT and exits 0   (Intune = "installed")
#   - if NOT detected: writes nothing to STDOUT and exits 1 (Intune = "not installed")
#
# It layers several signals so a half-installed box (MSI registered but agent
# deploy failed) is reported correctly.
#
# Usage:
#   .\detect.ps1                         # any Quilr Sentinel install present?
#   .\detect.ps1 -Env uspoc              # specifically the uspoc build (by UpgradeCode + Env marker)
#   .\detect.ps1 -MinVersion 0.30.291    # installed AND agent version >= this
#   .\detect.ps1 -RequireService         # also require the SentinelAgent service to exist
#   .\detect.ps1 -Verbose                # print every signal that was evaluated
#
# Exit codes: 0 = detected, 1 = not detected, 2 = bad arguments.

[CmdletBinding()]
param(
    [ValidateSet('quartz','preprod','usprod','uspoc','india-prod','india-poc','secure','qualtrix-secure')]
    [string]$Env,
    [string]$MinVersion,
    [switch]$RequireService
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'SilentlyContinue'

# Stable per-env UpgradeCodes (must match scripts\build-msi.ps1 EnvMap).
$UpgradeCodes = @{
    'quartz'          = '2C9D3E5A-6F12-4E0B-9B6A-7F4A1D2E0001'
    'preprod'         = '2C9D3E5A-6F12-4E0B-9B6A-7F4A1D2E0002'
    'usprod'          = '2C9D3E5A-6F12-4E0B-9B6A-7F4A1D2E0003'
    'uspoc'           = '2C9D3E5A-6F12-4E0B-9B6A-7F4A1D2E0004'
    'india-prod'      = '2C9D3E5A-6F12-4E0B-9B6A-7F4A1D2E0005'
    'india-poc'       = '2C9D3E5A-6F12-4E0B-9B6A-7F4A1D2E0006'
    'secure'          = '2C9D3E5A-6F12-4E0B-9B6A-7F4A1D2E0007'
    'qualtrix-secure' = '2C9D3E5A-6F12-4E0B-9B6A-7F4A1D2E0008'
}

$InstallDir  = 'C:\Program Files\Sentinel'
$VersionFile = Join-Path $InstallDir '.installed_version'
$ServiceName = 'SentinelAgent'

# ── Signal 1: agent version file ─────────────────────────────────────────────
$agentVersion = $null
if (Test-Path -LiteralPath $VersionFile) {
    $agentVersion = (Get-Content -LiteralPath $VersionFile -Raw).Trim()
}
Write-Verbose "installed_version file: $(if($agentVersion){$agentVersion}else{'<absent>'})"

# ── Signal 2: agent binary present ───────────────────────────────────────────
$binPresent = Test-Path -LiteralPath (Join-Path $InstallDir 'sentinel.exe')
Write-Verbose "sentinel.exe present: $binPresent"

# ── Signal 3: SentinelAgent service ──────────────────────────────────────────
$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
$svcPresent = $null -ne $svc
$svcState = if ($svc) { "$($svc.Status)" } else { 'absent' }
Write-Verbose "service ${ServiceName}: $svcState"

# ── Signal 4: persisted env marker ───────────────────────────────────────────
$envMarker = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Quilr\Sentinel' -Name 'Env' -ErrorAction SilentlyContinue).Env
Write-Verbose "HKLM Env marker: $(if($envMarker){$envMarker}else{'<absent>'})"

# ── Signal 5: MSI registration (per env UpgradeCode -> ProductCode) ──────────
function Get-ProductCodesForUpgradeCode([string]$upgradeCode) {
    # Windows Installer maintains a registry index of UpgradeCode -> ProductCode.
    # Use the COM API (RelatedProducts) which reads it authoritatively.
    $codes = @()
    # The Installer.RelatedProducts API expects the UpgradeCode GUID wrapped in
    # braces and upper-cased.
    $uc = $upgradeCode.Trim()
    if ($uc -notmatch '^\{') { $uc = '{' + $uc + '}' }
    $uc = $uc.ToUpperInvariant()
    try {
        $msi = New-Object -ComObject WindowsInstaller.Installer
        $related = $msi.GetType().InvokeMember('RelatedProducts','GetProperty',$null,$msi,@($uc))
        foreach ($pc in $related) { $codes += $pc }
    } catch { }
    return $codes
}

$msiInstalled = $false
$msiProductCodes = @()
if ($Env) {
    $msiProductCodes = Get-ProductCodesForUpgradeCode $UpgradeCodes[$Env]
    $msiInstalled = $msiProductCodes.Count -gt 0
    Write-Verbose "MSI (env=$Env, upgradeCode=$($UpgradeCodes[$Env])): $(if($msiInstalled){'registered ['+($msiProductCodes -join ', ')+']'}else{'not registered'})"
} else {
    foreach ($e in $UpgradeCodes.Keys) {
        $pc = Get-ProductCodesForUpgradeCode $UpgradeCodes[$e]
        if ($pc.Count -gt 0) { $msiInstalled = $true; $msiProductCodes += $pc; Write-Verbose "MSI registered for env '$e': $($pc -join ', ')" }
    }
}

# ── Decision ─────────────────────────────────────────────────────────────────
# "Installed" = the agent is actually deployed (version file + binary). The MSI
# registration and service are corroborating signals. We treat agent-deployed
# as the source of truth because that is what the package is supposed to leave
# behind; a bare MSI registration without the agent is a failed install.
$installed = ($null -ne $agentVersion) -and $binPresent

if ($RequireService) { $installed = $installed -and $svcPresent }

# Env-specific: also require the env marker (and/or MSI registration) to match.
if ($Env -and $installed) {
    $envMatches = ($envMarker -eq $Env) -or $msiInstalled
    if (-not $envMatches) {
        Write-Verbose "Agent installed but not for env '$Env' (marker='$envMarker', msi=$msiInstalled)."
        $installed = $false
    }
}

# Version floor.
if ($installed -and $MinVersion) {
    try {
        $have = [version]($agentVersion -replace '[^0-9.]','')
        $need = [version]($MinVersion   -replace '[^0-9.]','')
        if ($have -lt $need) {
            Write-Verbose "Agent version $agentVersion < required $MinVersion."
            $installed = $false
        }
    } catch {
        Write-Verbose "Could not compare versions ('$agentVersion' vs '$MinVersion')."
    }
}

# ── Output (Intune contract: stdout+exit0 = detected) ────────────────────────
if ($installed) {
    $envLabel = if ($envMarker) { $envMarker } elseif ($Env) { $Env } else { 'unknown' }
    Write-Output ("Quilr Sentinel Endpoint Agent installed: version=$agentVersion env=$envLabel service=$svcState" +
                  $(if($msiProductCodes.Count){" msi=$($msiProductCodes -join ',')"}else{''}))
    exit 0
} else {
    # No STDOUT on purpose -> Intune reads "not installed".
    exit 1
}

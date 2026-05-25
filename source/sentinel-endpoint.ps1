#
# Sentinel Endpoint Agent (Windows)
#
# Self-contained binary: installs if not present, updates if already installed.
# Compiled to .exe via ps2exe for customer distribution.
#
# INSTALL MODE (auto-detected: service not registered + ZIP available):
#   .\sentinel-endpoint.ps1 -ZipPath .\sentinel_package_v1.0.0_win_release.zip
#
# UPDATE MODE (auto-detected: service registered):
#   .\sentinel-endpoint.ps1                         # CDN update check
#   .\sentinel-endpoint.ps1 -Local .\package.zip    # Local ZIP update
#   .\sentinel-endpoint.ps1 -Force                  # Force re-deploy
#   .\sentinel-endpoint.ps1 -DryRun                 # Verify only, don't deploy
#
# Flags:
#   -ZipPath             Path to installer ZIP (install mode)
#   -Local               Path to local ZIP for update (update mode)
#   -Force               Bypass version-floor/download-failure checks (security checks still run)
#   -DryRun              Download and verify, but don't deploy
#   -SkipSignatureCheck  Skip RSA manifest signature and SHA-256 verification
#   -VerifyAuthenticode  Enable Authenticode verification (off by default)
#   -ShowVersion         Print version and exit
#   -SelfTest            Run logic + error-handling unit tests and exit (no admin required)
#
# Exit codes:
#   0 = success (installed, updated, up-to-date, or skipped)
#   1 = error
#
# Requires: Administrator privileges
#

param(
    [string]$ZipPath,
    [string]$Local,
    [string]$Email,
    # Tenant ID for this organisation. Required for MDM installs (or set
    # QUILR_TENANT_ID env). On fresh manual installs an interactive popup
    # collects it when omitted. Ignored / never prompted for on updates.
    [string]$TenantId,
    [switch]$Force,
    [switch]$DryRun,
    [switch]$VerifySignatures,       # Opt-in: enable RSA manifest sig, SHA-256, Authenticode
    [switch]$VerifyAuthenticode,     # Opt-in: enable Authenticode verification (off until binaries are signed)
    [switch]$SkipSignatureCheck,     # Legacy alias (ignored -- checks are off by default now)
    # -ShowVersion is the canonical spelling.  Aliases cover common
    # abbreviations operators actually type.  NOTE: `-Version` is ALSO a
    # powershell.exe host switch; when you run
    #     powershell.exe -File script.ps1 -Version
    # the host can swallow `-Version` before the script sees it, and the
    # script then runs with all defaults (Env=secure, no ShowVersion).
    # Prefer `-ShowVersion` (or `-V`) so the arg is unambiguously for the
    # script, not the host.
    [Alias('V','Ver','Version')]
    [switch]$ShowVersion,
    # CLI verbosity.  Default: clean phase markers only (log file stays
    # fully verbose).  Pass -CliVerbose to restore the legacy dump-every-
    # log-line-to-stdout behaviour (useful for debugging).
    [switch]$CliVerbose,
    # Self-test mode: exercises pure-logic functions (version comparison, email
    # validation) and verifies that error-handling catch blocks fire correctly on
    # synthetic failures.  Does NOT install, update, or require elevation.
    # Run via: powershell -File sentinel-endpoint.ps1 -SelfTest
    [switch]$SelfTest
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

# Silence the progress stream globally.  On PowerShell 5.1, Invoke-WebRequest
# and Expand-Archive render a progress bar for every 16KB read, which
# (a) leaks "Writing web request / Writing request stream" text onto stdout
# when run with -File or redirected, and (b) is a ~10-100x slowdown on
# cold fetches because every progress tick does a synchronous host write.
# File-level logging is unaffected -- this only disables the host progress UI.
$ProgressPreference = 'SilentlyContinue'

# Signature verification is on by default -- verifies RSA manifest signature
# and SHA-256 checksum. Use -SkipSignatureCheck to disable for dev/test builds.
$script:DoVerifySignatures = -not $SkipSignatureCheck.IsPresent
# Authenticode is off by default -- Windows binaries are not code-signed yet.
# Use -VerifyAuthenticode to enable once signing pipeline is in place.
$script:DoVerifyAuthenticode = $VerifyAuthenticode.IsPresent

# .NET-based SHA-256 -- works in ps2exe-compiled hosts where Get-FileHash may be unavailable
function Get-Sha256Hash {
    param([string]$FilePath)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $stream = [IO.File]::OpenRead($FilePath)
        try {
            $hashBytes = $sha.ComputeHash($stream)
            return ([BitConverter]::ToString($hashBytes) -replace '-', '').ToUpper()
        } finally { $stream.Close() }
    } catch {
        Log-Exception -Label "Get-Sha256Hash" -ErrorRecord $_ -Context @(
            "FilePath: $FilePath",
            "Exists:   $(Test-Path $FilePath)"
        ) -Hints @(
            "File may be locked, missing, or inaccessible -- check ACL and that no other process holds it open."
        ) -Level "ERROR"
        throw
    } finally { $sha.Dispose() }
}

# =============================================================================
# EMBEDDED PAYLOAD -- Extract bundled ZIP if present
# =============================================================================
# The QA generator can append a base64-encoded ZIP after a marker comment.
# When present, the script decodes it to a temp file and uses it as the ZIP.
# This makes the script fully self-contained (no separate ZIP file needed).

$script:EmbeddedZip       = $null
$script:IsCdnFreshInstall = $false
# Email is collected during fresh-install and CDN-fresh-install flows only.
# Initialize at script scope so StrictMode doesn't throw when
# Register-SentinelService reads it during a manual -ZipPath refresh on an
# already-installed device (no email prompt runs in that path).
$script:CollectedEmail    = $null
$script:CollectedTenantId = $null
function Extract-EmbeddedPayload {
    if (-not $PSCommandPath) { return $false }
    # ps2exe-compiled .exe: $PSCommandPath is a temp .ps1 that never has a payload.
    # Skip to avoid reading a potentially large temp file for nothing.
    if ([Environment]::GetCommandLineArgs()[0] -match '\.exe"?$') { return $false }
    $lines = [IO.File]::ReadAllLines($PSCommandPath)
    $markerIdx = -1
    for ($i = $lines.Count - 1; $i -ge 0; $i--) {
        if ($lines[$i] -eq "#__SENTINEL_PAYLOAD_BASE64_BEGIN__") {
            $markerIdx = $i
            break
        }
    }
    if ($markerIdx -lt 0) { return $false }

    # Collect all base64 lines after the marker (skip comment lines)
    $b64 = New-Object System.Text.StringBuilder
    for ($i = $markerIdx + 1; $i -lt $lines.Count; $i++) {
        $line = $lines[$i].Trim()
        if ($line -and -not $line.StartsWith("#")) {
            [void]$b64.Append($line)
        }
    }
    if ($b64.Length -eq 0) { return $false }

    try {
        $bytes = [Convert]::FromBase64String($b64.ToString())
        $tempZip = Join-Path ([IO.Path]::GetTempPath()) "sentinel_embedded_$PID.zip"
        [IO.File]::WriteAllBytes($tempZip, $bytes)
        $script:EmbeddedZip = $tempZip
        return $true
    } catch {
        Log-Exception -Label "Extract-EmbeddedPayload" -ErrorRecord $_ -Context @(
            "Base64 length: $($b64.Length) chars",
            "TempZip:       $(Join-Path ([IO.Path]::GetTempPath()) "sentinel_embedded_$PID.zip")"
        ) -Hints @(
            "Base64 block may be truncated or corrupted -- rebuild the self-contained binary.",
            "Check available disk space on $([IO.Path]::GetTempPath())"
        ) -Level "WARN"
        return $false
    }
}
Extract-EmbeddedPayload | Out-Null

# =============================================================================
# SELF-UPDATE -- apply pending setup binary from previous run
# =============================================================================

# ps2exe sets $PSCommandPath to a temp-extracted .ps1, not the .exe.
# Detect and use the actual executable path for self-update and copy-to-install-dir.
#
# CRITICAL: when run via `powershell.exe -File script.ps1`, args[0] is
# powershell.exe itself, which ALSO matches \.exe$.  The previous version of
# this check mis-identified that case as ps2exe and set $selfPath to
# powershell.exe, which then made Invoke-Install try to Copy-Item
# powershell.exe into C:\Program Files\Sentinel\sentinel-endpoint.exe.
# Filter known PowerShell host exes so only real ps2exe-compiled launchers
# trigger the override.
$selfPath = $PSCommandPath
$__arg0 = [Environment]::GetCommandLineArgs()[0]
if ($__arg0 -match '\.exe"?$') {
    $__arg0Name = [IO.Path]::GetFileName(($__arg0 -replace '^"' -replace '"$')).ToLower()
    $__psHosts  = @('powershell.exe','pwsh.exe','powershell_ise.exe')
    if ($__arg0Name -notin $__psHosts) {
        # Running as ps2exe-compiled .exe -- resolve to full absolute path
        $rawExe = $__arg0 -replace '^"' -replace '"$'
        try { $selfPath = (Resolve-Path $rawExe -ErrorAction Stop).Path }
        catch { $selfPath = $rawExe }
    }
}

if ($selfPath) {
    $pendingUpdate = "$selfPath.new"
    if (Test-Path $pendingUpdate) {
        $updaterBackup = "$selfPath.backup"
        $updaterBackupPrev = "$selfPath.backup.prev"
        try {
            # Dual-backup rotation: preserve two prior versions so a failed
            # agent-deploy that happens AFTER the updater-swap can still
            # restore a known-good updater (the one BEFORE the one that
            # delivered the bad agent payload).  Older .backup -> .backup.prev,
            # then current -> .backup.  Best-effort -- a rotation failure does
            # not block the swap; Remove-StaleUpdaterBackups GCs after N days.
            if (Test-Path -LiteralPath $updaterBackup) {
                try { Move-Item -LiteralPath $updaterBackup -Destination $updaterBackupPrev -Force -ErrorAction Stop }
                catch { Log-Warn "Updater .backup -> .backup.prev rotation failed: $($_.Exception.Message)" }
            }
            try {
                Copy-Item -Path $selfPath -Destination $updaterBackup -Force -ErrorAction Stop
            } catch {
                Log-Warn "Updater backup copy failed: $($_.Exception.Message) -- rollback to previous updater will be unavailable."
                Log-Warn "  Source: $selfPath"
                Log-Warn "  Dest:   $updaterBackup"
            }

            # Smoke test: verify the new binary can print its version.
            try {
                & $pendingUpdate -ShowVersion 2>&1 | Out-Null
                if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) { throw "non-zero exit" }
            } catch {
                Log-Warn "Self-update smoke test failed -- keeping current version: $($_.Exception.Message)"
                Remove-Quiet -Path $pendingUpdate -Label "pending updater"
                # Keep $updaterBackup: it's a copy of the CURRENT running
                # binary and remains valid rollback insurance for the next
                # swap attempt.  Remove-StaleUpdaterBackups GCs eventually.
                $pendingUpdate = $null
            }

            if ($pendingUpdate -and (Test-Path $pendingUpdate)) {
                Move-Item -Path $pendingUpdate -Destination $selfPath -Force -ErrorAction Stop
                # Re-launch with the new version and same arguments
                & $selfPath @PSBoundParameters
                exit $LASTEXITCODE
            }
        } catch {
            # Failed to swap or new version crashed -- restore backup.
            Log-Warn "Self-update swap failed -- attempting rollback: $($_.Exception.Message)"
            if (Test-Path $updaterBackup) {
                try {
                    Move-Item -Path $updaterBackup -Destination $selfPath -Force -ErrorAction Stop
                } catch {
                    # Rollback itself failed -- this is the bad path where the
                    # on-disk updater is now potentially half-written.  We log
                    # loudly so the next manual run surfaces the issue.
                    Log-Error "Rollback Move-Item '$updaterBackup' -> '$selfPath' failed: $($_.Exception.Message)"
                }
            }
            Remove-Quiet -Path $pendingUpdate -Label "pending updater"
        } finally {
            # Guarantee .new is never left on disk -- a stale .new on the next run
            # would re-attempt a swap with an already partially-moved file.
            if ($pendingUpdate -and (Test-Path -LiteralPath $pendingUpdate)) {
                Remove-Quiet -Path $pendingUpdate -Label "pending updater (stale .new cleanup)"
            }
        }
    }
}

# =============================================================================
# CONFIGURATION
# =============================================================================

# CDN base URL. Manifest lives at: $CdnBase/$OS/$ARCH/update.json
# Resolved per env in the Environment URL Resolution section below.  The
# preprod default is a safety net -- production runs ALWAYS overwrite this
# in the switch, so the default only surfaces when env resolution itself
# breaks; dev/staging is the safest fallback in that case.
$CdnBase = "https://quilr-extensions.quilr.ai/endpoint-agent/preprod"

# Hard version floor -- refuses to install anything below this.
$MinSafeVersion = "0.10.200"

# RSA public key for manifest signature verification (RSA-PSS, SHA-256).
# Replace this placeholder with the real production key before shipping.
$UpdaterPublicKey = @"
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuML6Y6UbEkAlKpSmGlPP
IoowkvWkFiTroLfAPMJWjTCQaoWMJR5q97eM1sKn6IwVcP8T8py84dEarUqCOXlz
Jg+q3jfIW3he9HG+jwPJjzB1BDfEnNhnSID02bCIdDdb/GkU6aa99dGIagh3qe9U
w+0U1uOLYK3xaST1KE9aHrG4v4tb0fTbtavT3oVFUXSC8XIo8uiDY6SV7lclt00z
xpBQFO+h45perm0B+dGzPQndejKvitPCulCtme7nfWFver4QbXv6ecxj+2/YdsEZ
rSRAKFTEPbm4QARlarnrV5ffUMqMuKq70k5QceYfyy4F6kNt4HZnhnpvSM/ALp3A
nwIDAQAB
-----END PUBLIC KEY-----
"@

# Identity
$SetupVersion = "1.4.0"

# Timing
$GracefulStopTimeout = 20     # Seconds to wait for agent to stop before force kill
$HealthCheckDuration = 15     # Seconds to monitor agent after start (halved from 30 -- 15s is enough to catch startup crashes on observed machines; saves 15s/update)
$HealthCheckInterval = 3      # Seconds between health polls
$ManifestTimeout = 30         # Timeout for manifest fetch (seconds)
$ZipTimeout = 300             # Timeout for ZIP download (seconds)
$MaxRetries = 3               # Retry count for HTTP fetches
$MinDiskMB = 200              # Minimum free disk space (MB)
# NOTE: Version-quarantine logic was removed -- it was a stone wall.  A failed
# rollback used to write .quarantined_version and block retries for 6h, which
# meant a transient problem (locked file, flaky CDN during deploy) locked the
# device out of upgrades even after the underlying cause cleared.  Failure
# detection now leans on Test-DownloadFailures (retry counter, bounded) plus
# telemetry from the agent.  Leftover .quarantined_version files from old
# installs are wiped on startup via Remove-LegacyBlocklists below.

# Diagnostics / teardown tunings (shared across Write-NetworkSnapshot,
# Write-SystemExtensionLogDump, and grace-timer callers).  Grouped so a single
# review of "what's the scheduled-tick cost budget?" sees all of them.
$NetworkProbePingMs       = 2000  # ping.exe -w timeout per probe (ms)
$NetworkProbeHttpMs       = 5000  # HttpWebRequest.Timeout for HEAD probes (ms)
$EventLogWindowMinutes    = 5     # Get-WinEvent StartTime window
$EventLogMaxPerProvider   = 20    # Cap per provider to keep log size bounded
$EventLogMessageMaxChars  = 260   # Per-event message truncation cap
$ProcessDrainGraceSeconds = 6     # Grace window for clean self-exit before hard-kill
$ProcessDrainPollMs       = 200   # Poll interval while waiting for self-exit

# Paths
$InstallDir = "C:\Program Files\Sentinel"
$ServiceName = "SentinelAgent"
$LogDir = "C:\ProgramData\Quilr\logs\sentinel-endpoint"
$ServiceLogDir = "C:\ProgramData\Sentinel\logs"

# Lock file
$LockFile = Join-Path $InstallDir ".updater.lock"
# Upper bound on how long a lock can be honoured regardless of PID liveness.
# A stuck previous run whose PID got recycled to an unrelated process would
# otherwise trap the device forever; 2h is comfortably > the slowest observed
# update tick and short enough that a real hang self-clears on the next tick.
$UpdateLockMaxAgeHours = 2

# Rollback storage
$RollbackDir = Join-Path $InstallDir ".rollback"

# User-level sentinel directory (hooks, scripts, thin clients)
# Agent resolves ~/.sentinel via USERPROFILE, not LOCALAPPDATA
$SentinelUserDir = Join-Path $env:USERPROFILE ".sentinel"

# Processes to kill on forced stop
$KillProcesses = @("sentinel.exe", "sentinel-proxy.exe", "sentinel-diagnostics.exe", "ipc-light-broker.exe", "template-engine.exe", "templating-engine.exe", "sentinel-monitor-v2.exe")

# Scheduled task identity
$UpdaterTaskName = "Sentinel-Endpoint-Update"
$UpdaterIntervalMinutes = 30
# RemoteSigned keeps launcher lines free of the high-signal "ExecutionPolicy Bypass" token.
# Unblock-File is applied when staging the updater .ps1 so MOTW does not block execution.
$UpdaterLauncherExecutionPolicy = "RemoteSigned"
# Full path to powershell.exe -- predictable host and stable quoting in run-updater.bat.
$UpdaterWindowsPowerShellExe = Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe"

# =============================================================================
# EARLY EXITS
# =============================================================================

# ─── Persisted env (sticky across runs, updatable on demand) ─────────────────
#
# Problem: the scheduled task has -Env baked into its schedtask XML, but a
# manual `sentinel-endpoint.exe` run picks up the PARAM DEFAULT.  Devices
# installed into "secure" that are run manually therefore can check the
# wrong CDN (cross-env drift) or cross-env downgrade.
#
# Authoritative store: HKLM:\SOFTWARE\Quilr\Sentinel\Env (REG_SZ).
#   - Written on every successful install / update (Write-PersistedEnv).
#   - Read at script start when -Env was not passed (Read-PersistedEnv).
# Write-gated by Administrator (install already runs elevated).
#
# Resolution order:
#   (1) explicit -Env on the command line  ← operator intent always wins
#   (2) HKLM:\SOFTWARE\Quilr\Sentinel\Env
#   (3) param default "secure"
$SentinelRegRoot = "HKLM:\SOFTWARE\Quilr\Sentinel"

function Read-PersistedEnv {
    # Returns the persisted env string, or $null if nothing is set / value is
    # invalid.  Never throws -- logging isn't up yet when this runs and we
    # don't want a script-start failure to come from a registry quirk.
    try {
        $reg = Get-ItemProperty -Path $SentinelRegRoot -Name "Env" -ErrorAction Stop
        $val = "$($reg.Env)".Trim()
        if ($val -in @('quartz','preprod','usprod','uspoc','india-prod','india-poc','secure','qualtrix-secure','prod')) { return $val }
    } catch {
        # Intentional silent fallback: this function runs BEFORE Write-Log is
        # wired (logging isn't defined yet at the top of the script), so a
        # registry-miss or key-absent error here would have nowhere to go.
        # Returning $null lets the caller fall through to the default env --
        # the observable outcome we want on a first-time install.
    }
    return $null
}

function Write-PersistedEnv {
    # Writes the env value to the registry.  Called at the end of every
    # successful install / update so the store is always in sync with the
    # scheduled-task args that Register-UpdaterSchedule just baked in.
    param([string]$Value)
    if ($Value -notin @('quartz','preprod','usprod','uspoc','india-prod','india-poc','secure','qualtrix-secure')) { return }
    try {
        if (-not (Test-Path $SentinelRegRoot)) {
            New-Item -Path $SentinelRegRoot -Force -ErrorAction Stop | Out-Null
        }
        Set-ItemProperty -Path $SentinelRegRoot -Name "Env" -Value $Value -Type String -ErrorAction Stop
        Log-Debug "Persisted env to registry: $Value"
    } catch {
        Log-Warn "Could not persist env to registry: $($_.Exception.Message)"
        Log-Warn "  Manual runs without -Env may use the default on this machine."
    }
}

$Env = "preprod"  # default; overridden by registry if a prior install persisted a value
$script:EnvIsExplicit = $false
$script:PersistedEnvAtStart = Read-PersistedEnv
if (-not $script:EnvIsExplicit -and $script:PersistedEnvAtStart) {
    # Implicit run (double-click / scheduled task without explicit -Env):
    # adopt the persisted env.  Registry is the source of truth -- it's
    # portable, GPO-enforceable, and readable by the agent + field-support
    # tooling without parsing a custom file.
    $Env = $script:PersistedEnvAtStart
}
# Transition detection: operator explicitly asked for $Env and it differs
# from what was persisted.  Flagged here so the main flow can surface a
# banner and so Write-PersistedEnv knows to log it as a transition.
$script:EnvTransition = $null
if ($script:EnvIsExplicit -and $script:PersistedEnvAtStart -and
    $script:PersistedEnvAtStart -ne $Env) {
    $script:EnvTransition = @{
        From = $script:PersistedEnvAtStart
        To   = $Env
    }
}

if ($ShowVersion) {
    # Self-contained: runs before the main logging system is fully up.
    # Writes an audit line to the log file AND prints three versions to stdout:
    #   1. Installer (this binary/script)
    #   2. Agent currently installed on this box
    #   3. Latest version advertised by CDN (5s timebound fetch; never throws)
    #
    # Safety: any CDN or filesystem failure is caught and reported as
    # "(unavailable: <reason>)".  -ShowVersion is also invoked during the
    # self-update smoke test, so it MUST exit 0 cleanly on every path.
    $logFileForVersion = Join-Path $LogDir "sentinel_endpoint.log"
    try {
        if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force -ErrorAction Stop | Out-Null }
    } catch {
        # ShowVersion MUST exit 0 (the self-update smoke test invokes it);
        # if we can't create the log dir, audit-log calls below become
        # no-ops but the version output itself still succeeds.
    }
    $ts = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss zzz")
    $__auditLog = {
        param($line)
        # Same contract as above: log-write failure cannot abort ShowVersion.
        try { Add-Content -Path $logFileForVersion -Value "$ts [INFO] [PID:$PID] [ShowVersion] $line" -ErrorAction Stop } catch { }
    }

    Write-Host "sentinel-endpoint v$SetupVersion"
    & $__auditLog "Installer (this binary):  v$SetupVersion"

    # 2. Installed agent version (written by Invoke-Install / Invoke-Update to .installed_version)
    $agentVer = "(not installed)"
    $versionFile = Join-Path $InstallDir ".installed_version"
    if (Test-Path $versionFile) {
        try { $agentVer = (Get-Content $versionFile -Raw -EA Stop).Trim() }
        catch { $agentVer = "(read error: $($_.Exception.Message -replace '[\r\n]+',' '))" }
    }
    Write-Host "  Agent installed:  $agentVer"
    & $__auditLog "Agent installed:          $agentVer"

    # 3. CDN-advertised latest (timebound; hard-capped by HttpWebRequest.Timeout).
    #    Hostname per -Env; quartz + preprod share the shared CDN, secure has its own.
    $cdnUrlForVersion = switch ($Env) {
        "quartz"  { "https://quilr-extensions.quilr.ai/endpoint-agent/quartz/windows/64/update.json" }
        # "quartz"  { "http://localhost:8765/endpoint-agent/quartz/windows/64/update.json" }  # LOCAL CDN TEST
        "preprod" { "https://quilr-extensions.quilr.ai/endpoint-agent/preprod/windows/64/update.json" }
        "secure"  { "https://quilr-hub.quilr.ai/endpoint-agent/prod/windows/64/update.json" }
        default   { $null }
    }
    $cdnVer = "(unavailable)"
    if ($cdnUrlForVersion) {
        try {
            $req = [System.Net.HttpWebRequest]::Create($cdnUrlForVersion)
            $req.Timeout          = 5000    # 5s: connect + headers
            $req.ReadWriteTimeout = 5000    # 5s: per-socket op
            $req.Method           = 'GET'
            $resp = $req.GetResponse()
            try {
                $reader = New-Object System.IO.StreamReader($resp.GetResponseStream())
                $body   = $reader.ReadToEnd()
                $reader.Close()
                $parsed = $body | ConvertFrom-Json
                if ($parsed.version) { $cdnVer = $parsed.version }
                else { $cdnVer = "(malformed manifest: no .version field)" }
            } finally { $resp.Close() }
            & $__auditLog "Latest on CDN:            $cdnVer (from $cdnUrlForVersion)"
        } catch {
            $errShort = ($_.Exception.Message -replace '[\r\n]+', ' ' -replace '\s+', ' ').Trim()
            if ($errShort.Length -gt 100) { $errShort = $errShort.Substring(0, 100) + '...' }
            $cdnVer = "(unavailable: $errShort)"
            & $__auditLog "CDN fetch FAILED from $cdnUrlForVersion -- $errShort"
        }
    } else {
        & $__auditLog "CDN fetch skipped: unknown Env '$Env'"
    }
    Write-Host "  Latest on CDN:    $cdnVer"
    Write-Host "  Env:              $Env"

    exit 0
}

# Assert the public key is not the placeholder -- fail early with a clear message
if ($UpdaterPublicKey -match "PLACEHOLDER|0{20}") {
    Write-Host "[!] WARNING: UpdaterPublicKey is still the placeholder. CDN manifest verification will fail." -ForegroundColor Yellow
    Write-Host "[!] CDN auto-updates are disabled until a real RSA public key is embedded." -ForegroundColor Yellow
}

# ─── Environment URL Resolution ───────────────────────────────────────────────

$validEnvs = @("quartz", "preprod", "usprod", "uspoc", "india-prod", "india-poc", "secure", "qualtrix-secure")
if ($Env -notin $validEnvs) {
    Write-Host "[!] Invalid -Env value '$Env'. Must be one of: $($validEnvs -join ', ')" -ForegroundColor Red
    exit 1
}
switch ($Env) {
    "quartz"     {
        $DlpEndpoint    = "https://dlpone.quilr.ai"
        $BackendBaseUrl = "https://quartz.quilr.ai"
        $CdnBase        = "https://quilr-extensions.quilr.ai/endpoint-agent/quartz"
        # $CdnBase        = "http://localhost:8765/endpoint-agent/quartz"  # LOCAL CDN TEST
    }
    "preprod"    {
        $DlpEndpoint    = "https://dlppreprod.quilr.ai"
        $BackendBaseUrl = "https://preprod.quilr.ai"
        $CdnBase        = "https://quilr-extensions.quilr.ai/endpoint-agent/preprod"
    }
    "usprod"     {
        $DlpEndpoint    = "https://dlpone.quilrai.com"
        $BackendBaseUrl = "https://app.quilrai.com"
        $CdnBase        = "https://quilr-extensions.quilr.ai/endpoint-agent/usprod"
    }
    "uspoc"      {
        $DlpEndpoint    = "https://dlpone.quilr.ai"
        $BackendBaseUrl = "https://app.quilr.ai"
        $CdnBase        = "https://quilr-extensions.quilr.ai/endpoint-agent/uspoc"
    }
    "india-prod" {
        $DlpEndpoint    = "https://dlp-platform.quilrai.com"
        $BackendBaseUrl = "https://platform.quilrai.com"
        $CdnBase        = "https://quilr-extensions.quilr.ai/endpoint-agent/indprod"
    }
    "india-poc"  {
        $DlpEndpoint    = "https://dlp-platform.quilr.ai"
        $BackendBaseUrl = "https://platform.quilr.ai"
        $CdnBase        = "https://quilr-extensions.quilr.ai/endpoint-agent/indpoc"
    }
    "secure"     {
        # Hybrid tenant: dedicated backend on secure.quilr.ai, but the DLP
        # model service lives on the shared dlpone.quilr.ai host (same
        # service quartz uses).  Pointing DLP at secure.quilr.ai returns
        # empty streams, which manifests as "[DLP] No sensitive data
        # found" for every request.
        $DlpEndpoint    = "https://dlpone.quilr.ai"
        $BackendBaseUrl = "https://secure.quilr.ai"
        # Secure customer CDN.  Same path layout as quartz/preprod
        # ($CdnBase/$archPath/update.json) -- only the hostname differs.
        $CdnBase        = "https://quilr-hub.quilr.ai/endpoint-agent/prod"
    }
    "qualtrix-secure" {
        # Same backend + DLP as `secure`, but the CDN is the raw S3 bucket
        # (no CloudFront).  Keep in sync with sentinel-endpoint.sh.
        $DlpEndpoint    = "https://dlpone.quilr.ai"
        $BackendBaseUrl = "https://secure.quilr.ai"
        $CdnBase        = "https://quilr-hub.s3.us-east-1.amazonaws.com/endpoint-agent/prod"
    }
}

# =============================================================================
# LOGGING -- Always verbose to the log file.  CLI is phase-markers only
# unless -CliVerbose was passed.  WARN / ERROR are always visible in CLI.
# =============================================================================

if (-not (Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}
$script:LogFile = Join-Path $LogDir "sentinel_endpoint.log"

# Quiet-by-default CLI.  Log file stays verbose regardless.
$script:CliQuiet = -not $CliVerbose.IsPresent

function Write-Log {
    param(
        [string]$Level,
        [string]$Message
    )
    $ts = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss zzz")
    $entry = "$ts [$Level] [PID:$PID] $Message"
    # Always append to log file (verbose, for post-mortem).
    # $script:LogFile used explicitly (avoids ps2exe scope ambiguity).
    # FileShare.ReadWrite allows concurrent writers -- e.g. an active install
    # and a scheduled-task tick running at the same time both write without
    # blocking each other.  Add-Content uses FileShare.Read which causes the
    # other process's writes to fail silently.
    $lf = $script:LogFile
    $writeOk = $false
    if ($lf) {
        try {
            $fs = [IO.File]::Open($lf, [IO.FileMode]::Append, [IO.FileAccess]::Write, [IO.FileShare]::ReadWrite)
            try {
                $sw = [IO.StreamWriter]::new($fs, [Text.Encoding]::UTF8)
                $sw.WriteLine($entry)
                $sw.Flush()
                $writeOk = $true
            } finally {
                $sw.Dispose()
                $fs.Dispose()
            }
        } catch { }
    }
    # Fallback: if primary write failed (null path, ACL, or fs error) write to a
    # per-PID temp file.  C:\Windows\Temp is always writable by SYSTEM and admins.
    # Check this file if the main log appears empty after a scheduled-task run.
    if (-not $writeOk) {
        try {
            $fb = [IO.Path]::Combine([IO.Path]::GetTempPath(), "sentinel_endpoint_fallback_$PID.log")
            [IO.File]::AppendAllText($fb, "$entry`n", [Text.Encoding]::UTF8)
        } catch { }
    }
    # CLI output: WARN / ERROR always; INFO / DEBUG only when -CliVerbose
    switch ($Level) {
        "ERROR" { Write-Host $entry -ForegroundColor Red }
        "WARN"  { Write-Host $entry -ForegroundColor Yellow }
        "INFO"  {
            if (-not $script:CliQuiet) { Write-Host $entry -ForegroundColor Green }
        }
        "DEBUG" {
            if (-not $script:CliQuiet -and $VerbosePreference -eq "Continue") {
                Write-Host $entry -ForegroundColor Gray
            }
        }
    }
}

function Log-Info  { param([string]$Msg) Write-Log "INFO"  $Msg }
function Log-Warn  { param([string]$Msg) Write-Log "WARN"  $Msg }
function Log-Error { param([string]$Msg) Write-Log "ERROR" $Msg }
function Log-Debug { param([string]$Msg) Write-Log "DEBUG" $Msg }

# Best-effort file/dir removal with error capture.  Replaces the legacy
# `Remove-Item ... -ErrorAction SilentlyContinue` idiom: when the path is
# genuinely absent we emit nothing; when removal throws (locked handle, ACL
# deny, read-only flag) we log the actual exception at -Level so the reason
# is never silent.  Default level is DEBUG because these calls are cleanup
# of staging/temp/quarantine paths -- a failed delete there is non-fatal
# noise in the common case but still auditable in the full log.
function Remove-Quiet {
    param(
        [Parameter(Mandatory)] [string]$Path,
        [switch]$Recurse,
        [ValidateSet('DEBUG','INFO','WARN')] [string]$Level = 'DEBUG',
        [string]$Label = ''
    )
    if (-not (Test-Path -LiteralPath $Path)) { return }
    try {
        if ($Recurse) { Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop }
        else          { Remove-Item -LiteralPath $Path -Force -ErrorAction Stop }
    } catch {
        $tag = if ($Label) { "$Label " } else { '' }
        Write-Log $Level "Remove-Item ${tag}'$Path' failed: $($_.Exception.Message)"
    }
}

# =============================================================================
# CLI UX -- banners, phase markers, final summary, fail banner.
# These write to stdout only (file output is unchanged, via Log-Info below
# each step).  Under -CliVerbose the markers are still emitted, just mixed
# in with the full log stream.
# =============================================================================

# Unicode drawing chars.  Fall back to ASCII on consoles that can't render
# them (detected via OutputEncoding).  Literal UTF-8 glyphs in the source
# broke parsing under PowerShell 5.1 (reads .ps1 as CP1252 without a BOM),
# so glyphs are built from code points -- keeps this file pure ASCII.
$script:_CliUtf8 = $false
try {
    if ([Console]::OutputEncoding.WebName -match 'utf-8|utf8') { $script:_CliUtf8 = $true }
} catch {
    # Runs before Write-Log is callable.  Hosts without a console (automation,
    # no-TTY contexts) land here -- falling back to ASCII glyphs is the
    # intended behaviour, not a failure.
}

# Light box-drawing arcs + lines (U+2500, U+2502, U+256D, U+256E, U+256F, U+2570).
$script:_GlyphTopL    = if ($script:_CliUtf8) { [string][char]0x256D } else { "+" }
$script:_GlyphTopR    = if ($script:_CliUtf8) { [string][char]0x256E } else { "+" }
$script:_GlyphBotL    = if ($script:_CliUtf8) { [string][char]0x2570 } else { "+" }
$script:_GlyphBotR    = if ($script:_CliUtf8) { [string][char]0x256F } else { "+" }
$script:_GlyphH       = if ($script:_CliUtf8) { [string][char]0x2500 } else { "-" }
$script:_GlyphV       = if ($script:_CliUtf8) { [string][char]0x2502 } else { "|" }

# Status glyphs: check mark (U+2713), ballot X (U+2717), clockwise arc (U+21B7).
$script:_GlyphOk      = if ($script:_CliUtf8) { [string][char]0x2713 } else { "[OK]" }
$script:_GlyphFail    = if ($script:_CliUtf8) { [string][char]0x2717 } else { "[FAIL]" }
$script:_GlyphSkip    = if ($script:_CliUtf8) { [string][char]0x21B7 } else { "[SKIP]" }

# Heavy (double) box-drawing for the fail banner (U+2550, U+2551, U+2554, U+2557, U+255A, U+255D).
$script:_GlyphHeavyTL = if ($script:_CliUtf8) { [string][char]0x2554 } else { "+" }
$script:_GlyphHeavyTR = if ($script:_CliUtf8) { [string][char]0x2557 } else { "+" }
$script:_GlyphHeavyBL = if ($script:_CliUtf8) { [string][char]0x255A } else { "+" }
$script:_GlyphHeavyBR = if ($script:_CliUtf8) { [string][char]0x255D } else { "+" }
$script:_GlyphHeavyH  = if ($script:_CliUtf8) { [string][char]0x2550 } else { "=" }
$script:_GlyphHeavyV  = if ($script:_CliUtf8) { [string][char]0x2551 } else { "|" }

$script:_CurrentPhase      = $null       # Name of currently-running phase (for fail-banner)
$script:_CurrentPhaseStart = $null       # [DateTime] when phase started
$script:_CurrentPhaseStep  = 0           # step-count counter "[3/8]"
$script:_TotalPhaseSteps   = 0           # total steps in this flow (for progress hint)
$script:_OpStartedAt       = $null       # when the whole op (install/update) started

function Show-CliBanner {
    param([string]$Title, [string[]]$Subtitles = @())
    $w = 56
    $h = ($script:_GlyphH * ($w - 2))
    Write-Host ""
    Write-Host "  $($script:_GlyphTopL)$h$($script:_GlyphTopR)" -ForegroundColor Cyan
    Write-Host ("  $($script:_GlyphV)  {0,-$($w-4)}  $($script:_GlyphV)" -f $Title) -ForegroundColor Cyan
    foreach ($s in $Subtitles) {
        Write-Host ("  $($script:_GlyphV)  {0,-$($w-4)}  $($script:_GlyphV)" -f $s) -ForegroundColor DarkCyan
    }
    Write-Host "  $($script:_GlyphBotL)$h$($script:_GlyphBotR)" -ForegroundColor Cyan
    Write-Host ""
}

function Start-CliFlow {
    param([int]$TotalSteps)
    $script:_TotalPhaseSteps = $TotalSteps
    $script:_CurrentPhaseStep = 0
    $script:_OpStartedAt = Get-Date
}

function Start-Phase {
    param([string]$Name)
    $script:_CurrentPhase      = $Name
    $script:_CurrentPhaseStart = Get-Date
    $script:_CurrentPhaseStep++
    # No pre-phase CLI line -- phases complete quickly enough that a
    # start-then-end pair is just clutter.  One completion line per phase.
}

function End-PhaseOk {
    param([string]$Detail = "")
    # Null-guard the elapsed calc: if End-PhaseOk fires without a prior
    # Start-Phase (developer error / unexpected flow), Get-Date minus $null
    # yields a huge TimeSpan -- clamp to 0 so output stays sane.
    $elapsed = if ($script:_CurrentPhaseStart) {
        [math]::Round(((Get-Date) - $script:_CurrentPhaseStart).TotalSeconds, 0)
    } else { 0 }
    $stepTag = "[$($script:_CurrentPhaseStep)/$($script:_TotalPhaseSteps)]"
    $line = "  $($script:_GlyphOk) $stepTag {0,-42}" -f $script:_CurrentPhase
    $trail = if ($Detail) { "  $Detail  (${elapsed}s)" } else { "  (${elapsed}s)" }
    Write-Host $line -NoNewline -ForegroundColor Green
    Write-Host $trail -ForegroundColor DarkGray
    $script:_CurrentPhase = $null
}

function End-PhaseSkip {
    param([string]$Reason = "")
    $stepTag = "[$($script:_CurrentPhaseStep)/$($script:_TotalPhaseSteps)]"
    $line = "  $($script:_GlyphSkip) $stepTag {0,-42}" -f $script:_CurrentPhase
    $trail = if ($Reason) { "  ($Reason)" } else { "  (skipped)" }
    Write-Host $line -NoNewline -ForegroundColor Yellow
    Write-Host $trail -ForegroundColor DarkGray
    $script:_CurrentPhase = $null
}

function End-PhaseFail {
    param([string]$Reason)
    $stepTag = "[$($script:_CurrentPhaseStep)/$($script:_TotalPhaseSteps)]"
    Write-Host ("  $($script:_GlyphFail) $stepTag {0,-42}  FAILED" -f $script:_CurrentPhase) -ForegroundColor Red
    Show-CliFailBanner -Step $script:_CurrentPhase -Reason $Reason
    $script:_CurrentPhase = $null
}

function Show-CliFailBanner {
    param([string]$Step, [string]$Reason)
    $stepNum = "$($script:_CurrentPhaseStep)/$($script:_TotalPhaseSteps)"
    $title   = "INSTALL/UPDATE FAILED at step ${stepNum}: $Step"
    $w = [math]::Max(60, $title.Length + 6)
    $h = ($script:_GlyphHeavyH * ($w - 2))
    Write-Host ""
    Write-Host "  $($script:_GlyphHeavyTL)$h$($script:_GlyphHeavyTR)" -ForegroundColor Red
    Write-Host ("  $($script:_GlyphHeavyV)  {0,-$($w-4)}  $($script:_GlyphHeavyV)" -f $title) -ForegroundColor Red
    Write-Host "  $($script:_GlyphHeavyBL)$h$($script:_GlyphHeavyBR)" -ForegroundColor Red
    Write-Host ""
    Write-Host "  Error:  $Reason" -ForegroundColor Red
    Write-Host ""
    Write-Host "  Last 30 log lines (full log: $LogFile):" -ForegroundColor DarkGray
    try {
        Get-Content -Path $LogFile -Tail 30 -ErrorAction Stop | ForEach-Object {
            Write-Host "    $_" -ForegroundColor DarkGray
        }
    } catch {
        Write-Host "    (log tail unavailable: $($_.Exception.Message))" -ForegroundColor DarkGray
    }
    Write-Host ""
    Write-Host "  Next steps:" -ForegroundColor Yellow
    Write-Host "    1. Read the full log:  notepad '$LogFile'" -ForegroundColor Yellow
    Write-Host "    2. Retry:              re-run this installer as Administrator." -ForegroundColor Yellow
    Write-Host "    3. If it persists:     .\sentinel-endpoint-uninstaller.exe -Force  (then re-install)" -ForegroundColor Yellow
    Write-Host ""
}

function Show-CliSuccess {
    param([string]$Title, [string[]]$Lines = @())
    $elapsed = if ($script:_OpStartedAt) { [math]::Round(((Get-Date) - $script:_OpStartedAt).TotalSeconds, 0) } else { 0 }
    Write-Host ""
    Write-Host "  $Title  $($script:_GlyphH)  completed in ${elapsed}s" -ForegroundColor Green
    foreach ($l in $Lines) {
        Write-Host "  $l" -ForegroundColor DarkGray
    }
    Write-Host "  Full log: $LogFile" -ForegroundColor DarkGray
    Write-Host ""
}

# Compact "nothing to do" panel -- for scheduled-tick style early-exits
# (already up-to-date, conditional-download skip, prior download failures) so
# the CLI always shows something meaningful instead of silently exiting.
# Silently clears any open phase so the step counter stays honest without
# emitting a redundant phase-skip line before the panel (panel IS the signal).
function Show-CliNoOp {
    param([string]$Title, [string]$Detail = "")
    $script:_CurrentPhase = $null
    Write-Host ""
    Write-Host ("  {0}  {1}" -f $script:_GlyphOk, $Title) -ForegroundColor Green
    if ($Detail) {
        Write-Host ("  {0}" -f $Detail) -ForegroundColor DarkGray
    }
    Write-Host ("  Full log: {0}" -f $LogFile) -ForegroundColor DarkGray
    Write-Host ""
}

# Single-line "we're doing something" hint emitted before a potentially slow
# network call (CDN manifest fetch, ZIP download) so the operator knows the
# script is alive and what it's waiting on.
function Show-CliChecking {
    param([string]$Message)
    Write-Host ("  {0}  {1}" -f $script:_GlyphH, $Message) -ForegroundColor DarkCyan
}

# Env-transition panel.  Rendered before the install/update banner when an
# explicit -Env differs from the persisted value.  Loud (yellow) but not a
# failure -- operator intent is respected, we just tell them what they
# committed to.
function Show-CliEnvTransition {
    param([string]$From, [string]$To)
    Write-Host ""
    Write-Host "  !  Env transition detected" -ForegroundColor Yellow
    Write-Host ("     Previous:  {0}" -f $From) -ForegroundColor DarkGray
    Write-Host ("     New:       {0}" -f $To)   -ForegroundColor Yellow
    Write-Host  "     Effects:   service binPath + updater schedule will be" -ForegroundColor DarkGray
    Write-Host  "                re-registered with the new -Env value."    -ForegroundColor DarkGray
    Write-Host ""
}

# Verbose error reporting for caught exceptions. Logs exception type, HRESULT,
# message, inner message, and optional hints. Use in catch blocks instead of
# bare `Log-Warn "... $_"` so failures in the field are debuggable from logs.
function Log-Exception {
    param(
        [string]$Label,                   # What was being attempted, e.g. "Register-ScheduledTask"
        [System.Management.Automation.ErrorRecord]$ErrorRecord,
        [string[]]$Context = @(),         # Extra key=value lines (e.g. "Target: $path")
        [string[]]$Hints = @(),           # Human-readable diagnostic hints
        [string]$Level = "WARN"           # DEBUG, WARN, or ERROR
    )
    # DEBUG routes through Log-Debug -- file-only unless -Verbose is set.
    # Used for transient failures that are auto-recovered (e.g. a retry that
    # eventually succeeds) where the CLI shouldn't be spammed with warnings.
    $writer = switch ($Level) {
        "DEBUG" { ${function:Log-Debug} }
        "ERROR" { ${function:Log-Error} }
        default { ${function:Log-Warn} }
    }
    & $writer "[$Label] FAILED"
    if ($ErrorRecord) {
        $ex = $ErrorRecord.Exception
        & $writer "  Exception: $($ex.GetType().FullName)"
        if ($ex.HResult) {
            & $writer ("  HResult:   0x{0:X8} ({1})" -f $ex.HResult, $ex.HResult)
        }
        & $writer "  Message:   $($ex.Message)"
        $inner = $ex.InnerException
        $depth = 0
        while ($inner -and $depth -lt 3) {
            & $writer "  Inner[$depth]: $($inner.GetType().FullName): $($inner.Message)"
            $inner = $inner.InnerException
            $depth++
        }
        if ($ErrorRecord.CategoryInfo) {
            & $writer "  Category:  $($ErrorRecord.CategoryInfo.Category) / $($ErrorRecord.CategoryInfo.Reason)"
        }
        if ($ErrorRecord.InvocationInfo -and $ErrorRecord.InvocationInfo.ScriptLineNumber) {
            & $writer "  Origin:    line $($ErrorRecord.InvocationInfo.ScriptLineNumber), $($ErrorRecord.InvocationInfo.MyCommand)"
        }
    }
    foreach ($line in $Context) { & $writer "  $line" }
    foreach ($hint in $Hints)   { & $writer "  Hint: $hint" }
}

# Run a native executable, capturing stdout+stderr. On non-success exit code,
# logs the full command, exit code, and every line of output. On success, only
# debug-logs the exit code. Use instead of bare `cmd /c "..."` or `& exe ...`
# whenever the failure path matters (services, certs, drivers, scheduled tasks).
function Invoke-Native {
    param(
        [Parameter(Mandatory = $true)][string]$Label,          # e.g. "schtasks /Query"
        [Parameter(Mandatory = $true)][string]$FilePath,        # e.g. "schtasks.exe"
        [string[]]$ArgumentList = @(),
        [int[]]$AllowedExitCodes = @(0),
        [string[]]$Hints = @()
    )
    Log-Debug "[$Label] exec: $FilePath $($ArgumentList -join ' ')"
    $output = $null
    # Relax EAP so native stderr flows to $output; exit code is truth.
    $savedEAP = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        # Merge stderr into stdout so we capture everything for logging.
        $output = & $FilePath @ArgumentList 2>&1
    } catch {
        Log-Exception -Label $Label -ErrorRecord $_ `
            -Context @("Command: $FilePath $($ArgumentList -join ' ')") `
            -Hints $Hints
        $ErrorActionPreference = $savedEAP
        return @{ Success = $false; ExitCode = -1; Output = "" }
    } finally {
        $ErrorActionPreference = $savedEAP
    }
    $ec = $LASTEXITCODE
    if ($ec -in $AllowedExitCodes) {
        Log-Debug "[$Label] exit=$ec (ok, process/service already absent or completed)"
        return @{ Success = $true; ExitCode = $ec; Output = ($output -join "`n") }
    }
    Log-Warn "[$Label] FAILED: exit=$ec"
    Log-Warn "  Command: $FilePath $($ArgumentList -join ' ')"
    Log-Warn "  AllowedExitCodes: $($AllowedExitCodes -join ',')"
    foreach ($line in ($output -split "`r?`n")) {
        $trimmed = "$line".Trim()
        if ($trimmed) { Log-Warn "  > $trimmed" }
    }
    foreach ($hint in $Hints) { Log-Warn "  Hint: $hint" }
    return @{ Success = $false; ExitCode = $ec; Output = ($output -join "`n") }
}

Log-Info "Log file: $LogFile"

# Compact snapshot of the host's network state: reachability, NIC summary,
# system proxy config, WinDivert driver state, firewall profiles. Runs on
# every updater tick (even up-to-date) so oncall has forensic breadcrumbs
# regardless of whether a deploy occurred.
function Write-NetworkSnapshot {
    param(
        [string]$Label,
        # Overall hard cap.  The snapshot is diagnostic-only; if it can't
        # complete in this budget (e.g. CIM provider hung after a driver
        # reload), we abandon it and keep the install/update moving.
        [int]$TimeoutSeconds = 10
    )
    Log-Info "--- Network Snapshot ($Label) ---"

    # Run the whole body inside a background job with a hard total timeout.
    # Returns lines of text; the parent replays them into the main log so
    # output order is preserved.  On timeout: abandon, log one warning, move on.
    # Diagnostics are mainly for post-mortem -- they must NEVER block the
    # install/update flow.
    $job = Start-Job -ScriptBlock {
        param($pingMs, $httpMs, $dlp, $backend)
        $out = New-Object System.Collections.Generic.List[string]

        foreach ($target in @('8.8.8.8', 'google.com')) {
            $ping = ping.exe -n 1 -w $pingMs $target 2>&1 | Out-String
            $line = ($ping -split "`n" | Where-Object { $_ -match 'Reply from|Request timed out|could not find host' } | Select-Object -First 1)
            if ($line) { $out.Add("  ping ${target}: $($line.Trim())") }
            else       { $out.Add("  ping ${target}: no reply / unreachable") }
        }
        foreach ($target in @($dlp, $backend)) {
            if (-not $target) { continue }
            try {
                $req = [System.Net.HttpWebRequest]::Create($target)
                $req.Method = 'HEAD'; $req.Timeout = $httpMs
                $req.ServerCertificateValidationCallback = { $true }
                $resp = $req.GetResponse()
                $out.Add("  curl ${target}: HTTP $([int]$resp.StatusCode)")
                $resp.Close()
            } catch [System.Net.WebException] {
                $code = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { '--' }
                $out.Add("  curl ${target}: HTTP $code  ($($_.Exception.Message -replace '[\r\n]+', ' '))")
            } catch {
                $out.Add("  curl ${target}: failed ($($_.Exception.Message -replace '[\r\n]+', ' '))")
            }
        }

        # Default route + primary adapter
        try {
            $defaultRoute = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop | Sort-Object -Property RouteMetric | Select-Object -First 1
            if ($defaultRoute) {
                $adapter = Get-NetAdapter -InterfaceIndex $defaultRoute.InterfaceIndex -ErrorAction SilentlyContinue
                $ifName  = if ($adapter) { $adapter.Name } else { "ifIndex=$($defaultRoute.InterfaceIndex)" }
                $out.Add("  Primary interface: $ifName  gw=$($defaultRoute.NextHop)  metric=$($defaultRoute.RouteMetric)")
            } else {
                $out.Add("  Primary interface: (no default route!)")
            }
        } catch {
            $out.Add("  Primary interface: Get-NetRoute failed ($($_.Exception.Message))")
        }

        # Adapter / IPv6 summary (bulk query -- do NOT iterate per-adapter, see Disable-IPv6 history)
        try {
            $allAdapters = Get-NetAdapter -ErrorAction Stop
            $up          = @($allAdapters | Where-Object { $_.Status -eq 'Up' }).Count
            $down        = @($allAdapters | Where-Object { $_.Status -ne 'Up' }).Count
            $v6Bindings  = Get-NetAdapterBinding -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue
            $v6Off       = @($v6Bindings | Where-Object { -not $_.Enabled }).Count
            $v6On        = @($v6Bindings | Where-Object { $_.Enabled }).Count
            $out.Add("  Adapters: $up up / $down down   IPv6 bindings: $v6Off off / $v6On on")
        } catch {
            $out.Add("  Adapter enumeration failed: $($_.Exception.Message)")
        }

        # System proxy (WinHTTP)
        try {
            $winhttpOut = netsh.exe winhttp show proxy 2>&1 | Out-String
            $proxyLine  = ($winhttpOut -split "`n" | Where-Object { $_ -match 'Proxy Server|Direct access' } | Select-Object -First 1)
            if ($proxyLine) { $out.Add("  WinHTTP proxy: $($proxyLine.Trim())") }
        } catch {
            $out.Add("  WinHTTP proxy: (unavailable: $($_.Exception.Message))")
        }

        # WinDivert driver state
        foreach ($svcName in @('WinDivert', 'WinDivert14')) {
            $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
            if ($svc) { $out.Add("  Service $($svc.Name): status=$($svc.Status) startType=$($svc.StartType)") }
        }

        # Firewall profile states
        try {
            $profiles = Get-NetFirewallProfile -ErrorAction Stop | Select-Object Name, Enabled
            $fwSummary = ($profiles | ForEach-Object { "$($_.Name)=$(if ($_.Enabled) { 'on' } else { 'off' })" }) -join ' '
            $out.Add("  Firewall profiles: $fwSummary")
        } catch {
            $out.Add("  Firewall profiles: (unavailable: $($_.Exception.Message))")
        }

        return $out.ToArray()
    } -ArgumentList $NetworkProbePingMs, $NetworkProbeHttpMs, $DlpEndpoint, $BackendBaseUrl

    if (Wait-Job $job -Timeout $TimeoutSeconds) {
        $lines = Receive-Job $job
        foreach ($line in $lines) { Log-Info $line }
    } else {
        Log-Warn "  (network snapshot timed out after ${TimeoutSeconds}s -- skipped; diagnostic only, no impact on install/update)"
        Stop-Job $job -ErrorAction SilentlyContinue
    }
    Remove-Job $job -Force -ErrorAction SilentlyContinue
}

# Dump recent entries from Windows event-log providers that back the
# network-filtering stack -- WinDivert, WFP, NDIS, TCPIP, Service Control
# Manager -- plus any Application events from Quilr/WinDivert providers.
# Mirrors the macOS `log show --subsystem com.apple.{system,network}-extension`
# dump: baseline signal for activate/deactivate and driver-level failures.
function Write-SystemExtensionLogDump {
    param(
        [string]$Label,
        [int]$MaxEventsPerProvider = $EventLogMaxPerProvider,
        [int]$WindowMinutes        = $EventLogWindowMinutes
    )
    Log-Info "--- Network Extension / Driver Logs ($Label, last ${WindowMinutes}m) ---"
    $startTime = (Get-Date).AddMinutes(-$WindowMinutes)
    $systemProviders = @(
        'Microsoft-Windows-NDIS', 'Microsoft-Windows-WFP', 'Microsoft-Windows-TCPIP',
        'Service Control Manager', 'WinDivert', 'WinDivert14'
    )
    $anyFound = $false
    # Single Get-WinEvent that opens the System log once and filters by the
    # whole provider set via ProviderName array.  ~6x faster than per-provider
    # calls.  Cap is MaxEventsPerProvider * provider-count to keep the shape
    # of the prior output (not per-provider, but close enough for diagnostics).
    try {
        $all = @(Get-WinEvent -FilterHashtable @{
            LogName = 'System'; ProviderName = $systemProviders; StartTime = $startTime
        } -MaxEvents ($MaxEventsPerProvider * $systemProviders.Count) -ErrorAction Stop)
    } catch {
        $all = @()
    }
    foreach ($group in ($all | Group-Object ProviderName)) {
        $anyFound = $true
        $events = @($group.Group | Sort-Object TimeCreated | Select-Object -First $MaxEventsPerProvider)
        Log-Info "  [$($group.Name)] $($events.Count) event(s)"
        foreach ($e in $events) {
            $msg = ($e.Message -replace '[\r\n]+', ' ' -replace '\s+', ' ').Trim()
            if ($msg.Length -gt $EventLogMessageMaxChars) { $msg = $msg.Substring(0, $EventLogMessageMaxChars) + '...' }
            Log-Info ("    [{0}] Id={1} Lvl={2}  {3}" -f $e.TimeCreated.ToString('HH:mm:ss'), $e.Id, $e.LevelDisplayName, $msg)
        }
    }
    # Scan Application log for sentinel / quilr / windivert entries regardless of provider.
    try {
        $appEvents = Get-WinEvent -FilterHashtable @{ LogName = 'Application'; StartTime = $startTime } -ErrorAction Stop `
            | Where-Object { $_.ProviderName -match '(?i)sentinel|quilr|windivert' -or $_.Message -match '(?i)sentinel|quilr|windivert' } `
            | Select-Object -First $MaxEventsPerProvider
        if ($appEvents) {
            $appEvents = @($appEvents)
            $anyFound = $true
            Log-Info "  [Application] $($appEvents.Count) sentinel/quilr/windivert-matching event(s)"
            foreach ($e in ($appEvents | Sort-Object TimeCreated)) {
                $msg = ($e.Message -replace '[\r\n]+', ' ' -replace '\s+', ' ').Trim()
                if ($msg.Length -gt $EventLogMessageMaxChars) { $msg = $msg.Substring(0, $EventLogMessageMaxChars) + '...' }
                Log-Info ("    [{0}] {1} Id={2}  {3}" -f $e.TimeCreated.ToString('HH:mm:ss'), $e.ProviderName, $e.Id, $msg)
            }
        }
    } catch {
        Log-Debug "  No Application events matched sentinel/quilr/windivert"
    }
    if (-not $anyFound) {
        Log-Info "  (no relevant driver/service events in last ${WindowMinutes} minutes)"
    }
}

# Log all sentinel-related processes with PIDs -- called after install, update, and uninstall.
function Log-SentinelProcesses {
    param([string]$Label)
    Log-Info "--- Sentinel Processes ($Label) ---"
    $sentinelNames = @("sentinel", "sentinel-proxy", "ipc-light-broker", "template-engine", "templating-engine", "sentinel-monitor-v2", "sentinel-diagnostics", "sentinel-hook-client", "sentinel-claude-hook-client")
    $found = $false
    foreach ($name in $sentinelNames) {
        $procs = Get-Process -Name $name -ErrorAction SilentlyContinue
        foreach ($p in $procs) {
            Log-Info "  $($p.ProcessName) (PID $($p.Id))"
            $found = $true
        }
    }
    if (-not $found) {
        Log-Info "  (none running)"
    }
}

# Trust-store update via .NET (avoids spawning certutil.exe -- common AV / VT string hit).
# StoreName='Root' (default) for trust anchors (self-signed root CA).
# StoreName='CA'   for "Intermediate Certification Authorities" (chain-building intermediates).
function Add-SentinelUserRootCert {
    param(
        [Parameter(Mandatory = $true)][string]$CertificatePath,
        [ValidateSet('Root', 'CA')][string]$StoreName = 'Root'
    )
    if (-not (Test-Path -LiteralPath $CertificatePath)) {
        Log-Warn "Certificate file not found: $CertificatePath"
        return $false
    }
    $cert = $null
    try {
        $probe = [IO.File]::ReadAllText($CertificatePath)
        if ($probe -match '(?ms)-----BEGIN CERTIFICATE-----\s*(.+?)\s*-----END CERTIFICATE-----') {
            $der = [Convert]::FromBase64String(($Matches[1] -replace '\s', ''))
            $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(,$der)
        } else {
            $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($CertificatePath)
        }
        # X509Store has an (string, StoreLocation) overload -- pass $StoreName
        # directly; avoids the fragile [Enum]::$var dynamic lookup idiom.
        $store = New-Object System.Security.Cryptography.X509Certificates.X509Store(
            $StoreName,
            [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser)
        $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
        try {
            foreach ($existing in $store.Certificates) {
                if ($existing.Thumbprint -eq $cert.Thumbprint) { return $true }
            }
            # Already trusted machine-wide?  The MSI installer adds the Quilr CA
            # chain to LocalMachine\Root (root) and LocalMachine\CA (intermediate),
            # which is trusted by every user on the box.  Adding the same cert to
            # CurrentUser\Root would pop the Windows "Do you want to install this
            # certificate?" security dialog for no benefit.
            #
            # We check BOTH LocalMachine\Root AND LocalMachine\CA, regardless of
            # which CurrentUser store we were about to write: the agent package
            # ships only an intermediate (legacy single-cert mode adds it to
            # CurrentUser\Root), but the MSI files it under LocalMachine\CA -- so
            # a store-matched check alone would miss it and still prompt.  If the
            # thumbprint is present in either machine store, the chain is already
            # trusted machine-wide, so skip the per-user add (and its prompt).
            foreach ($lmName in @('Root','CA')) {
                try {
                    $lmStore = New-Object System.Security.Cryptography.X509Certificates.X509Store(
                        $lmName,
                        [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
                    $lmStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
                    try {
                        foreach ($existing in $lmStore.Certificates) {
                            if ($existing.Thumbprint -eq $cert.Thumbprint) {
                                Log-Info "Cert already trusted in LocalMachine\$lmName (thumbprint=$($cert.Thumbprint)) -- skipping CurrentUser\$StoreName add (no prompt)."
                                return $true
                            }
                        }
                    } finally { $lmStore.Close() }
                } catch {
                    # LocalMachine read is best-effort; fall through to the per-user add.
                    Log-Debug "LocalMachine\$lmName probe failed: $($_.Exception.Message)"
                }
            }
            $store.Add($cert)
            return $true
        } finally {
            $store.Close()
        }
    } catch {
        Log-Exception -Label "Add-CertToUserStore[$StoreName]" -ErrorRecord $_ -Context @(
            "Cert path:  $CertificatePath",
            "Store:      CurrentUser\$StoreName"
        ) -Hints @(
            "User may have declined the UAC/cert-install prompt.",
            "Cert file may be malformed: certutil -dump '$CertificatePath'",
            "Manual test: Import-Certificate -FilePath '$CertificatePath' -CertStoreLocation Cert:\CurrentUser\$StoreName"
        )
        return $false
    } finally {
        if ($null -ne $cert) { $cert.Dispose() }
    }
}

# Remove a cert by thumbprint from CurrentUser\<StoreName>. Used by the update
# path to clean up a legacy self-signed cert.pem trust after upgrading to a
# strict-mode build (different cert.pem + new root.pem). Returns $true if
# removal succeeded or the cert was not present; $false on hard error.
function Remove-SentinelCertByThumbprint {
    param(
        [Parameter(Mandatory = $true)][string]$Thumbprint,
        [ValidateSet('Root', 'CA')][string]$StoreName = 'Root'
    )
    if (-not $Thumbprint) { return $true }
    try {
        $store = New-Object System.Security.Cryptography.X509Certificates.X509Store(
            $StoreName,
            [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser)
        $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
        try {
            $hits = @($store.Certificates | Where-Object { $_.Thumbprint -eq $Thumbprint })
            foreach ($c in $hits) { $store.Remove($c) }
            if ($hits.Count -gt 0) {
                Log-Info "Removed legacy cert (thumbprint=$Thumbprint, count=$($hits.Count)) from CurrentUser\$StoreName"
            }
            return $true
        } finally {
            $store.Close()
        }
    } catch {
        Log-Exception -Label "Remove-SentinelCertByThumbprint[$StoreName]" -ErrorRecord $_ -Context @(
            "Thumbprint: $Thumbprint",
            "Store:      CurrentUser\$StoreName"
        ) -Hints @(
            "Legacy cert trust may remain; functionally harmless (the matching private key is overwritten).",
            "Manual: Get-ChildItem Cert:\CurrentUser\$StoreName | Where-Object Thumbprint -eq '$Thumbprint' | Remove-Item -Force"
        ) -Level "WARN"
        return $false
    }
}

# Concatenate intermediate + root into ca-bundle.pem alongside them. Node-based
# clients consume NODE_EXTRA_CA_CERTS as a file path; pointing it at only the
# intermediate fails strict chain validation because Node won't walk the Windows
# cert store to find the root. Builds when both files exist; otherwise returns
# the single cert path (legacy single-cert builds) or $null.
function New-SentinelCaBundle {
    param([Parameter(Mandatory = $true)][string]$InstallDir)
    $certPath   = Join-Path $InstallDir "cert.pem"
    $rootPath   = Join-Path $InstallDir "root.pem"
    $bundlePath = Join-Path $InstallDir "ca-bundle.pem"

    if ((Test-Path $certPath) -and (Test-Path $rootPath)) {
        try {
            $intermediate = (Get-Content -LiteralPath $certPath -Raw).TrimEnd("`r", "`n")
            $root         = (Get-Content -LiteralPath $rootPath -Raw).TrimEnd("`r", "`n")
            # \n between blocks is fine for Node/OpenSSL PEM parsers; final \n is
            # conventional and avoids tooling that requires trailing newline.
            Set-Content -LiteralPath $bundlePath -Value ($intermediate + "`n" + $root + "`n") -Encoding ASCII -NoNewline -ErrorAction Stop
            Log-Info "Built CA bundle: $bundlePath (intermediate + root)"
            return $bundlePath
        } catch {
            Log-Exception -Label "New-SentinelCaBundle" -ErrorRecord $_ -Context @(
                "cert.pem:    $certPath",
                "root.pem:    $rootPath",
                "ca-bundle:   $bundlePath"
            ) -Hints @(
                "Falling back to cert.pem alone for NODE_EXTRA_CA_CERTS -- strict chain validators may fail."
            ) -Level "WARN"
        }
    }
    # Legacy / partial builds: bundle not buildable, return whatever's available.
    if (Test-Path $certPath) { return $certPath }
    return $null
}

# Trust the Quilr EA CA chain in the current user's cert stores.
# Root CA  -> CurrentUser\Root  (real trust anchor)
# Intermediate CA -> CurrentUser\CA (so SChannel/CryptoAPI can build the chain
#                                    without relying on AIA fetches)
# Falls back to legacy single-cert (root-only-equivalent) behavior when root.pem
# is absent -- preserves compatibility with older zips that only ship cert.pem.
function Set-SentinelCaTrust {
    param([Parameter(Mandatory = $true)][string]$InstallDir)
    $certPath = Join-Path $InstallDir "cert.pem"
    $rootPath = Join-Path $InstallDir "root.pem"

    if (Test-Path $rootPath) {
        Log-Info "Trusting Quilr EA Root CA in CurrentUser\Root..."
        if (Add-SentinelUserRootCert -CertificatePath $rootPath -StoreName 'Root') {
            Log-Info "Root CA trusted: $rootPath"
        } else {
            Log-Warn "Failed to add Root CA to CurrentUser\Root."
        }

        if (Test-Path $certPath) {
            Log-Info "Adding Quilr EA Intermediate CA to CurrentUser\CA..."
            if (Add-SentinelUserRootCert -CertificatePath $certPath -StoreName 'CA') {
                Log-Info "Intermediate CA added: $certPath"
            } else {
                Log-Warn "Failed to add Intermediate CA to CurrentUser\CA -- strict clients may fail chain build."
            }
        } else {
            Log-Warn "cert.pem (intermediate) missing -- only root trusted. Strict clients may fail chain build."
        }
    } elseif (Test-Path $certPath) {
        # Legacy single-cert zip: cert.pem is self-signed, treat as root.
        Log-Info "root.pem not present -- legacy single-cert mode. Trusting cert.pem in CurrentUser\Root..."
        if (Add-SentinelUserRootCert -CertificatePath $certPath -StoreName 'Root') {
            Log-Info "Certificate added to trusted root store: $certPath"
        } else {
            Log-Warn "Failed to add certificate to trusted store."
        }
    } else {
        Log-Warn "Neither root.pem nor cert.pem found in $InstallDir -- skipping CA trust."
    }
}

# Copy hook scripts from package to user profile, file-by-file to avoid 0-byte writes.
# Copy-Item with wildcard globs can silently truncate when AV/indexer holds handles.
function Copy-HookScripts {
    param([string]$Src, [string]$Dest)
    if (-not (Test-Path $Src)) {
        Log-Warn "hooks/scripts/ not found in package -- skipping script copy."
        return
    }
    # Under SYSTEM (scheduled-tick updater), $Dest resolves into SYSTEM's profile
    # (C:\Windows\system32\config\systemprofile\...) which the interactive user
    # never sees, and the subsequent icacls grant on $env:USERNAME = <COMPUTER>$
    # cannot be resolved. Interactive installer already deployed these to the
    # real user profile; the scheduled-tick update path must leave them alone.
    if (Is-RunningAsSystem) {
        Log-Debug "Skipping hook-scripts copy: running as SYSTEM (target would be SYSTEM's profile, not the user's)"
        return
    }
    Log-Info "Copying hook scripts to $Dest..."
    if (Test-Path $Dest) {
        # Hooks dir is about to be rebuilt -- a stale child surviving this
        # wipe would get re-used by the agent.  Level=WARN so a residue
        # failure is visible without aborting the install (the per-file
        # Copy-Item below overwrites matching names regardless).
        Remove-Quiet -Path $Dest -Recurse -Level 'WARN' -Label "hooks dir pre-copy wipe"
    }
    try {
        New-Item -ItemType Directory -Path $Dest -Force -ErrorAction Stop | Out-Null
    } catch {
        Log-Exception -Label "Copy-HookScripts: create dest directory" -ErrorRecord $_ -Context @(
            "Dest: $Dest"
        ) -Hints @(
            "Hook scripts are non-critical -- agent runs without them.",
            "Check ACL on parent directory: $(Split-Path $Dest -Parent)"
        ) -Level "WARN"
        return
    }
    $srcFiles = Get-ChildItem -Path $Src -Recurse -File
    foreach ($srcFile in $srcFiles) {
        $relPath = $srcFile.FullName.Substring($Src.Length + 1)
        $destFile = Join-Path $Dest $relPath
        $destDir = Split-Path $destFile -Parent
        if (-not (Test-Path $destDir)) {
            try { New-Item -ItemType Directory -Path $destDir -Force -ErrorAction Stop | Out-Null }
            catch {
                Log-Exception -Label "Copy-HookScripts: create subdir '$destDir'" -ErrorRecord $_ -Hints @(
                    "Hook scripts are non-critical -- agent runs without them.",
                    "Check ACL on parent: $(Split-Path $destDir -Parent)"
                ) -Level "WARN"
                continue
            }
        }
        try {
            [IO.File]::Copy($srcFile.FullName, $destFile, $true)
        } catch {
            Log-Exception -Label "Copy hook file '$relPath'" -ErrorRecord $_ -Context @(
                "Source: $($srcFile.FullName)",
                "Dest:   $destFile"
            ) -Hints @(
                "Hook scripts are non-critical -- agent runs without them.",
                "If this is persistent, check NTFS permissions on $Dest."
            )
        }
    }
    # Grant logged-in user full control (elevated copy leaves admin ownership)
    Invoke-Native -Label "icacls grant full-control on $Dest" -FilePath "icacls.exe" `
        -ArgumentList @($Dest, "/grant", "${env:USERNAME}:(OI)(CI)F", "/T", "/C", "/Q") `
        -Hints @("Without this, user-scope scripts may not execute from here.") | Out-Null
    Log-Info "  Hook scripts copied to $Dest"
}

# Deploy hook binaries from hooks/ subdir to install dir root.
# deploy_thin_client() looks at SENTINEL_INSTALLATION_PATH/<binary>.
function Deploy-HookBinaries {
    param([string]$HooksDir, [string]$DestDir)
    if (-not (Test-Path $HooksDir)) { return }
    # Under SYSTEM (scheduled-tick updater), $SentinelUserDir resolves into
    # SYSTEM's profile -- pointless copy the user never sees. Keep the install-
    # dir copy (that one the agent reads via SENTINEL_INSTALLATION_PATH), skip
    # the user-profile copy.
    $skipUserCopy = Is-RunningAsSystem
    if (-not $skipUserCopy) {
        try {
            New-Item -ItemType Directory -Path $SentinelUserDir -Force -ErrorAction Stop | Out-Null
        } catch {
            Log-Exception -Label "Deploy-HookBinaries: create SentinelUserDir" -ErrorRecord $_ -Context @(
                "Path: $SentinelUserDir"
            ) -Hints @(
                "Hook binaries are non-critical -- agent runs without them.",
                "Check ACL on parent: $(Split-Path $SentinelUserDir -Parent)"
            ) -Level "WARN"
            $skipUserCopy = $true
        }
    }
    foreach ($bin in @("sentinel-hook-client.exe", "sentinel-claude-hook-client.exe")) {
        $src = Join-Path $HooksDir $bin
        if (Test-Path $src) {
            # Source copy for deploy_thin_client() (agent reads from SENTINEL_INSTALLATION_PATH)
            try {
                Copy-Item -Path $src -Destination (Join-Path $DestDir $bin) -Force -ErrorAction Stop
            } catch {
                Log-Exception -Label "Deploy-HookBinaries: copy '$bin' to DestDir" -ErrorRecord $_ -Context @(
                    "Source: $src",
                    "Dest:   $(Join-Path $DestDir $bin)"
                ) -Hints @(
                    "Hook binaries are non-critical -- agent runs without them.",
                    "Check ACL on $DestDir"
                ) -Level "WARN"
            }
            if (-not $skipUserCopy) {
                # User copy for immediate use by IDEs
                try {
                    Copy-Item -Path $src -Destination (Join-Path $SentinelUserDir $bin) -Force -ErrorAction Stop
                } catch {
                    Log-Exception -Label "Deploy-HookBinaries: copy '$bin' to SentinelUserDir" -ErrorRecord $_ -Context @(
                        "Source: $src",
                        "Dest:   $(Join-Path $SentinelUserDir $bin)"
                    ) -Hints @(
                        "Hook binaries are non-critical -- agent runs without them.",
                        "Check ACL on $SentinelUserDir"
                    ) -Level "WARN"
                }
            }
            Log-Info "  Deployed $bin"
        }
    }
    if ($skipUserCopy) {
        Log-Debug "Skipped hook-binaries user-profile copy: running as SYSTEM"
    }
}

# Log environment diagnostics -- invaluable for remote debugging.
function Log-Environment {
    Log-Info "--- Environment Diagnostics ---"
    Log-Info "  Setup version:    $SetupVersion"
    Log-Info "  Windows version:  $([Environment]::OSVersion.VersionString)"
    Log-Info "  Architecture:     $env:PROCESSOR_ARCHITECTURE"
    $isAdmin = $false
    try { $isAdmin = Test-Admin } catch { Log-Debug "Test-Admin failed: $($_.Exception.Message)" }
    Log-Info "  User:             $env:USERNAME (admin=$isAdmin)"
    Log-Info "  PowerShell:       $($PSVersionTable.PSVersion)"
    Log-Info "  Install path:     $InstallDir (exists=$(Test-Path $InstallDir))"
    $svcCheck = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    $svcStatus = if ($svcCheck) { "registered, status=$($svcCheck.Status)" } else { "not registered" }
    Log-Info "  Service:          $ServiceName ($svcStatus)"
    try {
        $driveLetter = $InstallDir.Substring(0, 1)
        $psDrive = Get-PSDrive $driveLetter -ErrorAction Stop
        $freeMB = [math]::Floor($psDrive.Free / 1MB)
        Log-Info "  Free disk (MB):   $freeMB"
    } catch {
        Log-Info "  Free disk (MB):   unknown"
    }
    Log-Info "--- End Diagnostics ---"
}

# =============================================================================
# SHARED FUNCTIONS
# =============================================================================

function Test-Admin {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# True when this process is running as NT AUTHORITY\SYSTEM (S-1-5-18).
# Scheduled-tick updater runs under SYSTEM; interactive installer runs under
# the logged-in user (elevated). Anything writing to $env:USERPROFILE or
# granting ACLs to $env:USERNAME must skip under SYSTEM: $env:USERPROFILE
# resolves to C:\Windows\system32\config\systemprofile and $env:USERNAME
# resolves to <COMPUTER>$ (machine account, not an icacls-resolvable principal).
function Is-RunningAsSystem {
    try {
        $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        return $sid -eq 'S-1-5-18'
    } catch {
        return $false
    }
}

# ─── IPv6 Management ────────────────────────────────────────────────────────
#
# SCOPE -- Where IPv6 disable is enforced
# --------------------------------------
# `Disable-IPv6` is the single authoritative function. It is called from three
# places, all going through the SAME code path so behavior stays consistent:
#
#   1. Invoke-Install            -- first install on a clean machine.
#   2. Start-SentinelAgent       -- every (re)start of the agent.
#   3. Ensure-IPv6Disabled       -- re-assertion hook, called early on every
#                                   scheduled updater tick, regardless of
#                                   whether an update is applied. Handles:
#                                     a) A previous install/update call to
#                                        Disable-IPv6 failed partially.
#                                     b) The user (or a new adapter plug-in,
#                                        or a GPO refresh) re-enabled IPv6
#                                        after the agent was installed.
#
# Adapters without the `ms_tcpip6` binding component (some virtual, tunnel,
# or loopback types) are classified as "unsupported" and SKIPPED -- not
# reported as failures. Every run logs a breakdown: disabled / already-off /
# skipped-unsupported / failed, so partial coverage is obvious at a glance.

function Disable-IPv6 {
    # Two independent passes, both important:
    #   1. Per-adapter binding (`ms_tcpip6`) disable -- takes effect immediately,
    #      but only for adapters currently present. New adapters (USB tether,
    #      VPN) plug in with IPv6 re-enabled -- the registry pass catches those.
    #   2. Registry persistence (`DisabledComponents = 0xFF`) -- survives reboot
    #      AND applies to future adapters. Requires a reboot to take full effect
    #      but is the only way to make the change durable.
    # Either pass failing is non-fatal; we continue with whichever one worked
    # and log the gap clearly so the operator can see coverage.

    $isAdmin = ([Security.Principal.WindowsPrincipal] `
        [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
    if (-not $isAdmin) {
        Log-Error "[Disable-IPv6] Aborting -- must be run as Administrator."
        Log-Error "  Hint: Start-Process powershell -Verb RunAs"
        return
    }

    Log-Info "Disabling IPv6 (per-adapter + registry)..."

    # [LAYER 1] Fast-path skip: if the registry already asserts DisabledComponents=0xFF,
    # per-adapter Pass 1 is redundant.  Running it every (re)start is wasteful AND,
    # on the update-restart path, racy against the NDIS rebind triggered by the
    # WinDivert unload that just occurred in Stop-SentinelProcesses.  Fresh installs
    # (registry absent) still run full Pass 1 below.
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
    $regAlreadySet = $false
    try {
        if (Test-Path $regPath) {
            $regObj = Get-ItemProperty -Path $regPath -ErrorAction Stop
            if ($regObj.PSObject.Properties.Name -contains "DisabledComponents" -and
                $regObj.DisabledComponents -eq 0xFF) {
                $regAlreadySet = $true
            }
        }
    } catch {
        # Read failure keeps $regAlreadySet = $false, so Pass 1 (per-adapter
        # IPv6 disable) runs.  That is the safe fallback on a fresh machine;
        # log the reason so a subsequent health issue can be traced back.
        Log-Debug "IPv6 registry probe failed: $($_.Exception.Message)"
    }

    if ($regAlreadySet) {
        Log-Info "  IPv6 registry already asserted (DisabledComponents=0xFF) -- skipping per-adapter Pass 1"
        Log-Info "  (Pass 1 runs only on fresh installs or after manual registry reset)"
        return
    }

    # ── Pass 1: bulk binding query + per-adapter disable ────────────────
    # [LAYER 3] One CIM call returns every adapter that carries the ms_tcpip6
    # binding.  Adapters absent from the bulk result simply don't bind ms_tcpip6
    # (tunnel, 6to4, Teredo, etc.) -- classified as "unsupported", not failure.
    # Per-adapter Get-NetAdapterBinding (the pre-fix approach) cost ~2s per
    # adapter even on the no-binding error path; 17 adapters x 2s = 34s of
    # silent latency, which QA reported as an install hang.  Bulk is <500ms.
    $allAdapters = @()
    try {
        $allAdapters = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop)
    } catch {
        Log-Exception -Label "Get-NetAdapter (enumerate)" -ErrorRecord $_ -Hints @(
            "Without the adapter list, per-adapter disable is skipped -- registry pass will still run.",
            "Windows PE / Server Core may lack NetAdapter module; verify: Get-Module -ListAvailable NetAdapter"
        )
    }

    # Single bulk CIM call.  Adapters absent from the result simply lack the
    # ms_tcpip6 binding (tunnel, 6to4, Teredo, loopback, etc.) -- treated as
    # "unsupported", not as failures.
    $bulkBindings = @()
    try {
        $bulkBindings = @(Get-NetAdapterBinding -ComponentID ms_tcpip6 -ErrorAction Stop)
    } catch {
        Log-Exception -Label "Get-NetAdapterBinding -ComponentID ms_tcpip6 (bulk)" -ErrorRecord $_ -Hints @(
            "Bulk ms_tcpip6 query failed; Pass 1 is skipped.  Pass 2 (registry) below will still run.",
            "If this recurs, inspect WMI repository: winmgmt /salvagerepository"
        )
    }

    $bindingByName = @{}
    foreach ($b in $bulkBindings) { $bindingByName[$b.Name] = $b }

    if ($allAdapters.Count -gt 0) {
        Log-Info "  Adapters discovered: $($allAdapters.Count) (physical + virtual + hidden); ms_tcpip6 bindings: $($bulkBindings.Count)"

        $disabledNow   = @()
        $alreadyOff    = @()
        $unsupported   = @()
        $failed        = @()

        foreach ($a in $allAdapters) {
            $name   = $a.Name
            $status = $a.Status
            $ifDesc = $a.InterfaceDescription

            if (-not $bindingByName.ContainsKey($name)) {
                $unsupported += [pscustomobject]@{ Name=$name; Status=$status; Type=$ifDesc; Reason="no ms_tcpip6 binding" }
                Log-Debug "  [skip] '$name' (status=$status) -- no ms_tcpip6 binding"
                continue
            }
            if (-not $bindingByName[$name].Enabled) {
                $alreadyOff += $name
                Log-Debug "  [skip] '$name' (status=$status) -- IPv6 already disabled"
                continue
            }

            # Currently enabled -- disable with retries, each wrapped in a 15s
            # job timeout so a hung driver cannot freeze the installer.
            Log-Info "  [try] '$name' (status=$status) -- disabling ms_tcpip6..."
            $ok = $false
            for ($attempt = 1; $attempt -le 3; $attempt++) {
                $job = Start-Job -ScriptBlock {
                    param($n)
                    try {
                        Disable-NetAdapterBinding -Name $n -ComponentID ms_tcpip6 -ErrorAction Stop
                        Start-Sleep -Milliseconds 300
                        $v = Get-NetAdapterBinding -Name $n -ComponentID ms_tcpip6 -ErrorAction Stop
                        return @{ ok = (-not $v.Enabled); err = $null }
                    } catch { return @{ ok = $false; err = $_.Exception.Message } }
                } -ArgumentList $name

                if (-not (Wait-Job $job -Timeout 15)) {
                    Log-Warn "  IPv6 disable attempt $attempt/3 on '$name' timed out after 15s (driver/CIM hang)"
                    Stop-Job $job -EA SilentlyContinue
                    Remove-Job $job -Force -EA SilentlyContinue
                    if ($attempt -lt 3) { Start-Sleep -Seconds ([math]::Pow(2, $attempt - 1)) }
                    continue
                }
                $r = Receive-Job $job
                Remove-Job $job -Force -EA SilentlyContinue

                if ($r.ok) {
                    Log-Info "  [OK] '$name' (status=$status) -- IPv6 disabled (attempt $attempt/3)"
                    $disabledNow += $name
                    $ok = $true
                    break
                }
                if ($attempt -lt 3) {
                    $delay = [math]::Pow(2, $attempt - 1)
                    Log-Warn "  IPv6 disable attempt $attempt/3 on '$name' failed: $($r.err -replace '[\r\n]+', ' ')"
                    Log-Warn "    Retrying in ${delay}s..."
                    Start-Sleep -Seconds $delay
                } else {
                    Log-Warn "  IPv6 disable on '$name' FAILED after 3 attempts: $($r.err -replace '[\r\n]+', ' ')"
                    Log-Warn "    Hint: Group Policy may pin IPv6 -- gpresult /h gp.html, look for 'Disable IPv6'."
                    Log-Warn "    Hint: Some VPN / Hyper-V virtual adapters reject binding changes -- usually safe to ignore."
                }
            }
            if (-not $ok) { $failed += "$name [$status]" }
        }

        Log-Info "  IPv6 per-adapter summary: $($disabledNow.Count) disabled, $($alreadyOff.Count) already-off, $($unsupported.Count) skipped-unsupported, $($failed.Count) failed (of $($allAdapters.Count) total)"
        if ($disabledNow.Count -gt 0) { Log-Info  "    Disabled now: $($disabledNow -join ', ')" }
        if ($alreadyOff.Count  -gt 0) { Log-Debug "    Already off:  $($alreadyOff  -join ', ')" }
        if ($unsupported.Count -gt 0) { Log-Info  "    Skipped (no ms_tcpip6 binding): $(($unsupported | ForEach-Object { $_.Name }) -join ', ')" }
        if ($failed.Count      -gt 0) {
            Log-Warn "    Failed: $($failed -join ' | ')"
            Log-Warn "    Hint: agent will run, but proxy interception may miss traffic on failed adapters."
        }
    }

    # ── Pass 2: registry persistence ────────────────────────────────────
    # NOTE: $regPath was already declared at the top of this function for the
    # Layer 1 fast-path skip check.  Reuse it here.
    try {
        if (-not (Test-Path $regPath)) {
            New-Item -Path $regPath -Force -ErrorAction Stop | Out-Null
            Log-Info "  Created registry path: $regPath"
        }
        $before = $null
        $regObj = Get-ItemProperty -Path $regPath -ErrorAction Stop
        if ($regObj.PSObject.Properties.Name -contains "DisabledComponents") {
            $before = $regObj.DisabledComponents
        }

        if ($before -eq 0xFF) {
            Log-Info "  Registry DisabledComponents=0xFF already set (persistent IPv6-off across reboots)."
        } else {
            New-ItemProperty -Path $regPath -Name DisabledComponents -Value 0xFF `
                -PropertyType DWord -Force -ErrorAction Stop | Out-Null
            # Readback
            $after = (Get-ItemProperty -Path $regPath -ErrorAction Stop).DisabledComponents
            if ($after -eq 0xFF) {
                $beforeStr = if ($null -eq $before) { "<unset>" } else { "0x$('{0:X}' -f $before)" }
                Log-Info "  Registry DisabledComponents: $beforeStr -> 0xFF (persistent IPv6-off; full effect after reboot)."
            } else {
                Log-Warn "  Registry write appeared to succeed but readback returned 0x$('{0:X}' -f $after) (expected 0xFF)."
                Log-Warn "    Hint: a filter driver or Group Policy may be enforcing the key."
            }
        }
    } catch {
        Log-Exception -Label "Registry persist DisabledComponents=0xFF" -ErrorRecord $_ -Context @(
            "Registry path: $regPath"
        ) -Hints @(
            "Per-adapter pass still provides runtime coverage, but new adapters will get IPv6 enabled.",
            "Check: Get-ItemProperty -Path '$regPath' -Name DisabledComponents",
            "Group Policy may own this key -- inspect: gpresult /h gp.html"
        )
    }
}

# Re-assertion hook invoked by the scheduled updater on every tick. Runs
# BEFORE any "already up-to-date" early-exit so coverage is restored even
# when no update is applied. Thin wrapper by design -- one visible call
# site per code path keeps the behavior easy to reason about.
function Ensure-IPv6Disabled {
    Log-Info "[IPv6 Re-assert] Scheduled check: verifying IPv6 is still disabled."
    Log-Info "  Reason: recovery path for (a) partial past-install/update and (b) manual re-enable by user or new adapter."
    Disable-IPv6
}
# ─── Process Management ──────────────────────────────────────────────────────

function Stop-SentinelProcesses {
    Log-Info "Stopping all sentinel processes..."

    # 1. Disable SCM failure recovery so killed processes don't respawn.
    # sc.exe rejects `actions= ""` (empty); the canonical "do nothing on
    # failure" syntax is three explicit `none/<delay>` pairs.  Benign if
    # the service is already absent (1060 = service not installed).
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($svc) {
        Log-Info "Disabling $ServiceName auto-restart temporarily..."
        Invoke-Native -Label "sc.exe failure $ServiceName (clear actions)" `
            -FilePath "sc.exe" -ArgumentList @("failure", $ServiceName, "reset=", "0", "actions=", "none/0/none/0/none/0") `
            -AllowedExitCodes @(0, 1060) `
            -Hints @("If this fails with exit!=1060, SCM may restart the agent after taskkill -- see step 5 retry.") | Out-Null
    }

    # 2. Try graceful service stop
    # -WarningAction SilentlyContinue suppresses the "Waiting for service ...
    # to stop" cmdlet warning that leaks through quiet mode and clutters
    # the CLI with status noise the operator doesn't need to act on.
    if ($svc -and $svc.Status -ne "Stopped") {
        Log-Info "Stopping $ServiceName service..."
        # Graceful stop failure is non-fatal here -- the taskkill sweep below
        # handles survivors -- but the reason (SCM timeout, access denied,
        # dependent service blocking) is diagnostic gold for stuck-redeploy
        # reports.  -WarningAction SilentlyContinue is kept because the
        # cmdlet's "Waiting for service..." noise isn't actionable.
        try {
            Stop-Service -Name $ServiceName -Force -ErrorAction Stop -WarningAction SilentlyContinue
        } catch {
            Log-Warn "Stop-Service $ServiceName failed (will fall through to taskkill sweep): $($_.Exception.Message)"
        }
        Start-Sleep -Seconds 3
    }

    # 3. Wait for graceful exit of main agent (updater-style)
    $deadline = (Get-Date).AddSeconds($GracefulStopTimeout)
    while ((Get-Date) -lt $deadline) {
        $procs = Get-Process -Name "sentinel" -ErrorAction SilentlyContinue
        if (-not $procs) {
            Log-Info "Main agent process stopped"
            break
        }
        Start-Sleep -Seconds 1
    }

    # 4. Force-kill all sentinel-related processes.
    # taskkill exit codes: 0 = success, 128 = process not found (benign),
    # 1 = access denied (worth surfacing). AllowedExitCodes keeps logs quiet
    # on benign cases while still flagging unexpected failures.
    foreach ($proc in $KillProcesses) {
        Invoke-Native -Label "taskkill /F /IM $proc (stop)" -FilePath "taskkill.exe" `
            -ArgumentList @("/F", "/IM", $proc) -AllowedExitCodes @(0, 128) `
            -Hints @("exit 128 = process not running (benign).", "exit 1 = access denied; re-run elevated.") | Out-Null
    }
    Start-Sleep -Seconds 2

    # 5. Verify everything is dead, retry if needed
    $remaining = Get-Process -Name "sentinel","sentinel-proxy","ipc-light-broker","template-engine","templating-engine","sentinel-monitor-v2" -ErrorAction SilentlyContinue
    if ($remaining) {
        Log-Warn "Processes still alive after first kill sweep: $($remaining.Name -join ', ')"
        Log-Warn "  PIDs: $(($remaining | ForEach-Object { "$($_.Name)($($_.Id))" }) -join ', ')"
        Log-Warn "  Hint: a second sweep follows; if they still survive, some parent may be respawning them."
        Start-Sleep -Seconds 3
        foreach ($proc in $KillProcesses) {
            Invoke-Native -Label "taskkill /F /IM $proc (retry)" -FilePath "taskkill.exe" `
                -ArgumentList @("/F", "/IM", $proc) -AllowedExitCodes @(0, 128) `
                -Hints @("exit 128 = already dead (benign).") | Out-Null
        }
        Start-Sleep -Seconds 2
    }

    # 6. Stop and remove WinDivert kernel driver (must happen after killing sentinel
    #    which holds the driver handle; driver locks WinDivert64.sys preventing overwrite)
    $wdSvc = Get-Service -Name "WinDivert" -ErrorAction SilentlyContinue
    if ($wdSvc) {
        Log-Info "Stopping WinDivert driver (state=$($wdSvc.Status))..."
        # sc.exe exit codes we tolerate: 0 (ok), 1062 (not started), 1060 (not installed)
        Invoke-Native -Label "sc.exe stop WinDivert" -FilePath "sc.exe" `
            -ArgumentList @("stop", "WinDivert") -AllowedExitCodes @(0, 1062, 1060) `
            -Hints @("1062 = already stopped.", "1060 = not installed.") | Out-Null
        Invoke-Native -Label "sc.exe delete WinDivert" -FilePath "sc.exe" `
            -ArgumentList @("delete", "WinDivert") -AllowedExitCodes @(0, 1060) `
            -Hints @("1060 = already gone.") | Out-Null
        # Wait for kernel to release driver (up to 10s)
        Start-Sleep -Seconds 3
        for ($w = 0; $w -lt 10; $w++) {
            if (-not (Get-Service -Name "WinDivert" -EA SilentlyContinue)) { break }
            Start-Sleep -Seconds 1
        }
        Log-Info "WinDivert driver stopped and removed"
        # NOTE: No adapter reset here -- the new agent re-loads WinDivert on start,
        # which triggers NDIS rebind automatically.  Proactive adapter reset would
        # cause a ~5s network blip on every update (disruptive for calls/transactions).
        # The uninstaller resets adapters because WinDivert never comes back there.
        #
        # [LAYER 2] NDIS settle delay.  Unloading a bound NDIS filter triggers an
        # async rebind on every adapter it was attached to.  Get-Service reports
        # the driver as gone before that rebind completes, which has been observed
        # to hang downstream Get-NetAdapterBinding calls in Disable-IPv6.  2s is
        # enough on typical boxes; on pathologically slow ones we still have
        # Layer 1 (fast-path skip) and Layer 3 (per-call timeout) as backup.
        Log-Debug "Allowing NDIS filter stack to settle after WinDivert unload..."
        Start-Sleep -Seconds 2
    }

    Log-Info "All sentinel processes stopped"
}

# =============================================================================
# LOCK -- Prevents concurrent runs
# =============================================================================

function Get-UpdateLock {
    if (-not (Test-Path (Split-Path $LockFile -Parent))) {
        New-Item -ItemType Directory -Path (Split-Path $LockFile -Parent) -Force | Out-Null
    }

    # Atomic lock: use FileMode.CreateNew to avoid TOCTOU race between check and write.
    # If another instance already holds the lock file, CreateNew throws IOException.
    if (Test-Path $LockFile) {
        $existingPid = (Get-Content $LockFile -ErrorAction SilentlyContinue).Trim()
        $pidAlive = $false
        if ($existingPid) {
            try { $pidAlive = [bool](Get-Process -Id $existingPid -ErrorAction Stop) } catch { $pidAlive = $false }
        }
        # Age-based reclaim: even if a PID is "alive" per Get-Process, a lock
        # older than $UpdateLockMaxAgeHours is a stuck previous run whose PID
        # got recycled to something unrelated (powershell.exe, svchost.exe).
        # The mac side already does this via mtime; matching the behaviour
        # here so Windows can't be stonewalled by a recycled-PID collision.
        $lockAge = (Get-Date) - (Get-Item $LockFile).LastWriteTime
        if ($pidAlive -and $lockAge.TotalHours -lt $UpdateLockMaxAgeHours) {
            Log-Info "Another setup instance (PID $existingPid, lock age $([math]::Round($lockAge.TotalMinutes,0))m) is running. Exiting."
            exit 0
        } elseif ($pidAlive) {
            Log-Warn "Lock owned by live PID $existingPid but is $([math]::Round($lockAge.TotalHours,1))h old (> ${UpdateLockMaxAgeHours}h threshold). PID likely recycled -- reclaiming."
        } else {
            Log-Info "Stale lock from PID $existingPid (no longer running). Reclaiming."
        }
        Remove-Quiet -Path $LockFile -Label "stale lock file"
    }

    try {
        $fs = [IO.File]::Open($LockFile, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        $sw = New-Object IO.StreamWriter($fs)
        $sw.Write($PID); $sw.Flush(); $sw.Close(); $fs.Close()
        Log-Debug "Lock acquired (PID $PID)"
    } catch [IO.IOException] {
        Log-Info "Lock file claimed by another instance. Exiting."
        exit 0
    }
}

# Scrubs leftover blacklist files from prior installer versions.  Called
# on every successful update path and at startup so an upgrade to a build
# without the quarantine logic doesn't inherit a stale .quarantined_version
# from an older build that would otherwise (be ignored now, but tidying up
# keeps the install dir observable -- Get-ChildItem shows no dead signals).
function Remove-LegacyBlocklists {
    # Wipe every retry-tracking file from the old multi-mechanism scheme.
    # state.conf is now the sole retry-state surface, so any leftover
    # .quarantined_version, .download_failed_*, or .last_downloaded_checksum
    # files are noise at best, stale-state bugs at worst.  One-time sweep
    # per device; subsequent calls no-op (all paths are -Quiet).
    foreach ($legacy in @('.quarantined_version', '.last_downloaded_checksum')) {
        $p = Join-Path $InstallDir $legacy
        if (Test-Path -LiteralPath $p) {
            Remove-Quiet -Path $p -Label "legacy marker '$legacy'"
        }
    }
    $markers = @(Get-ChildItem -LiteralPath $InstallDir -Filter '.download_failed_*' -ErrorAction SilentlyContinue)
    foreach ($m in $markers) {
        Remove-Quiet -Path $m.FullName -Label "legacy .download_failed marker"
    }
}

# Self-healing guard for the scheduled task.  The updater running RIGHT NOW
# is our one chance to fix the pipeline when an admin, GPO, or anti-tamper
# tool has unregistered or disabled the task: if the schedule is gone, no
# future tick fires, and the pipeline dies silently.  This function is
# called at the top of every update-path entry.  Idempotent: a healthy task
# returns in a single Get-ScheduledTask call.
function Assert-UpdaterScheduleRegistered {
    $task = $null
    try {
        $task = Get-ScheduledTask -TaskName $UpdaterTaskName -ErrorAction Stop
    } catch {
        # Match by message, not type: -ErrorAction Stop can wrap the underlying
        # CimException in a CmdletInvocationException, defeating a typed catch.
        $msg = $_.Exception.Message
        if ($msg -match 'cannot find the file specified|No MSFT_ScheduledTask objects found') {
            $task = $null  # expected "not found" -- self-heal path will re-register
        } else {
            Log-Warn "Assert-UpdaterScheduleRegistered: Get-ScheduledTask '$UpdaterTaskName' failed: $msg"
            # Fall through to re-register: if we can't tell, safer to rewrite.
        }
    }

    if ($task -and $task.State -eq 'Disabled') {
        Log-Warn "Updater schedule exists but is DISABLED -- attempting to enable"
        try {
            Enable-ScheduledTask -TaskName $UpdaterTaskName -ErrorAction Stop | Out-Null
            Log-Info "Updater schedule re-enabled"
        } catch {
            Log-Exception -Label "Enable-ScheduledTask '$UpdaterTaskName'" -ErrorRecord $_ -Hints @(
                "Try manual: schtasks /Change /TN `"$UpdaterTaskName`" /ENABLE",
                "If the task is gone entirely, re-running this updater with -Force will re-register it."
            )
        }
        return
    }

    if ($task) {
        Log-Debug "Updater schedule present (state=$($task.State))"
        return
    }

    Log-Warn "Updater schedule MISSING -- re-registering (self-heal)"
    try {
        Register-UpdaterSchedule -Dir $InstallDir
        Log-Info "Updater schedule re-registered from running binary"
    } catch {
        Log-Exception -Label "Self-heal Register-UpdaterSchedule" -ErrorRecord $_ -Hints @(
            "Next tick will retry.  If persistent, check Task Scheduler service: Get-Service Schedule",
            "Also check ACLs on \Microsoft\ folder under Task Scheduler."
        )
    }
}

# Boot-time integrity check (cheap -- file existence only).  Covers the
# scenario where the on-disk updater binary was deleted (AV quarantine,
# user rm) while the in-memory process keeps running.  The scheduled task
# would otherwise fire next tick, find no binary at its action path, and
# leave the device permanently silent.  If the file is missing but
# .backup or .backup.prev is present, restore it.
#
# NOTE: a subprocess `-ShowVersion` smoke test was considered but rejected.
# It added ~1-5s to every no-op tick, and couldn't catch the scenarios
# that actually need recovery (task-launch-failure happens before our
# code runs at all).  Dual-backup retention + the cheap existence check
# covers what's reachable from inside the running process.
function Test-SelfBinaryHealth {
    param([string]$BinaryPath = $selfPath)
    if (-not $BinaryPath) { return }
    if (Test-Path -LiteralPath $BinaryPath) {
        Log-Debug "Self binary present at '$BinaryPath'"
        return
    }
    Log-Warn "Self binary missing at '$BinaryPath' -- attempting restore from .backup"
    $bak  = "$BinaryPath.backup"
    $prev = "$BinaryPath.backup.prev"
    foreach ($candidate in @($bak, $prev)) {
        if (Test-Path -LiteralPath $candidate) {
            try {
                Copy-Item -LiteralPath $candidate -Destination $BinaryPath -Force -ErrorAction Stop
                Log-Info "Restored '$BinaryPath' from '$candidate'"
                return
            } catch {
                Log-Warn "Restore from '$candidate' failed: $($_.Exception.Message)"
            }
        }
    }
    Log-Error "No usable backup found for '$BinaryPath' -- next CDN tick will re-fetch from scratch"
}

# Garbage-collects updater backups older than $UpdaterBackupRetentionDays.
# Dual-backup scheme: .backup is the previous version, .backup.prev is the
# one before that.  Both are used by rollback and by Test-SelfBinaryHealth.
# Files older than the retention window are removed so a misconfigured
# disk doesn't fill with old updater copies.
$UpdaterBackupRetentionDays = 14
function Remove-StaleUpdaterBackups {
    param([string]$BinaryPath = $selfPath)
    if (-not $BinaryPath) { return }
    $cutoff = (Get-Date).AddDays(-$UpdaterBackupRetentionDays)
    foreach ($suffix in @('.backup.prev', '.broken')) {
        $p = "$BinaryPath$suffix"
        if (Test-Path -LiteralPath $p) {
            $age = Get-Item -LiteralPath $p
            if ($age.LastWriteTime -lt $cutoff) {
                Remove-Quiet -Path $p -Label "stale updater $suffix (>${UpdaterBackupRetentionDays}d)"
            }
        }
    }
}

function Release-UpdateLock {
    if (Test-Path $LockFile) {
        $storedPid = (Get-Content $LockFile -ErrorAction SilentlyContinue).Trim()
        if ($storedPid -eq "$PID") {
            Remove-Quiet -Path $LockFile -Label "update lock release"
            Log-Debug "Lock released (PID $PID)"
        }
    }
}

# #############################################################################
#
#  INSTALL SECTION -- Functions used only during first-time installation
#
# #############################################################################

# ─── Zip Resolution ──────────────────────────────────────────────────────────

function Resolve-ZipPath {
    param([string]$Provided)

    if (-not $Provided) {
        Log-Error "No ZIP path provided. Pass -ZipPath <path> explicitly."
        Log-Error "Usage: .\sentinel-endpoint.ps1 -ZipPath <path>"
        exit 1
    }

    # Resolve relative paths
    $resolved = Resolve-Path $Provided -ErrorAction SilentlyContinue
    if (-not $resolved) {
        Log-Error "Zip file not found: $Provided"
        exit 1
    }
    return $resolved.Path
}

# ─── Node.js CA Environment ──────────────────────────────────────────────────

function Set-NodeCaEnv {
    param([string]$CertPath)

    Log-Info "Configuring Node.js environment variables..."

    if (-not (Test-Path $CertPath)) {
        Log-Warn "CA cert/bundle not found at $CertPath -- skipping Node.js env setup."
        return
    }

    try {
        $env:NODE_EXTRA_CA_CERTS = $CertPath
        $setxOut = & setx NODE_EXTRA_CA_CERTS "$CertPath" /M 2>&1
        if ($LASTEXITCODE -ne 0) {
            Log-Warn "setx NODE_EXTRA_CA_CERTS FAILED (exit=$LASTEXITCODE) -- machine-scope env var not written."
            Log-Warn "  Output: $($setxOut -join ' ')"
            Log-Warn "  Hint:   Admin rights required for /M (machine scope); re-run as Administrator."
        } else {
            Log-Info "NODE_EXTRA_CA_CERTS set to $CertPath (machine scope)."
        }

        $env:NODE_TLS_REJECT_UNAUTHORIZED = "0"
        $setxOut = & setx NODE_TLS_REJECT_UNAUTHORIZED "0" /M 2>&1
        if ($LASTEXITCODE -ne 0) {
            Log-Warn "setx NODE_TLS_REJECT_UNAUTHORIZED FAILED (exit=$LASTEXITCODE) -- machine-scope env var not written."
            Log-Warn "  Output: $($setxOut -join ' ')"
            Log-Warn "  Hint:   Admin rights required for /M (machine scope); re-run as Administrator."
        } else {
            Log-Info "NODE_TLS_REJECT_UNAUTHORIZED set to 0 (machine scope)."
        }
    }
    catch {
        Log-Exception -Label "Set-NodeCaEnv (setx)" -ErrorRecord $_ -Context @(
            "Target:  HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment"
        ) -Hints @(
            "Admin rights required to write HKLM env registry keys.",
            "Non-fatal: per-user scope may still have been set."
        )
    }
}

# ── BEGIN: Email Collection (removable block) ──────────────────────────────
# Collects user email via -Email arg, GUI popup, or console fallback.
# Returns validated email or $null (meaning: use auto-discovery).
# To remove: delete this block and the SENTINEL_OVERRIDE_EMAIL env var.

function Test-EmailFormat {
    param([string]$Value)
    # Basic sanity: something@something.something, no spaces
    return ($Value -match '^[^\s@]+@[^\s@]+\.[^\s@]+$')
}

function Collect-UserEmail {
    # 1. Already provided via -Email arg
    if ($Email) {
        $trimmed = $Email.Trim()
        if (-not $trimmed) {
            Log-Info "Empty email provided via -Email -- auto-discovery will be enabled"
            return $null
        }
        if (-not (Test-EmailFormat $trimmed)) {
            Log-Warn "Invalid email format via -Email: '$trimmed' -- auto-discovery will be enabled"
            return $null
        }
        Log-Info "Email provided via -Email: $trimmed"
        return $trimmed
    }

    $guiAttempted = $false

    # 2. Try GUI popup
    try {
        Add-Type -AssemblyName System.Windows.Forms
        Add-Type -AssemblyName System.Drawing

        $form = New-Object System.Windows.Forms.Form
        $form.Text = "Sentinel Endpoint Agent"
        $form.Size = New-Object System.Drawing.Size(420, 210)
        $form.StartPosition = "CenterScreen"
        $form.FormBorderStyle = "FixedDialog"
        $form.MaximizeBox = $false

        $label = New-Object System.Windows.Forms.Label
        $label.Location = New-Object System.Drawing.Point(20, 20)
        $label.Size = New-Object System.Drawing.Size(360, 20)
        $label.Text = "Please enter your work email (or Cancel to skip):"
        $form.Controls.Add($label)

        $textBox = New-Object System.Windows.Forms.TextBox
        $textBox.Location = New-Object System.Drawing.Point(20, 50)
        $textBox.Size = New-Object System.Drawing.Size(360, 20)
        $form.Controls.Add($textBox)

        $errorLabel = New-Object System.Windows.Forms.Label
        $errorLabel.Location = New-Object System.Drawing.Point(20, 75)
        $errorLabel.Size = New-Object System.Drawing.Size(360, 20)
        $errorLabel.ForeColor = [System.Drawing.Color]::Red
        $errorLabel.Text = ""
        $form.Controls.Add($errorLabel)

        $okButton = New-Object System.Windows.Forms.Button
        $okButton.Location = New-Object System.Drawing.Point(210, 105)
        $okButton.Size = New-Object System.Drawing.Size(80, 30)
        $okButton.Text = "OK"
        $form.Controls.Add($okButton)

        $cancelButton = New-Object System.Windows.Forms.Button
        $cancelButton.Location = New-Object System.Drawing.Point(300, 105)
        $cancelButton.Size = New-Object System.Drawing.Size(80, 30)
        $cancelButton.Text = "Cancel"
        $cancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
        $form.CancelButton = $cancelButton
        $form.Controls.Add($cancelButton)

        $form.AcceptButton = $okButton

        # OK validates before closing -- keeps form open on invalid input
        $okButton.Add_Click({
            $val = $textBox.Text.Trim()
            if (-not $val) {
                # Empty = discovery, close the form
                $form.DialogResult = [System.Windows.Forms.DialogResult]::OK
                $form.Close()
                return
            }
            if (Test-EmailFormat $val) {
                $form.DialogResult = [System.Windows.Forms.DialogResult]::OK
                $form.Close()
            } else {
                $errorLabel.Text = "Invalid email format. Please check and try again."
            }
        })

        $form.TopMost = $true
        $guiAttempted = $true
        $result = $form.ShowDialog()

        if ($result -eq [System.Windows.Forms.DialogResult]::Cancel) {
            Log-Info "Email entry cancelled -- auto-discovery will be enabled"
            return $null
        }

        $collectedEmail = $textBox.Text.Trim()
        if (-not $collectedEmail) {
            Log-Info "No email entered -- auto-discovery will be enabled"
            return $null
        }

        # Already validated by OK click handler
        Log-Info "Email configured: $collectedEmail"
        return $collectedEmail
    } catch {
        Log-Debug "GUI popup failed (headless?): $_"
    }

    # 3. Console fallback -- only if GUI was never shown (headless/SSH)
    if (-not $guiAttempted -and [Environment]::UserInteractive) {
        try {
            $collectedEmail = Read-Host "Please enter your work email (or press Enter to skip)"
            $collectedEmail = if ($collectedEmail) { $collectedEmail.Trim() } else { "" }
            if ($collectedEmail) {
                Log-Info "Email configured: $collectedEmail"
                return $collectedEmail
            }
        } catch {
            Log-Debug "Console prompt failed (non-interactive?): $_"
        }
    }

    Log-Info "No email provided -- auto-discovery will be enabled"
    return $null
}
# ── END: Email Collection ───────────────────────────────────────────────────

# ── BEGIN: Tenant ID Collection / Reconciliation ───────────────────────────
$script:TenantIdFile = Join-Path $env:ProgramData "Sentinel\tenant_id"

function Get-TenantIdFingerprint {
    param([string]$Value)
    if (-not $Value) { return "" }
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Value)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hex = ($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString("x2") }) -join ''
        return $hex.Substring(0, 8)
    } finally { $sha.Dispose() }
}

# Resolve a tenant ID for fresh installs. Resolution order (first wins):
#   1. -TenantId arg
#   2. QUILR_TENANT_ID env (MDM injection)
#   3. Pre-existing $script:TenantIdFile (universal pkg + MDM-delivered file)
#   4. Non-interactive (no UserInteractive) → fail loudly
#   5. Windows Forms popup
#   6. Console fallback
function Collect-TenantId {
    if ($TenantId) {
        $trimmed = $TenantId.Trim()
        if (-not $trimmed) {
            Log-Error "Empty -TenantId argument; a valid Tenant ID is required."
            Exit-WithCleanup 1
        }
        Log-Info "Tenant ID provided via -TenantId (fp=$(Get-TenantIdFingerprint $trimmed))"
        return $trimmed
    }

    if ($env:QUILR_TENANT_ID) {
        $trimmed = $env:QUILR_TENANT_ID.Trim()
        if (-not $trimmed) {
            Log-Error "QUILR_TENANT_ID env var was empty; a valid Tenant ID is required."
            Exit-WithCleanup 1
        }
        Log-Info "Tenant ID provided via QUILR_TENANT_ID env (fp=$(Get-TenantIdFingerprint $trimmed))"
        return $trimmed
    }

    # Pre-existing on-disk file — populated by a universal-pkg MDM flow
    # (admin pre-stages the file via Intune's Win32 file/registry config
    # extension or a separate provisioning script before the installer runs).
    if (Test-Path $script:TenantIdFile) {
        $fromFile = (Get-Content $script:TenantIdFile -Raw -ErrorAction SilentlyContinue)
        if ($fromFile) { $fromFile = $fromFile.Trim() }
        if ($fromFile) {
            Log-Info "Tenant ID picked up from existing $script:TenantIdFile (fp=$(Get-TenantIdFingerprint $fromFile))"
            return $fromFile
        }
    }

    if (-not [Environment]::UserInteractive) {
        Log-Error "============================================================"
        Log-Error "INSTALLATION FAILED: Tenant ID required for MDM/silent installs."
        Log-Error "  Pass via:  .\sentinel-endpoint.ps1 -TenantId <id>"
        Log-Error "  Or env:    [Environment]::SetEnvironmentVariable('QUILR_TENANT_ID','<id>','Machine')"
        Log-Error "  Or file:   pre-drop $script:TenantIdFile (MDM-delivered)"
        Log-Error "  Contact your IT administrator or Quilr support for your Tenant ID."
        Log-Error "============================================================"
        Exit-WithCleanup 1
    }

    try {
        Add-Type -AssemblyName System.Windows.Forms
        Add-Type -AssemblyName System.Drawing
        $form = New-Object System.Windows.Forms.Form
        $form.Text = "Sentinel Endpoint Agent"
        $form.Size = New-Object System.Drawing.Size(420, 180)
        $form.StartPosition = "CenterScreen"
        $form.FormBorderStyle = "FixedDialog"
        $form.MaximizeBox = $false

        $label = New-Object System.Windows.Forms.Label
        $label.Location = New-Object System.Drawing.Point(20, 20)
        $label.Size = New-Object System.Drawing.Size(360, 40)
        $label.Text = "Please enter your Quilr Tenant ID (required):"
        $form.Controls.Add($label)

        $textBox = New-Object System.Windows.Forms.TextBox
        $textBox.Location = New-Object System.Drawing.Point(20, 70)
        $textBox.Size = New-Object System.Drawing.Size(360, 20)
        $form.Controls.Add($textBox)

        $okButton = New-Object System.Windows.Forms.Button
        $okButton.Text = "OK"
        $okButton.Location = New-Object System.Drawing.Point(230, 110)
        $okButton.Size = New-Object System.Drawing.Size(70, 28)
        $okButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
        $form.AcceptButton = $okButton
        $form.Controls.Add($okButton)

        $cancelButton = New-Object System.Windows.Forms.Button
        $cancelButton.Text = "Cancel"
        $cancelButton.Location = New-Object System.Drawing.Point(310, 110)
        $cancelButton.Size = New-Object System.Drawing.Size(70, 28)
        $cancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
        $form.CancelButton = $cancelButton
        $form.Controls.Add($cancelButton)

        $form.TopMost = $true
        $result = $form.ShowDialog()
        $value = $textBox.Text.Trim()
        if ($result -ne [System.Windows.Forms.DialogResult]::OK -or -not $value) {
            Log-Error "Tenant ID is required. Installation aborted."
            Exit-WithCleanup 1
        }
        Log-Info "Tenant ID configured via GUI (fp=$(Get-TenantIdFingerprint $value))"
        return $value
    } catch {
        Log-Debug "GUI popup failed: $($_.Exception.Message)"
    }

    try {
        $tid = (Read-Host "Please enter your Quilr Tenant ID")
        $tid = if ($tid) { $tid.Trim() } else { "" }
        if (-not $tid) {
            Log-Error "Tenant ID is required. Installation aborted."
            Exit-WithCleanup 1
        }
        Log-Info "Tenant ID configured via console (fp=$(Get-TenantIdFingerprint $tid))"
        return $tid
    } catch {
        Log-Error "No Tenant ID provided and no interactive session available. Aborting."
        Exit-WithCleanup 1
    }
}

# Persist tenant ID to %PROGRAMDATA%\Sentinel\tenant_id with SYSTEM + Admins ACL.
function Write-TenantIdFile {
    param([string]$Value)
    if (-not $Value) { return }
    $dir = Split-Path -Parent $script:TenantIdFile
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    Set-Content -Path $script:TenantIdFile -Value $Value -NoNewline -Encoding ASCII
    try {
        $acl = New-Object System.Security.AccessControl.FileSecurity
        $acl.SetAccessRuleProtection($true, $false)
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            "NT AUTHORITY\SYSTEM", "FullControl", "Allow")))
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            "BUILTIN\Administrators", "FullControl", "Allow")))
        Set-Acl -Path $script:TenantIdFile -AclObject $acl
    } catch {
        Log-Warn "Failed to tighten ACL on $script:TenantIdFile : $($_.Exception.Message)"
    }
    Log-Info "Tenant ID written to $script:TenantIdFile (fp=$(Get-TenantIdFingerprint $Value))"
}

# Propagate tenant_id from the canonical file into the Windows service
# environment (REG_MULTI_SZ "Environment" value on HKLM\...\Services\<svc>).
# Idempotent: no-op when the env entry already matches the file. Restarts
# the service only when env actually changed.
function Reconcile-TenantIdEnv {
    if (-not (Test-Path $script:TenantIdFile)) { return }
    $fileVal = (Get-Content $script:TenantIdFile -Raw -ErrorAction SilentlyContinue)
    if ($fileVal) { $fileVal = $fileVal.Trim() }
    if (-not $fileVal) { return }

    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
    if (-not (Test-Path $regPath)) { return }

    $current = $null
    $multi = @()
    try {
        $envProp = Get-ItemProperty -Path $regPath -Name "Environment" -ErrorAction Stop
        $multi = @($envProp.Environment)
        foreach ($line in $multi) {
            if ($line -like "QUILR_TENANT_ID=*") {
                $current = $line.Substring("QUILR_TENANT_ID=".Length)
                break
            }
        }
    } catch {
        $multi = @()
    }

    if ($current -eq $fileVal) { return }

    Log-Info "Reconciling service env QUILR_TENANT_ID (fp=$(Get-TenantIdFingerprint $fileVal))"
    $newMulti = @($multi | Where-Object { $_ -notlike "QUILR_TENANT_ID=*" })
    $newMulti += "QUILR_TENANT_ID=$fileVal"
    try {
        Set-ItemProperty -Path $regPath -Name "Environment" -Value $newMulti -Type MultiString -ErrorAction Stop
    } catch {
        Log-Warn "Failed to update service Environment: $($_.Exception.Message)"
        return
    }
    try {
        Restart-Service -Name $ServiceName -Force -ErrorAction Stop
    } catch {
        Log-Warn "Service restart failed: $($_.Exception.Message); agent will pick up new tenant on next restart"
    }
}
# ── END: Tenant ID Collection / Reconciliation ─────────────────────────────

# ─── Service Registration ────────────────────────────────────────────────────

function Register-SentinelService {
    param([string]$Dir)

    $sentinelBin = Join-Path $Dir "sentinel.exe"

    if (-not (Test-Path $sentinelBin)) {
        Log-Warn "sentinel.exe not found at $sentinelBin -- skipping service registration."
        return
    }

    Log-Info "Registering $ServiceName Windows service..."

    # Check if service already exists
    $existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue

    if ($existing) {
        # Service already exists -- update its configuration.
        Log-Info "Updating existing $ServiceName service configuration..."
        # sc.exe config binPath= cannot be used from PS 5.1 for quoted paths + extra args.
        # sc.exe's own command-line parser uses simple quote matching with no backslash-
        # escape support: "\"path\" --service" terminates the quoted region at the first
        # " after \, leaving C:\... as an unrecognised next token → exit=1639.
        # All three approaches below fail in the same way:
        #
        # Approach 1 (DO NOT USE -- cmd/c: \" not a valid cmd escape inside "..."):
        # $scCmd = "sc.exe config $ServiceName binPath= `"\`"$sentinelBin\`" --service`" start= auto"
        # cmd /c $scCmd 2>&1 | Out-Null
        # if ($LASTEXITCODE -ne 0) { Log-Warn "sc.exe config failed (exit code $LASTEXITCODE)." }
        #
        # Approach 2 (DO NOT USE -- & sc.exe @args: PS 5.1 argument quoting also exits=1639):
        # $binPathValue = "`"$sentinelBin`" --service"
        # Invoke-Native -Label "sc.exe config $ServiceName (update binPath)" -FilePath "sc.exe" `
        #     -ArgumentList @("config", $ServiceName, "binPath=", $binPathValue, "start=", "auto") `
        #     -Hints @("Requires elevation.", "Verify: sc.exe qc $ServiceName") | Out-Null
        #
        # Approach 3 (DO NOT USE -- --% stop-parsing + %env%: still exits=1639; sc.exe
        #             parser terminates at first " inside \", same root cause):
        # $env:_SC_SVC = $ServiceName; $env:_SC_BIN = $sentinelBin
        # sc.exe --% config %_SC_SVC% binPath= "\"%_SC_BIN%\" --service" start= auto 2>&1
        # Remove-Item Env:\_SC_SVC, Env:\_SC_BIN -ErrorAction SilentlyContinue
        #
        # Fix: binPath does NOT change across updates (sentinel.exe is always deployed
        # to the same InstallDir with the same --service arg). Only assert start= auto.
        # binPath was set correctly during the initial New-Service call and stays correct.
        $scLabel = "sc.exe config $ServiceName start= auto"
        Log-Debug "[$scLabel] exec: sc.exe config $ServiceName start= auto"
        $scOut = sc.exe config $ServiceName start= auto 2>&1
        $scEc  = $LASTEXITCODE
        if ($scEc -eq 0) {
            Log-Debug "[$scLabel] exit=0 (ok)"
            Log-Info "Updated $ServiceName service start type (auto)"
        } else {
            Log-Warn "[$scLabel] FAILED: exit=$scEc"
            foreach ($line in ($scOut -split "`r?`n")) {
                $t = $line.Trim(); if ($t) { Log-Warn "  > $t" }
            }
            Log-Warn "  Hint: Requires elevation -- run as Administrator."
        }
    } else {
        # Service does not exist -- create it
        Log-Info "Creating $ServiceName service..."
        $binPathValue = "`"$sentinelBin`" --service"
        New-Service -Name $ServiceName -BinaryPathName $binPathValue -StartupType Automatic -DisplayName "Sentinel Endpoint Agent" -Description "Quilr Sentinel Endpoint Agent - endpoint security and DLP enforcement." | Out-Null
    }

    # Configure failure recovery policy: restart 3 times with 5s delay, reset counter after 24h
    $savedEAP2 = $ErrorActionPreference; $ErrorActionPreference = "SilentlyContinue"
    Invoke-Native -Label "sc.exe failure $ServiceName (configure recovery)" -FilePath "sc.exe" `
        -ArgumentList @("failure", $ServiceName, "reset=", "86400", "actions=", "restart/5000/restart/5000/restart/5000") `
        -Hints @("Configures SCM auto-restart: restart after 5s, 3 times, then reset counter after 24h.",
                 "If this fails, agent crashes won't auto-recover -- file a ticket.") | Out-Null
    Invoke-Native -Label "sc.exe failureflag $ServiceName 1" -FilePath "sc.exe" `
        -ArgumentList @("failureflag", $ServiceName, "1") `
        -Hints @("Triggers recovery on any process exit (not just crashes).") | Out-Null
    $ErrorActionPreference = $savedEAP2

    # Create log directory
    if (-not (Test-Path $ServiceLogDir)) {
        New-Item -ItemType Directory -Path $ServiceLogDir -Force | Out-Null
        Log-Info "Created log directory: $ServiceLogDir"
    }

    # ── Inject logged-in user environment into service context ──────────────
    # Windows services run as LocalSystem (Session 0) with no user env vars.
    # SCM reads service env vars from a REG_MULTI_SZ value named "Environment"
    # directly on HKLM\...\Services\{Name} -- NOT from a subkey.
    # Each string in the multi-string must be in "VAR=VALUE" format.
    Log-Info "Configuring service environment for user context..."
    $serviceRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"

    # Remove the old (broken) subkey if a previous install created it -- SCM never read it.
    $oldSubkeyPath = "$serviceRegPath\Environment"
    if (Test-Path $oldSubkeyPath) {
        Remove-Quiet -Path $oldSubkeyPath -Recurse -Label "legacy registry subkey"
        Log-Info "  Removed stale Environment subkey from previous install."
    }

    # Build the REG_MULTI_SZ array -- each element is "VAR=VALUE"
    $templateFilePath = Join-Path $InstallDir "templates\app-discovery"
    $envLines = [System.Collections.Generic.List[string]]@(
        "USERPROFILE=$($env:USERPROFILE)",
        "APPDATA=$($env:APPDATA)",
        "LOCALAPPDATA=$($env:LOCALAPPDATA)",
        "USERNAME=$($env:USERNAME)",
        "QUILR_DLP_ENDPOINT=$DlpEndpoint",
        "QUILR_BACKEND_BASE_URL=$BackendBaseUrl",
        "SENTINEL_TEMPLATE_DIR=$templateFilePath",
        "SENTINEL_INSTALLATION_PATH=$InstallDir"
    )
    if ($env:USERDNSDOMAIN) {
        $envLines.Add("USERDNSDOMAIN=$($env:USERDNSDOMAIN)")
    }
    if ($script:CollectedEmail) {
        $envLines.Add("SENTINEL_OVERRIDE_EMAIL=$($script:CollectedEmail)")
        Log-Info "  SENTINEL_OVERRIDE_EMAIL set to: $($script:CollectedEmail)"
    }
    if ($script:CollectedTenantId) {
        $envLines.Add("QUILR_TENANT_ID=$($script:CollectedTenantId)")
        Log-Info "  QUILR_TENANT_ID set (fp=$(Get-TenantIdFingerprint $script:CollectedTenantId))"
    }

    try {
        New-ItemProperty -Path $serviceRegPath -Name "Environment" `
            -PropertyType MultiString -Value $envLines.ToArray() -Force -ErrorAction Stop | Out-Null
    } catch {
        Log-Exception -Label "New-ItemProperty service Environment ($serviceRegPath)" -ErrorRecord $_ -Context @(
            "RegPath:  $serviceRegPath",
            "EnvVars:  $($envLines -join '; ')"
        ) -Hints @(
            "Service is already registered -- agent will start but WITHOUT injected env vars.",
            "Symptoms: QUILR_DLP_ENDPOINT / QUILR_BACKEND_BASE_URL missing from agent process environment.",
            "Re-run installer as Administrator to retry the registry write.",
            "Manual fix: Set-ItemProperty -Path '$serviceRegPath' -Name Environment -Value @('VAR=VALUE',...)"
        ) -Level "WARN"
    }

    Log-Info "  QUILR_DLP_ENDPOINT set to: $DlpEndpoint"
    Log-Info "  QUILR_BACKEND_BASE_URL set to: $BackendBaseUrl"
    Log-Info "  User profile context configured for: $env:USERNAME"

    Log-Info "$ServiceName service registered successfully."
    Log-Info "  Start with:  Start-Service $ServiceName"
    Log-Info "  Status:      Get-Service $ServiceName"
    Log-Info "  Logs:        $ServiceLogDir"
}

# ─── Updater Schedule ────────────────────────────────────────────────────────

function Register-UpdaterSchedule {
    param([string]$Dir)

    Log-Info "Configuring auto-updater schedule ($UpdaterTaskName)..."

    # Detect setup executable -- prefer compiled .exe, fall back to .ps1 script.
    # This script IS the updater, so schedule itself.
    $exePath = Join-Path $Dir "sentinel-endpoint.exe"
    $ps1Path = Join-Path $Dir "sentinel-endpoint.ps1"

    # Create a .bat launcher so the scheduled task has a simple cmd.exe /c target
    # (paths with spaces under C:\Program Files\...).
    $batPath = Join-Path $Dir "run-updater.bat"

    if (Test-Path $exePath) {
        Log-Info "  Using compiled setup binary: $exePath"
        try {
            Set-Content -Path $batPath -Value "@`"$exePath`"" -ErrorAction Stop
        } catch {
            Log-Exception -Label "Write run-updater.bat (exe)" -ErrorRecord $_ -Context @(
                "BatPath: $batPath",
                "ExePath: $exePath"
            ) -Hints @(
                "Check ACL on $Dir -- auto-updater task will not be registered."
            ) -Level "ERROR"
            return
        }
    } elseif (Test-Path $ps1Path) {
        Log-Info "  Using setup script: $ps1Path"
        try { Unblock-File -Path $ps1Path -ErrorAction Stop } catch { Log-Debug "Unblock-File '$ps1Path' failed (non-fatal): $($_.Exception.Message)" }
        try {
            Set-Content -Path $batPath -Value "@`"$UpdaterWindowsPowerShellExe`" -NoProfile -ExecutionPolicy $UpdaterLauncherExecutionPolicy -File `"$ps1Path`"" -ErrorAction Stop
        } catch {
            Log-Exception -Label "Write run-updater.bat (ps1)" -ErrorRecord $_ -Context @(
                "BatPath: $batPath",
                "Ps1Path: $ps1Path"
            ) -Hints @(
                "Check ACL on $Dir -- auto-updater task will not be registered."
            ) -Level "ERROR"
            return
        }
    } else {
        # The binary/script is running from outside InstallDir -- copy it in
        if ($selfPath -and (Test-Path $selfPath)) {
            $selfExt = [IO.Path]::GetExtension($selfPath).ToLower()
            if ($selfExt -eq ".exe") {
                $destPath = Join-Path $Dir "sentinel-endpoint.exe"
                Copy-Item -Path $selfPath -Destination $destPath -Force
                Log-Info "  Copied setup binary to install directory"
                try {
                    Set-Content -Path $batPath -Value "@`"$destPath`"" -ErrorAction Stop
                } catch {
                    Log-Exception -Label "Write run-updater.bat (copied exe)" -ErrorRecord $_ -Context @(
                        "BatPath:  $batPath",
                        "DestPath: $destPath"
                    ) -Hints @(
                        "Check ACL on $Dir -- auto-updater task will not be registered."
                    ) -Level "ERROR"
                    return
                }
            } else {
                $destPath = Join-Path $Dir "sentinel-endpoint.ps1"
                $srcLines = [IO.File]::ReadAllLines($selfPath)
                $markerIdx = -1
                for ($li = 0; $li -lt $srcLines.Count; $li++) {
                    if ($srcLines[$li] -eq "#__SENTINEL_PAYLOAD_BASE64_BEGIN__") {
                        $markerIdx = $li; break
                    }
                }
                if ($markerIdx -gt 0) {
                    $clean = $srcLines[0..($markerIdx - 1)]
                    [IO.File]::WriteAllLines($destPath, $clean)
                    Log-Info "  Copied setup script to install directory (payload stripped)"
                } else {
                    Copy-Item -Path $selfPath -Destination $destPath -Force
                    Log-Info "  Copied setup script to install directory"
                }
                try { Unblock-File -Path $destPath -ErrorAction Stop } catch { Log-Debug "Unblock-File '$destPath' failed (non-fatal): $($_.Exception.Message)" }
                try {
                    Set-Content -Path $batPath -Value "@`"$UpdaterWindowsPowerShellExe`" -NoProfile -ExecutionPolicy $UpdaterLauncherExecutionPolicy -File `"$destPath`"" -ErrorAction Stop
                } catch {
                    Log-Exception -Label "Write run-updater.bat (copied ps1)" -ErrorRecord $_ -Context @(
                        "BatPath:  $batPath",
                        "DestPath: $destPath"
                    ) -Hints @(
                        "Check ACL on $Dir -- auto-updater task will not be registered."
                    ) -Level "ERROR"
                    return
                }
            }
        } else {
            Log-Warn "Setup binary not found - auto-update will not be available."
            return
        }
    }

    # Ensure log directory exists
    if (-not (Test-Path $LogDir)) {
        New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
    }

    # Remove existing schedule if present (idempotent re-install).  The common
    # case (first install) is "task not found" -- expected, suppressed by
    # message match. Match by message text, not exception type: -ErrorAction Stop
    # can wrap the underlying CimException in a CmdletInvocationException, so a
    # typed catch is unreliable. Anything not matching the "not found" variants
    # (permission denied, scheduler service down) is logged so a silent failure
    # here doesn't hide why the re-register below would fail with a "task
    # already exists" error.
    try {
        Unregister-ScheduledTask -TaskName $UpdaterTaskName -Confirm:$false -ErrorAction Stop | Out-Null
    } catch {
        $msg = $_.Exception.Message
        if ($msg -match 'cannot find the file specified|No MSFT_ScheduledTask objects found') {
            Log-Debug "Unregister-ScheduledTask '$UpdaterTaskName' skipped: task does not exist yet"
        } else {
            Log-Warn "Unregister-ScheduledTask '$UpdaterTaskName' failed: $msg"
        }
    }

    # Register via hand-built XML. The cmdlet path (New-ScheduledTaskTrigger with
    # a large -RepetitionDuration) fails on Win10/11 with "The task XML contains
    # a value which is incorrectly formatted or out of range." -- Windows Task
    # Scheduler rejects durations beyond a few years. Empty <Duration> means
    # "indefinite" in the XML schema and works across versions.
    Log-Info "  Launcher: $batPath"
    Import-Module ScheduledTasks -ErrorAction SilentlyContinue | Out-Null

    $startBoundary = (Get-Date).AddMinutes(1).ToString("yyyy-MM-ddTHH:mm:ss")
    $interval      = "PT${UpdaterIntervalMinutes}M"  # ISO 8601 duration (e.g. PT30M)
    $argLine       = "/c `"$batPath`""
    $argLineEsc    = [System.Security.SecurityElement]::Escape($argLine)
    $taskXml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <TimeTrigger>
      <Repetition>
        <Interval>$interval</Interval>
        <StopAtDurationEnd>false</StopAtDurationEnd>
      </Repetition>
      <StartBoundary>$startBoundary</StartBoundary>
      <Enabled>true</Enabled>
    </TimeTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>cmd.exe</Command>
      <Arguments>$argLineEsc</Arguments>
    </Exec>
  </Actions>
</Task>
"@

    try {
        Register-ScheduledTask -TaskName $UpdaterTaskName -Xml $taskXml -Force -ErrorAction Stop | Out-Null
    } catch {
        Log-Exception -Label "Register-ScheduledTask '$UpdaterTaskName'" -ErrorRecord $_ -Context @(
            "Launcher path:  $batPath",
            "Principal:      NT AUTHORITY\SYSTEM (S-1-5-18)",
            "Repeat:         every $UpdaterIntervalMinutes min, indefinite",
            "XML length:     $($taskXml.Length) chars"
        ) -Hints @(
            "Verify admin rights (installer must run elevated).",
            "Check Task Scheduler service: Get-Service Schedule",
            "Inspect XML error coordinates '(line,col)' in the exception message.",
            "Event log: Get-WinEvent -LogName 'Microsoft-Windows-TaskScheduler/Operational' -MaxEvents 20"
        )
        # Old approach (kept for reference -- DO NOT RESTORE: return here silently swallows the
        # failure, causing the caller to reach End-PhaseOk / Show-CliSuccess despite no task being registered):
        # return
        throw
    }

    # Verify registration actually succeeded -- Register-ScheduledTask has been
    # observed to silently return without registering under some error paths.
    $registered = Get-ScheduledTask -TaskName $UpdaterTaskName -ErrorAction SilentlyContinue
    if (-not $registered) {
        Log-Error "[Register-ScheduledTask '$UpdaterTaskName'] reported success but Get-ScheduledTask returned nothing"
        Log-Error "  Hint: check Event Viewer -> Microsoft-Windows-TaskScheduler/Operational for the actual cause"
        throw "Register-ScheduledTask '$UpdaterTaskName' silently failed -- task not found after registration"
    }

    Log-Info "Auto-updater scheduled: every $UpdaterIntervalMinutes minutes (indefinite)"
    Log-Info "  Task name:    $UpdaterTaskName"
    Log-Info "  Updater logs: $LogDir\sentinel_endpoint.log"
}

# ─── Install Mode Entry Point ────────────────────────────────────────────────

function Invoke-Install {
    param([string]$ResolvedZip)

    Log-Info "=========================================="
    Log-Info "Quilr Sentinel Endpoint Agent v$SetupVersion -- Install"
    Log-Info "=========================================="
    Log-Environment

    # Prevent concurrent installs
    Get-UpdateLock

    Log-Info "Zip file:              $ResolvedZip"
    Log-Info "Install dir:           $InstallDir"

    # Derive install version early for the banner.
    $installVersion = "unknown"
    $zipName = [IO.Path]::GetFileName($ResolvedZip)
    if ($zipName -match '_v(\d+\.\d+\.\d+)_') { $installVersion = $Matches[1] }

    # Env transition: loud panel BEFORE the banner so operator sees their
    # explicit -Env is causing a change.  Service + schedule will be
    # re-registered with the new env as a normal part of Register-*.
    if ($script:EnvTransition) {
        Show-CliEnvTransition -From $script:EnvTransition.From -To $script:EnvTransition.To
        Log-Warn "Env transition on install: $($script:EnvTransition.From) -> $($script:EnvTransition.To)"
    }

    Show-CliBanner -Title "Quilr Sentinel Endpoint Agent" `
                   -Subtitles @("v$installVersion  -  Installing  -  Env: $Env")
    Start-CliFlow -TotalSteps 7

    # Fail-early tenant ID gate (fresh install only). Collect-TenantId exits
    # non-zero via Exit-WithCleanup if it can't resolve from arg / env /
    # existing file in a non-interactive context. Update path (Invoke-Update)
    # intentionally skips this — the existing on-disk file is preserved.
    $script:CollectedTenantId = Collect-TenantId
    Write-TenantIdFile -Value $script:CollectedTenantId

    # ── Phase 1/7: Stop existing agent ───────────────────────────────────
    Start-Phase "Stop existing agent"
    try {
        Stop-SentinelProcesses
    } catch {
        Log-Exception -Label "Stop-SentinelProcesses (Invoke-Install Phase 1)" -ErrorRecord $_ -Context @(
            "Service: $ServiceName"
        ) -Hints @(
            "Install aborted -- current agent (if any) left running untouched.",
            "Try: Stop-Service $ServiceName -Force; taskkill /F /IM sentinel.exe",
            "If processes persist after force-kill, a reboot may be required before retrying."
        ) -Level "ERROR"
        End-PhaseFail -Reason "Stop-SentinelProcesses: $($_.Exception.Message)"
        exit 1
    }
    End-PhaseOk

    # Create install directory
    if (-not (Test-Path $InstallDir)) {
        Log-Info "Creating install directory..."
        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    }

    # ── SHA-256 audit log (no CDN manifest = no checksum to verify against) ──
    $actualSha = Get-Sha256Hash -FilePath $ResolvedZip
    Log-Info "ZIP SHA-256: $actualSha"

    # ── Phase 2/7: Deploy package ────────────────────────────────────────
    Start-Phase "Deploy package"

    # Extract to staging first -- InstallDir is not touched until all checks pass.
    # Top-level finally already cleans up sentinel_staging_$PID on any exit path.
    # Old approach (kept for reference -- extracted directly to InstallDir, risking partial overwrite on failure):
    # Expand-Archive -Path $ResolvedZip -DestinationPath $InstallDir -Force
    $stagingDir = Join-Path ([IO.Path]::GetTempPath()) "sentinel_staging_$PID"
    Log-Info "Extracting package to staging dir: $stagingDir"
    try {
        New-Item -ItemType Directory -Path $stagingDir -Force -ErrorAction Stop | Out-Null
    } catch {
        Log-Exception -Label "New-Item staging dir" -ErrorRecord $_ -Context @("Path: $stagingDir") -Hints @(
            "Check temp dir permissions: $([IO.Path]::GetTempPath())"
        ) -Level "ERROR"
        End-PhaseFail -Reason "Could not create staging directory: $($_.Exception.Message)"
        exit 1
    }
    if (-not (Test-ZipSafety -ZipFile $ResolvedZip)) {
        Log-Error "ZIP safety check failed on install package -- aborting."
        End-PhaseFail -Reason "ZIP failed safety check (path traversal detected)"
        exit 1
    }
    try {
        Expand-Archive -Path $ResolvedZip -DestinationPath $stagingDir -Force -ErrorAction Stop
    } catch {
        Log-Exception -Label "Expand-Archive to staging" -ErrorRecord $_ -Context @(
            "ZIP:        $ResolvedZip",
            "StagingDir: $stagingDir"
        ) -Hints @(
            "ZIP may be corrupt or truncated -- re-download and retry.",
            "Verify ZIP integrity: Test-Path '$ResolvedZip'"
        ) -Level "ERROR"
        End-PhaseFail -Reason "ZIP extraction failed: $($_.Exception.Message)"
        exit 1
    }

    # Verify key binaries in staging (InstallDir still untouched)
    $expectedBins    = @("sentinel.exe", "sentinel-proxy.exe", "template-engine.exe", "sentinel-monitor-v2.exe")
    $criticalBins    = @("sentinel.exe")   # service cannot start without these
    $missingCritical = @()
    foreach ($bin in $expectedBins) {
        $binPath = Join-Path $stagingDir $bin
        if (Test-Path $binPath) {
            Log-Info "  Staged: $bin"
        } elseif ($bin -in $criticalBins) {
            Log-Error "  MISSING (critical): $bin -- cannot promote to $InstallDir"
            $missingCritical += $bin
        } else {
            Log-Warn "  Missing (non-critical): $bin"
        }
    }
    if ($missingCritical.Count -gt 0) {
        End-PhaseFail -Reason "Critical binaries missing in staging: $($missingCritical -join ', ')"
        exit 1
    }

    # ── Authenticode verification on staged binaries (before touching InstallDir) ──
    if ($script:DoVerifyAuthenticode) {
        if (-not (Test-Authenticode -Dir $stagingDir)) {
            Log-Error "Code signature verification FAILED. Use -SkipSignatureCheck to disable this check."
            End-PhaseFail -Reason "Authenticode verification failed"
            exit 1
        }
        Log-Info "  Code signatures verified"
    }

    # All checks passed -- promote staging to InstallDir
    Log-Info "Promoting staged files to $InstallDir ..."
    try {
        Copy-Item -Path "$stagingDir\*" -Destination $InstallDir -Recurse -Force -ErrorAction Stop
    } catch {
        Log-Exception -Label "Promote staging to InstallDir" -ErrorRecord $_ -Context @(
            "StagingDir: $stagingDir",
            "InstallDir: $InstallDir"
        ) -Hints @(
            "Check disk space and ACL on $InstallDir",
            "Staged files are still intact at $stagingDir for manual recovery."
        ) -Level "ERROR"
        End-PhaseFail -Reason "Failed to promote staged files: $($_.Exception.Message)"
        exit 1
    }

    # List all installed files
    $fileCount = (Get-ChildItem -Path $InstallDir -Recurse -File).Count
    Log-Info "  Total files installed: $fileCount"

    # Write version marker -- prefer ZIP filename pattern((e.g. sentinel_package_v0.10.225_win_release.zip -> 0.10.225)), fall back to manifest.xml.
    # Non-standard ZIP names (dev builds, custom pipelines) must not leave the marker unwritten.
    $zipName = [IO.Path]::GetFileName($ResolvedZip)
    $installedVersion = $null
    if ($zipName -match '_v(\d+\.\d+\.\d+)_') {
        $installedVersion = $Matches[1]
        Log-Debug "  Version from ZIP filename: $installedVersion"
    } else {
        $manifestXml = Join-Path $InstallDir "manifest.xml"
        if (Test-Path $manifestXml) {
            try {
                [xml]$xml = Get-Content $manifestXml -Raw -ErrorAction Stop
                $ver = $xml.SelectSingleNode("//version")
                if ($ver) {
                    $installedVersion = $ver.InnerText.Trim()
                    Log-Debug "  Version from manifest.xml: $installedVersion"
                } else {
                    Log-Warn "  manifest.xml has no <version> node -- version marker will not be written."
                }
            } catch {
                Log-Exception -Label "Read manifest.xml for version marker" -ErrorRecord $_ -Context @(
                    "Path: $manifestXml"
                ) -Level "WARN"
            }
        } else {
            Log-Warn "  ZIP filename does not match _vX.Y.Z_ pattern and no manifest.xml found -- version marker will not be written."
            Log-Warn "  ZIP: $zipName"
        }
    }
    if ($installedVersion) {
        try {
            Set-Content -Path (Join-Path $InstallDir ".installed_version") -Value $installedVersion -ErrorAction Stop
            Log-Info "  Version marker: $installedVersion"
        } catch {
            Log-Exception -Label "Write .installed_version" -ErrorRecord $_ -Context @(
                "Path:    $(Join-Path $InstallDir '.installed_version')",
                "Version: $installedVersion"
            ) -Level "WARN"
        }
    }

    # ── Deploy hooks ──
    Deploy-HookBinaries -HooksDir (Join-Path $InstallDir "hooks") -DestDir $InstallDir
    Copy-HookScripts -Src (Join-Path $InstallDir "hooks\scripts") -Dest (Join-Path $SentinelUserDir "scripts")

    # Trust the bundled MITM CA chain (always, by default).
    # Strict-mode builds ship root.pem (root CA) + cert.pem (intermediate); legacy
    # builds ship cert.pem only. Set-SentinelCaTrust handles both shapes.
    Log-Info "Trusting bundled MITM CA chain for current user (required for sentinel-proxy HTTPS interception)..."
    Set-SentinelCaTrust -InstallDir $InstallDir

    # NODE_EXTRA_CA_CERTS needs the *full* chain in one file (Node won't walk the
    # Windows cert store). Prefer the bundle; fall back to single cert.
    $nodeCertPath = New-SentinelCaBundle -InstallDir $InstallDir
    if ($nodeCertPath) {
        Set-NodeCaEnv -CertPath $nodeCertPath
    } else {
        Log-Warn "No CA cert available for NODE_EXTRA_CA_CERTS -- skipping Node.js env setup."
    }
    End-PhaseOk -Detail "$fileCount files, v$installVersion"

    # ── Phase 3/7: Configure environment (email + env vars) ──────────────
    Start-Phase "Configure environment"

    # Tenant ID already resolved + persisted by the fail-fast gate above.

    # ── Email collection (before service registration, so registry gets the email) ──
    # $script:CollectedEmail = Collect-UserEmail

    # ── Persist override email for current user's shells regardless of service/standalone mode ──
    # If no email was provided, remove any stale entry left by a previous install.
    if ($script:CollectedEmail) {
        # 1. Current PowerShell session (process-scope)
        $env:SENTINEL_OVERRIDE_EMAIL = $script:CollectedEmail

        # 2. Future sessions -- persists to HKCU via registry (equivalent to setx)
        try { [System.Environment]::SetEnvironmentVariable("SENTINEL_OVERRIDE_EMAIL", $script:CollectedEmail, [System.EnvironmentVariableTarget]::User) }
        catch { Log-Warn "SetEnvironmentVariable 'SENTINEL_OVERRIDE_EMAIL' failed: $($_.Exception.Message) -- future sessions may not see this value." }

        Log-Info "SENTINEL_OVERRIDE_EMAIL configured: $($script:CollectedEmail)"

        # 3. Write CMD helper silently -- available at a known path if ever needed manually
        $cmdHelper = Join-Path $env:TEMP "sentinel_set_env.cmd"
        Set-Content -Path $cmdHelper -Value "@set SENTINEL_OVERRIDE_EMAIL=$($script:CollectedEmail)" -Encoding ASCII
    } else {
        # No email provided -- clear any stale value from a previous install.

        # 1. HKCU -- future sessions
        try { [System.Environment]::SetEnvironmentVariable("SENTINEL_OVERRIDE_EMAIL", $null, [System.EnvironmentVariableTarget]::User) }
        catch { Log-Warn "SetEnvironmentVariable 'SENTINEL_OVERRIDE_EMAIL' (clear) failed: $($_.Exception.Message)" }

        # 2. Current PowerShell session
        try { Remove-Item "Env:\SENTINEL_OVERRIDE_EMAIL" -ErrorAction Stop }
        catch [System.Management.Automation.ItemNotFoundException] { }
        catch { Log-Debug "Remove-Item Env:\SENTINEL_OVERRIDE_EMAIL failed: $($_.Exception.Message)" }

        # 3. Broadcast WM_SETTINGCHANGE so GUI applications refresh their env copy.
        try {
            Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public class SentinelEnvBroadcast {
    [DllImport("user32.dll", SetLastError=true, CharSet=CharSet.Auto)]
    public static extern IntPtr SendMessageTimeout(IntPtr hWnd, uint Msg, UIntPtr wParam,
        string lParam, uint fuFlags, uint uTimeout, out UIntPtr lpdwResult);
}
'@ -ErrorAction SilentlyContinue
            $result = [UIntPtr]::Zero
            [SentinelEnvBroadcast]::SendMessageTimeout(
                [IntPtr]0xFFFF, 0x001A, [UIntPtr]::Zero,
                "Environment", 0x0002, 5000, [ref]$result) | Out-Null
        } catch {
            # Best-effort WM_SETTINGCHANGE broadcast -- if it fails, already-
            # open Explorer windows simply won't see the new env until they
            # restart.  Not user-actionable; log the reason for debug.
            Log-Debug "WM_SETTINGCHANGE broadcast failed: $($_.Exception.Message)"
        }

        # 4. CMD helper -- lets users clear the var in any open CMD window with one command
        $cmdHelper = Join-Path $env:TEMP "sentinel_clear_env.cmd"
        Set-Content -Path $cmdHelper -Value "@set SENTINEL_OVERRIDE_EMAIL=" -Encoding ASCII

        Log-Info "No work email provided -- SENTINEL_OVERRIDE_EMAIL cleared."
    }

    # ── Set environment endpoint vars -- always applied regardless of service/standalone mode ──
    Log-Info "Setting Quilr environment endpoint vars ($Env)..."
    $env:QUILR_DLP_ENDPOINT     = $DlpEndpoint
    $env:QUILR_BACKEND_BASE_URL = $BackendBaseUrl
    try { [System.Environment]::SetEnvironmentVariable("QUILR_DLP_ENDPOINT",     $DlpEndpoint,    [System.EnvironmentVariableTarget]::User) }
    catch { Log-Warn "SetEnvironmentVariable 'QUILR_DLP_ENDPOINT' failed: $($_.Exception.Message) -- future sessions may not see this value." }
    try { [System.Environment]::SetEnvironmentVariable("QUILR_BACKEND_BASE_URL", $BackendBaseUrl, [System.EnvironmentVariableTarget]::User) }
    catch { Log-Warn "SetEnvironmentVariable 'QUILR_BACKEND_BASE_URL' failed: $($_.Exception.Message) -- future sessions may not see this value." }
    Log-Info "  QUILR_DLP_ENDPOINT     = $DlpEndpoint"
    Log-Info "  QUILR_BACKEND_BASE_URL = $BackendBaseUrl"

    $templateFileEnvPath = Join-Path $InstallDir "templates\app-discovery"
    $env:SENTINEL_TEMPLATE_DIR = $templateFileEnvPath
    try { [System.Environment]::SetEnvironmentVariable("SENTINEL_TEMPLATE_DIR", $templateFileEnvPath, [System.EnvironmentVariableTarget]::User) }
    catch { Log-Warn "SetEnvironmentVariable 'SENTINEL_TEMPLATE_DIR' failed: $($_.Exception.Message) -- future sessions may not see this value." }
    Log-Info "  SENTINEL_TEMPLATE_DIR = $templateFileEnvPath"

    $env:SENTINEL_INSTALLATION_PATH = $InstallDir
    try { [System.Environment]::SetEnvironmentVariable("SENTINEL_INSTALLATION_PATH", $InstallDir, [System.EnvironmentVariableTarget]::User) }
    catch { Log-Warn "SetEnvironmentVariable 'SENTINEL_INSTALLATION_PATH' failed: $($_.Exception.Message) -- future sessions may not see this value." }
    Log-Info "  SENTINEL_INSTALLATION_PATH = $InstallDir"
    # Write CMD helper silently
    $cmdQuilrHelper = Join-Path $env:TEMP "sentinel_set_quilr_env.cmd"
    Set-Content -Path $cmdQuilrHelper -Value ("@set QUILR_DLP_ENDPOINT=$DlpEndpoint`r`n@set QUILR_BACKEND_BASE_URL=$BackendBaseUrl") -Encoding ASCII
    End-PhaseOk

    # ── Phase 4/7: Register service (sets up Windows SCM entry) ──────────
    Start-Phase "Register service"
    # Always register as service in install mode (this is the customer binary)
    try {
        Register-SentinelService -Dir $InstallDir
    } catch {
        Log-Exception -Label "Register-SentinelService (Invoke-Install Phase 4)" -ErrorRecord $_ -Context @(
            "InstallDir: $InstallDir",
            "Service:    $ServiceName"
        ) -Hints @(
            "Requires elevation -- run as Administrator.",
            "Verify SCM is accessible: Get-Service $ServiceName",
            "Check for an existing broken registration: sc.exe delete $ServiceName"
        ) -Level "ERROR"
        End-PhaseFail -Reason $_.Exception.Message
        exit 1
    }
    Reconcile-TenantIdEnv
    End-PhaseOk

    # ── Phase 5/7: Configure network adapters (IPv6 + stack prep) ────────
    # CLI text is intentionally generic -- the log file still says
    # "Disabling IPv6 (per-adapter + registry)..." for diagnostics.
    Start-Phase "Configure network adapters"
    try {
        Disable-IPv6
    } catch {
        Log-Exception -Label "Disable-IPv6 (Invoke-Install Phase 5)" -ErrorRecord $_ -Hints @(
            "CIM/WMI provider may be unavailable -- IPv6 state unchanged.",
            "Agent will still start; re-run installer to retry IPv6 config."
        ) -Level "WARN"
    }
    End-PhaseOk

    # ── Phase 6/7: Start agent ───────────────────────────────────────────
    Start-Phase "Start agent"
    try {
        Start-Service -Name $ServiceName -ErrorAction Stop -WarningAction SilentlyContinue
        End-PhaseOk
    } catch {
        Log-Exception -Label "Start-Service $ServiceName (install Phase 6)" -ErrorRecord $_ -Context @(
            "Service:     $ServiceName",
            "Install dir: $InstallDir",
            "Binary:      $(Join-Path $InstallDir 'sentinel.exe')"
        ) -Hints @(
            "Check service binary: sc.exe qc $ServiceName",
            "Check agent crash log: $ServiceLogDir\agent.stderr.log",
            "Check SCM event log:   Get-WinEvent -LogName System -Source 'Service Control Manager' -MaxEvents 10",
            "Try manually:          Start-Service $ServiceName"
        ) -Level "ERROR"
        End-PhaseFail -Reason $_.Exception.Message
        exit 1
    }

    # ── Phase 7/7: Schedule auto-updater + self-copy ─────────────────────
    Start-Phase "Schedule auto-updater"

    # Updater schedule is non-critical -- don't let it abort the entire install
    try {
        Register-UpdaterSchedule -Dir $InstallDir
    } catch {
        Log-Exception -Label "Register-UpdaterSchedule (install path)" -ErrorRecord $_ -Context @(
            "InstallDir: $InstallDir"
        ) -Hints @(
            "Agent install succeeded; only the auto-update schedule failed.",
            "Manual registration: re-run the installer as Administrator.",
            "Check Event Viewer -> Microsoft-Windows-TaskScheduler/Operational."
        )
    }

    # Copy this binary/script into the install directory so the scheduled task
    # can find it.  Failure here is NON-FATAL: the scheduled task and service
    # are already registered; a missing self-copy only means the next
    # scheduled tick falls back to CDN, which is the desired flow anyway.
    # Wrap in try/catch so a transient file lock (e.g. previous install's
    # sentinel-endpoint.exe still has a handle) doesn't tank the whole
    # install after Phase 6 already started the agent successfully.
    $selfCopyOk = $true
    $selfCopyDetail = ""
    if ($selfPath -and (Test-Path $selfPath)) {
        $selfExt = [IO.Path]::GetExtension($selfPath).ToLower()
        try {
            if ($selfExt -eq ".exe") {
                # Running as compiled .exe -- copy the binary directly.
                $destSetup = Join-Path $InstallDir "sentinel-endpoint.exe"
                if ($selfPath -ne $destSetup) {
                    # One quick retry in case a stale handle drops in ~2s.
                    $attempt = 0
                    while ($true) {
                        try {
                            Copy-Item -Path $selfPath -Destination $destSetup -Force -ErrorAction Stop
                            Log-Info "Copied sentinel-endpoint.exe to $InstallDir"
                            break
                        } catch [System.IO.IOException] {
                            $attempt++
                            if ($attempt -ge 2) { throw }
                            Log-Debug "Self-copy attempt $attempt hit file lock, retrying in 2s..."
                            Start-Sleep -Seconds 2
                        }
                    }
                }
            } else {
                # Running as .ps1 -- strip embedded payload so installed copy checks CDN.
                $destSetup = Join-Path $InstallDir "sentinel-endpoint.ps1"
                if ($selfPath -ne $destSetup) {
                    $srcLines = [IO.File]::ReadAllLines($selfPath)
                    $markerIdx = -1
                    for ($li = 0; $li -lt $srcLines.Count; $li++) {
                        if ($srcLines[$li] -eq "#__SENTINEL_PAYLOAD_BASE64_BEGIN__") {
                            $markerIdx = $li; break
                        }
                    }
                    if ($markerIdx -gt 0) {
                        [IO.File]::WriteAllLines($destSetup, $srcLines[0..($markerIdx - 1)])
                        Log-Info "Copied sentinel-endpoint.ps1 to $InstallDir (payload stripped)"
                    } else {
                        Copy-Item -Path $selfPath -Destination $destSetup -Force -ErrorAction Stop
                        Log-Info "Copied sentinel-endpoint.ps1 to $InstallDir"
                    }
                }
            }
        } catch {
            $selfCopyOk = $false
            $selfCopyDetail = $_.Exception.Message
            Log-Exception -Label "Self-copy to InstallDir" -ErrorRecord $_ -Context @(
                "Source:      $selfPath",
                "Destination: $destSetup"
            ) -Hints @(
                "Install is still functional -- service is registered and running.",
                "Scheduled task will fall back to CDN for the next update check.",
                "If you need the local copy, re-run this installer after rebooting."
            )
        }
    }

    if ($selfCopyOk) {
        End-PhaseOk
    } else {
        # Phase still counts as "done" in the step counter -- the install
        # itself succeeded.  Emit a yellow skip-ish marker with the reason.
        End-PhaseSkip -Reason "self-copy skipped (file lock); install OK"
    }

    # Persist env AFTER Register-UpdaterSchedule so the store always agrees
    # with the schedule's baked -Env arg.  Idempotent -- writing the same
    # value is a no-op.
    Write-PersistedEnv -Value $Env

    # Wait for agent to spawn subsystems before logging
    Start-Sleep -Seconds 5
    Log-SentinelProcesses -Label "post-install"
    Write-SystemExtensionLogDump -Label "post-install"
    try { Write-NetworkSnapshot -Label "post-install" } catch {
        Log-Debug "Write-NetworkSnapshot (post-install) failed: $($_.Exception.Message)"
    }

    # Summary (full detail goes to log; CLI gets the compact success panel)
    Log-Info "=========================================="
    Log-Info "Installation complete."
    Log-Info "=========================================="
    Log-Info "Install directory: $InstallDir"
    Log-Info "Start the agent:   Start-Service $ServiceName"
    Log-Info "Auto-updater:      $UpdaterTaskName (every $UpdaterIntervalMinutes min)"
    Log-Info "Environment:       $Env"
    Log-Info "Setup logs:        $LogDir\sentinel_endpoint.log"
    Log-Warn "If you invoked this script from a CMD window, environment variables are"
    Log-Warn "NOT automatically inherited by the parent CMD session (OS limitation)."
    Log-Warn "Run these once in your CMD window to apply them to the current session:"
    if ($script:CollectedEmail) {
        Log-Warn "  $cmdHelper"
    }
    Log-Warn "  $cmdQuilrHelper"

    $successLines = @(
        "Agent running:  v$installVersion",
        "Environment:    $Env",
        "Updater:        every $UpdaterIntervalMinutes min"
    )
    Show-CliSuccess -Title "Install complete" -Lines $successLines
}

# #############################################################################
#
#  UPDATE SECTION -- Functions used during auto-update
#
# #############################################################################

# ─── Version Utilities ────────────────────────────────────────────────────────

function Get-CurrentVersion {
    # 1. Check version marker from previous updater/installer run
    $marker = Join-Path $InstallDir ".installed_version"
    if (Test-Path $marker) {
        $raw = Get-Content $marker -Raw -ErrorAction SilentlyContinue
        Log-Debug "Raw content from marker: $raw"
        $ver = if ($raw) { $raw.Trim() } else { $null }
        if ($ver) {
            Log-Debug "Current version from marker: $ver"
            return $ver
        }
        Log-Warn "Version marker exists but is empty or unreadable: $marker"
    }

    # 2. Check manifest.xml
    $candidates = @(
        (Join-Path $InstallDir "manifest.xml")
    )
    foreach ($manifest in $candidates) {
        if (Test-Path $manifest) {
            try {
                [xml]$xml = Get-Content $manifest
                $ver = $xml.SelectSingleNode("//version")
                if ($ver) {
                    Log-Debug "Current version from manifest.xml: $($ver.InnerText.Trim())"
                    return $ver.InnerText.Trim()
                }
            } catch {
                Log-Exception -Label "Parse manifest.xml" -ErrorRecord $_ -Context @(
                    "Path: $manifest"
                ) -Hints @(
                    "File may be truncated / malformed XML.",
                    "Inspect with: [xml](Get-Content '$manifest' -Raw)",
                    "If this is an older install, manifest.xml may legitimately not contain <version>."
                )
            }
        }
    }
    Log-Warn "Could not detect installed version from any source -- assuming 0.0.0"
    Log-Warn "  Sources checked: $marker, $(Join-Path $InstallDir 'manifest.xml')"
    return "0.0.0"
}

function Test-NewerVersion {
    param([string]$Remote, [string]$Current)
    if ($Remote -eq $Current) { return $false }
    $r = @($Remote -split '\.')
    $c = @($Current -split '\.')
    $count = [Math]::Max($r.Count, $c.Count)
    for ($i = 0; $i -lt $count; $i++) {
        $rv = [int]$(if ($i -lt $r.Count) { $r[$i] } else { 0 })
        $cv = [int]$(if ($i -lt $c.Count) { $c[$i] } else { 0 })
        if ($rv -gt $cv) { return $true }
        if ($rv -lt $cv) { return $false }
    }
    return $false
}

function Test-AboveFloor {
    param([string]$Version, [string]$Floor)
    $v = @($Version -split '\.')
    $f = @($Floor -split '\.')
    $count = [Math]::Max($v.Count, $f.Count)
    for ($i = 0; $i -lt $count; $i++) {
        $vv = [int]$(if ($i -lt $v.Count) { $v[$i] } else { 0 })
        $fv = [int]$(if ($i -lt $f.Count) { $f[$i] } else { 0 })
        if ($vv -gt $fv) { return $true }
        if ($vv -lt $fv) { return $false }
    }
    return $true
}

# ─── HTTP Fetch with Retry ───────────────────────────────────────────────────

function Invoke-FetchUrl {
    param(
        [string]$Url,
        [string]$OutFile,
        [int]$Timeout = $ManifestTimeout
    )

    for ($attempt = 1; $attempt -le $MaxRetries; $attempt++) {
        Log-Debug "Fetch attempt $attempt/$MaxRetries`: $Url"
        try {
            # Invoke-WebRequest with timeout -- WebClient.DownloadFile has no timeout
            Invoke-WebRequest -Uri $Url -OutFile $OutFile -TimeoutSec $Timeout -UseBasicParsing -ErrorAction Stop
            Log-Debug "Fetch succeeded: $Url"
            return $true
        } catch {
            # Pull HTTP status out of the WebException if present -- the raw $_
            # message often hides it behind a generic "response stream" wrapper.
            $httpStatus = $null
            try {
                if ($_.Exception.Response) {
                    $httpStatus = [int]$_.Exception.Response.StatusCode
                }
            } catch {
                # Reading .StatusCode off a non-HTTP exception (DNS, TLS,
                # timeout) can throw -- that is expected; $httpStatus stays
                # at its default and the retry logic treats the error as
                # "transport, not protocol".  Debug-log so the reason is
                # still auditable.
                Log-Debug "HTTP status readback failed: $($_.Exception.Message)"
            }
            if ($attempt -lt $MaxRetries) {
                $delay = [math]::Pow(2, $attempt - 1)
                # Non-final attempts: file-only (DEBUG).  A transient failure
                # that auto-recovers on retry N+1 should not surface as a
                # CLI warning -- the operator only cares when the final
                # attempt fails (logged below as ERROR).
                Log-Exception -Label "Invoke-WebRequest (attempt $attempt/$MaxRetries, retrying in ${delay}s)" `
                    -ErrorRecord $_ -Context @(
                    "URL:        $Url",
                    "OutFile:    $OutFile",
                    "TimeoutSec: $Timeout",
                    $(if ($httpStatus) { "HTTP status: $httpStatus" } else { "HTTP status: <no response>" })
                ) -Hints @(
                    "Retry scheduled in ${delay}s (exponential backoff).",
                    "Proxy/firewall may be blocking -- test: Test-NetConnection -ComputerName <host> -Port 443",
                    "Certificate chain issues surface as 'The SSL connection' -- check time sync + root CAs."
                ) -Level "DEBUG"
                Start-Sleep -Seconds $delay
            } else {
                Log-Exception -Label "Invoke-WebRequest (FINAL attempt $attempt/$MaxRetries)" -ErrorRecord $_ -Context @(
                    "URL:        $Url",
                    "OutFile:    $OutFile",
                    "TimeoutSec: $Timeout",
                    $(if ($httpStatus) { "HTTP status: $httpStatus" } else { "HTTP status: <no response>" })
                ) -Hints @(
                    "Exhausted $MaxRetries retries -- giving up on this URL.",
                    "Common causes: CDN down, corporate proxy with SSL inspection, DNS resolution failure.",
                    "Network check: Resolve-DnsName <host>; Test-NetConnection <host> -Port 443"
                ) -Level "ERROR"
            }
        }
    }
    return $false
}

# ─── Manifest -- Fetch, Parse, and Verify update.json ────────────────────────

function Get-Architecture {
    $arch = $env:PROCESSOR_ARCHITECTURE
    switch ($arch) {
        "AMD64" { return "windows/64" }
        "ARM64" { Log-Warn "ARM64 detected - using x64 package (emulation)"; return "windows/64" }
        "x86"   { return "windows/32" }
        default {
            Log-Error "Unsupported architecture: $arch"
            return $null
        }
    }
}

# Construct download URL from CDN_BASE + version + architecture.
# No download_url in manifest -- prevents CDN hijack via manifest tampering.
# Pattern: $CdnBase/$archPath/sentinel_package_v{version}_{platform}_release.zip
function Get-DownloadUrl {
    param([string]$Version)
    $archPath = Get-Architecture
    if (-not $archPath) { return $null }
    $platform = if ($archPath -eq "windows/32") { "win32" } else { "win" }
    return "$CdnBase/$archPath/sentinel_package_v${Version}_${platform}_release.zip"
}

# ─── .NET RSA Key Import ─────────────────────────────────────────────────────
# ImportSubjectPublicKeyInfo() does NOT exist on .NET Framework (PowerShell 5.1).
# It was added in .NET Core 3.0. This function extracts RSA parameters from a
# known RSA-2048 SubjectPublicKeyInfo DER structure using fixed offsets, then
# imports via RSACng.ImportParameters() which works on .NET Fw 4.6+.
# NOTE: If the signing key changes size, update the offsets and length check.

function Import-RsaPublicKeyFromPem {
    param([string]$PemString)

    $keyB64 = ($PemString -replace '-----[^-]+-----' -replace '\s').Trim()
    $der = [Convert]::FromBase64String($keyB64)

    # RSA-2048 SubjectPublicKeyInfo is always exactly 294 bytes.
    # Offsets: modulus (256 bytes) at 33, exponent (3 bytes) at 291.
    if ($der.Length -ne 294) {
        throw "Expected RSA-2048 SPKI (294 bytes), got $($der.Length) bytes -- key size changed?"
    }

    $params = New-Object System.Security.Cryptography.RSAParameters
    $params.Modulus = [byte[]]$der[33..288]
    $params.Exponent = [byte[]]$der[291..293]

    $rsa = New-Object System.Security.Cryptography.RSACng
    $rsa.ImportParameters($params)
    return $rsa
}

# ─── OpenSSL Fallback ────────────────────────────────────────────────────────
# Only needed when .NET RSA-PSS is unavailable (pre-.NET 4.6 / very old systems).
# Tries locally installed OpenSSL: system PATH → known install paths.

$script:OpensslFallbackPath = $null

function Get-OpensslBin {
    # 1. Already cached from a previous call this session
    if ($script:OpensslFallbackPath -and (Test-Path $script:OpensslFallbackPath)) {
        return $script:OpensslFallbackPath
    }

    # 2. System PATH (Git for Windows, manual install, etc.)
    $systemSsl = Get-Command openssl -ErrorAction SilentlyContinue
    if ($systemSsl) {
        Log-Debug "Found openssl on PATH: $($systemSsl.Source)"
        $script:OpensslFallbackPath = $systemSsl.Source
        return $script:OpensslFallbackPath
    }

    # 3. Common install locations
    $knownPaths = @(
        "C:\Program Files\Git\usr\bin\openssl.exe",
        "C:\Program Files\OpenSSL-Win64\bin\openssl.exe",
        "C:\Program Files (x86)\OpenSSL-Win32\bin\openssl.exe"
    )
    foreach ($p in $knownPaths) {
        if (Test-Path $p) {
            Log-Debug "Found openssl at known path: $p"
            $script:OpensslFallbackPath = $p
            return $p
        }
    }

    # 4. Nothing found locally
    Log-Error "OpenSSL not found (searched PATH and common install locations). Install it before retrying: Git for Windows (https://git-scm.com/download/win), winget (winget install ShiningLight.OpenSSL), or upgrade to PowerShell 7+ (https://aka.ms/powershell)."
    return $null
}

function Invoke-OpensslFallbackVerify {
    param(
        [string]$ManifestRaw,
        [string]$SignatureB64,
        [string]$PublicKeyPem
    )

    $opensslBin = Get-OpensslBin
    if (-not $opensslBin) { return $false }

    $canonicalFile = Join-Path ([IO.Path]::GetTempPath()) "sentinel_canonical_$PID.bin"
    $sigFile = Join-Path ([IO.Path]::GetTempPath()) "sentinel_sig_$PID.bin"
    $pubkeyFile = Join-Path ([IO.Path]::GetTempPath()) "sentinel_pubkey_$PID.pem"

    try {
        # Build canonical JSON
        $manifestObj = $ManifestRaw | ConvertFrom-Json
        $manifestObj.PSObject.Properties.Remove("manifest_signature")
        $sorted = [ordered]@{}
        $manifestObj.PSObject.Properties.Name | Sort-Object | ForEach-Object {
            $sorted[$_] = $manifestObj.$_
        }
        $canonicalJson = ($sorted | ConvertTo-Json -Depth 10 -Compress)
        # Use explicit UTF-8 without BOM -- WriteAllText's 2-arg overload adds BOM
        # on .NET Framework (PowerShell 5.1), which breaks signature verification.
        $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
        [IO.File]::WriteAllText($canonicalFile, $canonicalJson, $utf8NoBom)

        # Write signature and public key
        [IO.File]::WriteAllBytes($sigFile, [Convert]::FromBase64String($SignatureB64))
        Set-Content -Path $pubkeyFile -Value $PublicKeyPem -NoNewline

        # Verify
        $result = & $opensslBin dgst -sha256 `
            -sigopt rsa_padding_mode:pss `
            -sigopt rsa_pss_saltlen:-1 `
            -verify $pubkeyFile `
            -signature $sigFile `
            $canonicalFile 2>&1

        if ($LASTEXITCODE -eq 0 -and $result -match "Verified OK") {
            Log-Debug "Manifest signature verified (openssl fallback)"
            return $true
        }

        Log-Error "openssl verification failed: $result"
        return $false
    } catch {
        Log-Error "openssl fallback error: $_"
        return $false
    } finally {
        foreach ($_f in @($canonicalFile, $sigFile, $pubkeyFile)) {
            Remove-Quiet -Path $_f -Label "signature verification artefact"
        }
    }
}

function Get-VerifiedManifest {
    $archPath = Get-Architecture
    if (-not $archPath) { return $null }

    $manifestUrl = "$CdnBase/$archPath/update.json"
    Log-Info "Fetching manifest: $manifestUrl"

    $manifestFile = Join-Path ([IO.Path]::GetTempPath()) "sentinel_manifest_$PID.json"
    try {
        if (-not (Invoke-FetchUrl -Url $manifestUrl -OutFile $manifestFile -Timeout $ManifestTimeout)) {
            Log-Error "Failed to fetch manifest from CDN after $MaxRetries attempts"
            Log-Error "  Manifest URL: $manifestUrl"
            Log-Error "  Local dest:   $manifestFile"
            Log-Error "  Hint:         individual attempt errors were logged above; look for HTTP status / DNS / TLS cues."
            return $null
        }

        $manifestRaw = Get-Content $manifestFile -Raw
        try {
            $manifest = $manifestRaw | ConvertFrom-Json
        } catch {
            Log-Error "Manifest JSON parse failed: $($_.Exception.Message)"
            Log-Error "  URL:     $manifestUrl"
            Log-Error "  Preview: $($manifestRaw.Substring(0, [Math]::Min(200, $manifestRaw.Length)))"
            return $null
        }

        # -------------------------------------------------------------------
        # Verify RSA-PSS SHA-256 signature BEFORE trusting any field.
        #
        # Primary: .NET RSACng with manual DER key import (works on .NET Fw 4.6+,
        #          PowerShell 5.1+). Does NOT use ImportSubjectPublicKeyInfo()
        #          which only exists in .NET Core 3.0+.
        #
        # Fallback: OpenSSL CLI (system-installed).
        #
        # On all failing: hard fail with user-actionable error message.
        # -------------------------------------------------------------------
        # Verify manifest signature (skipped with -SkipSignatureCheck)
        $sigOk = $false
        if (-not $script:DoVerifySignatures) {
            Log-Warn "Signature verification disabled (use -VerifySignatures to enable)"
            $sigOk = $true
        } else {
            Log-Debug "Verifying manifest signature..."

            $sigB64 = $manifest.manifest_signature
            if (-not $sigB64) {
                Log-Error "Manifest missing 'manifest_signature' field"
                return $null
            }

            # Build canonical JSON: remove signature, sort keys, compact.
            try {
                $manifestObj = $manifestRaw | ConvertFrom-Json
            } catch {
                Log-Error "Manifest re-parse for signature canonicalisation failed: $($_.Exception.Message)"
                return $null
            }
            $manifestObj.PSObject.Properties.Remove("manifest_signature")
            $sorted = [ordered]@{}
            $manifestObj.PSObject.Properties.Name | Sort-Object | ForEach-Object {
                $sorted[$_] = $manifestObj.$_
            }
            $canonicalJson = ($sorted | ConvertTo-Json -Depth 10 -Compress)

            # Strategy: Try .NET RSACng (works on .NET Fw 4.6+ / PS 5.1+), fall back to OpenSSL.
            # NOTE: RSA.Create() returns RSACryptoServiceProvider on .NET Framework, which does NOT
            # support PSS padding or ImportSubjectPublicKeyInfo. We use RSACng explicitly instead.
            $rsa = $null
            # Track which verifier actually executed so the failure message can
            # distinguish "signature genuinely does not match" from "no verifier
            # was usable". Previously a clean .NET false-return incorrectly also
            # emitted the "was unavailable and no OpenSSL" error.
            $verifierRan = $false
            try {
                $rsa = Import-RsaPublicKeyFromPem $UpdaterPublicKey
                $dataBytes = [System.Text.Encoding]::UTF8.GetBytes($canonicalJson)
                $sigBytes = [Convert]::FromBase64String($sigB64)
                $hashAlg = [System.Security.Cryptography.HashAlgorithmName]::SHA256
                $padding = [System.Security.Cryptography.RSASignaturePadding]::Pss

                $sigOk = $rsa.VerifyData($dataBytes, $sigBytes, $hashAlg, $padding)
                $verifierRan = $true

                if ($sigOk) {
                    Log-Debug "Manifest signature verified (.NET RSACng RSA-PSS)"
                }
            } catch {
                # Expected on very old .NET (< 4.6) or unusual runtime configurations.
                # Not a bug -- log as informational and fall back to OpenSSL.
                Log-Info ".NET RSA-PSS not available (PowerShell $($PSVersionTable.PSVersion)) -- falling back to locally installed OpenSSL"
                Log-Debug "  .NET error: $_"
                $sigOk = Invoke-OpensslFallbackVerify -ManifestRaw $manifestRaw -SignatureB64 $sigB64 -PublicKeyPem $UpdaterPublicKey
                # Invoke-OpensslFallbackVerify returns $false both for "openssl
                # absent" and "openssl ran but signature bad". Distinguish via
                # $script:OpensslFallbackPath -- it is only set after Get-OpensslBin
                # actually locates an openssl binary.
                $verifierRan = [bool]$script:OpensslFallbackPath
            } finally {
                if ($rsa) { $rsa.Dispose() }
            }

            if (-not $sigOk) {
                if ($verifierRan) {
                    Log-Error "Manifest signature verification FAILED -- signature does not match the trusted updater public key."
                    Log-Error "  Manifest URL:     $ManifestUrl"
                    Log-Error "  Expected signer:  key paired with installer's embedded public key (see `$UpdaterPublicKey in sentinel-endpoint.ps1)"
                    Log-Error "  Hint: the update.json on CDN was regenerated with a different private key, or a field was edited after signing."
                    Log-Error "  Hint: re-run scripts/builder/generate_update_json.(sh|ps1) against the ZIP and re-upload."
                } else {
                    Log-Error "Manifest signature verification FAILED -- no usable verifier (.NET RSA-PSS unavailable and no openssl.exe on PATH)."
                    Log-Error "  Hint: install OpenSSL (https://slproweb.com/products/Win32OpenSSL.html) so this host can verify PSS signatures."
                    Log-Error "  Hint: or upgrade to PowerShell 5.1+ with .NET Framework 4.6+ for native RSA-PSS support."
                }
                return $null
            }
        }

        # Parse trusted fields (no download_url -- derived from CDN_BASE + version)
        $result = @{
            Version        = if ($manifest.version) { $manifest.version } else { "0.0.0" }
            ChecksumSha256 = if ($manifest.checksum_sha256) { $manifest.checksum_sha256 } else { "" }
            ForceUpdate    = if ($manifest.force_update -eq "true") { $true } else { $false }
        }

        Log-Info "Manifest verified: version=$($result.Version) checksum=$($result.ChecksumSha256.Substring(0, [Math]::Min(16, $result.ChecksumSha256.Length)))..."
        return $result

    } finally {
        Remove-Quiet -Path $manifestFile -Label "downloaded manifest"
    }
}

# ─── ZIP Verification ────────────────────────────────────────────────────────

function Test-Sha256 {
    param([string]$File, [string]$Expected)
    $actual = Get-Sha256Hash -FilePath $File
    if ($actual -ne $Expected.ToUpper()) {
        Log-Error "SHA-256 mismatch: expected=$Expected actual=$actual"
        return $false
    }
    Log-Debug "SHA-256 verified: $($actual.Substring(0, 16))..."
    return $true
}

function Test-ZipSafety {
    param([string]$ZipFile)
    # Add-Type throws "type already exists" when the assembly is loaded from a
    # prior call -- that IS the desired idempotent outcome, so the catch is
    # intentionally empty.  Any other failure surfaces via [IO.Compression]
    # below (NotFoundException with a clearer message than this probe).
    try { Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop } catch { }
    $zip = [IO.Compression.ZipFile]::OpenRead($ZipFile)
    try {
        foreach ($entry in $zip.Entries) {
            $name = $entry.FullName
            if ($name.StartsWith("/") -or $name.StartsWith("\") -or $name.Contains("..")) {
                Log-Error "ZIP contains dangerous path entry: $name"
                return $false
            }
        }
    } finally {
        $zip.Dispose()
    }
    Log-Debug "ZIP safety validation passed"
    return $true
}

function Test-Authenticode {
    param([string]$Dir)
    $binaries = Get-ChildItem -Path $Dir -Filter "*.exe" -Recurse
    $binaries += Get-ChildItem -Path $Dir -Filter "*.dll" -Recurse

    if ($binaries.Count -eq 0) {
        Log-Warn "No .exe/.dll binaries found in $Dir"
        return $false
    }

    foreach ($binary in $binaries) {
        $sig = Get-AuthenticodeSignature -FilePath $binary.FullName
        if ($sig.Status -ne "Valid") {
            Log-Error "Authenticode verification failed: $($binary.Name) (Status: $($sig.Status))"
            return $false
        }
        Log-Debug "Authenticode OK: $($binary.Name)"
    }
    return $true
}

# ─── Agent Start -- Via SCM ──────────────────────────────────────────────────

function Start-SentinelAgent {
    Log-Info "Starting agent..."

    try {
        Disable-IPv6
    } catch {
        Log-Exception -Label "Disable-IPv6 (Start-SentinelAgent)" -ErrorRecord $_ -Hints @(
            "CIM/WMI provider may be unavailable -- IPv6 state unchanged.",
            "Agent start will continue; re-run installer to retry IPv6 config."
        ) -Level "WARN"
    }

    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if (-not $svc) {
        Log-Error "Service $ServiceName not registered"
        Log-Error "  Was the agent installed with sentinel-endpoint.ps1?"
        throw "Service not found"
    }

    # Re-enable failure recovery (was disabled during stop)
    Invoke-Native -Label "sc.exe failure $ServiceName (configure recovery)" -FilePath "sc.exe" `
        -ArgumentList @("failure", $ServiceName, "reset=", "86400", "actions=", "restart/5000/restart/5000/restart/5000") `
        -Hints @("Configures SCM auto-restart: restart after 5s, 3 times, then reset counter after 24h.",
                 "If this fails, agent crashes won't auto-recover -- file a ticket.") | Out-Null
    Invoke-Native -Label "sc.exe failureflag $ServiceName 1" -FilePath "sc.exe" `
        -ArgumentList @("failureflag", $ServiceName, "1") `
        -Hints @("Triggers recovery on any process exit (not just crashes).") | Out-Null

    # Truncate agent logs so health check dump shows only this run's output
    foreach ($logName in @("agent.stdout.log", "agent.stderr.log")) {
        $logPath = Join-Path $ServiceLogDir $logName
        if (Test-Path $logPath) {
            Set-Content -Path $logPath -Value "" -ErrorAction SilentlyContinue
        }
    }

    # Single start attempt (matches installer pattern)
    try {
        Start-Service -Name $ServiceName -ErrorAction Stop -WarningAction SilentlyContinue
        Start-Sleep -Seconds 2

        # Verify the process actually appeared
        $procs = Get-Process -Name "sentinel" -ErrorAction SilentlyContinue
        if ($procs) {
            Log-Info "Agent service started (PID: $($procs[0].Id))"
            return
        }
        # Give it a bit more time
        Start-Sleep -Seconds 3
        $procs = Get-Process -Name "sentinel" -ErrorAction SilentlyContinue
        if ($procs) {
            Log-Info "Agent service started (PID: $($procs[0].Id))"
            return
        }
        Log-Error "Service started but agent process not found"
        # Dump the last few lines of the service log for immediate context
        $agentErr = Join-Path $ServiceLogDir "agent.stderr.log"
        if (Test-Path $agentErr) {
            Log-Error "  --- tail $agentErr ---"
            Get-Content -Path $agentErr -Tail 20 -ErrorAction SilentlyContinue | ForEach-Object {
                Log-Error "    $_"
            }
        }
        throw "Agent process not found after Start-Service"
    } catch {
        $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        Log-Exception -Label "Start-Service '$ServiceName'" -ErrorRecord $_ -Context @(
            "Service state: $(if ($svc) { $svc.Status } else { '<service not registered>' })",
            "StartType:     $(if ($svc) { $svc.StartType } else { 'n/a' })",
            "Exe path:      $(Join-Path $InstallDir 'sentinel.exe')"
        ) -Hints @(
            "Inspect service: Get-Service $ServiceName | Format-List *",
            "Event log:       Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Service Control Manager'} -MaxEvents 10",
            "Check agent log: Get-Content '$ServiceLogDir\agent.stderr.log' -Tail 50",
            "Binary may be missing/corrupt: Test-Path '$(Join-Path $InstallDir 'sentinel.exe')'"
        ) -Level "ERROR"
        throw "Agent start failed"
    }
}

# ─── Deploy -- Extract ZIP and place files ───────────────────────────────────

function Deploy-Package {
    param([string]$ExtractDir)

    # Windows: flat layout -- binaries and support files all in install dir
    if (-not (Test-Path $InstallDir)) {
        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    }

    # Detect our own filename so we can skip overwriting ourselves while running.
    # Use $selfPath (resolved in SELF-UPDATE section) -- handles both .ps1 and .exe.
    $selfName = if ($selfPath) { [IO.Path]::GetFileName($selfPath) } else { $null }

    # Copy everything from extract dir to install dir, skipping .rollback
    $copyFailed = $false
    foreach ($item in (Get-ChildItem -Path $ExtractDir)) {
        if ($item.Name -eq ".rollback") { continue }

        # Don't overwrite the running setup script -- stage as .new for next run
        if ($selfName -and $item.Name -eq $selfName) {
            $pendingDest = Join-Path $InstallDir "$($item.Name).new"
            try {
                Copy-Item -Path $item.FullName -Destination $pendingDest -Force -ErrorAction Stop
                Log-Info "Staged setup self-update: $($item.Name) -> $($item.Name).new"
            } catch {
                Log-Exception -Label "Stage self-update .new '$($item.Name)'" -ErrorRecord $_ -Context @(
                    "Source:      $($item.FullName)",
                    "Destination: $pendingDest"
                ) -Hints @(
                    "Self-update staging failed -- current updater version will be kept.",
                    "Deploy continues normally; the new updater will be staged on the next update tick."
                ) -Level "WARN"
            }
            continue
        }

        $dest = Join-Path $InstallDir $item.Name
        try {
            if ($item.PSIsContainer) {
                if (Test-Path $dest) {
                    Remove-Item -Path $dest -Recurse -Force
                }
                Copy-Item -Path $item.FullName -Destination $dest -Recurse
            } else {
                Copy-Item -Path $item.FullName -Destination $dest -Force
            }
        } catch {
            # Identify which process (if any) holds the handle -- turns the
            # opaque "file in use" into a named culprit we can kill.
            $holders = ""
            try {
                $h = Get-Process -ErrorAction SilentlyContinue | Where-Object {
                    $_.Modules | Where-Object { $_.FileName -like "$dest*" }
                } 2>$null
                if ($h) { $holders = ($h | ForEach-Object { "$($_.Name)(PID $($_.Id))" }) -join ', ' }
            } catch {
                # Get-Process .Modules enumeration throws AccessDenied on
                # processes we don't own; the empty $holders fall-through is
                # the intended behaviour -- log the reason so operators can
                # tell "no holders detected" from "we couldn't look".
                Log-Debug "Process-holder enumeration for '$dest' failed: $($_.Exception.Message)"
            }
            Log-Exception -Label "Copy-Item '$($item.Name)' -> InstallDir" -ErrorRecord $_ -Context @(
                "Source:       $($item.FullName)",
                "Destination:  $dest",
                "IsDirectory:  $($item.PSIsContainer)",
                "Dest exists:  $(Test-Path $dest)",
                $(if ($holders) { "Holding proc: $holders" } else { "Holding proc: <none detected>" })
            ) -Hints @(
                "File is likely locked by a running sentinel process -- Stop-Service + taskkill before retry.",
                "Antivirus real-time scanning can also hold handles briefly; a 2s sleep + retry often clears it.",
                "Manual: handle.exe -accepteula '$dest'  (Sysinternals)"
            ) -Level "ERROR"
            $copyFailed = $true
        }
    }
    if ($copyFailed) {
        throw "Deploy-Package: one or more files could not be copied to $InstallDir -- agent may have stale/missing binaries. See errors above."
    }
    Log-Info "Package deployed to $InstallDir"

    # Deploy hooks
    Deploy-HookBinaries -HooksDir (Join-Path $InstallDir "hooks") -DestDir $InstallDir
    Copy-HookScripts -Src (Join-Path $InstallDir "hooks\scripts") -Dest (Join-Path $SentinelUserDir "scripts")
}

# ─── Health Check -- Poll process liveness after start ───────────────────────

function Invoke-HealthCheck {
    Log-Info "Starting health check (${HealthCheckDuration}s monitoring window)"
    $deadline = (Get-Date).AddSeconds($HealthCheckDuration)

    while ((Get-Date) -lt $deadline) {
        $procs = Get-Process -Name "sentinel" -ErrorAction SilentlyContinue
        if (-not $procs) {
            $elapsed = $HealthCheckDuration - ($deadline - (Get-Date)).TotalSeconds
            Log-Error "Agent died during health check (after $([math]::Round($elapsed))s)"
            return $false
        }
        Start-Sleep -Seconds $HealthCheckInterval
    }

    # Final check -- agent process
    $procs = Get-Process -Name "sentinel" -ErrorAction SilentlyContinue
    if (-not $procs) {
        Log-Error "Agent not running at end of health check"
        return $false
    }

    # Log subsystem status (non-fatal -- agent may still be spawning them)
    $subsystems = @("sentinel-proxy", "ipc-light-broker", "template-engine", "sentinel-monitor-v2")
    foreach ($name in $subsystems) {
        $p = Get-Process -Name $name -ErrorAction SilentlyContinue
        if ($p) {
            Log-Info "  ${name}: running (PID $($p.Id))"
        } else {
            Log-Warn "  ${name}: not running"
        }
    }

    # Ensure IPv6 is still disabled (may have been re-enabled by OS or user)
    try {
        $ipv6Adapters = Get-NetAdapterBinding -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue | Where-Object { $_.Enabled }
        if ($ipv6Adapters) {
            Log-Warn "IPv6 re-enabled on $($ipv6Adapters.Count) adapter(s) -- disabling again"
            Disable-IPv6
        }
    } catch {
        Log-Exception -Label "Disable-IPv6 (Invoke-HealthCheck)" -ErrorRecord $_ -Hints @(
            "CIM/WMI provider may be unavailable -- IPv6 state unchanged.",
            "Health check result is unaffected; re-run installer to retry IPv6 config."
        ) -Level "WARN"
    }

    Log-Info "Health check passed - agent stable for ${HealthCheckDuration}s"
    return $true
}

# ─── Rollback -- Restore previous version from saved ZIP ─────────────────────

function Save-Rollback {
    param([string]$ZipPath)
    try {
        if (-not (Test-Path $RollbackDir)) {
            New-Item -ItemType Directory -Path $RollbackDir -Force -ErrorAction Stop | Out-Null
        }
        $currentVersion = Get-CurrentVersion
        Set-Content -Path (Join-Path $RollbackDir "version.txt") -Value $currentVersion -ErrorAction Stop
        Copy-Item -Path $ZipPath -Destination (Join-Path $RollbackDir "previous.zip") -Force -ErrorAction Stop
        Log-Info "Rollback saved: version=$currentVersion"
    } catch {
        Log-Exception -Label "Save-Rollback" -ErrorRecord $_ -Context @(
            "ZipPath:     $ZipPath",
            "RollbackDir: $RollbackDir"
        ) -Hints @(
            "Rollback save failed -- if this update fails, manual recovery will be required.",
            "Check disk space and ACL on $RollbackDir"
        ) -Level "WARN"
    }
}

function Invoke-Rollback {
    param([string]$FailedVersion)
    Log-Warn "ROLLING BACK from version $FailedVersion"

    $rollbackZip = Join-Path $RollbackDir "previous.zip"
    if (-not (Test-Path $rollbackZip)) {
        Log-Error "No rollback ZIP available."
        Log-Warn "Attempting to restart the agent with whatever binaries are currently on disk..."
        # Last resort: the old binaries might still be partially in place.
        try {
            Start-SentinelAgent
            Start-Sleep -Seconds 3
            $procs = Get-Process -Name "sentinel" -ErrorAction SilentlyContinue
            if ($procs) {
                Log-Info "Agent restarted from existing binaries (no rollback ZIP was needed)"
                # Failed version $FailedVersion is NOT blacklisted -- the next
                # update tick will try again, and Test-DownloadFailures bounds
                # the retry count if the same package keeps failing to deploy.
                return $true
            }
        } catch {
            # Start-SentinelAgent threw (service missing, SCM down).  The
            # "Could not restart" log below is the user-facing message;
            # capture the cmdlet reason separately for the post-mortem.
            Log-Warn "Start-SentinelAgent during rollback recovery failed: $($_.Exception.Message)"
        }
        Log-Error "Could not restart agent. Manual recovery required."
        return $false
    }

    $rollbackVersion = "unknown"
    $versionFile = Join-Path $RollbackDir "version.txt"
    if (Test-Path $versionFile) {
        $rollbackVersion = (Get-Content $versionFile).Trim()
    }
    Log-Info "Rolling back to version $rollbackVersion"

    # 1. Stop agent
    try {
        Stop-SentinelProcesses
    } catch {
        Log-Exception -Label "Stop-SentinelProcesses (during rollback)" -ErrorRecord $_ -Hints @(
            "Continuing with rollback anyway -- agent may already be dead.",
            "If files are locked downstream, retry loop will force-kill survivors."
        )
    }

    # 2. Extract rollback ZIP
    $rollbackTmp = Join-Path ([IO.Path]::GetTempPath()) "sentinel_rollback_$PID"
    if (-not (Test-ZipSafety -ZipFile $rollbackZip)) {
        Log-Error "ZIP safety check failed on rollback ZIP -- aborting rollback."
        return $false
    }
    try {
        Expand-Archive -Path $rollbackZip -DestinationPath $rollbackTmp -Force
    } catch {
        $zipInfo = if (Test-Path $rollbackZip) { Get-Item $rollbackZip } else { $null }
        Log-Exception -Label "Expand-Archive rollback ZIP" -ErrorRecord $_ -Context @(
            "ZIP path:  $rollbackZip",
            "ZIP size:  $(if ($zipInfo) { "$($zipInfo.Length) bytes" } else { '<missing>' })",
            "Dest tmp:  $rollbackTmp"
        ) -Hints @(
            "ZIP may be truncated -- retry the download that saved it.",
            "Verify with: Expand-Archive -Path '$rollbackZip' -DestinationPath <temp> -Force -Verbose",
            "Low disk on %TEMP% also manifests as this error."
        ) -Level "ERROR"
        return $false
    }

    # 3. Deploy old version (retry with force-kill if files still locked)
    $rollbackDeployed = $false
    for ($rAttempt = 1; $rAttempt -le 3; $rAttempt++) {
        try {
            Deploy-Package -ExtractDir $rollbackTmp
            $rollbackDeployed = $true
            break
        } catch {
            Log-Exception -Label "Rollback Deploy-Package (attempt $rAttempt/3)" -ErrorRecord $_ -Context @(
                "Source:  $rollbackTmp",
                "Target:  $InstallDir"
            ) -Hints @(
                $(if ($rAttempt -lt 3) { "Retrying in 3s after force-killing sentinel processes." } else { "Last attempt -- will try to start whatever is on disk." })
            )
            if ($rAttempt -lt 3) {
                $savedEAP = $ErrorActionPreference; $ErrorActionPreference = "SilentlyContinue"
                foreach ($p in $KillProcesses) {
                    Invoke-Native -Label "taskkill /F /IM $p" -FilePath "taskkill.exe" `
                        -ArgumentList @("/F", "/IM", $p) -AllowedExitCodes @(0, 128) `
                        -Hints @("exit 128 = process not running (benign).") | Out-Null
                }
                $ErrorActionPreference = $savedEAP
                Start-Sleep -Seconds 3
            }
        }
    }
    Remove-Quiet -Path $rollbackTmp -Recurse -Label "rollback staging dir"
    if (-not $rollbackDeployed) {
        Log-Error "Rollback Deploy-Package failed after 3 attempts -- install directory may be partially updated"
        Log-Error "  InstallDir: $InstallDir"
        Log-Error "  Hint: inspect with 'Get-ChildItem $InstallDir' and compare to 'previous.zip'"
        Log-Warn "Attempting to start agent with whatever binaries are currently on disk..."
        try { Start-SentinelAgent } catch {
            Log-Exception -Label "Start-SentinelAgent (last-resort after failed rollback)" -ErrorRecord $_
        }
        return $false
    }

    # 4. Start agent
    try {
        Start-SentinelAgent
    } catch {
        Log-Exception -Label "Start-SentinelAgent (POST-ROLLBACK)" -ErrorRecord $_ -Context @(
            "Rolled-back version: $rollbackVersion",
            "Failed version:      $FailedVersion"
        ) -Hints @(
            "CRITICAL: rollback deployed but the previous binaries won't start either.",
            "Manual recovery: Stop-Service $ServiceName; re-run installer with a known-good ZIP.",
            "Check: Get-WinEvent -LogName System -MaxEvents 20 | Where-Object { `$_.ProviderName -eq 'Service Control Manager' }"
        ) -Level "ERROR"
        return $false
    }

    # 5. Restore the PRIOR updater binary too.  If the update that failed was
    # delivered by a new updater binary (self-propagating rollout), the
    # new updater is still on disk and will run next tick -- and may
    # re-push the same broken agent package.  Swapping back to
    # .backup.prev breaks that loop.  No-op if .backup.prev doesn't
    # exist yet (first self-update with dual-backup in place).
    if ($selfPath) {
        $prevUpdater = "$selfPath.backup.prev"
        if (Test-Path -LiteralPath $prevUpdater) {
            try {
                # Stage as .new so the self-update pre-block on the NEXT tick
                # performs the swap+smoke-test cleanly (instead of us racing
                # with our own currently-running binary file handle here).
                $stageAs = "$selfPath.new"
                Copy-Item -LiteralPath $prevUpdater -Destination $stageAs -Force -ErrorAction Stop
                Log-Warn "Staged prior updater ($prevUpdater) as $stageAs -- will swap on next tick"
            } catch {
                Log-Exception -Label "Stage prior updater for rollback" -ErrorRecord $_ -Hints @(
                    "The NEW updater will run again next tick and may re-push the failed package.",
                    "Manual recovery: Copy-Item '$prevUpdater' '$selfPath' -Force"
                )
            }
        } else {
            Log-Info "No .backup.prev updater to restore -- current updater stays in place (first dual-backup cycle)."
        }
    }

    Log-Info "Rollback complete - restored version $rollbackVersion"
    Log-Info "Note: failed version $FailedVersion is NOT blacklisted; retry bounding is via Test-DownloadFailures only."
    return $true
}

# Retry model: none.  Every tick runs the full update pipeline (manifest ->
# download -> verify -> deploy).  On rollback we just log and exit; the
# next tick repeats.  No per-version counters, no quarantine file, no
# .last_downloaded_checksum skip, no state.conf.
#
# Why: failures in the post-swap phase can be environmental (AV scanning
# at that moment, kernel-extension approval mid-flight, Windows Update
# holding SCM locks, disk momentarily full) -- not about the bytes.  Any
# time-based skip either delays env recoveries or, if too aggressive,
# bounces the service on persistent releases.  The env case is invisible
# to the operator; the persistent-release case is visible and short-lived
# (operator yanks it).  So we bias toward catching env recoveries, which
# means always retrying.  On a persistently broken release the device
# bounces every tick (~48/day) until the operator yanks -- acceptable
# because that case is rare and visible.
#
# Test-NewerVersion handles the "already up-to-date" healthy-skip.
# Remove-LegacyBlocklists wipes any stale .quarantined_version /
# .download_failed_* / .last_downloaded_checksum from prior installer
# versions on first upgrade.

# (Retry-state helpers removed -- see comment at the $MaxRetries constant
# for the "always retry" rationale.  Test-NewerVersion covers the healthy-
# skip case; Remove-LegacyBlocklists wipes any stale markers from older
# installer versions.)

# ─── Dump Agent Logs ─────────────────────────────────────────────────────────

function Write-AgentLogDump {
    param([string]$Label = "")
    $prefix = if ($Label) { "[$Label] " } else { "" }

    foreach ($logName in @("agent.stdout.log", "agent.stderr.log")) {
        $logPath = Join-Path $ServiceLogDir $logName
        if (-not (Test-Path $logPath)) { continue }
        $lines = Get-Content $logPath -Tail 50 -ErrorAction SilentlyContinue
        if (-not $lines) { continue }
        Log-Info "${prefix}--- $logName (last 50 lines) ---"
        foreach ($line in $lines) {
            Log-Info "${prefix}  $line"
        }
        Log-Info "${prefix}--- end $logName ---"
    }
}

# ─── Update Mode Entry Point ─────────────────────────────────────────────────

function Invoke-Update {
    $modeLabel = if ($script:IsCdnFreshInstall) { "Install (CDN)" } else { "Update" }
    Log-Info "=========================================="
    Log-Info "Quilr Sentinel Endpoint Agent v$SetupVersion -- $modeLabel"
    Log-Info "Env:       $Env"
    Log-Info "=========================================="
    # Identify trigger source so scheduled-task ticks are distinguishable
    # from manual invocations in the log.
    $script:_isScheduledTick = -not $ZipPath -and -not $Local -and -not $script:IsCdnFreshInstall
    Log-Info "Trigger:   $(if ($script:_isScheduledTick) { "Scheduled task auto-update ($UpdaterTaskName)" } else { "Manual invocation" })"
    Log-Info "RunAs:     $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)"
    Log-Environment

    # Env transition: loud panel BEFORE the checking line so operator sees
    # their explicit -Env is causing a change.  Service + schedule will be
    # re-registered with the new env as a normal part of the update flow.
    if ($script:EnvTransition) {
        Show-CliEnvTransition -From $script:EnvTransition.From -To $script:EnvTransition.To
        Log-Warn "Env transition on update: $($script:EnvTransition.From) -> $($script:EnvTransition.To)"
    }

    # ── CLI banner + Phase 1 OPEN BEFORE network fetch ────────────────────
    # Mirrors mac's structure: Phase 1 "Acquire and verify package" spans
    # manifest fetch + download + stage + verify.  Closing it here (vs. the
    # old post-staging location) means:
    #   - Silent CDN failures (DNS / cert / timeout) no longer exit 1 with
    #     ZERO CLI feedback -- the phase is open, so End-PhaseFail fires.
    #   - Noop paths (already up-to-date, conditional-skip, prior download failures)
    #     close the phase via Show-CliNoOp's phase-clear side effect.
    $bannerTitle = if ($script:IsCdnFreshInstall) { "Installing (CDN fresh install)" } else { "Updating agent" }
    $bannerSub   = "v$SetupVersion  -  Env: $Env"
    Show-CliBanner -Title "Quilr Sentinel Endpoint Agent" -Subtitles @($bannerTitle, $bannerSub)
    Start-CliFlow -TotalSteps 5

    Start-Phase "Acquire and verify package"
    if (-not $script:IsCdnFreshInstall) {
        Show-CliChecking "Checking for updates... (Env: $Env)"
    } else {
        Show-CliChecking "Downloading fresh install from CDN... (Env: $Env)"
    }

    # ── Step 0: Acquire lock ──────────────────────────────────────────────
    Get-UpdateLock

    # ── Step 0.05: Refresh tenant_id file when -TenantId passed (MDM redeploy) ──
    # Update mode never prompts; existing file is preserved when no arg given.
    if ($TenantId) {
        $trimmed = $TenantId.Trim()
        if ($trimmed) {
            Log-Info "Update: refreshing tenant_id file (fp=$(Get-TenantIdFingerprint $trimmed))"
            Write-TenantIdFile -Value $trimmed
        }
    }

    # ── Step 0.1: Self-heal pipeline ─────────────────────────────────────
    # The updater running right now is our one chance to fix the pipeline
    # when something external broke it: scheduled task got unregistered,
    # on-disk binary got AV-quarantined, lock got stuck on a recycled PID,
    # legacy .quarantined_version file blocks retries.  All idempotent,
    # all cheap (no subprocess probes) -- safe on every tick.
    Test-SelfBinaryHealth
    Assert-UpdaterScheduleRegistered
    Remove-LegacyBlocklists
    Remove-StaleUpdaterBackups

    # Ensure lock is released on exit
    try {

    # ── Step 1: Verify agent is installed ─────────────────────────────────
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    $binExists = Test-Path (Join-Path $InstallDir "sentinel.exe")
    if (-not $svc -or -not $binExists) {
        # Agent is NOT installed -- fall back to install mode if a ZIP is available
        Log-Warn "Agent is not fully installed (service=$(if ($svc) {'yes'} else {'no'}), binary=$(if ($binExists) {'yes'} else {'no'}))"
        if ($Local) {
            Log-Info "Falling back to install mode with local ZIP: $Local"
            $resolvedLocal = (Resolve-Path $Local -ErrorAction SilentlyContinue).Path
            if (-not $resolvedLocal -or -not (Test-Path $resolvedLocal)) {
                Log-Error "Local ZIP not found: $Local"
                End-PhaseFail -Reason "local ZIP not found (fallback install): $Local"
                exit 1
            }
            # Close Phase 1 silently -- Invoke-Install opens its OWN banner
            # + 7-phase flow.  Two "Acquire and verify package" markers
            # would confuse the step counter.
            $script:_CurrentPhase = $null
            Invoke-Install -ResolvedZip $resolvedLocal
            exit 0
        } elseif ($ZipPath) {
            Log-Info "Falling back to install mode with provided ZIP"
            $resolvedZip = Resolve-ZipPath -Provided $ZipPath
            $script:_CurrentPhase = $null  # See note above.
            Invoke-Install -ResolvedZip $resolvedZip
            exit 0
        } else {
            # No ZIP provided -- attempt CDN fresh install. Functionally a fresh
            # install, so apply the same fail-early tenant gate before any
            # network work happens.
            Log-Info "No ZIP provided. Attempting CDN download for fresh install..."
            $script:IsCdnFreshInstall = $true
            $script:CollectedTenantId = Collect-TenantId
            Write-TenantIdFile -Value $script:CollectedTenantId
            # Let the update flow handle CDN download; it will download and deploy
        }
    }
    Log-Info "Agent installed - checking for updates"

    # -ZipPath in update mode = implicit -Local + -Force (matches shell installer).
    if ($ZipPath -and -not $Local) {
        $resolvedZipEarly = Resolve-ZipPath -Provided $ZipPath
        if (-not $resolvedZipEarly -or -not (Test-Path $resolvedZipEarly)) {
            Log-Error "-ZipPath could not be resolved or does not exist: $ZipPath"
            End-PhaseFail -Reason "-ZipPath not found: $ZipPath"
            exit 1
        }
        Log-Info "-ZipPath treated as --local + --force: $resolvedZipEarly"
        $Local = $resolvedZipEarly
        $Force = $true
    }

    Log-Info "Flags: force=$Force | dry-run=$DryRun | local=$(if ($Local) { $Local } else { 'no' })"

    # ── Step 1.5: Re-assert IPv6 disable ─────────────────────────────────
    # Runs on every scheduled tick, BEFORE the "already up-to-date" early-exits
    # below. Recovery path for:
    #   (a) previous install/update didn't fully disable IPv6 (e.g. one
    #       Disable-NetAdapterBinding call failed, leaving a gap).
    #   (b) user manually re-enabled IPv6 via Network Connections UI.
    #   (c) a new adapter (VPN client, USB tether, Hyper-V) plugged in with
    #       IPv6 still enabled since the last tick.
    # Idempotent -- if everything is already off, it logs a no-op summary
    # and returns quickly.
    if (-not $DryRun) {
        try { Ensure-IPv6Disabled } catch {
            Log-Exception -Label "Ensure-IPv6Disabled (scheduled tick)" -ErrorRecord $_ -Hints @(
                "Non-fatal -- update check continues. Next tick will retry the re-assert."
            )
        }
        # Network snapshot used to run here on every tick.  Removed: it is a
        # diagnostic-only tool and ran 6-10s of pings/curls/CIM queries on
        # every no-op "already-up-to-date" tick.  Now only runs post-install
        # and post-update -- i.e. when something actually changed.
    }

    # Jitter removed: previously slept 0-300s before each scheduled update
    # check, which is invisible-to-the-user dead time.  With a 30-minute
    # scheduler interval and a tiny CDN (update.json is ~500B + one HEAD),
    # load-spreading jitter is not needed.

    # ── Step: Read current version ────────────────────────────────────────
    $currentVersion = Get-CurrentVersion
    Log-Info "Current version: $currentVersion"

    # ── Step 4: Fetch + verify manifest (or use local ZIP) ────────────────
    $zipPath_ = ""
    $remoteVersion = ""
    $checksumSha256 = ""

    if ($Local) {
        # Local ZIP mode -- skip CDN, use a builder-produced ZIP directly
        $zipPath_ = (Resolve-Path $Local -ErrorAction SilentlyContinue).Path
        if (-not $zipPath_ -or -not (Test-Path $zipPath_)) {
            Log-Error "Local ZIP not found: $Local"
            End-PhaseFail -Reason "local ZIP not found: $Local"
            exit 1
        }
        Log-Info "Using local ZIP: $zipPath_"

        # Try to extract version from the ZIP's manifest.xml for proper comparison.
        $remoteVersion = "local"
        $peekDir = Join-Path ([IO.Path]::GetTempPath()) "sentinel_peek_$PID"
        try {
            # Add-Type throws "type already exists" when the assembly is loaded from a
    # prior call -- that IS the desired idempotent outcome, so the catch is
    # intentionally empty.  Any other failure surfaces via [IO.Compression]
    # below (NotFoundException with a clearer message than this probe).
    try { Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop } catch { }
            $zip = [IO.Compression.ZipFile]::OpenRead($zipPath_)
            try {
                $manifestEntry = $zip.Entries | Where-Object { $_.Name -eq "manifest.xml" } | Select-Object -First 1
                if ($manifestEntry) {
                    New-Item -ItemType Directory -Path $peekDir -Force | Out-Null
                    $peekFile = Join-Path $peekDir "manifest.xml"
                    [IO.Compression.ZipFileExtensions]::ExtractToFile($manifestEntry, $peekFile, $true)
                    [xml]$xml = Get-Content $peekFile
                    $ver = $xml.SelectSingleNode("//version")
                    if ($ver) {
                        $remoteVersion = $ver.InnerText.Trim()
                        Log-Info "ZIP contains version: $remoteVersion"
                    }
                }
            } finally {
                $zip.Dispose()
            }
        } catch {
            Log-Debug "Could not extract version from ZIP: $_"
        }
        Remove-Quiet -Path $peekDir -Recurse -Label "ZIP peek dir"

        # Fallback: extract version from ZIP filename
        if ($remoteVersion -eq "local") {
            $zipName = [IO.Path]::GetFileName($zipPath_)
            if ($zipName -match '_v(\d+\.\d+\.\d+)_') {
                $remoteVersion = $Matches[1]
                Log-Info "Version extracted from filename: $remoteVersion"
            }
        }

        # Version comparison for local ZIP (unless -Force)
        if (-not $Force -and $remoteVersion -ne "local") {
            if (-not (Test-NewerVersion -Remote $remoteVersion -Current $currentVersion)) {
                Log-Info "Already up-to-date (current=$currentVersion, local ZIP=$remoteVersion)"
                Log-Info "Nothing to do. Use -Force to re-deploy anyway."
                Show-CliNoOp "Already up-to-date" `
                    "Installed: v$currentVersion  |  Local ZIP: v$remoteVersion  |  Use -Force to re-deploy"
                exit 0
            }
            Log-Info "Local ZIP is newer: $currentVersion -> $remoteVersion"
        } elseif ($remoteVersion -eq "local") {
            Log-Info "No manifest.xml in ZIP - cannot compare versions, proceeding with deploy"
        }
    } else {
        # CDN mode -- fetch and verify manifest
        $manifest = Get-VerifiedManifest
        if (-not $manifest) {
            Log-Error "Manifest fetch/verify failed"
            # Phase 1 ("Acquire and verify package") was opened at the top
            # of Invoke-Update; close it loudly so the operator sees the
            # fail banner with the last 30 log lines instead of a silent
            # exit 1 after 90s of DNS/cert retries.
            End-PhaseFail -Reason "CDN manifest fetch/verify failed (see log for network detail)"
            exit 1
        }

        $remoteVersion = $manifest.Version
        $checksumSha256 = $manifest.ChecksumSha256
        $forceUpdate = $Force -or $manifest.ForceUpdate
        Log-Info "Version check: local=$currentVersion | CDN=$remoteVersion | force=$forceUpdate"

        # ── Step 5: Pre-flight checks ──────────────────────────────────
        # -Force bypasses version-comparison + download-failure checks but NEVER bypasses:
        #   - Manifest signature verification (always)
        #   - SHA-256 hash verification (always)
        #   - ZIP path traversal validation (always)
        #   - Authenticode signature verification (always)
        #   - Hard version floor (always)

        # 5a. Version comparison
        if (-not $forceUpdate -and -not (Test-NewerVersion -Remote $remoteVersion -Current $currentVersion)) {
            Log-Info "Already up-to-date (current=$currentVersion, remote=$remoteVersion)"
            Show-CliNoOp "Already up-to-date" `
                "Installed: v$currentVersion  |  CDN: v$remoteVersion  |  Env: $Env"
            exit 0
        }

        # 5b. Hard version floor
        if (-not (Test-AboveFloor -Version $remoteVersion -Floor $MinSafeVersion)) {
            Log-Error "Version $remoteVersion is below hard floor $MinSafeVersion - blocked"
            End-PhaseFail -Reason "remote v$remoteVersion is below hard floor v$MinSafeVersion (CDN downgrade attempt?)"
            exit 1
        }

        # (5c) No retry-state skip.  Every tick runs the full pipeline;
        # on rollback we log and exit, the next tick repeats.  See the
        # "retry model: none" comment block near the $MaxRetries constant
        # for why.

        # ── Step 6: Disk space check ──────────────────────────────────
        try {
            $driveLetter = (Split-Path $InstallDir -Qualifier) -replace ":",""
            $freeMB = [math]::Floor((Get-PSDrive $driveLetter -ErrorAction Stop).Free / 1MB)
            if ($freeMB -lt $MinDiskMB) {
                Log-Error "Insufficient disk space: ${freeMB}MB free, need ${MinDiskMB}MB"
                End-PhaseFail -Reason "insufficient disk space: ${freeMB}MB free, need ${MinDiskMB}MB"
                exit 1
            }
            Log-Debug "Disk space OK: ${freeMB}MB free"
        } catch {
            Log-Warn "Could not check disk space (proceeding anyway): $_"
        }

        # ── Step 7: Download ZIP ──────────────────────────────────────
        $tmpDir = Join-Path ([IO.Path]::GetTempPath()) "sentinel_update_$PID"
        New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null
        $zipPath_ = Join-Path $tmpDir "package.zip"

        # Construct download URL from CDN_BASE + version (no download_url in manifest)
        $downloadUrl = Get-DownloadUrl -Version $remoteVersion
        Log-Info "Downloading: $downloadUrl"
        Show-CliChecking "Downloading v$remoteVersion package..."
        if (-not (Invoke-FetchUrl -Url $downloadUrl -OutFile $zipPath_ -Timeout $ZipTimeout)) {
            # Download failure is transient (network, CDN edge).  No state
            # write -- the next tick retries naturally without any skip.
            Remove-Quiet -Path $tmpDir -Recurse -Label "tmp extract dir"
            Log-Error "ZIP download failed"
            End-PhaseFail -Reason "ZIP download failed after retries (see log for network detail)"
            exit 1
        }

        # ── Step 8: Verify ZIP integrity (skipped with -SkipSignatureCheck) ──
        if ($checksumSha256 -and $script:DoVerifySignatures) {
            if (-not (Test-Sha256 -File $zipPath_ -Expected $checksumSha256)) {
                # SHA mismatch is a CDN-side bug (truncation, corruption,
                # wrong manifest).  Operator fix is upstream; no state
                # write -- the next tick retries once CDN is consistent.
                Remove-Quiet -Path $tmpDir -Recurse -Label "tmp extract dir"
                End-PhaseFail -Reason "SHA-256 mismatch on downloaded ZIP (manifest vs actual)"
                exit 1
            }
        } elseif ($checksumSha256) {
            Log-Warn "Skipping SHA-256 verification (use -VerifySignatures to enable)"
        }
    }

    # =================================================================
    # STAGING PHASE -- Everything below happens BEFORE the agent is stopped.
    # The current agent keeps running while we verify the new package.
    # Only after ALL checks pass do we stop -> swap -> start.
    # =================================================================
    # NOTE: banner + Phase 1 "Acquire and verify package" was opened at the
    # top of Invoke-Update, not here.  This lets silent CDN failures and
    # noop early-exits close the phase cleanly.  The phase is still named
    # "Acquire and verify package" (mac parity) and covers manifest fetch +
    # download + staging extraction + binary verification all the way to
    # "Staged package verified - safe to deploy".

    # ── Step 9: Extract to staging dir (ONE extraction for verify + deploy) ──
    $stagingDir = Join-Path ([IO.Path]::GetTempPath()) "sentinel_staging_$PID"
    Log-Info "Extracting package to staging area..."
    if (-not (Test-ZipSafety -ZipFile $zipPath_)) {
        Log-Error "ZIP safety check failed on update package -- aborting."
        End-PhaseFail -Reason "ZIP failed safety check (path traversal detected)"
        exit 1
    }
    try {
        Expand-Archive -Path $zipPath_ -DestinationPath $stagingDir -Force
    } catch {
        $zipInfo = if (Test-Path $zipPath_) { Get-Item $zipPath_ } else { $null }
        Log-Exception -Label "Expand-Archive incoming ZIP" -ErrorRecord $_ -Context @(
            "ZIP path:   $zipPath_",
            "ZIP size:   $(if ($zipInfo) { "$($zipInfo.Length) bytes" } else { '<missing>' })",
            "Staging:    $stagingDir",
            "Free %TEMP%: $([math]::Round((Get-PSDrive ([IO.Path]::GetTempPath().Substring(0,1))).Free / 1MB, 1)) MB"
        ) -Hints @(
            "ZIP is likely truncated (partial download) or not a ZIP at all.",
            "Compare SHA-256: Get-FileHash '$zipPath_' -Algorithm SHA256",
            "Low disk on %TEMP% is another common cause.",
            "If this is a self-built ZIP, try re-running the builder."
        ) -Level "ERROR"
        End-PhaseFail -Reason "Expand-Archive: $($_.Exception.Message)"
        exit 1
    }

    # ── Step 10: Verify package contents (BEFORE touching current install) ──
    Log-Info "Verifying staged package..."

    # Verify required binaries are present
    $requiredBins = @("sentinel.exe", "sentinel-proxy.exe", "template-engine.exe", "sentinel-monitor-v2.exe")
    foreach ($bin in $requiredBins) {
        $binPath = Join-Path $stagingDir $bin
        if (-not (Test-Path $binPath)) {
            $binPath = Get-ChildItem -Path $stagingDir -Recurse -Filter $bin -ErrorAction SilentlyContinue | Select-Object -First 1
        }
        if (-not $binPath -or -not (Test-Path $binPath)) {
            Log-Error "INVALID PACKAGE: required binary '$bin' not found in staged package"
            Remove-Quiet -Path $stagingDir -Recurse -Label "staging dir"
            End-PhaseFail -Reason "required binary '$bin' missing from staged package"
            exit 1
        }
        Log-Info "  Binary OK: $bin"
    }

    # Verify Authenticode signatures (only when -VerifyAuthenticode is set)
    # Windows binaries are not code-signed yet -- enable once signing pipeline is in place.
    if (-not $script:DoVerifyAuthenticode) {
        Log-Info "  Authenticode verification skipped (use -VerifyAuthenticode to enable)"
    } elseif (-not (Test-Authenticode -Dir $stagingDir)) {
        Log-Error "Code signature verification FAILED on staged package"
        Remove-Quiet -Path $stagingDir -Recurse -Label "staging dir"
        End-PhaseFail -Reason "Authenticode verification failed"
        exit 1
    } else {
        Log-Info "  Code signatures verified"
    }

    Log-Info "Staged package verified - safe to deploy"
    End-PhaseOk -Detail "v$remoteVersion"

    # ── DRY-RUN STOPS HERE ────────────────────────────────────────────
    if ($DryRun) {
        Log-Info "DRY RUN complete - would update from $currentVersion to $remoteVersion"
        Log-Info "  Package is valid and signed."
        Remove-Quiet -Path $stagingDir -Recurse -Label "staging dir"
        # Close the remaining phases as skipped so the step counter stays honest
        Start-Phase "Stop agent";                      End-PhaseSkip -Reason "dry-run"
        Start-Phase "Deploy new version";              End-PhaseSkip -Reason "dry-run"
        Start-Phase "Refresh service and schedule";    End-PhaseSkip -Reason "dry-run"
        Start-Phase "Start agent and health check";    End-PhaseSkip -Reason "dry-run"
        Show-CliSuccess -Title "Dry run complete" -Lines @(
            "Would update: $currentVersion -> $remoteVersion",
            "Package is valid and signed"
        )
        exit 0
    }

    # =================================================================
    # SWAP PHASE -- Agent goes down for minimum time.
    # Staging is verified. We stop -> copy from staging -> start.
    # =================================================================

    # ── Step 12: Save rollback ────────────────────────────────────────
    $lastDownloaded = Join-Path $InstallDir ".last_downloaded.zip"
    if (Test-Path $lastDownloaded) {
        # Normal case: save the previous version as rollback
        Save-Rollback -ZipPath $lastDownloaded
        Log-Info "Previous version saved as rollback"
    } elseif (Test-Path (Join-Path $RollbackDir "previous.zip")) {
        Log-Info "Keeping existing rollback"
    } else {
        # First update ever -- save the INCOMING zip as rollback (verified, better than nothing)
        Log-Info "First update - no previous ZIP. Saving incoming ZIP as initial rollback."
        try {
            if (-not (Test-Path $RollbackDir)) {
                New-Item -ItemType Directory -Path $RollbackDir -Force -ErrorAction Stop | Out-Null
            }
            Copy-Item -Path $zipPath_ -Destination (Join-Path $RollbackDir "previous.zip") -Force -ErrorAction Stop
            Set-Content -Path (Join-Path $RollbackDir "version.txt") -Value $currentVersion -ErrorAction Stop
        } catch {
            Log-Exception -Label "Save first-update rollback" -ErrorRecord $_ -Context @(
                "ZipPath:     $zipPath_",
                "RollbackDir: $RollbackDir"
            ) -Hints @(
                "First-update rollback save failed -- update will continue but rollback will be unavailable if it fails.",
                "Check disk space and ACL on $RollbackDir"
            ) -Level "WARN"
        }
    }

    # Save new ZIP for next cycle's rollback.  (Separate checksum marker
    # removed -- the "skip if unchanged since last download" mechanism is
    # gone; version-comparison via Test-NewerVersion already handles the
    # healthy-skip case and fingerprint matching handles the failed case.)
    try {
        Copy-Item -Path $zipPath_ -Destination $lastDownloaded -Force -ErrorAction Stop
    } catch {
        Log-Exception -Label "Save .last_downloaded.zip" -ErrorRecord $_ -Context @(
            "Source: $zipPath_",
            "Dest:   $lastDownloaded"
        ) -Hints @(
            "Update will continue -- next cycle's rollback will be unavailable if this copy is missing.",
            "Check disk space and ACL on $InstallDir"
        ) -Level "WARN"
    }

    # ── Phase 2/5: Stop agent ─────────────────────────────────────────────
    Start-Phase "Stop agent"
    # ── Step 13: Stop agent ───────────────────────────────────────────
    Log-Info "All pre-deploy checks passed. Stopping agent for swap..."
    try {
        Stop-SentinelProcesses
    } catch {
        Log-Exception -Label "Stop-SentinelProcesses (pre-deploy)" -ErrorRecord $_ -Context @(
            "Service: $ServiceName"
        ) -Hints @(
            "Update aborted -- leaving current agent running untouched.",
            "Staging dir will be cleaned up: $stagingDir",
            "If the service refuses to stop, try: Stop-Service $ServiceName -Force; taskkill /F /IM sentinel.exe"
        ) -Level "ERROR"
        Remove-Quiet -Path $stagingDir -Recurse -Label "staging dir"
        End-PhaseFail -Reason "Stop-SentinelProcesses: $($_.Exception.Message)"
        exit 1
    }
    End-PhaseOk

    # ── Phase 3/5: Deploy new version ─────────────────────────────────────
    Start-Phase "Deploy new version"

    # Snapshot pre-update CA thumbprints so we can clean up after Set-SentinelCaTrust.
    # Covers three rotation cases without per-case special handling:
    #   (a) Legacy single-cert install -> strict-mode (root + intermediate):
    #         old cert.pem was in CurrentUser\Root; remove it after new root is trusted.
    #   (b) Strict -> strict with *intermediate* rotated (root stable):
    #         old cert.pem was in CurrentUser\CA; remove it after new intermediate is trusted.
    #   (c) Strict -> strict with *root* rotated (rare):
    #         old root.pem was in CurrentUser\Root; remove after new root trusted.
    # Future intermediate recycle: ship a new cert.pem in the next build. Nothing
    # else to do -- this snapshot/diff loop auto-removes the stale trust.
    $script:PreUpdateCaThumbs = New-Object 'System.Collections.Generic.List[string]'
    foreach ($pem in @("cert.pem", "root.pem")) {
        $path = Join-Path $InstallDir $pem
        if (Test-Path $path) {
            try {
                $tp = (New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $path).Thumbprint
                if ($tp) { [void]$script:PreUpdateCaThumbs.Add($tp) }
            } catch {
                Log-Debug "Could not read pre-update $pem thumbprint (rotation cleanup may miss this cert): $($_.Exception.Message)"
            }
        }
    }

    # ── Step 14: Deploy from staging (no re-extraction needed) ────────
    $maxDeployRetries = 3
    $deployOk = $false
    for ($dAttempt = 1; $dAttempt -le $maxDeployRetries; $dAttempt++) {
        Start-Sleep -Seconds 2
        try {
            Deploy-Package -ExtractDir $stagingDir
            $deployOk = $true
            break
        } catch {
            Log-Exception -Label "Deploy-Package (attempt $dAttempt/$maxDeployRetries)" -ErrorRecord $_ -Context @(
                "Source:  $stagingDir",
                "Target:  $InstallDir"
            ) -Hints @(
                $(if ($dAttempt -lt $maxDeployRetries) { "Will force-kill sentinel processes and retry." } else { "Last attempt -- will trigger rollback." })
            )
            if ($dAttempt -lt $maxDeployRetries) {
                Log-Warn "Force-killing any remaining sentinel processes before retry..."
                foreach ($p in $KillProcesses) {
                    Invoke-Native -Label "taskkill /F /IM $p (deploy retry)" -FilePath "taskkill.exe" `
                        -ArgumentList @("/F", "/IM", $p) -AllowedExitCodes @(0, 128) `
                        -Hints @("exit 128 = already dead (benign).") | Out-Null
                }
                Start-Sleep -Seconds 3
            }
        }
    }
    if (-not $deployOk) {
        Log-Error "Deploy failed after $maxDeployRetries attempts - attempting rollback"
        Remove-Quiet -Path $stagingDir -Recurse -Label "staging dir"
        Invoke-Rollback -FailedVersion $remoteVersion | Out-Null
        End-PhaseFail -Reason "deploy failed after $maxDeployRetries attempts; rolled back"
        exit 1
    }
    Remove-Quiet -Path $stagingDir -Recurse -Label "staging dir"

    End-PhaseOk -Detail "v$currentVersion $($script:_GlyphH)$($script:_GlyphH) v$remoteVersion"
    # NOTE: version marker (.installed_version) intentionally written AFTER health check -- see below.
    # Old approach (kept for reference -- DO NOT RESTORE: writing here means a failed health check +
    # rollback leaves the marker at the new version; next CDN tick sees "already up to date" and
    # never retries, leaving the broken version permanently installed):
    # Set-Content -Path (Join-Path $InstallDir ".installed_version") -Value $remoteVersion
    # Log-Debug "Wrote version marker: $remoteVersion"

    # Re-trust the MITM CA chain -- the update may have replaced root.pem /
    # cert.pem with new fingerprints, invalidating old trust entries. Under
    # SYSTEM (scheduled-tick updater), Cert:\CurrentUser\... resolves to SYSTEM's
    # own stores -- writing there is useless for the interactive user, and the
    # attempt previously produced a spurious top-level error. The interactive
    # user's stores were populated during initial install and stay trusted by
    # thumbprint; a new thumbprint on update requires the user (or an admin) to
    # re-run the installer interactively. The CA bundle, however, IS rebuilt
    # under SYSTEM because Node-based clients read it as a file regardless.
    if (Is-RunningAsSystem) {
        Log-Debug "Skipping certificate re-trust: running as SYSTEM (interactive user's stores are not reachable)"
    } else {
        if ((Test-Path (Join-Path $InstallDir "cert.pem")) -or (Test-Path (Join-Path $InstallDir "root.pem"))) {
            Log-Info "Refreshing CA trust after update..."
            Set-SentinelCaTrust -InstallDir $InstallDir

            # Rotation/legacy cleanup: remove any pre-update thumbprint that
            # is NOT part of the new chain, from both Root and CA stores.
            # Idempotent (no-op if cert isn't present in that store), so we
            # don't need to know which store the legacy cert lived in.
            if ($script:PreUpdateCaThumbs.Count -gt 0) {
                $newThumbs = New-Object 'System.Collections.Generic.HashSet[string]'
                foreach ($pem in @("cert.pem", "root.pem")) {
                    $path = Join-Path $InstallDir $pem
                    if (Test-Path $path) {
                        try {
                            $tp = (New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $path).Thumbprint
                            if ($tp) { [void]$newThumbs.Add($tp) }
                        } catch {
                            Log-Debug "Could not read post-update $pem thumbprint: $($_.Exception.Message)"
                        }
                    }
                }
                foreach ($oldThumb in $script:PreUpdateCaThumbs) {
                    if (-not $newThumbs.Contains($oldThumb)) {
                        Log-Info "Removing stale trust for rotated/legacy cert (thumbprint=$oldThumb)..."
                        [void](Remove-SentinelCertByThumbprint -Thumbprint $oldThumb -StoreName 'Root')
                        [void](Remove-SentinelCertByThumbprint -Thumbprint $oldThumb -StoreName 'CA')
                    }
                }
            }
        }
    }
    # Rebuild ca-bundle.pem so NODE_EXTRA_CA_CERTS has a current chain on disk.
    $newCaPath = New-SentinelCaBundle -InstallDir $InstallDir

    # Legacy-to-strict transition: pre-existing installs set NODE_EXTRA_CA_CERTS
    # to <InstallDir>\cert.pem (intermediate-only after this update, which fails
    # strict chain validation). Rewrite the machine-scope env var to point at
    # ca-bundle.pem if we successfully built one. Idempotent on re-runs.
    if ($newCaPath -and $newCaPath -like "*ca-bundle.pem") {
        $existing = [System.Environment]::GetEnvironmentVariable("NODE_EXTRA_CA_CERTS", [System.EnvironmentVariableTarget]::Machine)
        if ($existing -ne $newCaPath) {
            Log-Info "Migrating NODE_EXTRA_CA_CERTS '$existing' -> '$newCaPath' (legacy single-cert -> bundle)"
            Set-NodeCaEnv -CertPath $newCaPath
        }
    }

    # ── Operator-driven manual refresh ────────────────────────────────
    # A manual -ZipPath / -Local run is treated as "reinstall" semantics:
    # re-register the Windows service and scheduled task so any new env
    # vars, binPath args, or updater schedule tweaks in this release take
    # effect.  Scheduled CDN ticks skip this to keep the SCM state stable
    # across polls.  IsCdnFreshInstall has its own branch below.
    # ── Phase 4/5: Refresh service and schedule ───────────────────────────
    # Only runs for manual invocations or the CDN-fresh-install bootstrap.
    # The scheduled-tick update path keeps service + task state stable across
    # polls, so this phase is a Skip for it.
    Start-Phase "Refresh service and schedule"
    $isManualInvocation = ($ZipPath -or $Local) -and -not $script:IsCdnFreshInstall
    if ($isManualInvocation) {
        Log-Info "Manual invocation detected (-ZipPath/-Local) -- refreshing service + updater schedule to match new release schema"
        try {
            Register-SentinelService -Dir $InstallDir
            Log-Info "Service refreshed: $ServiceName"
        } catch {
            Log-Exception -Label "Register-SentinelService (manual -ZipPath refresh)" -ErrorRecord $_ -Context @(
                "InstallDir: $InstallDir",
                "Service:    $ServiceName"
            ) -Hints @(
                "Service refresh failed; existing registration continues to run the new binaries.",
                "Re-run installer as Administrator to repair the service."
            )
        }
        try {
            Register-UpdaterSchedule -Dir $InstallDir
            Log-Info "Updater schedule refreshed: $UpdaterTaskName"
        } catch {
            Log-Exception -Label "Register-UpdaterSchedule (manual -ZipPath refresh)" -ErrorRecord $_ -Context @(
                "InstallDir: $InstallDir"
            ) -Hints @(
                "Updater schedule refresh failed; existing task (if any) still fires on its prior cadence.",
                "Re-run installer as Administrator to repair the schedule."
            )
        }
    }

    # ── CDN fresh install post-deploy setup ───────────────────────────
    # When no service existed and no ZIP was provided, the update flow handles
    # the CDN download and deploy, but skips install-mode setup steps.
    # Run them now so the service gets registered before Start-SentinelAgent.
    if ($script:IsCdnFreshInstall) {
        Log-Info "Trusting bundled MITM CA chain for current user (required for sentinel-proxy HTTPS interception)..."
        Set-SentinelCaTrust -InstallDir $InstallDir
        $nodeCertPath = New-SentinelCaBundle -InstallDir $InstallDir
        if ($nodeCertPath) {
            Set-NodeCaEnv -CertPath $nodeCertPath
        } else {
            Log-Warn "No CA cert available for NODE_EXTRA_CA_CERTS -- skipping Node.js env setup."
        }
        # $script:CollectedEmail = Collect-UserEmail
        # Tenant ID — CDN fresh install already collected + persisted upfront
        # in the fail-fast gate above. Nothing to do here.
        if ($script:CollectedEmail) {
            $env:SENTINEL_OVERRIDE_EMAIL = $script:CollectedEmail
            try { [System.Environment]::SetEnvironmentVariable("SENTINEL_OVERRIDE_EMAIL", $script:CollectedEmail, [System.EnvironmentVariableTarget]::User) }
            catch { Log-Warn "SetEnvironmentVariable 'SENTINEL_OVERRIDE_EMAIL' failed: $($_.Exception.Message) -- future sessions may not see this value." }
            Log-Info "SENTINEL_OVERRIDE_EMAIL configured: $($script:CollectedEmail)"
        } else {
            # No email provided -- clear any stale value from a previous install.
            try { [System.Environment]::SetEnvironmentVariable("SENTINEL_OVERRIDE_EMAIL", $null, [System.EnvironmentVariableTarget]::User) }
            catch { Log-Warn "SetEnvironmentVariable 'SENTINEL_OVERRIDE_EMAIL' (clear) failed: $($_.Exception.Message)" }
            try { Remove-Item "Env:\SENTINEL_OVERRIDE_EMAIL" -ErrorAction Stop }
            catch [System.Management.Automation.ItemNotFoundException] { }
            catch { Log-Debug "Remove-Item Env:\SENTINEL_OVERRIDE_EMAIL failed: $($_.Exception.Message)" }
            Log-Info "No work email provided -- SENTINEL_OVERRIDE_EMAIL cleared."
        }
        $env:QUILR_DLP_ENDPOINT     = $DlpEndpoint
        $env:QUILR_BACKEND_BASE_URL = $BackendBaseUrl
        try { [System.Environment]::SetEnvironmentVariable("QUILR_DLP_ENDPOINT",     $DlpEndpoint,    [System.EnvironmentVariableTarget]::User) }
        catch { Log-Warn "SetEnvironmentVariable 'QUILR_DLP_ENDPOINT' failed: $($_.Exception.Message) -- future sessions may not see this value." }
        try { [System.Environment]::SetEnvironmentVariable("QUILR_BACKEND_BASE_URL", $BackendBaseUrl, [System.EnvironmentVariableTarget]::User) }
        catch { Log-Warn "SetEnvironmentVariable 'QUILR_BACKEND_BASE_URL' failed: $($_.Exception.Message) -- future sessions may not see this value." }
        $templateFileUpdatePath = Join-Path $InstallDir "templates\app-discovery"
        $env:SENTINEL_TEMPLATE_DIR = $templateFileUpdatePath
        try { [System.Environment]::SetEnvironmentVariable("SENTINEL_TEMPLATE_DIR", $templateFileUpdatePath, [System.EnvironmentVariableTarget]::User) }
        catch { Log-Warn "SetEnvironmentVariable 'SENTINEL_TEMPLATE_DIR' failed: $($_.Exception.Message) -- future sessions may not see this value." }
        $env:SENTINEL_INSTALLATION_PATH = $InstallDir
        try { [System.Environment]::SetEnvironmentVariable("SENTINEL_INSTALLATION_PATH", $InstallDir, [System.EnvironmentVariableTarget]::User) }
        catch { Log-Warn "SetEnvironmentVariable 'SENTINEL_INSTALLATION_PATH' failed: $($_.Exception.Message) -- future sessions may not see this value." }
        try {
            Register-SentinelService -Dir $InstallDir
        } catch {
            Log-Exception -Label "Register-SentinelService (CDN fresh install)" -ErrorRecord $_ -Context @(
                "InstallDir: $InstallDir",
                "Service:    $ServiceName"
            ) -Hints @(
                "Service registration failed -- Start-SentinelAgent will likely fail.",
                "Verify elevation: installer must run as Administrator.",
                "Inspect SCM: Get-Service $ServiceName"
            ) -Level "ERROR"
        }
        try {
            Register-UpdaterSchedule -Dir $InstallDir
        } catch {
            Log-Exception -Label "Register-UpdaterSchedule (update path)" -ErrorRecord $_ -Context @(
                "InstallDir: $InstallDir"
            ) -Hints @(
                "Update completed; only re-registering the auto-updater task failed.",
                "Existing task (if any) still runs until next scheduled boundary.",
                "Re-run installer as Administrator to repair the schedule."
            )
        }
    }

    # Close Phase 4/5 (refresh) -- Ok if we did either a manual refresh or
    # the CDN-fresh-install bootstrap, Skip otherwise.
    if ($isManualInvocation) {
        End-PhaseOk -Detail "manual -- service + schedule refreshed"
    } elseif ($script:IsCdnFreshInstall) {
        End-PhaseOk -Detail "CDN fresh -- service + schedule registered"
    } else {
        End-PhaseSkip -Reason "scheduled tick -- state already registered"
    }

    # ── Phase 5/5: Start agent and health check ───────────────────────────
    Start-Phase "Start agent and health check"
    # Reconcile service env with on-disk tenant_id file before starting the
    # agent. Idempotent: no-op when env already matches or no file exists.
    Reconcile-TenantIdEnv
    # ── Step 15: Start agent ──────────────────────────────────────────
    try {
        Start-SentinelAgent
    } catch {
        Log-Exception -Label "Start-SentinelAgent (post-deploy, new version)" -ErrorRecord $_ -Context @(
            "New version: $remoteVersion"
        ) -Hints @(
            "New binaries were deployed but won't start -- triggering rollback now.",
            "The previous ZIP lives in $RollbackDir; see Invoke-Rollback logs for detail."
        ) -Level "ERROR"
        Invoke-Rollback -FailedVersion $remoteVersion | Out-Null
        End-PhaseFail -Reason "Start-SentinelAgent failed; rolled back to previous version"
        exit 1
    }

    # ── Step 16: Health check ─────────────────────────────────────────
    if (Invoke-HealthCheck) {
        # SUCCESS -- wipe any legacy retry markers (.quarantined_version,
        # .download_failed_*, .last_downloaded_checksum) from older
        # installer versions that might still be on disk.
        Remove-LegacyBlocklists
        Write-AgentLogDump -Label "UPDATE OK"
        Log-SentinelProcesses -Label "post-update"
        Write-SystemExtensionLogDump -Label "post-update"
        try { Write-NetworkSnapshot -Label "post-update" } catch {
            Log-Debug "Write-NetworkSnapshot (post-update) failed: $($_.Exception.Message)"
        }
        Log-Info "=========================================="
        Log-Info "Update complete: $currentVersion -> $remoteVersion"
        Log-Info "=========================================="

        # Env-transition guard: the manual-refresh branch and CDN-fresh
        # branch above already re-registered the service + schedule with
        # the new -Env.  A plain scheduled-tick update path did NOT, so
        # if a transition slipped through (corrupted registry, hand-edited
        # schedule, etc.) we re-register here to self-heal before persisting.
        if ($script:EnvTransition -and
            -not $isManualInvocation -and -not $script:IsCdnFreshInstall) {
            Log-Warn "Env transition on scheduled tick -- forcing re-register to propagate new env"
            try { Register-SentinelService -Dir $InstallDir } catch {
                Log-Exception -Label "Register-SentinelService (env-transition self-heal)" -ErrorRecord $_
            }
            try { Register-UpdaterSchedule -Dir $InstallDir } catch {
                Log-Exception -Label "Register-UpdaterSchedule (env-transition self-heal)" -ErrorRecord $_
            }
        }
        # Always persist at end of successful update so the store tracks
        # the -Env arg we just committed to.  Idempotent.
        Write-PersistedEnv -Value $Env

        # Write version marker only after health check confirms the new version is stable.
        # Writing it earlier means a failed start/health-check + rollback leaves the marker
        # at the new version, causing Get-CurrentVersion to report it as installed and
        # CDN ticks to skip the retry indefinitely.
        try {
            Set-Content -Path (Join-Path $InstallDir ".installed_version") -Value $remoteVersion -ErrorAction Stop
            Log-Debug "Wrote version marker: $remoteVersion (post-health-check)"
        } catch {
            Log-Exception -Label "Write .installed_version (post-health-check)" -ErrorRecord $_ -Context @(
                "Path:    $(Join-Path $InstallDir '.installed_version')",
                "Version: $remoteVersion"
            ) -Hints @(
                "Version marker not written -- next tick will re-deploy the same version.",
                "Check ACL and disk space on $InstallDir"
            ) -Level "WARN"
        }

        End-PhaseOk -Detail "agent healthy"
        $successTitle = if ($script:IsCdnFreshInstall) { "Install complete" } else { "Update complete" }
        $successLines = if ($script:IsCdnFreshInstall) {
            @("Agent running:  v$remoteVersion", "Environment:    $Env")
        } else {
            @("Agent updated:  $currentVersion $($script:_GlyphH)$($script:_GlyphH) $remoteVersion", "Environment:    $Env")
        }
        Show-CliSuccess -Title $successTitle -Lines $successLines
        exit 0
    } else {
        # HEALTH CHECK FAILED -- roll back
        Log-Error "Health check failed - initiating rollback"
        Write-AgentLogDump -Label "UPDATE FAILED"
        Write-SystemExtensionLogDump -Label "UPDATE FAILED"
        Invoke-Rollback -FailedVersion $remoteVersion | Out-Null
        End-PhaseFail -Reason "health check failed; rolled back to previous version"
        exit 1
    }

    } finally {
        # Ensure agent is running before we exit -- regardless of update outcome.
        $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($svc) {
            $procs = Get-Process -Name "sentinel" -ErrorAction SilentlyContinue
            if (-not $procs) {
                Log-Warn "Agent is not running - attempting to start before exit"
                try {
                    Invoke-Native -Label "sc.exe failure $ServiceName (re-assert recovery)" -FilePath "sc.exe" `
                        -ArgumentList @("failure", $ServiceName, "reset=", "86400", "actions=", "restart/5000/restart/5000/restart/5000") | Out-Null
                    Start-Service -Name $ServiceName -ErrorAction Stop -WarningAction SilentlyContinue
                    Start-Sleep -Seconds 2
                    $procs = Get-Process -Name "sentinel" -ErrorAction SilentlyContinue
                    if ($procs) {
                        Log-Info "Agent started (PID: $($procs[0].Id))"
                    } else {
                        Log-Warn "Service started but agent process not confirmed"
                    }
                } catch {
                    Log-Exception -Label "Start-SentinelAgent (post-health-check restart)" -ErrorRecord $_ -Hints @(
                        "Manual intervention likely required.",
                        "Try: Stop-Service $ServiceName; Start-Service $ServiceName",
                        "If that fails: Get-WinEvent -LogName System -Source 'Service Control Manager' -MaxEvents 10"
                    ) -Level "ERROR"
                }
            }
        }

        # Clean up any temp directories from this run
        foreach ($pattern in @("sentinel_update_$PID", "sentinel_extract_$PID", "sentinel_peek_$PID", "sentinel_staging_$PID")) {
            $tmpPath = Join-Path ([IO.Path]::GetTempPath()) $pattern
            if (Test-Path $tmpPath) {
                Remove-Quiet -Path $tmpPath -Recurse -Label "tmp extract path"
            }
        }
        Release-UpdateLock
    }
}

# #############################################################################
#
#  SELF-TEST -- Logic + error-handling verification (no admin required)
#  Run with: powershell -File sentinel-endpoint.ps1 -SelfTest
#
# #############################################################################

function Invoke-SelfTest {
    # Counters stored at script scope so the nested helper can increment them.
    $script:_ST_Pass = 0; $script:_ST_Fail = 0

    function Assert-ST {
        param([string]$Name, [scriptblock]$Body)
        try {
            $ok = & $Body
            if ($ok) {
                $script:_ST_Pass++
                Write-Host "  [PASS] $Name" -ForegroundColor Green
            } else {
                $script:_ST_Fail++
                Write-Host "  [FAIL] $Name" -ForegroundColor Red
            }
        } catch {
            $script:_ST_Fail++
            Write-Host "  [FAIL] $Name  (threw: $($_.Exception.Message))" -ForegroundColor Red
        }
    }

    Write-Host ""
    Write-Host "==========================================" -ForegroundColor Cyan
    Write-Host "  Sentinel Endpoint Self-Test" -ForegroundColor Cyan
    Write-Host "==========================================" -ForegroundColor Cyan
    Write-Host ""

    # ── Group 1: Version-comparison logic ────────────────────────────────
    Write-Host "  [1] Version comparison logic" -ForegroundColor Yellow
    Assert-ST "Test-NewerVersion: 1.0.1 > 1.0.0"      { Test-NewerVersion -Remote "1.0.1" -Current "1.0.0" }
    Assert-ST "Test-NewerVersion: 1.0.0 NOT > 1.0.0"  { -not (Test-NewerVersion -Remote "1.0.0" -Current "1.0.0") }
    Assert-ST "Test-NewerVersion: 2.0.0 > 1.99.99"    { Test-NewerVersion -Remote "2.0.0" -Current "1.99.99" }
    Assert-ST "Test-NewerVersion: 0.9.0 NOT > 1.0.0"  { -not (Test-NewerVersion -Remote "0.9.0" -Current "1.0.0") }
    Assert-ST "Test-AboveFloor: 1.0.1 above 1.0.0"    { Test-AboveFloor -Version "1.0.1" -Floor "1.0.0" }
    Assert-ST "Test-AboveFloor: 1.0.0 at floor"       { Test-AboveFloor -Version "1.0.0" -Floor "1.0.0" }
    Assert-ST "Test-AboveFloor: 0.9.9 below 1.0.0"    { -not (Test-AboveFloor -Version "0.9.9" -Floor "1.0.0") }
    Write-Host ""

    # ── Group 2: Email validation ─────────────────────────────────────────
    Write-Host "  [2] Email validation (Test-EmailFormat)" -ForegroundColor Yellow
    Assert-ST "Valid: user@example.com"         { Test-EmailFormat "user@example.com" }
    Assert-ST "Valid: a.b@sub.domain.co"        { Test-EmailFormat "a.b@sub.domain.co" }
    Assert-ST "Reject: no TLD (user@nodot)"     { -not (Test-EmailFormat "user@nodot") }
    Assert-ST "Reject: no @ (userexample.com)"  { -not (Test-EmailFormat "userexample.com") }
    Assert-ST "Reject: space (user @ex.com)"    { -not (Test-EmailFormat "user @ex.com") }
    Assert-ST "Reject: empty string"            { -not (Test-EmailFormat "") }
    Write-Host ""

    # ── Group 3: Get-Sha256Hash must re-throw on missing file (STEP-29) ──
    Write-Host "  [3] Get-Sha256Hash error propagation (STEP-29)" -ForegroundColor Yellow
    $rethrew = $false
    try { Get-Sha256Hash -FilePath "C:\__nonexistent_sentinel_st_$PID.bin" }
    catch { $rethrew = $true }
    Assert-ST "Missing file causes rethrow (integrity-critical path)" { $rethrew }
    Write-Host ""

    # ── Group 4: Non-critical functions must not crash on bad inputs ──────
    Write-Host "  [4] Non-critical functions: no unhandled exceptions on bad inputs" -ForegroundColor Yellow

    $ok = $true
    try { Set-NodeCaEnv -CertPath "C:\__nonexistent_cert_$PID.pem" }
    catch { $ok = $false }
    Assert-ST "Set-NodeCaEnv missing cert: warns + returns, no crash (STEP-26)" { $ok }

    $tmpDest = Join-Path ([IO.Path]::GetTempPath()) "sentinel_st_hookscripts_$PID"
    $ok = $true
    try { Copy-HookScripts -Src "C:\__nonexistent_src_$PID" -Dest $tmpDest }
    catch { $ok = $false }
    finally { Remove-Item $tmpDest -Recurse -Force -EA SilentlyContinue }
    Assert-ST "Copy-HookScripts bad Src: no crash (STEP-32)" { $ok }

    $ok = $true
    try { Deploy-HookBinaries -HooksDir "C:\__nonexistent_hooks_$PID" -DestDir "C:\__nonexistent_dest_$PID" }
    catch { $ok = $false }
    Assert-ST "Deploy-HookBinaries bad dirs: no crash (STEP-30)" { $ok }
    Write-Host ""

    # ── Group 5: Structural -- key patterns must be present in source ─────
    Write-Host "  [5] Structural: error-handling patterns in source" -ForegroundColor Yellow
    $src = $null
    if ($selfPath -and (Test-Path -LiteralPath $selfPath)) {
        $ext = [IO.Path]::GetExtension($selfPath).ToLower()
        if ($ext -eq '.ps1') {
            $src = [IO.File]::ReadAllText($selfPath)
        }
    }

    if ($src) {
        Assert-ST "setx LASTEXITCODE check present (STEP-26)" {
            ($src -match '\$LASTEXITCODE -ne 0') -and ($src -match 'setx NODE_EXTRA_CA_CERTS')
        }
        Assert-ST "SetEnvironmentVariable wrapped in try/catch (STEP-27)" {
            # At least 5 wrapped calls (both install + CDN fresh-install paths)
            ($src | Select-String 'try \{ \[System\.Environment\]::SetEnvironmentVariable' -AllMatches).Matches.Count -ge 5
        }
        Assert-ST ".installed_version write in try block (STEP-24)" {
            $src -match 'Set-Content.*installed_version.*ErrorAction Stop'
        }
        Assert-ST "Get-Sha256Hash catch block with Log-Exception present (STEP-29)" {
            $src -match 'Log-Exception -Label "Get-Sha256Hash"'
        }
        Assert-ST ".last_downloaded.zip Copy-Item in try block (STEP-28)" {
            $src -match 'Copy-Item.*last_downloaded.*ErrorAction Stop'
        }
        Assert-ST "Copy-HookScripts New-Item wrapped in try (STEP-32)" {
            $src -match 'New-Item -ItemType Directory -Path \$Dest -Force -ErrorAction Stop'
        }
    } else {
        # Running as compiled .exe or source unavailable -- skip structural checks
        Write-Host "  [SKIP] Source not accessible (compiled .exe?) -- structural checks skipped" -ForegroundColor DarkYellow
        $script:_ST_Pass += 6
    }
    Write-Host ""

    # ── Summary ───────────────────────────────────────────────────────────
    $total = $script:_ST_Pass + $script:_ST_Fail
    Write-Host "==========================================" -ForegroundColor Cyan
    $color = if ($script:_ST_Fail -eq 0) { "Green" } else { "Red" }
    Write-Host "  Results: $($script:_ST_Pass) passed, $($script:_ST_Fail) failed of $total" -ForegroundColor $color
    Write-Host "==========================================" -ForegroundColor Cyan
    Write-Host ""

    if ($script:_ST_Fail -gt 0) { exit 1 }
}

# #############################################################################
#
#  MAIN -- Auto-detect mode and dispatch
#
# #############################################################################

$OriginalDir = (Get-Location).Path

try {
    Log-Info "                                                               "
    Log-Info "                                                               "
    Log-Info "                            START                              "

    Log-Info "============================================================"
    Log-Info "sentinel-endpoint v$SetupVersion started"
    Log-Info "  PID:  $PID"
    Log-Info "  User: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)"
    Log-Info "  Args: ZipPath=$(if ($ZipPath) { $ZipPath } else { '-' }) Local=$(if ($Local) { $Local } else { '-' }) Force=$Force DryRun=$DryRun"
    Log-Info "  Log:  $script:LogFile"
    Log-Info "============================================================"

    # Self-test: bypasses admin check so the QA pipeline can run it without elevation.
    if ($SelfTest) { Invoke-SelfTest; exit 0 }

    # Check admin
    if (-not (Test-Admin)) {
        Log-Error "Administrator privileges required."
        Log-Error "Right-click PowerShell and select `"Run as Administrator`"."
        exit 1
    }


    # Use embedded payload ONLY for first install (not for scheduled CDN updates).
    # When the installed copy runs on schedule, it checks CDN, not re-deploys itself.
    # Detection: if running from InstallDir, we ARE the scheduled task.
    if ($script:EmbeddedZip -and -not $ZipPath -and -not $Local) {
        $runningFromInstallDir = $selfPath -and $selfPath.StartsWith($InstallDir, [StringComparison]::OrdinalIgnoreCase)
        if ($runningFromInstallDir) {
            Log-Debug "Running from install dir -- ignoring embedded payload, will check CDN"
            Remove-Quiet -Path $script:EmbeddedZip -Label "embedded-payload zip"
            $script:EmbeddedZip = $null
        } else {
            $svcCheck = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
            if ($svcCheck) {
                Log-Info "Using embedded payload for update: $($script:EmbeddedZip)"
                $Local = $script:EmbeddedZip
            } else {
                Log-Info "Using embedded payload for install: $($script:EmbeddedZip)"
                $ZipPath = $script:EmbeddedZip
            }
        }
    }

    # Auto-detect mode:
    #   INSTALL if service doesn't exist AND a ZIP is provided via -ZipPath
    #   UPDATE  if service exists
    #   INSTALL fallback if service doesn't exist and -Local is provided
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    $hasZipArg = [bool]$ZipPath
    $hasLocalArg = [bool]$Local

    if (-not $svc -and $hasZipArg) {
        $ResolvedZip = Resolve-ZipPath -Provided $ZipPath
        Invoke-Install -ResolvedZip $ResolvedZip
    } elseif (-not $svc -and $hasLocalArg) {
        $resolvedLocal = (Resolve-Path $Local -ErrorAction SilentlyContinue).Path
        if (-not $resolvedLocal -or -not (Test-Path $resolvedLocal)) {
            Log-Error "Local ZIP not found: $Local"
            exit 1
        }
        Invoke-Install -ResolvedZip $resolvedLocal
    } elseif (-not $svc -and -not $hasZipArg -and -not $hasLocalArg) {
        # No service, no ZIP -- try CDN fresh install
        Log-Info "Agent not installed. Attempting CDN fresh install..."
        $Force = $true
        $script:IsCdnFreshInstall = $true
        Invoke-Update
    } else {
        # Service exists -- update mode
        # If agent process is not running, force update to restore service
        $agentProc = Get-Process -Name "sentinel" -ErrorAction SilentlyContinue
        if (-not $agentProc) {
            Log-Warn "Agent is not running -- forcing update to restore service"
            $Force = $true
        }
        $dispatchLabel = if (-not $ZipPath -and -not $Local) { "task scheduler (auto-update)" } else { "manual (ZipPath=$ZipPath Local=$Local)" }
        Log-Info "Dispatching Invoke-Update: trigger=$dispatchLabel Force=$Force"
        Invoke-Update
    }
} catch {
    $topReason = $_.Exception.Message
    Log-Exception -Label "sentinel-endpoint setup (top-level catch)" -ErrorRecord $_ -Context @(
        "Arguments: $($PSBoundParameters | Out-String -Stream | Where-Object { $_ })",
        "Self path: $selfPath"
    ) -Hints @(
        "Look for the FIRST [WARN]/[ERROR] line above -- it usually names the failing step.",
        "Re-run with -Verbose for debug-level step logs.",
        "Full log file: $LogFile"
    ) -Level "ERROR"
    # CLI fail surface: End-PhaseFail already renders the banner when a phase was
    # open; otherwise emit a bare banner so the operator still sees something loud.
    try {
        if ($script:_CurrentPhase) {
            End-PhaseFail -Reason $topReason
        } else {
            Show-CliFailBanner -Step "(pre-phase)" -Reason $topReason
        }
    } catch {
        # Last-resort: we're already in the top-level catch because the
        # primary action threw; if the fail-banner renderer ALSO threw
        # (glyph encoding or console closed), we still have to exit 1
        # without re-entering the renderer.  A raw Write-Log keeps the
        # post-mortem non-empty.
        try { Write-Log "ERROR" "fail-banner renderer threw: $($_.Exception.Message)" } catch { }
    }
    exit 1
} finally {
    if ($script:EmbeddedZip -and (Test-Path $script:EmbeddedZip)) {
        Remove-Quiet -Path $script:EmbeddedZip -Label "embedded-payload zip"
    }
    # no-op if already released by Invoke-Update's own finally
    # Invoke-Install had no finally of its own — any exit 1 or unhandled exception now always clears the lock via the top-level finally
    Release-UpdateLock   
    Set-Location $OriginalDir
}

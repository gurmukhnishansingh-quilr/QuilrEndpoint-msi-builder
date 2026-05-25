#
# Sentinel Endpoint Agent -- Complete Uninstaller (Windows)
#
# Reverses EVERYTHING the installer, runner, and updater did.
# Leaves zero residue -- the machine returns to pre-Sentinel state.
#
# Core uninstall logic matches scripts/uninstaller/sentinel_uninstaller.ps1
# (authored by Divyansh). This file adds deployment extras: updater task
# cleanup, WinDivert driver cleanup, dry-run mode, per-step error handling,
# and post-uninstall health checks. When updating uninstall logic, update
# uninstaller/ first, then copy the changed functions here.
#
# What this does:
#   - Stops and deletes the SentinelAgent Windows service
#   - Kills all Sentinel processes
#   - Removes install dir, hooks, Quilr app data, logs
#   - Removes trusted CA certificate from user Root store
#   - Removes environment variables (NODE_EXTRA_CA_CERTS, NODE_TLS_REJECT_UNAUTHORIZED,
#     SENTINEL_OVERRIDE_EMAIL, QUILR_DLP_ENDPOINT, QUILR_BACKEND_BASE_URL) from machine and user scope
#   - Removes QUIC browser policies (Chrome, Edge)
#   - Re-enables IPv6 on all active network adapters
#   - [Deployment extra] Removes updater scheduled task and scripts
#   - [Deployment extra] Removes WinDivert driver
#   - [Deployment extra] Post-uninstall health checks
#
# Usage:
#   .\sentinel-endpoint-uninstaller.ps1                      # Full uninstall (removes logs and data)
#   .\sentinel-endpoint-uninstaller.ps1 -KeepLogs            # Preserve C:\ProgramData\Sentinel
#   .\sentinel-endpoint-uninstaller.ps1 -KeepData            # Preserve %LOCALAPPDATA%\Quilr
#   (Force mode is always on -- continues past individual step failures)
#   .\sentinel-endpoint-uninstaller.ps1 -DryRun              # Show what would be done, change nothing
#   .\sentinel-endpoint-uninstaller.ps1 -SkipIPv6            # Don't re-enable IPv6
#
# Requires: Administrator privileges
#

param(
    [switch]$KeepLogs,
    [switch]$KeepData,
    [switch]$DryRun,
    [switch]$KeepInstallDir,
    [switch]$SkipIPv6,
    # CLI verbosity.  Default: clean phase markers + warnings/errors on CLI,
    # everything else in the log file.  -CliVerbose restores the legacy
    # dump-every-INFO-line-to-stdout behavior (debugging).
    [switch]$CliVerbose
)

# Distribution uninstaller always continues past step failures (no confirmation prompt).
# Individual step errors are logged but don't stop the uninstall.
$Force = $true

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

# Silence the progress stream so Invoke-WebRequest / Expand-Archive / registry
# enumerators don't leak "Writing web request / Writing request stream" text
# onto stdout and (more importantly) don't eat 10-100x performance on cold fetches.
$ProgressPreference = 'SilentlyContinue'

# =============================================================================
# CONFIGURATION -- Must match installer/runner/updater constants
# =============================================================================

# Paths (from installer -- rebranded QuilrAI agent)
$InstallDir  = "C:\Program Files\QuilrAI"
$ServiceName = "QuilrAIAgent"
# Hooks land in %LOCALAPPDATA%\.quilrai (installer's $SentinelUserDir); this is
# also QUILRAI_INSTALLATION_PATH.
$HooksDir    = Join-Path $env:LOCALAPPDATA ".quilrai"
$QuilrDir    = Join-Path $env:LOCALAPPDATA "Quilr"
# Legacy user dir from older Sentinel builds -- removed if present (no-op otherwise).
$SentinelUserDir = Join-Path $env:LOCALAPPDATA "Sentinel"
$DataDir     = "C:\ProgramData\QuilrAI"
$ServiceLogDir = "C:\ProgramData\QuilrAI\logs"
$QuilrProgramDataDir = "C:\ProgramData\Quilr"

# Updater (the lite installer registers no updater task; kept for legacy cleanup).
$UpdaterTaskName = "Sentinel-Endpoint-Update"
$UpdaterLogDir = "C:\ProgramData\QuilrAI\logs"

# Canonical agent process list -- base names (no .exe).  Used by the grace-timer
# poll, the survivor taskkill, and Log-SentinelProcesses.  Suffix `.exe` when a
# caller needs the Windows executable name (taskkill /IM).  quilrai-proxy holds
# the WinDivert driver handle, so killing it lets the driver image be removed.
$SentinelProcessNames = @(
    "quilrai", "quilrai-proxy", "ipc-light-broker", "quilrai-diagnostics",
    "template-engine", "templating-engine", "quilrai-monitor-v2",
    "bootstrap", "email-discovery", "quilrai-hook-client", "quilrai-claude-hook-client",
    # Legacy Sentinel-named binaries -- harmless to include (skipped if absent).
    "sentinel", "sentinel-proxy", "sentinel-endpoint"
)

# Diagnostics / teardown tunings (shared across Write-NetworkSnapshot,
# Write-SystemExtensionLogDump, and Stop-SentinelAll grace-timer).
$NetworkProbePingMs       = 2000  # ping.exe -w timeout per probe (ms)
$EventLogWindowMinutes    = 5     # Get-WinEvent StartTime window
$EventLogMaxPerProvider   = 20    # Cap per provider to keep log size bounded
$EventLogMessageMaxChars  = 260   # Per-event message truncation cap
$ProcessDrainGraceSeconds = 6     # Grace window for clean self-exit before hard-kill
$ProcessDrainPollMs       = 200   # Poll interval while waiting for self-exit

# QUIC browser policy registry paths
$QuicPolicyPaths = @(
    "HKLM:\SOFTWARE\Policies\Google\Chrome",
    "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
)

# =============================================================================
# LOGGING -- Always verbose to the log file.  CLI is phase-markers only
# unless -CliVerbose was passed.  WARN / ERROR are always visible in CLI.
# =============================================================================
# Log to %TEMP% so the log survives install dir deletion during uninstall.

$LogFile = Join-Path $env:TEMP "sentinel-endpoint-uninstaller.log"

# Quiet-by-default CLI.  Log file stays verbose regardless.
$script:CliQuiet = -not $CliVerbose.IsPresent

function Write-Log {
    param([string]$Level, [string]$Message)
    $ts = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    $entry = "$ts [$Level] [PID:$PID] $Message"
    Add-Content -Path $LogFile -Value $entry -ErrorAction SilentlyContinue
}

# =============================================================================
# HELPERS
# =============================================================================

# ── Print helpers ───────────────────────────────────────────────────────────
# INFO / STEP / OK: file always, CLI only under -CliVerbose.
# WARN / ERROR:     always visible in CLI (actionable).

function Write-UninstallInfo  {
    param([string]$m)
    Write-Log "INFO" $m
    if (-not $script:CliQuiet) { Write-Host "[*] $m" -ForegroundColor Green }
}
function Write-UninstallOk    {
    param([string]$m)
    Write-Log "INFO" $m
    if (-not $script:CliQuiet) { Write-Host "[+] $m" -ForegroundColor Green }
}
function Write-UninstallError { param([string]$m); Write-Host "[!] $m" -ForegroundColor Red;    Write-Log "ERROR" $m }
function Write-UninstallWarn  { param([string]$m); Write-Host "[!] $m" -ForegroundColor Yellow; Write-Log "WARN"  $m }
function Write-UninstallStep  {
    param([string]$m)
    Write-Log "INFO" $m
    if (-not $script:CliQuiet) { Write-Host "[>] $m" -ForegroundColor Cyan }
}
function Write-UninstallDebug { param([string]$m); Write-Log "DEBUG" $m }

# =============================================================================
# CLI UX -- glyphs, banner, phase markers, success/fail panels.
# Glyphs are built from code points ([char]0xNNNN) to keep this source
# pure-ASCII -- PowerShell 5.1 reads .ps1 files in the system codepage
# (CP1252 in most locales) and literal UTF-8 glyphs break parsing.
# =============================================================================

$script:_CliUtf8 = $false
try {
    if ([Console]::OutputEncoding.WebName -match 'utf-8|utf8') { $script:_CliUtf8 = $true }
} catch {
    # Runs before Write-Log is callable (helper is defined later), so the
    # only thing we can do is leave $script:_CliUtf8 = $false (ASCII
    # fallback).  That IS the intended behaviour for hosts without a
    # console (automation, no-TTY contexts) -- recording the "why" here
    # so a reader doesn't think this is a silent swallow.
}

$script:_GlyphTopL    = if ($script:_CliUtf8) { [string][char]0x256D } else { "+" }
$script:_GlyphTopR    = if ($script:_CliUtf8) { [string][char]0x256E } else { "+" }
$script:_GlyphBotL    = if ($script:_CliUtf8) { [string][char]0x2570 } else { "+" }
$script:_GlyphBotR    = if ($script:_CliUtf8) { [string][char]0x256F } else { "+" }
$script:_GlyphH       = if ($script:_CliUtf8) { [string][char]0x2500 } else { "-" }
$script:_GlyphV       = if ($script:_CliUtf8) { [string][char]0x2502 } else { "|" }
$script:_GlyphOk      = if ($script:_CliUtf8) { [string][char]0x2713 } else { "[OK]" }
$script:_GlyphFail    = if ($script:_CliUtf8) { [string][char]0x2717 } else { "[FAIL]" }
$script:_GlyphSkip    = if ($script:_CliUtf8) { [string][char]0x21B7 } else { "[SKIP]" }
$script:_GlyphHeavyTL = if ($script:_CliUtf8) { [string][char]0x2554 } else { "+" }
$script:_GlyphHeavyTR = if ($script:_CliUtf8) { [string][char]0x2557 } else { "+" }
$script:_GlyphHeavyBL = if ($script:_CliUtf8) { [string][char]0x255A } else { "+" }
$script:_GlyphHeavyBR = if ($script:_CliUtf8) { [string][char]0x255D } else { "+" }
$script:_GlyphHeavyH  = if ($script:_CliUtf8) { [string][char]0x2550 } else { "=" }
$script:_GlyphHeavyV  = if ($script:_CliUtf8) { [string][char]0x2551 } else { "|" }

$script:_CurrentPhase      = $null
$script:_CurrentPhaseStart = $null
$script:_CurrentPhaseStep  = 0
$script:_TotalPhaseSteps   = 0
$script:_OpStartedAt       = $null

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
}

function End-PhaseOk {
    param([string]$Detail = "")
    $elapsed = if ($script:_CurrentPhaseStart) {
        [math]::Round(((Get-Date) - $script:_CurrentPhaseStart).TotalSeconds, 0)
    } else { 0 }
    $stepTag = "[$($script:_CurrentPhaseStep)/$($script:_TotalPhaseSteps)]"
    $line  = "  $($script:_GlyphOk) $stepTag {0,-42}" -f $script:_CurrentPhase
    $trail = if ($Detail) { "  $Detail  (${elapsed}s)" } else { "  (${elapsed}s)" }
    Write-Host $line -NoNewline -ForegroundColor Green
    Write-Host $trail -ForegroundColor DarkGray
    $script:_CurrentPhase = $null
}

function End-PhaseSkip {
    param([string]$Reason = "")
    $stepTag = "[$($script:_CurrentPhaseStep)/$($script:_TotalPhaseSteps)]"
    $line  = "  $($script:_GlyphSkip) $stepTag {0,-42}" -f $script:_CurrentPhase
    $trail = if ($Reason) { "  ($Reason)" } else { "  (skipped)" }
    Write-Host $line -NoNewline -ForegroundColor Yellow
    Write-Host $trail -ForegroundColor DarkGray
    $script:_CurrentPhase = $null
}

function End-PhaseWarn {
    # Used when the step had errors but -Force continued past them.  Yellow
    # marker so the operator sees the step was not clean, without making it
    # look like a hard failure.
    param([string]$Reason = "errors; continued (-Force)")
    $elapsed = if ($script:_CurrentPhaseStart) {
        [math]::Round(((Get-Date) - $script:_CurrentPhaseStart).TotalSeconds, 0)
    } else { 0 }
    $stepTag = "[$($script:_CurrentPhaseStep)/$($script:_TotalPhaseSteps)]"
    $line  = "  ! $stepTag {0,-42}" -f $script:_CurrentPhase
    $trail = "  ($Reason) (${elapsed}s)"
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
    $title   = "UNINSTALL FAILED at step ${stepNum}: $Step"
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
    Write-Host "    2. If networking is broken, reboot to restore NDIS state." -ForegroundColor Yellow
    Write-Host "    3. Re-run the uninstaller as Administrator to retry." -ForegroundColor Yellow
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

# Verbose error reporting for caught exceptions. Same shape as Log-Exception
# in sentinel-endpoint.ps1 -- use in catch blocks instead of bare `... $_`.
function Write-UninstallException {
    param(
        [string]$Label,
        [System.Management.Automation.ErrorRecord]$ErrorRecord,
        [string[]]$Context = @(),
        [string[]]$Hints = @(),
        [string]$Level = "WARN"
    )
    $writer = if ($Level -eq "ERROR") { ${function:Write-UninstallError} } else { ${function:Write-UninstallWarn} }
    & $writer "[$Label] FAILED"
    if ($ErrorRecord) {
        $ex = $ErrorRecord.Exception
        & $writer "  Exception: $($ex.GetType().FullName)"
        if ($ex.HResult) { & $writer ("  HResult:   0x{0:X8} ({1})" -f $ex.HResult, $ex.HResult) }
        & $writer "  Message:   $($ex.Message)"
        $inner = $ex.InnerException; $depth = 0
        while ($inner -and $depth -lt 3) {
            & $writer "  Inner[$depth]: $($inner.GetType().FullName): $($inner.Message)"
            $inner = $inner.InnerException; $depth++
        }
        if ($ErrorRecord.CategoryInfo) {
            & $writer "  Category:  $($ErrorRecord.CategoryInfo.Category) / $($ErrorRecord.CategoryInfo.Reason)"
        }
    }
    foreach ($line in $Context) { & $writer "  $line" }
    foreach ($hint in $Hints)   { & $writer "  Hint: $hint" }
}

# Run a native executable, logging verbosely on non-success exit.
function Invoke-UninstallNative {
    param(
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][string]$FilePath,
        [string[]]$ArgumentList = @(),
        [int[]]$AllowedExitCodes = @(0),
        [string[]]$Hints = @()
    )
    Write-UninstallDebug "[$Label] exec: $FilePath $($ArgumentList -join ' ')"
    $output = $null
    # Relax EAP so native stderr flows to $output; exit code is truth.
    $savedEAP = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $output = & $FilePath @ArgumentList 2>&1
    } catch {
        Write-UninstallException -Label $Label -ErrorRecord $_ `
            -Context @("Command: $FilePath $($ArgumentList -join ' ')") -Hints $Hints
        $ErrorActionPreference = $savedEAP
        return @{ Success = $false; ExitCode = -1; Output = "" }
    } finally {
        $ErrorActionPreference = $savedEAP
    }
    $ec = $LASTEXITCODE
    if ($ec -in $AllowedExitCodes) {
        Write-UninstallDebug "[$Label] exit=$ec (ok, process/service already absent or completed)"
        return @{ Success = $true; ExitCode = $ec; Output = ($output -join "`n") }
    }
    Write-UninstallWarn "[$Label] FAILED: exit=$ec"
    Write-UninstallWarn "  Command: $FilePath $($ArgumentList -join ' ')"
    Write-UninstallWarn "  AllowedExitCodes: $($AllowedExitCodes -join ',')"
    foreach ($line in ($output -split "`r?`n")) {
        $t = "$line".Trim()
        if ($t) { Write-UninstallWarn "  > $t" }
    }
    foreach ($hint in $Hints) { Write-UninstallWarn "  Hint: $hint" }
    return @{ Success = $false; ExitCode = $ec; Output = ($output -join "`n") }
}

# Compact snapshot of the host's network state: reachability, NIC summary,
# system proxy config, WinDivert driver state, firewall profiles. Baseline
# captured before teardown; final snapshot captured post-teardown so
# operators can diff what actually changed.
function Write-NetworkSnapshot {
    param([string]$Label)
    Write-UninstallInfo "--- Network Snapshot ($Label) ---"

    foreach ($probeHost in @('8.8.8.8', 'google.com')) {
        try {
            $ping = ping.exe -n 1 -w $NetworkProbePingMs $probeHost 2>&1 | Out-String
            $replyLine = ($ping -split "`n" | Where-Object { $_ -match 'Reply from|Request timed out|could not find host' } | Select-Object -First 1)
            if ($replyLine) {
                Write-UninstallInfo "  ping ${probeHost}: $($replyLine.Trim())"
            } else {
                Write-UninstallInfo "  ping ${probeHost}: no reply / unreachable"
            }
        } catch {
            Write-UninstallInfo "  ping ${probeHost}: probe failed"
        }
    }

    try {
        $defaultRoute = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop | Sort-Object -Property RouteMetric | Select-Object -First 1
        if ($defaultRoute) {
            $adapter = Get-NetAdapter -InterfaceIndex $defaultRoute.InterfaceIndex -ErrorAction SilentlyContinue
            $ifName  = if ($adapter) { $adapter.Name } else { "ifIndex=$($defaultRoute.InterfaceIndex)" }
            Write-UninstallInfo "  Primary interface: $ifName  gw=$($defaultRoute.NextHop)"
        } else {
            Write-UninstallInfo "  Primary interface: (no default route)"
        }
    } catch {
        Write-UninstallInfo "  Primary interface: Get-NetRoute failed"
    }

    try {
        $allAdapters = Get-NetAdapter -ErrorAction Stop
        $up          = @($allAdapters | Where-Object { $_.Status -eq 'Up' }).Count
        $down        = @($allAdapters | Where-Object { $_.Status -ne 'Up' }).Count
        $v6Bindings  = Get-NetAdapterBinding -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue
        $v6Off       = @($v6Bindings | Where-Object { -not $_.Enabled }).Count
        $v6On        = @($v6Bindings | Where-Object { $_.Enabled }).Count
        Write-UninstallInfo "  Adapters: $up up / $down down   IPv6 bindings: $v6Off off / $v6On on"
    } catch {
        Write-UninstallInfo "  Adapter enumeration failed"
    }

    try {
        $winhttpOut = netsh.exe winhttp show proxy 2>&1 | Out-String
        $proxyLine  = ($winhttpOut -split "`n" | Where-Object { $_ -match 'Proxy Server|Direct access' } | Select-Object -First 1)
        if ($proxyLine) { Write-UninstallInfo "  WinHTTP proxy: $($proxyLine.Trim())" }
    } catch {
        Write-UninstallDebug "netsh winhttp show proxy failed: $($_.Exception.Message)"
    }

    foreach ($svcName in @('WinDivert', 'WinDivert14')) {
        $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
        if ($svc) {
            Write-UninstallInfo "  Service $($svc.Name): status=$($svc.Status) startType=$($svc.StartType)"
        }
    }

    try {
        $profiles = Get-NetFirewallProfile -ErrorAction Stop | Select-Object Name, Enabled
        $fwSummary = ($profiles | ForEach-Object { "$($_.Name)=$(if ($_.Enabled) { 'on' } else { 'off' })" }) -join ' '
        Write-UninstallInfo "  Firewall profiles: $fwSummary"
    } catch {
        Write-UninstallDebug "Get-NetFirewallProfile failed: $($_.Exception.Message)"
    }
}

# Dump recent Windows event-log entries from providers that back the
# network-filtering stack (WinDivert / WFP / NDIS / TCPIP / Service Control
# Manager). Called before teardown (baseline) and after the proxy-stop step,
# so operators can see what the kernel said as the proxy went down.
function Write-SystemExtensionLogDump {
    param(
        [string]$Label,
        [int]$MaxEventsPerProvider = $EventLogMaxPerProvider,
        [int]$WindowMinutes        = $EventLogWindowMinutes
    )
    Write-UninstallInfo "--- Network Extension / Driver Logs ($Label, last ${WindowMinutes}m) ---"
    $startTime = (Get-Date).AddMinutes(-$WindowMinutes)
    $systemProviders = @(
        'Microsoft-Windows-NDIS', 'Microsoft-Windows-WFP', 'Microsoft-Windows-TCPIP',
        'Service Control Manager', 'WinDivert', 'WinDivert14'
    )
    $anyFound = $false
    # Single Get-WinEvent with ProviderName array: one log-open instead of six.
    try {
        $all = @(Get-WinEvent -FilterHashtable @{
            LogName = 'System'; ProviderName = $systemProviders; StartTime = $startTime
        } -MaxEvents ($MaxEventsPerProvider * $systemProviders.Count) -ErrorAction Stop)
    } catch {
        # "No events were found matching the specified selection criteria"
        # is the common case (nothing happened in the window); anything else
        # is a real enumeration failure worth noting in the log.
        if ($_.Exception.Message -notmatch 'No events were found') {
            Write-UninstallDebug "Get-WinEvent (System providers) failed: $($_.Exception.Message)"
        }
        $all = @()
    }
    foreach ($group in ($all | Group-Object ProviderName)) {
        $anyFound = $true
        $events = @($group.Group | Sort-Object TimeCreated | Select-Object -First $MaxEventsPerProvider)
        Write-UninstallInfo "  [$($group.Name)] $($events.Count) event(s)"
        foreach ($e in $events) {
            $msg = ($e.Message -replace '[\r\n]+', ' ' -replace '\s+', ' ').Trim()
            if ($msg.Length -gt $EventLogMessageMaxChars) { $msg = $msg.Substring(0, $EventLogMessageMaxChars) + '...' }
            Write-UninstallInfo ("    [{0}] Id={1} Lvl={2}  {3}" -f $e.TimeCreated.ToString('HH:mm:ss'), $e.Id, $e.LevelDisplayName, $msg)
        }
    }
    try {
        $appEvents = Get-WinEvent -FilterHashtable @{ LogName = 'Application'; StartTime = $startTime } -ErrorAction Stop `
            | Where-Object { $_.ProviderName -match '(?i)sentinel|quilr|windivert' -or $_.Message -match '(?i)sentinel|quilr|windivert' } `
            | Select-Object -First $MaxEventsPerProvider
        if ($appEvents) {
            $appEvents = @($appEvents)
            $anyFound = $true
            Write-UninstallInfo "  [Application] $($appEvents.Count) sentinel/quilr/windivert-matching event(s)"
            foreach ($e in ($appEvents | Sort-Object TimeCreated)) {
                $msg = ($e.Message -replace '[\r\n]+', ' ' -replace '\s+', ' ').Trim()
                if ($msg.Length -gt $EventLogMessageMaxChars) { $msg = $msg.Substring(0, $EventLogMessageMaxChars) + '...' }
                Write-UninstallInfo ("    [{0}] {1} Id={2}  {3}" -f $e.TimeCreated.ToString('HH:mm:ss'), $e.ProviderName, $e.Id, $msg)
            }
        }
    } catch {
        if ($_.Exception.Message -notmatch 'No events were found') {
            Write-UninstallDebug "Get-WinEvent (Application, sentinel/quilr/windivert filter) failed: $($_.Exception.Message)"
        }
    }
    if (-not $anyFound) {
        Write-UninstallInfo "  (no relevant driver/service events in last ${WindowMinutes} minutes)"
    }
}

# Log all sentinel-related processes with PIDs -- called after uninstall to verify teardown.
function Log-SentinelProcesses {
    param([string]$Label)
    Write-UninstallInfo "--- Sentinel Processes ($Label) ---"
    $found = $false
    foreach ($name in $SentinelProcessNames) {
        $procs = Get-Process -Name $name -ErrorAction SilentlyContinue
        foreach ($p in $procs) {
            Write-UninstallInfo "  $($p.ProcessName) (PID $($p.Id))"
            $found = $true
        }
    }
    if (-not $found) {
        Write-UninstallInfo "  (none running)"
    }
}

function Test-Admin {
    $p = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# (same as uninstaller/)
# Schedule a locked file/dir for deletion on the next reboot via MoveFileEx
# with MOVEFILE_DELAY_UNTIL_REBOOT. Used for driver images (WinDivert64.sys)
# whose kernel handle is still open when we tear down. Returns $true if the
# OS accepted the schedule request.
$script:RebootRequired = $false
$script:__moveFileExLoaded = $false
function Schedule-DeleteOnReboot {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $false }
    if (-not $script:__moveFileExLoaded) {
        try {
            Add-Type -Namespace Quilr -Name NativeFs -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError=true, CharSet=System.Runtime.InteropServices.CharSet.Unicode)]
public static extern bool MoveFileEx(string lpExistingFileName, string lpNewFileName, int dwFlags);
'@ -ErrorAction Stop
            $script:__moveFileExLoaded = $true
        } catch {
            Write-UninstallException -Label "Add-Type MoveFileEx" -ErrorRecord $_
            return $false
        }
    }
    # MOVEFILE_DELAY_UNTIL_REBOOT = 0x4 ; lpNewFileName must be a TRUE null
    # pointer (delete on reboot). PowerShell marshals $null as an empty string
    # (=> Win32 error 3), so use [NullString]::Value to pass an actual null.
    try {
        $ok = [Quilr.NativeFs]::MoveFileEx($Path, [NullString]::Value, 0x4)
        if (-not $ok) {
            $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-UninstallWarn "    MoveFileEx schedule failed for '$Path' (Win32 error $err)"
        }
        return $ok
    } catch {
        Write-UninstallException -Label "MoveFileEx '$Path'" -ErrorRecord $_
        return $false
    }
}

function Remove-DirSafe {
    param([string]$Path, [string]$Label)
    if (-not (Test-Path $Path)) {
        Write-UninstallInfo "  Not found (skipping): $Label"
        return
    }
    Write-UninstallStep "Removing $Label..."
    # Propagate failures: the old `-ErrorAction SilentlyContinue` silently
    # skipped locked children (Remove-Item's default behaviour on a lock),
    # then unconditionally logged "Removed" -- masking leftover residue.
    # Now we capture the error, re-verify with Test-Path, and surface any
    # gap as a WARN with the actual exception so the final health-check
    # "minor notes" block reflects reality.
    try {
        Remove-Item -Path $Path -Recurse -Force -ErrorAction Stop
    } catch {
        Write-UninstallException -Label "Remove-Item $Label" -ErrorRecord $_ -Hints @(
            "Most common cause: a process still holds a handle on a file inside $Path.",
            "Confirm nothing running: Get-Process | Where-Object { `$_.Path -like '$Path\*' }",
            "Then retry: Remove-Item '$Path' -Recurse -Force"
        )
    }
    if (Test-Path $Path) {
        # Residue survived -- typically a locked driver image (WinDivert64.sys
        # held by the still-loaded WinDivert kernel driver). Remove-Item skips
        # locked children. Schedule each surviving item (deepest-first) plus the
        # directory for deletion on the next reboot via MoveFileEx, so the tree
        # is guaranteed to clear even when a handle is held now.
        $residue = @()
        try { $residue = @(Get-ChildItem -Path $Path -Recurse -Force -ErrorAction Stop | Select-Object -ExpandProperty FullName) } catch {
            Write-UninstallException -Label "Get-ChildItem $Path (enumerate residue)" -ErrorRecord $_
        }
        Write-UninstallWarn "  Residue at $Path ($($residue.Count) item(s) remain) -- scheduling deletion on reboot"
        foreach ($r in ($residue | Select-Object -First 5)) { Write-UninstallWarn "    - $r" }
        if ($residue.Count -gt 5) { Write-UninstallWarn "    ... +$($residue.Count - 5) more" }

        # Deepest paths first so files are scheduled before their parent folders.
        $ordered = @($residue | Sort-Object -Property Length -Descending) + @($Path)
        $scheduled = 0
        foreach ($item in $ordered) {
            if (Schedule-DeleteOnReboot -Path $item) { $scheduled++ }
        }
        if ($scheduled -gt 0) {
            $script:RebootRequired = $true
            Write-UninstallWarn "  $scheduled item(s) will be removed on next reboot (locked now). A reboot completes cleanup."
        }
    } else {
        Write-UninstallInfo "  Removed: $Path"
    }
}

# ── [Deployment extra] Per-step error handling ───────────────────────────────
# The base uninstaller/ calls functions directly. This wrapper lets -Force
# continue past individual step failures instead of aborting.

function Invoke-Step {
    # Wraps every uninstall step in a phase marker.  $Name is the
    # operator-facing label shown after "[N/M]"; callers still pass
    # "Step 1/9: ..." strings for backwards compat with the log file, so
    # we strip that prefix here to keep the CLI label clean.
    param(
        [string]$Name,
        [scriptblock]$Action
    )
    $phaseLabel = $Name -replace '^Step\s+\d+/\d+:\s*', ''
    Start-Phase $phaseLabel
    Write-UninstallInfo "$Name..."

    if ($DryRun) {
        Write-UninstallStep "(dry-run) Would execute: $Name"
        End-PhaseSkip "dry-run"
        return
    }

    try {
        & $Action
        Write-UninstallOk "$Name complete."
        End-PhaseOk
    } catch {
        $level = if ($Force) { "WARN" } else { "ERROR" }
        $reason = $_.Exception.Message
        Write-UninstallException -Label $Name -ErrorRecord $_ -Level $level -Hints @(
            $(if ($Force) { "Continuing past this step (-Force). The uninstall will report success if later steps pass." }
              else        { "Use -Force to continue past individual step failures." })
        )
        if ($Force) {
            # Mark the phase with a yellow warning marker so the operator
            # sees the step had issues but the flow continued.  Log already
            # has full exception detail.
            End-PhaseWarn -Reason "errors; continued (-Force)"
        } else {
            End-PhaseFail -Reason $reason
            exit 1
        }
    }
}

# =============================================================================
# PREFLIGHT CHECKS
# =============================================================================

if (-not $DryRun -and -not (Test-Admin)) {
    Write-UninstallError "This script must be run as Administrator."
    Write-UninstallError 'Right-click PowerShell and select "Run as Administrator".'
    exit 1
}

# =============================================================================
# STEP 1: Process & Service Teardown
# =============================================================================
# (same as uninstaller/sentinel_uninstaller.ps1 -- Stop-SentinelAll)

function Stop-SentinelAll {
    Write-UninstallInfo "Stopping Sentinel service and processes..."

    # Disable SCM failure-recovery so the service does not respawn during teardown.
    # sc.exe rejects `actions= ""` (empty value) -- the canonical "do nothing on
    # failure" syntax is three explicit `none/<delay>` pairs.  Benign if the
    # service was already removed (1060 = service not installed).
    Invoke-UninstallNative -Label "sc.exe failure $ServiceName (clear actions)" -FilePath "sc.exe" `
        -ArgumentList @("failure", $ServiceName, "reset=", "0", "actions=", "none/0/none/0/none/0") `
        -AllowedExitCodes @(0, 1060) `
        -Hints @("If this fails with exit!=1060, SCM may restart the service mid-kill -- check admin rights.") | Out-Null

    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($svc) {
        if ($svc.Status -ne "Stopped") {
            Write-UninstallStep "Stopping $ServiceName service (state=$($svc.Status))..."
            try {
                Stop-Service -Name $ServiceName -Force -ErrorAction Stop -WarningAction SilentlyContinue
            } catch {
                Write-UninstallException -Label "Stop-Service $ServiceName" -ErrorRecord $_ -Hints @(
                    "Force-kill sweep below will clean up remaining processes.",
                    "If service is stuck: sc.exe queryex $ServiceName  (look at PID, force-kill directly)."
                )
            }
            Start-Sleep -Seconds 3
        }
        Write-UninstallStep "Deleting $ServiceName service..."
        # sc.exe delete: 0 = ok, 1060 = service not installed (benign).
        Invoke-UninstallNative -Label "sc.exe delete $ServiceName" -FilePath "sc.exe" `
            -ArgumentList @("delete", $ServiceName) -AllowedExitCodes @(0, 1060) `
            -Hints @("1060 = service already gone (benign).") | Out-Null
    } else {
        Write-UninstallInfo "  $ServiceName not found (skipping)."
    }

    # ── Grace window before hard-kill ────────────────────────────────────
    # Stop-Service above triggered the agent's graceful-shutdown path
    # (kill-switch drain, service teardown in reverse-dependency order).
    # Poll for each child process to self-exit before taskkill /F -- so
    # a process that exited cleanly is never hit with a hard kill, and
    # we only spam taskkill for the survivors.  Total grace is capped at
    # PROCESS_DRAIN_GRACE so a stuck child can't stall the uninstaller.
    $procBaseNames  = $SentinelProcessNames
    $graceDeadline  = (Get-Date).AddSeconds($ProcessDrainGraceSeconds)
    $lastAliveCount = -1
    $alive = @()
    while ((Get-Date) -lt $graceDeadline) {
        # Single Get-Process for all names in one call (faster than N per-name
        # calls).  -Name accepts wildcards, not an array of literals in PS 5.1,
        # so we fetch everything once and filter in-memory.
        $running = Get-Process -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name -Unique
        $alive = @($procBaseNames | Where-Object { $running -contains $_ })
        if ($alive.Count -eq 0) {
            Write-UninstallInfo "  All Sentinel processes self-exited within grace window."
            break
        }
        if ($alive.Count -ne $lastAliveCount) {
            Write-UninstallStep "  Waiting for $($alive.Count) process(es) to self-exit: $($alive -join ', ')"
            $lastAliveCount = $alive.Count
        }
        Start-Sleep -Milliseconds $ProcessDrainPollMs
    }

    # $alive from the last loop iteration IS the survivor list (grace expired
    # without break) or empty (self-exited cleanly, no force-kill needed).
    if ($alive.Count -eq 0) {
        Write-UninstallOk "Clean shutdown: no force-kill needed."
    } else {
        Write-UninstallWarn "Force-killing $($alive.Count) survivor(s) after ${ProcessDrainGraceSeconds}s grace: $($alive -join ', ')"
        foreach ($name in $alive) {
            Invoke-UninstallNative -Label "taskkill /F /IM $name.exe" -FilePath "taskkill.exe" `
                -ArgumentList @("/F", "/IM", "$name.exe") -AllowedExitCodes @(0, 128) `
                -Hints @("exit 128 = process not running (benign).") | Out-Null
        }
        Start-Sleep -Seconds 2
    }

    # Pre-stop WinDivert immediately after killing sentinel-proxy (which held the
    # driver handle). This minimises the window where the NDIS filter is active
    # with no proxy to handle intercepted packets. The dedicated Remove-WinDivertDriver
    # step later performs full cleanup; this is an early safety net.
    $wdSvc = Get-Service -Name "WinDivert" -ErrorAction SilentlyContinue
    if ($wdSvc) {
        Write-UninstallStep "Pre-stopping WinDivert driver (early safety stop; state=$($wdSvc.Status))..."
        # 1062 = already stopped, 1060 = not installed -- both benign here.
        Invoke-UninstallNative -Label "sc.exe stop WinDivert (pre-stop)" -FilePath "sc.exe" `
            -ArgumentList @("stop", "WinDivert") -AllowedExitCodes @(0, 1062, 1060) `
            -Hints @("1062 = already stopped.", "1060 = not installed.") | Out-Null
        Start-Sleep -Seconds 2
    }

    Write-UninstallInfo "  All Sentinel processes stopped."
}

# =============================================================================
# STEP 2: Certificate Removal (before install dir is deleted)
# =============================================================================
# (same as uninstaller/sentinel_uninstaller.ps1 -- Remove-SentinelCert,
#  extended to also check LocalMachine store)

function Remove-SentinelCertFromStore {
    param(
        [Parameter(Mandatory = $true)][string]$CertPath,
        [Parameter(Mandatory = $true)][ValidateSet('Root', 'CA')][string]$StoreName,
        [Parameter(Mandatory = $true)][string]$Label
    )

    if (-not (Test-Path $CertPath)) {
        Write-UninstallInfo "  $Label not found at $CertPath -- skipping $StoreName store cleanup."
        return
    }

    $thumb = $null
    try {
        $thumb = (New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $CertPath).Thumbprint
    } catch {
        Write-UninstallException -Label "Parse $Label ($CertPath)" -ErrorRecord $_
        return
    }
    if (-not $thumb) {
        Write-UninstallWarn "  Could not read thumbprint from $CertPath -- skipping."
        return
    }

    # Committing a Root-store deletion can pop a modal Windows security dialog
    # ("Deleting system root certificates might prevent some Windows components
    # from working properly").  If the user dismisses it with No -- or if no
    # user is present to dismiss it at all (scheduled task, locked session) --
    # the CAPI call blocks inside $store.Close() for up to ~2 minutes before
    # CryptoAPI surfaces the cancellation, and in headless cases blocks
    # indefinitely.  CA store removals don't pop the dialog, but use the same
    # safe path for consistency.  Two-part mitigation per store location:
    #   (1) Probe with ReadOnly -- no dialog, fast.  99% of runs skip here.
    #   (2) Only if the cert is present, do the write in a runspace with a
    #       15 s hard timeout.  On timeout we log a WARN + manual command and
    #       continue, because cert trust is cosmetic (install dir is about to
    #       be deleted anyway).
    foreach ($loc in @('CurrentUser', 'LocalMachine')) {
        # --- probe (ReadOnly; no dialog) ---
        $present = $false
        try {
            $probe = New-Object System.Security.Cryptography.X509Certificates.X509Store($StoreName, $loc)
            $probe.Open('ReadOnly')
            $present = [bool]@($probe.Certificates | Where-Object { $_.Thumbprint -eq $thumb }).Count
            $probe.Close()
        } catch {
            Write-UninstallWarn "  $loc $StoreName probe failed: $($_.Exception.Message)"
            continue
        }
        if (-not $present) {
            Write-UninstallInfo "  $Label not in $loc $StoreName store (skipping)."
            continue
        }

        # --- remove (ReadWrite, runspace, 15s timeout) ---
        $ps = [PowerShell]::Create()
        [void]$ps.AddScript({
            param($tp, $lc, $sn)
            $store = New-Object System.Security.Cryptography.X509Certificates.X509Store($sn, $lc)
            $store.Open('ReadWrite')
            $hits = @($store.Certificates | Where-Object { $_.Thumbprint -eq $tp })
            foreach ($c in $hits) { $store.Remove($c) }
            $store.Close()   # blocking dialog fires here, if at all
            return $hits.Count
        })
        [void]$ps.AddArgument($thumb)
        [void]$ps.AddArgument($loc)
        [void]$ps.AddArgument($StoreName)

        $handle = $ps.BeginInvoke()
        $done   = $handle.AsyncWaitHandle.WaitOne([TimeSpan]::FromSeconds(15))
        if (-not $done) {
            Write-UninstallWarn "  $loc $StoreName cert removal timed out after 15s (likely waiting on a Windows security dialog)."
            Write-UninstallWarn "  Uninstaller is continuing; residual cert trust is cosmetic.  Manual cleanup:"
            Write-UninstallWarn "    Get-ChildItem Cert:\$loc\$StoreName | Where-Object Thumbprint -eq '$thumb' | Remove-Item -Force"
            try { $ps.Stop() } catch {}
            $ps.Dispose()
            continue
        }
        try {
            $count = $ps.EndInvoke($handle)
            if ($ps.HadErrors) {
                $err = $ps.Streams.Error | Select-Object -First 1
                Write-UninstallWarn "  $loc $StoreName cert removal returned error: $($err.Exception.Message)"
            } else {
                Write-UninstallInfo "  $Label removed from $loc $StoreName store (thumbprint: $thumb, count=$count)."
            }
        } catch {
            Write-UninstallException -Label "$loc $StoreName cert removal" -ErrorRecord $_ -Hints @(
                "Cert may have been removed by the user after the probe; benign."
            )
        } finally {
            $ps.Dispose()
        }
    }
}

# Common Names ever planted into Windows cert stores by the installer or the
# dev builder. Edit alongside any cert-subject change. Mirrors the mac
# uninstaller's SENTINEL_CA_COMMON_NAMES array (commit 1e0a7127).
$SentinelCaSubjects = @(
    "Quilr EA Root CA",
    "Quilr EA Intermediate CA",
    "Quilr Proxy Root CA"
)

# Phase-2 CN sweep -- fallback for cases the path-based
# Remove-SentinelCertFromStore can't handle:
#   (a) $InstallDir was manually deleted before uninstall ran (no cert.pem
#       on disk to compute the thumbprint from)
#   (b) Stale duplicates from dev re-installs that never ran uninstall
#   (c) Rotated intermediate where the pre-rotation thumbprint differs from
#       the cert.pem currently on disk
# Uses the same probe-ReadOnly-then-runspace-with-15s-timeout pattern as
# Remove-SentinelCertFromStore so a blocking "delete system root cert"
# modal dialog can't hang the uninstaller.
function Remove-SentinelCertsBySubject {
    foreach ($subj in $SentinelCaSubjects) {
        $anyHit = $false
        foreach ($loc in @('CurrentUser', 'LocalMachine')) {
            foreach ($sn in @('Root', 'CA')) {
                # --- probe (ReadOnly; no dialog) ---
                $thumbs = @()
                try {
                    $probe = New-Object System.Security.Cryptography.X509Certificates.X509Store($sn, $loc)
                    $probe.Open('ReadOnly')
                    $thumbs = @($probe.Certificates | Where-Object { $_.Subject -like "*CN=$subj*" } | ForEach-Object { $_.Thumbprint })
                    $probe.Close()
                } catch {
                    Write-UninstallWarn "  CN='$subj' $loc\$sn probe failed: $($_.Exception.Message)"
                    continue
                }
                if ($thumbs.Count -eq 0) { continue }
                $anyHit = $true

                foreach ($thumb in $thumbs) {
                    # --- remove (ReadWrite, runspace, 15s timeout) ---
                    $ps = [PowerShell]::Create()
                    [void]$ps.AddScript({
                        param($tp, $lc, $sn)
                        $store = New-Object System.Security.Cryptography.X509Certificates.X509Store($sn, $lc)
                        $store.Open('ReadWrite')
                        $hits = @($store.Certificates | Where-Object { $_.Thumbprint -eq $tp })
                        foreach ($c in $hits) { $store.Remove($c) }
                        $store.Close()  # blocking dialog fires here, if at all
                        return $hits.Count
                    })
                    [void]$ps.AddArgument($thumb)
                    [void]$ps.AddArgument($loc)
                    [void]$ps.AddArgument($sn)

                    $handle = $ps.BeginInvoke()
                    $done   = $handle.AsyncWaitHandle.WaitOne([TimeSpan]::FromSeconds(15))
                    if (-not $done) {
                        Write-UninstallWarn "  CN='$subj' $loc\$sn cert removal timed out after 15s (likely waiting on a Windows security dialog)."
                        Write-UninstallWarn "    Manual cleanup: Get-ChildItem Cert:\$loc\$sn | Where-Object Thumbprint -eq '$thumb' | Remove-Item -Force"
                        try { $ps.Stop() } catch {}
                        $ps.Dispose()
                        continue
                    }
                    try {
                        $count = $ps.EndInvoke($handle)
                        if ($ps.HadErrors) {
                            $err = $ps.Streams.Error | Select-Object -First 1
                            Write-UninstallWarn "  CN='$subj' $loc\$sn cert removal returned error: $($err.Exception.Message)"
                        } else {
                            Write-UninstallInfo "  CN='$subj': removed from $loc\$sn (thumbprint: $thumb, count=$count)."
                        }
                    } catch {
                        Write-UninstallException -Label "CN='$subj' $loc\$sn cert removal" -ErrorRecord $_ -Hints @(
                            "Cert may have been removed by the user after the probe; benign."
                        )
                    } finally {
                        $ps.Dispose()
                    }
                }
            }
        }
        if (-not $anyHit) {
            Write-UninstallInfo "  CN='$subj': not present in any cert store."
        }
    }
}

function Remove-SentinelCert {
    Write-UninstallInfo "Removing Sentinel CA certificates from trusted stores..."

    # Phase 1 -- path-based removal (matches what the installer imported).
    # Strict-mode builds: root.pem trusted in Root, cert.pem (intermediate) in CA.
    # Legacy single-cert builds: only cert.pem in Root.
    # Each call is a no-op if the cert isn't present in that store.
    $rootPath = Join-Path $InstallDir "root.pem"
    $certPath = Join-Path $InstallDir "cert.pem"

    Remove-SentinelCertFromStore -CertPath $rootPath -StoreName 'Root' -Label 'Root CA (root.pem)'
    Remove-SentinelCertFromStore -CertPath $certPath -StoreName 'CA'   -Label 'Intermediate CA (cert.pem)'
    # Legacy path: pre-intermediate builds put cert.pem directly in Root.
    Remove-SentinelCertFromStore -CertPath $certPath -StoreName 'Root' -Label 'Legacy CA (cert.pem)'

    # Phase 2 -- CN sweep. Covers what Phase 1 misses: support dir already
    # deleted, certs imported from a different path (dev rebuilds, rotations),
    # or stale duplicates from earlier installs.
    Write-UninstallInfo "Sweeping cert stores by Common Name for any residual Quilr/Sentinel CAs..."
    Remove-SentinelCertsBySubject

    Write-UninstallInfo "  Verify none remain: Get-ChildItem Cert:\CurrentUser\Root, Cert:\CurrentUser\CA, Cert:\LocalMachine\Root, Cert:\LocalMachine\CA | Where-Object { `$_.Subject -like '*Quilr*' }"
}

# =============================================================================
# STEP 3: File System Cleanup
# =============================================================================
# (same as uninstaller/sentinel_uninstaller.ps1 -- Remove-SentinelFiles)

function Remove-SentinelFiles {
    Write-UninstallInfo "Removing Sentinel files..."

    if (-not $KeepInstallDir) {
        Remove-DirSafe -Path $InstallDir -Label "install dir ($InstallDir)"
    } else {
        Write-UninstallInfo "  Keeping install dir (-KeepInstallDir): $InstallDir"
    }

    Remove-DirSafe -Path $HooksDir -Label "hooks dir ($HooksDir)"

    if ($KeepData) {
        Write-UninstallInfo "  Quilr app data preserved (-KeepData): $QuilrDir"
    } else {
        Remove-DirSafe -Path $QuilrDir -Label "Quilr app data ($QuilrDir)"
        Remove-DirSafe -Path $SentinelUserDir -Label "Sentinel user data ($SentinelUserDir)"
        Remove-DirSafe -Path $QuilrProgramDataDir -Label "Quilr ProgramData ($QuilrProgramDataDir)"
    }

    # Tenant ID file (canonical QUILR_TENANT_ID source of truth). Always
    # remove regardless of -KeepLogs -- the tenant association is org-bound,
    # not log data, and must not leak across re-installs.
    $tenantIdFile = Join-Path $DataDir "tenant_id"
    if (Test-Path $tenantIdFile) {
        try {
            Remove-Item -Path $tenantIdFile -Force -ErrorAction Stop
            Write-UninstallStep "  Removed: $tenantIdFile"
        } catch {
            Write-UninstallWarn "  Could not remove $tenantIdFile -- $($_.Exception.Message)"
        }
    }

    if ($KeepLogs) {
        Write-UninstallInfo "  Data/logs preserved (-KeepLogs): $DataDir"
    } else {
        Remove-DirSafe -Path $DataDir -Label "Sentinel data/logs ($DataDir)"
    }
}

# =============================================================================
# STEP 4: Environment Variables
# =============================================================================
# (same as uninstaller/sentinel_uninstaller.ps1 -- Remove-SentinelEnvVars)

function Remove-SentinelEnvVars {
    Write-UninstallInfo "Removing Quilr environment variables..."

    # Machine-scope vars set by installer (HKLM, via setx /M)
    foreach ($var in @("NODE_EXTRA_CA_CERTS", "NODE_TLS_REJECT_UNAUTHORIZED")) {
        [System.Environment]::SetEnvironmentVariable($var, $null, [System.EnvironmentVariableTarget]::Machine)
        Write-UninstallStep "  Removed machine-scope: $var"
    }

    # User-scope vars set by the rebranded installer (HKCU) + the MSI launcher's
    # Machine-scope promotion. Include legacy SENTINEL_* names so older installs
    # are also cleaned. The MSI launcher promotes several to Machine scope, so we
    # clear both User and Machine for each.
    $quilrVars = @(
        "QUILRAI_OVERRIDE_EMAIL", "QUILRAI_TEMPLATE_DIR", "QUILRAI_INSTALLATION_PATH",
        "QUILRAI_UNIFIED_DLP_POLICY", "QUILR_DLP_ENDPOINT", "QUILR_BACKEND_BASE_URL",
        "QUILR_TENANT_ID",
        # legacy Sentinel-named vars from older builds
        "SENTINEL_OVERRIDE_EMAIL", "SENTINEL_TEMPLATE_DIR", "SENTINEL_INSTALLATION_PATH",
        "SENTINEL_UNIFIED_DLP_POLICY"
    )
    foreach ($var in $quilrVars) {
        [System.Environment]::SetEnvironmentVariable($var, $null, [System.EnvironmentVariableTarget]::User)
        [System.Environment]::SetEnvironmentVariable($var, $null, [System.EnvironmentVariableTarget]::Machine)
        Write-UninstallStep "  Removed user+machine scope: $var"
    }

    # Clear from current PowerShell session.  ItemNotFoundException here just
    # means the var wasn't set in this session -- expected when the uninstaller
    # is launched in a shell that never saw the installer's env.  Capture +
    # route to the log at WARN only if the error is something other than "not
    # found", so real issues (e.g. read-only env provider) don't stay silent.
    foreach ($var in (@("NODE_EXTRA_CA_CERTS", "NODE_TLS_REJECT_UNAUTHORIZED") + $quilrVars)) {
        try {
            Remove-Item "Env:\$var" -ErrorAction Stop
        } catch [System.Management.Automation.ItemNotFoundException] {
            # Benign: session never had this var.  Nothing to log.
        } catch {
            Write-UninstallException -Label "Remove-Item Env:\$var (session clear)" -ErrorRecord $_
        }
    }
    Write-UninstallInfo "  Cleared from current PowerShell session."

    # Remove the persisted-env registry key written by the installer.
    # Matches HKLM:\SOFTWARE\Quilr\Sentinel\Env (REG_SZ) -- the authoritative
    # record of "which env was this machine installed with".  Removing it
    # keeps a future re-install from silently inheriting the old env.
    $sentinelRegRoot = "HKLM:\SOFTWARE\Quilr\Sentinel"
    if (Test-Path $sentinelRegRoot) {
        try {
            Remove-Item -Path $sentinelRegRoot -Recurse -Force -ErrorAction Stop
            Write-UninstallStep "  Removed registry key: $sentinelRegRoot"
        } catch {
            Write-UninstallWarn "  Could not remove $sentinelRegRoot -- $($_.Exception.Message)"
            Write-UninstallWarn "  Manually: Remove-Item '$sentinelRegRoot' -Recurse -Force"
        }
    }

    # Write CMD helper for users in an existing CMD window
    $cmdHelper = Join-Path $env:TEMP "quilrai_clear_env.cmd"
    $lines = @(
        "@echo off",
        "set NODE_EXTRA_CA_CERTS=",
        "set NODE_TLS_REJECT_UNAUTHORIZED=",
        "set QUILRAI_OVERRIDE_EMAIL=",
        "set QUILRAI_TEMPLATE_DIR=",
        "set QUILRAI_INSTALLATION_PATH=",
        "set QUILRAI_UNIFIED_DLP_POLICY=",
        "set QUILR_TENANT_ID=",
        "set QUILR_DLP_ENDPOINT=",
        "set QUILR_BACKEND_BASE_URL=",
        "echo [*] Quilr environment variables cleared."
    )
    Set-Content -Path $cmdHelper -Value ($lines -join "`r`n") -Encoding ASCII
    # Route the "how to clear vars in current shell" hint through INFO (file
    # only in quiet mode).  It's informational, not a warning -- surfacing
    # it in the final success panel keeps the phase flow clean.
    Write-UninstallInfo "  CMD users: run once to clear vars in current session:"
    Write-UninstallInfo "    $cmdHelper"
    $script:CmdEnvResetHelper = $cmdHelper
}

# =============================================================================
# STEP 5: QUIC Browser Policy Cleanup
# =============================================================================
# (same as uninstaller/sentinel_uninstaller.ps1 -- Remove-QuicPolicies)

function Remove-QuicPolicies {
    Write-UninstallInfo "Removing QUIC browser policies..."
    foreach ($path in $QuicPolicyPaths) {
        if (Test-Path $path) {
            $prop = Get-ItemProperty -Path $path -Name "QuicAllowed" -ErrorAction SilentlyContinue
            if ($prop) {
                try {
                    Remove-ItemProperty -Path $path -Name "QuicAllowed" -ErrorAction Stop
                    Write-UninstallStep "  Removed QuicAllowed from $path"
                } catch {
                    # Residue here leaves the browser's QUIC policy unchanged,
                    # so the agent's proxy replacement won't see QUIC traffic
                    # post-uninstall -- user-actionable.
                    Write-UninstallException -Label "Remove-ItemProperty QuicAllowed @ $path" -ErrorRecord $_ -Hints @(
                        "Typical cause: HKLM write ACL denied -- rerun uninstaller as Administrator.",
                        "Manual: Remove-ItemProperty -Path '$path' -Name 'QuicAllowed' -Force"
                    )
                }
            } else {
                Write-UninstallInfo "  QuicAllowed not set in $path (skipping)."
            }
        }
    }
}

# =============================================================================
# STEP 6: IPv6 Re-enable
# =============================================================================
# (same as uninstaller/sentinel_uninstaller.ps1 -- Enable-IPv6Adapters)

function Enable-IPv6Adapters {
    Write-UninstallInfo "Re-enabling IPv6 on active network adapters..."

    # Enumerate all adapters (Up + Disconnected; adapter-reset may briefly
    # leave them non-Up). Query the ms_tcpip6 binding per-adapter so adapters
    # that simply don't have the binding component are classified as "skipped"
    # rather than contributing to a failure count.
    $adapters = @()
    try {
        $adapters = @(Get-NetAdapter -ErrorAction Stop | Where-Object { $_.Status -in @("Up", "Disconnected") })
    } catch {
        Write-UninstallException -Label "Get-NetAdapter (enumerate for IPv6 enable)" -ErrorRecord $_ -Hints @(
            "Per-adapter re-enable skipped; registry cleanup below will still run."
        )
    }

    if ($adapters.Count -eq 0) {
        Write-UninstallInfo "  No active/disconnected adapters found."
    } else {
        $enabledNow = @()
        $alreadyOn  = @()
        $unsupported = @()
        $failed = @()

        foreach ($adapter in $adapters) {
            $name = $adapter.Name
            $status = $adapter.Status
            $binding = $null
            try {
                $binding = Get-NetAdapterBinding -Name $name -ComponentID ms_tcpip6 -ErrorAction Stop
            } catch {
                $reason = $_.Exception.Message
                if ($reason -match "No MSFT_NetAdapterBinding") { $reason = "ms_tcpip6 binding not present on this adapter" }
                $unsupported += $name
                Write-UninstallStep "  [skip] '$name' (status=$status) -- $reason"
                continue
            }

            if ($binding.Enabled) {
                $alreadyOn += $name
                Write-UninstallStep "  [skip] '$name' (status=$status) -- IPv6 already enabled"
                continue
            }

            try {
                Enable-NetAdapterBinding -Name $name -ComponentID ms_tcpip6 -ErrorAction Stop
                $enabledNow += $name
                Write-UninstallStep "  [OK] IPv6 re-enabled: '$name' (status=$status)"
            } catch {
                $failed += "$name [$status]"
                Write-UninstallException -Label "Enable-NetAdapterBinding '$name'" -ErrorRecord $_ -Context @(
                    "Adapter status: $status",
                    "Component:      ms_tcpip6"
                ) -Hints @(
                    "Group Policy may pin IPv6 off -- inspect: gpresult /h gp.html.",
                    "Manual retry: Enable-NetAdapterBinding -Name '$name' -ComponentID ms_tcpip6"
                )
            }
        }

        Write-UninstallInfo "  IPv6 per-adapter summary: $($enabledNow.Count) re-enabled, $($alreadyOn.Count) already-on, $($unsupported.Count) skipped-unsupported, $($failed.Count) failed (of $($adapters.Count) total)"
        if ($enabledNow.Count  -gt 0) { Write-UninstallInfo "    Re-enabled:  $($enabledNow -join ', ')" }
        if ($unsupported.Count -gt 0) { Write-UninstallInfo "    Skipped (no ms_tcpip6 binding): $($unsupported -join ', ')" }
        if ($failed.Count      -gt 0) { Write-UninstallWarn "    Failed: $($failed -join ' | ')" }
    }

    # Registry cleanup -- drop the DisabledComponents override so future
    # reboots do not re-disable IPv6. Use PSObject.Properties.Name to guard
    # against StrictMode "property cannot be found" errors when the value
    # is absent (common on machines that never had our registry write applied).
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
    if (-not (Test-Path $regPath)) {
        Write-UninstallStep "  Registry path $regPath not present (nothing to clean)."
        return
    }
    try {
        $regObj = Get-ItemProperty -Path $regPath -ErrorAction Stop
        if ($regObj -and ($regObj.PSObject.Properties.Name -contains "DisabledComponents")) {
            $current = $regObj.DisabledComponents
            if ($current -eq 0xFF) {
                Remove-ItemProperty -Path $regPath -Name DisabledComponents -Force -ErrorAction Stop
                Write-UninstallStep "  Registry DisabledComponents=0xFF removed (IPv6 will not be pinned off across reboots)."
            } else {
                Write-UninstallStep "  Registry DisabledComponents=0x$('{0:X}' -f $current) -- not our override (0xFF), leaving untouched."
            }
        } else {
            Write-UninstallStep "  Registry DisabledComponents value not set (nothing to clean)."
        }
    } catch {
        Write-UninstallException -Label "Clean registry DisabledComponents" -ErrorRecord $_ -Context @(
            "Registry path: $regPath"
        ) -Hints @(
            "Non-fatal -- per-adapter re-enable above still applied.",
            "Check: Get-ItemProperty -Path '$regPath' -Name DisabledComponents"
        )
    }
}

# =============================================================================
# [Deployment extra] STEP 7: Remove updater scheduled task
# =============================================================================
# The updater schedule is created by the distribution installer's
# Register-UpdaterSchedule. The base uninstaller/ doesn't know about it.

function Remove-UpdaterSchedule {
    # Use ScheduledTasks cmdlets rather than schtasks.exe via cmd /c.
    # cmd /c leaks the native "ERROR: The system cannot find the file specified."
    # onto stderr when the task is absent, which surfaces as a caught exception
    # under $ErrorActionPreference = "Stop" despite the 2>$null redirect.
    $existing = Get-ScheduledTask -TaskName $UpdaterTaskName -ErrorAction SilentlyContinue
    if ($existing) {
        try {
            Unregister-ScheduledTask -TaskName $UpdaterTaskName -Confirm:$false -ErrorAction Stop | Out-Null
            Write-UninstallStep "Removed scheduled task: $UpdaterTaskName"
        } catch {
            Write-UninstallException -Label "Unregister-ScheduledTask '$UpdaterTaskName'" -ErrorRecord $_ -Hints @(
                "Task may be running right now -- schtasks /End /TN `"$UpdaterTaskName`", then retry.",
                "Manual fallback: schtasks /Delete /TN `"$UpdaterTaskName`" /F"
            )
        }
    } else {
        Write-UninstallStep "Updater scheduled task not found, skipping."
    }

    # Remove the launcher .bat and any staged self-update artifacts created by
    # the installer's Register-UpdaterSchedule / self-update path. The full
    # install dir is removed later, but cleaning these up defensively means a
    # re-install won't see stale .new / .backup files that trigger the
    # self-update swap with a prior-version binary.
    foreach ($name in @(
        "run-updater.bat",
        "sentinel-endpoint.exe.new",
        "sentinel-endpoint.exe.backup",
        "sentinel-endpoint.ps1.new",
        "sentinel-endpoint.ps1.backup"
    )) {
        $p = Join-Path $InstallDir $name
        if (Test-Path $p) {
            try {
                Remove-Item -Path $p -Force -ErrorAction Stop
                Write-UninstallStep "Removed $p"
            } catch {
                # Non-fatal: the install dir gets removed wholesale in
                # Remove-SentinelFiles, which will log its own residue WARN if
                # this file survives there too.  Still surface the reason
                # here so "why did the later step also fail?" is traceable.
                Write-UninstallException -Label "Remove-Item $p (updater artefact)" -ErrorRecord $_ -Hints @(
                    "If this is '.exe.new' or '.backup', the updater mid-swap has the handle."
                )
            }
        }
    }

    # Remove updater logs
    if (Test-Path $UpdaterLogDir) {
        try {
            Remove-Item -Path $UpdaterLogDir -Recurse -Force -ErrorAction Stop
            Write-UninstallStep "Removed $UpdaterLogDir"
        } catch {
            Write-UninstallException -Label "Remove-Item $UpdaterLogDir" -ErrorRecord $_ -Hints @(
                "A log file is likely still open by a running updater.  Kill lingering sentinel-endpoint.exe, then: Remove-Item '$UpdaterLogDir' -Recurse -Force"
            )
        }
    }

    # C:\ProgramData\Quilr is fully removed in Remove-SentinelFiles.
}

# =============================================================================
# [Deployment extra] STEP 8: Clean up WinDivert driver
# =============================================================================
# WinDivert is the packet redirection driver. If it's still loaded in the
# kernel after the agent is gone, it can intercept traffic with no handler.
# The base uninstaller/ relies on Remove-Item for the install dir. This
# explicitly stops the driver service first.

function Remove-WinDivertDriver {
    $sysFile = Join-Path $InstallDir "WinDivert64.sys"
    foreach ($drvName in @("WinDivert", "WinDivert14")) {
        $driverService = Get-Service -Name $drvName -ErrorAction SilentlyContinue
        $scExists = $false
        try { & sc.exe query $drvName *>$null; $scExists = ($LASTEXITCODE -eq 0) } catch { }
        if (-not $driverService -and -not $scExists) { continue }
        Write-UninstallStep "WinDivert driver '$drvName' present -- stopping and unloading..."

        # The driver image stays mapped (and WinDivert64.sys stays locked) until
        # its last handle closes. quilrai-proxy.exe is the usual holder; make
        # sure the known holders are dead so 'sc stop' can actually unload.
        foreach ($holder in @("quilrai-proxy", "quilrai", "sentinel-proxy", "sentinel")) {
            & taskkill.exe /F /IM "$holder.exe" *>$null
        }

        Invoke-UninstallNative -Label "sc.exe stop $drvName" -FilePath "sc.exe" `
            -ArgumentList @("stop", $drvName) -AllowedExitCodes @(0, 1062, 1060) `
            -Hints @("1062 = already stopped.", "1060 = not installed.") | Out-Null

        # Actively drive the unload: retry deleting WinDivert64.sys. The delete
        # succeeds the moment the kernel releases the driver image, so this both
        # confirms the unload AND removes the file -- no reboot needed in the
        # common case. Poll up to ~20s.
        $unloaded = $false
        for ($i = 0; $i -lt 20; $i++) {
            if (-not (Test-Path $sysFile)) { $unloaded = $true; break }
            try { Remove-Item -Path $sysFile -Force -ErrorAction Stop; $unloaded = $true; break }
            catch { Start-Sleep -Seconds 1 }
        }

        Invoke-UninstallNative -Label "sc.exe delete $drvName" -FilePath "sc.exe" `
            -ArgumentList @("delete", $drvName) -AllowedExitCodes @(0, 1060) `
            -Hints @("1060 = already gone.") | Out-Null

        if ($unloaded) {
            Write-UninstallStep "WinDivert driver '$drvName' unloaded and image removed."
        } else {
            Write-UninstallWarn "WinDivert driver '$drvName' image still locked after 20s -- a handle is held."
            Write-UninstallWarn "  WinDivert64.sys will be scheduled for deletion on reboot during file cleanup."
            Write-UninstallWarn "  Inspect now: handle.exe WinDivert64  (Sysinternals)"
        }
    }

    # Remove WinDivert files from install dir.  If the NDIS driver handle is
    # still pinned, the .sys / .dll sit locked until kernel releases them;
    # Remove-SentinelFiles runs after an extra settle and picks them up on
    # the dir-wide sweep.  Capture the specific failure for the log trail.
    foreach ($wdFile in @("WinDivert.dll", "WinDivert.lib", "WinDivert64.sys")) {
        $path = Join-Path $InstallDir $wdFile
        if (Test-Path $path) {
            try {
                Remove-Item -Path $path -Force -ErrorAction Stop
                Write-UninstallStep "Removed $wdFile"
            } catch {
                Write-UninstallException -Label "Remove-Item $wdFile (will retry at dir removal)" -ErrorRecord $_ -Hints @(
                    "Kernel driver handle likely still held.  The dir-wide Remove-Item in Remove-SentinelFiles will retry after the settle window."
                )
            }
        }
    }
}

# =============================================================================
# [Deployment extra] STEP 9: Reset network adapters after WinDivert removal
# =============================================================================
# WinDivert is a kernel-mode NDIS filter driver. When it is removed at runtime
# (without a reboot), NDIS must re-bind the remaining protocol stack (TCP/IP)
# to the adapter. This re-binding is asynchronous and can leave the adapter in
# a broken intermediate state: WiFi shows connected (L2/radio is fine) but IP
# traffic cannot flow. A Disable → Enable cycle on each adapter forces NDIS to
# fully reinitialize, avoiding the need for a reboot.

function Reset-NetworkAdapters {
    Write-UninstallInfo "Resetting network adapters to force NDIS stack rebind after WinDivert removal..."

    # Flush DNS cache (clears entries that were resolved through the proxy)
    ipconfig /flushdns 2>$null | Out-Null
    Write-UninstallStep "  DNS cache flushed."

    # Use a broader status filter -- the adapter may be in a transient state
    # (e.g., "Disconnected") immediately after WinDivert is removed.
    $adapters = Get-NetAdapter | Where-Object { $_.Status -in @("Up", "Disconnected") }
    if (-not $adapters) {
        Write-UninstallInfo "  No active/disconnected adapters found to reset."
        return
    }
    foreach ($adapter in $adapters) {
        Write-UninstallStep "  Resetting adapter: $($adapter.Name) (status: $($adapter.Status))..."
        try {
            Disable-NetAdapter -Name $adapter.Name -Confirm:$false -ErrorAction Stop
        } catch {
            # Network connectivity check further down is the true verdict --
            # if disable fails but the adapter was already in the desired
            # state (or we lost admin rights mid-run), the connectivity
            # probe catches it.  Record the cmdlet failure reason so a
            # downstream "Network connectivity test failed" WARN isn't mute.
            Write-UninstallException -Label "Disable-NetAdapter $($adapter.Name)" -ErrorRecord $_
        }
        Start-Sleep -Milliseconds 800
        try {
            Enable-NetAdapter -Name $adapter.Name -Confirm:$false -ErrorAction Stop
        } catch {
            Write-UninstallException -Label "Enable-NetAdapter $($adapter.Name)" -ErrorRecord $_ -Hints @(
                "Adapter left disabled -- re-enable manually: Enable-NetAdapter -Name '$($adapter.Name)' -Confirm:`$false"
            )
        }
        Write-UninstallStep "  Adapter reset: $($adapter.Name)"
    }

    # Give adapters time to re-associate with AP and complete DHCP
    Write-UninstallStep "  Waiting for adapters to re-initialize (5s)..."
    Start-Sleep -Seconds 5
    Write-UninstallInfo "  Network adapters reset."
}

# =============================================================================
# MAIN -- Execute all uninstall steps in order
# =============================================================================

$OriginalDir = (Get-Location).Path

# Initialize under strict mode so later `Test-Path variable:` / read doesn't
# throw if Remove-SentinelEnvVars didn't run (e.g. early exit, -DryRun).
$script:CmdEnvResetHelper = $null

try {
    # Audit-trail to file, compact banner to CLI.
    Write-UninstallInfo "Quilr Sentinel Endpoint Agent -- Uninstaller (Windows)"
    Write-UninstallInfo "Install dir:    $InstallDir"
    Write-UninstallInfo "Hooks dir:      $HooksDir"
    Write-UninstallInfo "Quilr data:     $QuilrDir"
    Write-UninstallInfo "Data/logs:      $DataDir"
    Write-UninstallInfo "Force mode:     $Force"
    Write-UninstallInfo "Dry-run:        $DryRun"
    Write-UninstallInfo "Keep logs:      $KeepLogs"
    Write-UninstallInfo "Keep data:      $KeepData"
    Write-UninstallInfo "Keep install:   $KeepInstallDir"
    Write-UninstallInfo "Skip IPv6:      $SkipIPv6"
    Write-UninstallInfo "Log file:       $LogFile"

    $bannerMode = if ($DryRun) { "Dry run (no changes)" } else { "Uninstalling" }
    Show-CliBanner -Title "Quilr Sentinel Endpoint Agent" `
                   -Subtitles @("$bannerMode  -  log: $LogFile")
    # 9 teardown steps + 1 post-uninstall verification phase.
    Start-CliFlow -TotalSteps 10

    # ── [Deployment extra] Dry-run: list steps and exit ──────────────────────

    if ($DryRun) {
        Write-UninstallInfo "DRY RUN - The following steps would be executed:"
        Write-Host ""
        $steps = @(
            "1.  Stop updater scheduled task ($UpdaterTaskName) -- prevents respawn during uninstall"
            "2.  Kill all running sentinel processes and delete service ($ServiceName)"
            "3.  Remove trusted certificate from Windows cert stores"
            "4.  Clean up WinDivert driver and files"
            "5.  Reset network adapters (NDIS rebind -- prevents internet loss without reboot)"
            "6.  Remove Sentinel files (install dir, hooks, app data, logs)"
            "7.  Remove Sentinel environment variables (machine-wide + user)"
            "8.  Remove QUIC browser policies (Chrome, Edge registry)"
        )
        if (-not $SkipIPv6) { $steps += "9.  Re-enable IPv6 on all network adapters" }
        $steps += ""
        $steps += "Post-uninstall: Health checks (processes, service, network connectivity)"

        foreach ($step in $steps) {
            Write-Host "    $step"
        }
        Write-Host ""
        Write-UninstallInfo "Re-run without -DryRun to execute."
        exit 0
    }

    # No confirmation prompt -- distribution uninstaller always executes.
    # Use -DryRun to preview what will be done.
    Write-UninstallInfo "Proceeding with uninstall (use -DryRun to preview without changes)..."
    Write-Host ""

    # ── Execute all steps in order ────────────────────────────────────────
    # ORDERING IS CRITICAL:
    # - Updater schedule stopped FIRST to prevent respawn during teardown
    # - Processes killed and service deleted BEFORE files are touched
    # - Certificate removed BEFORE install dir is deleted (needs cert.pem)
    # - WinDivert driver stopped BEFORE trying to delete its files
    # - Network adapters reset AFTER WinDivert removal to force NDIS rebind
    #   (prevents "WiFi connected but no internet" without requiring a reboot)

    # Capture driver / filter / service baseline BEFORE teardown modifies state.
    # Useful when the uninstall reveals a pre-existing stuck driver -- the
    # baseline distinguishes "we broke it" from "it was already broken".
    Write-SystemExtensionLogDump -Label "pre-uninstall"
    Write-NetworkSnapshot -Label "pre-uninstall"
    Write-Host ""

    Invoke-Step -Name "Step 1/10: Stopping updater schedule"         -Action { Remove-UpdaterSchedule }
    Invoke-Step -Name "Step 2/10: Stopping service and processes"    -Action { Stop-SentinelAll }
    Invoke-Step -Name "Step 3/10: Removing certificate trust"        -Action { Remove-SentinelCert }
    Invoke-Step -Name "Step 4/10: Cleaning up WinDivert driver"      -Action { Remove-WinDivertDriver }
    # Capture what the kernel just said about the WinDivert driver unload --
    # highest-signal window for stuck-filter-driver diagnosis.
    Write-SystemExtensionLogDump -Label "post-windivert-removal"
    Invoke-Step -Name "Step 5/10: Resetting network adapters"        -Action { Reset-NetworkAdapters }
    Invoke-Step -Name "Step 6/10: Removing files"                    -Action { Remove-SentinelFiles }
    Invoke-Step -Name "Step 7/10: Removing environment variables"    -Action { Remove-SentinelEnvVars }
    Invoke-Step -Name "Step 8/10: Removing QUIC policies"            -Action { Remove-QuicPolicies }

    if (-not $SkipIPv6) {
        Invoke-Step -Name "Step 9/10: Re-enabling IPv6"              -Action { Enable-IPv6Adapters }
    } else {
        Write-UninstallWarn "Step 9/10: Skipping IPv6 re-enable (-SkipIPv6)"
        Start-Phase "Re-enabling IPv6"
        End-PhaseSkip "-SkipIPv6 passed"
    }

    # ══════════════════════════════════════════════════════════════════════
    # [Deployment extra] POST-UNINSTALL HEALTH CHECKS
    # ══════════════════════════════════════════════════════════════════════

    Start-Phase "Post-uninstall verification"
    Write-UninstallInfo "Running post-uninstall health checks..."

    # Notes are collected as (label, action) tuples and surfaced in the
    # final success panel.  Network-broken is the one special case below
    # (elevated to Warning level because it affects the operator's ability
    # to do anything next).  Everything else is residue the user can
    # either clean up manually or ignore -- no red fail banner.
    $healthNotes  = @()
    $networkBroken = $false

    # 1. No sentinel processes lingering (residue note -- usually a locked
    # handle on the way out; a reboot clears it).  Re-use the canonical
    # $SentinelProcessNames so this stays in lockstep with the kill sweep --
    # a name added to the kill list must be visible to the health check.
    $procs = Get-Process -Name $SentinelProcessNames -ErrorAction SilentlyContinue
    if ($procs) {
        Write-UninstallWarn "Note: QuilrAI agent processes still running (PIDs: $($procs.Id -join ', '))"
        $healthNotes += "QuilrAI agent processes still running (PIDs $($procs.Id -join ', ')). Try: taskkill /F /IM quilrai.exe, or reboot."
    } else {
        Write-UninstallOk "Processes: none running"
    }

    # 2. Service should be gone (residue note).
    $svcCheck = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($svcCheck) {
        Write-UninstallWarn "Note: service $ServiceName still registered (status: $($svcCheck.Status))"
        $healthNotes += "Service '$ServiceName' still registered. Run: sc.exe delete $ServiceName"
    } else {
        Write-UninstallOk "Service: removed"
    }

    # 3. Updater task should be gone (residue note).
    $taskCheck = Get-ScheduledTask -TaskName $UpdaterTaskName -ErrorAction SilentlyContinue
    if ($taskCheck) {
        Write-UninstallWarn "Note: updater task $UpdaterTaskName still registered"
        $healthNotes += "Updater task '$UpdaterTaskName' still registered. Run: schtasks /Delete /TN `"$UpdaterTaskName`" /F"
    } else {
        Write-UninstallOk "Updater task: removed"
    }

    # 4. Network connectivity -- this IS critical; broken internet is the
    # one thing that stops the operator from doing anything next.  Keep
    # the adapter-reset remediation; if still broken afterwards, flag
    # loud (Warning, not Error -- uninstall itself succeeded).
    Write-UninstallInfo "Testing network connectivity..."
    try {
        $wc = New-Object System.Net.WebClient
        $wc.DownloadString("https://github.com") | Out-Null
        Write-UninstallOk "Network: HTTPS to github.com works"
    } catch {
        Write-UninstallWarn "Network connectivity test failed. Attempting adapter reset remediation..."
        Get-NetAdapter | Where-Object { $_.Status -in @("Up", "Disconnected") } | ForEach-Object {
            $adapterName = $_.Name
            try {
                Disable-NetAdapter -Name $adapterName -Confirm:$false -ErrorAction Stop
            } catch {
                Write-UninstallException -Label "Disable-NetAdapter $adapterName (health remediation)" -ErrorRecord $_
            }
            Start-Sleep -Milliseconds 500
            try {
                Enable-NetAdapter -Name $adapterName -Confirm:$false -ErrorAction Stop
            } catch {
                Write-UninstallException -Label "Enable-NetAdapter $adapterName (health remediation)" -ErrorRecord $_
            }
        }
        ipconfig /flushdns 2>$null | Out-Null
        Start-Sleep -Seconds 5
        try {
            $wc2 = New-Object System.Net.WebClient
            $wc2.DownloadString("https://github.com") | Out-Null
            Write-UninstallOk "Network: HTTPS to github.com works (recovered after adapter reset)"
        } catch {
            $networkBroken = $true
            Write-UninstallWarn "Note: cannot reach github.com via HTTPS -- reboot may be required to restore NDIS state."
            $healthNotes += "Network: cannot reach github.com via HTTPS. Reboot to clear residual NDIS state."
        }
    }

    # 5. Install dir should be gone. The usual residue is a single locked
    # driver image (WinDivert64.sys) still held by the kernel; Remove-DirSafe
    # has scheduled it for deletion on reboot, so it will clear automatically.
    if (-not $KeepInstallDir -and (Test-Path $InstallDir)) {
        if ($script:RebootRequired) {
            Write-UninstallWarn "Note: install dir has locked residue (e.g. WinDivert64.sys) -- scheduled for deletion on reboot: $InstallDir"
            $healthNotes += "Install dir residue scheduled for removal on next reboot: $InstallDir (reboot to finish)."
        } else {
            Write-UninstallWarn "Note: install dir still present: $InstallDir"
            $healthNotes += "Install dir not fully deleted: $InstallDir. Run: Remove-Item -Path '$InstallDir' -Recurse -Force"
        }
    } elseif (-not $KeepInstallDir) {
        Write-UninstallOk "Install directory: removed"
    }

    Log-SentinelProcesses -Label "post-uninstall"

    # Close Phase 10 as OK even with notes -- residue is not a failure.
    # Detail field carries the note count so the phase line hints at them
    # without shouting.
    if ($healthNotes.Count -eq 0) {
        End-PhaseOk -Detail "all checks passed"
    } else {
        $noteLabel = if ($healthNotes.Count -eq 1) { "1 note" } else { "$($healthNotes.Count) notes" }
        End-PhaseOk -Detail "$noteLabel (see summary)"
    }

    # Always render the green success panel.  Residue goes into a
    # "Notes" section (yellow, not red) -- uninstall itself succeeded,
    # these are optional cleanup items.
    $successLines = @("Your machine has been restored to pre-Sentinel state.")
    if (-not $SkipIPv6) { $successLines += "IPv6: re-enabled on all network adapters." }
    if (-not $networkBroken) { $successLines += "Network connectivity: verified." }
    if ($script:CmdEnvResetHelper) {
        $successLines += ""
        $successLines += "CMD users -- to clear env vars in current session, run once:"
        $successLines += "  $($script:CmdEnvResetHelper)"
    }
    Show-CliSuccess -Title "Uninstall complete" -Lines $successLines

    # If any residue notes, surface them in a small yellow panel after the
    # success panel -- visible but not alarming.
    if ($healthNotes.Count -gt 0) {
        Write-Host "  Minor cleanup notes:" -ForegroundColor Yellow
        foreach ($n in $healthNotes) {
            Write-Host "    - $n" -ForegroundColor DarkYellow
        }
        Write-Host "  (Uninstall itself succeeded; these are optional follow-ups.)" -ForegroundColor DarkGray
        Write-Host ""
    }

} catch {
    $topReason = $_.Exception.Message
    Write-UninstallException -Label "Uninstaller (top-level catch)" -ErrorRecord $_ -Hints @(
        "Look for the FIRST [!] line above -- it names the failing step.",
        "Full log file: $LogFile",
        "If the machine networking is broken, a reboot usually clears residual NDIS state."
    ) -Level "ERROR"
    # Surface a loud CLI fail banner.  If a phase is still open, End-PhaseFail
    # renders it; otherwise show a bare banner so the operator isn't left
    # with an orphan top-level exception and no context.
    try {
        if ($script:_CurrentPhase) {
            End-PhaseFail -Reason $topReason
        } else {
            Show-CliFailBanner -Step "(pre-phase)" -Reason $topReason
        }
    } catch {
        # Last-resort path: we're already in the top-level catch because the
        # primary action failed; if the fail-banner renderer ALSO threw
        # (glyph encoding, console closed, etc.) we still must exit 1 and
        # can't re-enter the rendering stack.  Best we can do is a raw
        # Write-Log line so the post-mortem isn't empty.
        try { Write-Log "ERROR" "fail-banner renderer threw: $($_.Exception.Message)" } catch { }
    }
    exit 1
} finally {
    Set-Location $OriginalDir
}

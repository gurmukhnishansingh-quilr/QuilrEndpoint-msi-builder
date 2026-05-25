#
# QuilrAI Endpoint Agent Installer (Windows)
#
# Installs a sentinel_package zip to C:\Program Files\QuilrAI\.
# Optionally trusts the bundled dev CA certificate for the current user.
# Optionally registers the agent as a Windows service (QuilrAIAgent) with -RegisterAsService.
#
# Usage:
#   .\sentinel_installer.ps1                                           # Auto-detect zip in CWD
#   .\sentinel_installer.ps1 -ZipPath .\dist\quilrai_package_v0.10.101_win_debug.zip
#   .\sentinel_installer.ps1 -ZipPath .\dist\quilrai_package_v0.10.101_win_debug.zip -TrustCert
#   .\sentinel_installer.ps1 -RegisterAsService                        # Install and register as Windows service
#   .\sentinel_installer.ps1 -WorkEmail user@company.com               # Pre-supply work email (skips prompt)
#   .\sentinel_installer.ps1 -Env preprod                              # Use pre-production environment (default: quartz)
#   .\sentinel_installer.ps1 -EnableProfiling                          # Enable request profiling logs (RUST_LOG entry)
#   .\sentinel_installer.ps1 -EnableUnifiedDlpPolicy                   # Opt in to unified DLP+policy pipeline (QUILRAI_UNIFIED_DLP_POLICY=1)
#
# Requires: Administrator privileges (installs to Program Files)
#

param(
    [string]$ZipPath,
    # -SourceDir: install from an already-extracted package folder instead of a
    # ZIP (used by the MSI, which bundles extracted files -- no zip). When set,
    # the package is copied from this folder; -ZipPath is ignored.
    [string]$SourceDir,
    # -TenantId: written to the service env + tenant file so the agent binds to
    # the right tenant (the lite installer originally had no tenant concept).
    [string]$TenantId,
    [switch]$TrustCert,
    [switch]$RegisterAsService,
    [switch]$EnableProfiling,
    [switch]$EnableUnifiedDlpPolicy,
    [string]$WorkEmail,
    [string]$Env = "quartz"
)

$ErrorActionPreference = "Stop"

$InstallDir = "C:\Program Files\QuilrAI"
$ServiceName = "QuilrAIAgent"

# ─── Helper Functions ─────────────────────────────────────────────────────────

function Write-InstallInfo {
    param([string]$Message)
    Write-Host "[*] $Message" -ForegroundColor Green
}

function Write-InstallError {
    param([string]$Message)
    Write-Host "[!] $Message" -ForegroundColor Red
}

function Write-InstallWarn {
    param([string]$Message)
    Write-Host "[!] $Message" -ForegroundColor Yellow
}

function Set-NodeCaEnv {
    param([string]$CertPath)

    Write-InstallInfo "Configuring Node.js environment variables..."

    if (-not (Test-Path $CertPath)) {
        Write-InstallWarn "cert.pem not found at $CertPath -- skipping Node.js env setup."
        return
    }

    try {
        $env:NODE_EXTRA_CA_CERTS = $CertPath
        & setx NODE_EXTRA_CA_CERTS "$CertPath" /M | Out-Null
        Write-InstallInfo "NODE_EXTRA_CA_CERTS set to $CertPath (machine scope)."

        $env:NODE_TLS_REJECT_UNAUTHORIZED = "0"
        & setx NODE_TLS_REJECT_UNAUTHORIZED "0" /M | Out-Null
        Write-InstallInfo "NODE_TLS_REJECT_UNAUTHORIZED set to 0 (machine scope)."
    }
    catch {
        Write-InstallWarn "Failed to set NODE_EXTRA_CA_CERTS: $_"
    }
}

function Test-Admin {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# ─── Zip Resolution ──────────────────────────────────────────────────────────

function Resolve-ZipPath {
    param([string]$Provided)

    if ($Provided) {
        # Resolve relative paths
        $resolved = Resolve-Path $Provided -ErrorAction SilentlyContinue
        if (-not $resolved) {
            Write-InstallError "Zip file not found: $Provided"
            exit 1
        }
        return $resolved.Path
    }

    # Auto-detect in current directory
    $matches = Get-ChildItem -Path "." -Filter "quilrai_package_v*_win_*.zip" -File
    if ($matches.Count -eq 0) {
        Write-InstallError 'No quilrai_package_v*_win_*.zip found in current directory.'
        Write-InstallError 'Provide the path explicitly: .\sentinel_installer.ps1 -ZipPath <path>'
        exit 1
    }
    if ($matches.Count -gt 1) {
        Write-InstallError 'Multiple matching zip files found in current directory:'
        foreach ($m in $matches) {
            Write-InstallError "  $($m.Name)"
        }
        Write-InstallError 'Provide the path explicitly: .\sentinel_installer.ps1 -ZipPath <path>'
        exit 1
    }

    Write-InstallInfo "Auto-detected: $($matches[0].FullName)"
    return $matches[0].FullName
}

# ─── Process Management ──────────────────────────────────────────────────────

function Stop-SentinelProcesses {
    # 1. Temporarily disable SCM failure recovery so killed processes don't respawn
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($svc) {
        Write-InstallInfo "Disabling $ServiceName auto-restart temporarily..."
        # Set failure actions to "take no action" so SCM won't respawn after taskkill
        cmd /c "sc.exe failure $ServiceName reset= 0 actions= `"`"" 2>&1 | Out-Null
    }

    # 2. Try graceful service stop
    if ($svc -and $svc.Status -ne "Stopped") {
        Write-InstallInfo "Stopping $ServiceName service..."
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 3
    }

    # 3. Force-kill all quilrai-related processes (regardless of how they were started)
    #    Using cmd /c to prevent $ErrorActionPreference="Stop" from treating
    #    taskkill "not found" stderr as a terminating error.
    $procs = @("quilrai.exe", "quilrai-proxy.exe", "ipc-light-broker.exe", "quilrai-diagnostics.exe", "templating-engine.exe", "template-engine.exe", "quilrai-monitor-v2.exe", "email-discovery.exe")
    foreach ($proc in $procs) {
        cmd /c "taskkill /F /IM $proc 2>nul" | Out-Null
    }
    Start-Sleep -Seconds 2

    # 4. Stop and remove WinDivert kernel driver (must happen after killing quilrai
    #    which holds the driver handle; driver locks WinDivert64.sys preventing overwrite)
    $wdSvc = Get-Service -Name "WinDivert" -ErrorAction SilentlyContinue
    if ($wdSvc) {
        Write-InstallInfo "Stopping WinDivert driver..."
        $savedEAP = $ErrorActionPreference; $ErrorActionPreference = "SilentlyContinue"
        cmd /c "sc.exe stop WinDivert" 2>$null | Out-Null
        cmd /c "sc.exe delete WinDivert" 2>$null | Out-Null
        $ErrorActionPreference = $savedEAP
        # Wait for kernel to release driver (up to 10s)
        Start-Sleep -Seconds 3
        for ($w = 0; $w -lt 10; $w++) {
            if (-not (Get-Service -Name "WinDivert" -EA SilentlyContinue)) { break }
            Start-Sleep -Seconds 1
        }
        Write-InstallInfo "WinDivert driver stopped and removed."
    }

    Write-InstallInfo "All quilrai processes stopped."
}

# ─── Service Registration ────────────────────────────────────────────────────

function Register-SentinelService {
    param(
        [string]$InstallDir,
        [string]$WorkEmail,
        [string]$DlpEndpoint,
        [string]$BackendBaseUrl,
        [string]$RustLog,
        [string]$SentinelUserDir,
        [bool]$UnifiedDlpPolicy,
        [string]$TenantId
    )

    $sentinelBin = Join-Path $InstallDir "quilrai.exe"

    if (-not (Test-Path $sentinelBin)) {
        Write-InstallWarn "quilrai.exe not found at $sentinelBin -- skipping service registration."
        return
    }

    Write-InstallInfo "Registering $ServiceName Windows service..."

    # Check if service already exists
    $existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue

    if ($existing) {
        # Service already exists -- update its configuration.
        # Processes were already stopped by Stop-SentinelProcesses earlier.
        Write-InstallInfo "Updating existing $ServiceName service configuration..."
        # Set-Service -BinaryPathName is PS 7+ only, not available in Windows PS 5.1.
        # Use cmd /c to call sc.exe config with proper quoting for binPath= value.
        $scCmd = "sc.exe config $ServiceName binPath= `"\`"$sentinelBin\`" --service`" start= auto"
        cmd /c $scCmd 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) {
            Write-InstallWarn "sc.exe config failed (exit code $LASTEXITCODE)."
        }
    } else {
        # Service does not exist -- create it
        # New-Service -BinaryPathName is available in PS 5.1+
        Write-InstallInfo "Creating $ServiceName service..."
        $binPathValue = "`"$sentinelBin`" --service"
        New-Service -Name $ServiceName -BinaryPathName $binPathValue -StartupType Automatic -DisplayName "QuilrAI Endpoint Agent" -Description "QuilrAI Endpoint Agent - endpoint security and DLP enforcement." | Out-Null
    }

    # Configure failure recovery policy: restart 3 times with 5s delay, reset counter after 24h
    # (New-Service/Set-Service don't support failure actions, so we use sc.exe via cmd /c)
    cmd /c "sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/5000/restart/5000" 2>&1 | Out-Null
    cmd /c "sc.exe failureflag $ServiceName 1" 2>&1 | Out-Null

    # Create log directory
    $logDir = "C:\ProgramData\QuilrAI\logs"
    if (-not (Test-Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir -Force | Out-Null
        Write-InstallInfo "Created log directory: $logDir"
    }

    # ── Inject logged-in user environment into service context ──────────────────
    # Windows services run as LocalSystem (Session 0) with no user env vars.
    # SCM reads service env vars from a REG_MULTI_SZ value named "Environment"
    # directly on HKLM\...\Services\{Name} — NOT from a subkey.
    # Each string in the multi-string must be in "VAR=VALUE" format.
    Write-InstallInfo "Configuring service environment for user context..."
    $serviceRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"

    # Remove the old (broken) subkey if a previous install created it — SCM never read it.
    $oldSubkeyPath = "$serviceRegPath\Environment"
    if (Test-Path $oldSubkeyPath) {
        Remove-Item -Path $oldSubkeyPath -Recurse -Force -ErrorAction SilentlyContinue
        Write-InstallInfo "  Removed stale Environment subkey from previous install."
    }

    # Build the REG_MULTI_SZ array — each element is "VAR=VALUE"
    $templateFilePath = Join-Path $InstallDir "templates\app-discovery"
    $envLines = [System.Collections.Generic.List[string]]@(
        "USERPROFILE=$($env:USERPROFILE)",
        "APPDATA=$($env:APPDATA)",
        "LOCALAPPDATA=$($env:LOCALAPPDATA)",
        "USERNAME=$($env:USERNAME)",
        "QUILR_DLP_ENDPOINT=$DlpEndpoint",
        "QUILR_BACKEND_BASE_URL=$BackendBaseUrl",
        "QUILRAI_TEMPLATE_DIR=$templateFilePath",
        "QUILRAI_INSTALLATION_PATH=$SentinelUserDir"
    )
    if ($env:USERDNSDOMAIN) {
        $envLines.Add("USERDNSDOMAIN=$($env:USERDNSDOMAIN)")
    }
    if ($WorkEmail) {
        $envLines.Add("QUILRAI_OVERRIDE_EMAIL=$WorkEmail")
        Write-InstallInfo "  QUILRAI_OVERRIDE_EMAIL set to: $WorkEmail"
    }
    if ($RustLog) {
        $envLines.Add("RUST_LOG=$RustLog")
        Write-InstallInfo "  RUST_LOG set to: $RustLog"
    }
    if ($UnifiedDlpPolicy) {
        $envLines.Add("QUILRAI_UNIFIED_DLP_POLICY=1")
        Write-InstallInfo "  QUILRAI_UNIFIED_DLP_POLICY set to: 1"
    }
    if ($TenantId) {
        $envLines.Add("QUILR_TENANT_ID=$TenantId")
        Write-InstallInfo "  QUILR_TENANT_ID set (tenant bound)."
    }

    New-ItemProperty -Path $serviceRegPath -Name "Environment" `
        -PropertyType MultiString -Value $envLines.ToArray() -Force | Out-Null

    Write-InstallInfo "  QUILR_DLP_ENDPOINT set to: $DlpEndpoint"
    Write-InstallInfo "  QUILR_BACKEND_BASE_URL set to: $BackendBaseUrl"
    Write-InstallInfo "  User profile context configured for: $env:USERNAME"

    Write-InstallInfo "$ServiceName service registered successfully."
    Write-InstallInfo "  Status:      Get-Service $ServiceName"
    Write-InstallInfo "  Logs:        $logDir"
}

# ─── Service Start ────────────────────────────────────────────────────────────
# Registering the service leaves it Stopped; the agent only runs once it's
# started. Start it here and verify it reaches Running so a fresh install (and
# an MSI install) comes up live, not just registered. Non-fatal: a service that
# fails to start should not roll back the file install -- we surface why instead.
function Start-QuilrService {
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if (-not $svc) {
        Write-InstallWarn "Cannot start $ServiceName -- service is not registered."
        return
    }
    if ($svc.Status -eq 'Running') {
        Write-InstallInfo "$ServiceName is already running."
        return
    }

    Write-InstallInfo "Starting $ServiceName service..."
    try {
        Start-Service -Name $ServiceName -ErrorAction Stop -WarningAction SilentlyContinue
    } catch {
        # sc.exe start as a fallback (surfaces the underlying Win32 error code).
        Write-InstallWarn "Start-Service failed ($($_.Exception.Message)); retrying via sc.exe..."
        cmd /c "sc.exe start $ServiceName" 2>&1 | Out-Null
    }

    # Poll up to ~30s for Running (the agent initialises WinDivert + proxy on start).
    $deadline = (Get-Date).AddSeconds(30)
    do {
        Start-Sleep -Milliseconds 1000
        $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    } while ($svc -and $svc.Status -ne 'Running' -and (Get-Date) -lt $deadline)

    if ($svc -and $svc.Status -eq 'Running') {
        Write-InstallInfo "$ServiceName is running."
        return
    }

    # Did not reach Running -- gather diagnostics so the failure is actionable.
    Write-InstallWarn "$ServiceName did not reach Running (status: $(if ($svc) { $svc.Status } else { 'absent' }))."
    $q = cmd /c "sc.exe query $ServiceName" 2>&1 | Out-String
    if ($q) {
        $exitLine = ($q -split "`r?`n" | Where-Object { $_ -match 'WIN32_EXIT_CODE|SERVICE_EXIT_CODE' })
        foreach ($l in $exitLine) { Write-InstallWarn "  $($l.Trim())" }
    }
    $agentLog = "C:\ProgramData\QuilrAI\logs\quilrai.log"
    if (Test-Path $agentLog) {
        Write-InstallWarn "  Last agent log lines ($agentLog):"
        try { Get-Content -Path $agentLog -Tail 8 -ErrorAction Stop | ForEach-Object { Write-InstallWarn "    $_" } } catch {}
    }
    Write-InstallWarn "  Retry manually: Start-Service $ServiceName   (then check $agentLog)"
    Write-InstallWarn "  Common cause: missing VC++ runtime, or another packet-filter driver holding WinDivert."
}

# ─── Main ─────────────────────────────────────────────────────────────────────

$OriginalDir = (Get-Location).Path

try {
    # Print header
    Write-Host ""
    Write-Host ("=" * 60) -ForegroundColor Cyan
    Write-InstallInfo 'QuilrAI Installer (Windows)'
    Write-Host ("=" * 60) -ForegroundColor Cyan
    Write-Host ""

    # Check admin
    if (-not (Test-Admin)) {
        Write-InstallError 'Administrator privileges required.'
        Write-InstallError 'Right-click PowerShell and select "Run as Administrator".'
        exit 1
    }

    # Resolve environment-specific endpoint URLs. Extended to the full env set
    # (the launcher resolves the env from discovery and passes it here).
    $validEnvs = @("quartz", "preprod", "usprod", "uspoc", "india-prod", "india-poc", "secure", "qualtrix-secure")
    if ($Env -notin $validEnvs) {
        Write-InstallError "Invalid -Env value '$Env'. Must be one of: $($validEnvs -join ', ')"
        exit 1
    }
    switch ($Env) {
        "quartz"          { $DlpEndpoint = "https://dlpone.quilr.ai";          $BackendBaseUrl = "https://quartz.quilr.ai" }
        "preprod"         { $DlpEndpoint = "https://dlppreprod.quilr.ai";       $BackendBaseUrl = "https://preprod.quilr.ai" }
        "usprod"          { $DlpEndpoint = "https://dlpone.quilrai.com";        $BackendBaseUrl = "https://app.quilrai.com" }
        "uspoc"           { $DlpEndpoint = "https://dlpone.quilr.ai";           $BackendBaseUrl = "https://app.quilr.ai" }
        "india-prod"      { $DlpEndpoint = "https://dlp-platform.quilrai.com";  $BackendBaseUrl = "https://platform.quilrai.com" }
        "india-poc"       { $DlpEndpoint = "https://dlp-platform.quilr.ai";     $BackendBaseUrl = "https://platform.quilr.ai" }
        # Hybrid secure: backend on secure.quilr.ai but DLP on shared dlpone.quilr.ai.
        "secure"          { $DlpEndpoint = "https://dlpone.quilr.ai";           $BackendBaseUrl = "https://secure.quilr.ai" }
        "qualtrix-secure" { $DlpEndpoint = "https://dlpone.quilr.ai";           $BackendBaseUrl = "https://secure.quilr.ai" }
    }
    Write-InstallInfo "Environment:           $Env"
    Write-InstallInfo "Enable profiling:      $EnableProfiling"
    Write-InstallInfo "Unified DLP+policy:    $EnableUnifiedDlpPolicy"

    # Prompt for optional work email ONLY in an interactive session. Under the
    # MSI (deferred CA runs as SYSTEM with no console) Read-Host would hang, so
    # skip the prompt when non-interactive.
    if (-not $WorkEmail -and [Environment]::UserInteractive) {
        try {
            $WorkEmail = Read-Host "Enter work email for this device (optional -- press Enter to skip)"
            $WorkEmail = $WorkEmail.Trim()
        } catch { $WorkEmail = "" }
    }
    if ($WorkEmail) {
        Write-InstallInfo "Work email provided: $WorkEmail"
    }
    Write-Host ""

    # Resolve install source: a pre-extracted folder (-SourceDir, used by the
    # MSI) takes precedence over a ZIP. Exactly one is used downstream.
    $ResolvedSourceDir = $null
    $ResolvedZip = $null
    if ($SourceDir) {
        $rs = Resolve-Path $SourceDir -ErrorAction SilentlyContinue
        if (-not $rs) { Write-InstallError "Source folder not found: $SourceDir"; exit 1 }
        $ResolvedSourceDir = $rs.Path
        Write-InstallInfo "Source folder:         $ResolvedSourceDir (extracted package)"
    } else {
        $ResolvedZip = Resolve-ZipPath -Provided $ZipPath
        Write-InstallInfo "Zip file:              $ResolvedZip"
    }
    Write-InstallInfo "Install dir:           $InstallDir"
    Write-InstallInfo "Trust cert:            $TrustCert"
    Write-InstallInfo "Register service:      $RegisterAsService"
    Write-Host ""

    # ── Stop all quilrai processes before extraction ────────────────────────
    # Prevents locked file errors (WinDivert64.sys, quilrai.exe, etc.)
    # Steps: disable SCM auto-restart → stop service → kill all processes
    Stop-SentinelProcesses

    # Create install directory
    if (-not (Test-Path $InstallDir)) {
        Write-InstallInfo "Creating install directory..."
        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    }

    # Deploy package into InstallDir. From an extracted folder we copy the
    # contents (no zip); otherwise we expand the ZIP. Both overwrite existing.
    if ($ResolvedSourceDir) {
        Write-InstallInfo "Copying extracted package from folder..."
        Copy-Item -Path (Join-Path $ResolvedSourceDir '*') -Destination $InstallDir -Recurse -Force
    } else {
        Write-InstallInfo "Extracting package..."
        Expand-Archive -Path $ResolvedZip -DestinationPath $InstallDir -Force
    }

    # Persist the tenant id (the agent reads it to bind this device to a tenant).
    if ($TenantId) {
        $tenantDir = "C:\ProgramData\QuilrAI"
        if (-not (Test-Path $tenantDir)) { New-Item -ItemType Directory -Path $tenantDir -Force | Out-Null }
        Set-Content -Path (Join-Path $tenantDir "tenant_id") -Value $TenantId -NoNewline -Encoding ASCII
        Write-InstallInfo "Tenant ID persisted to $tenantDir\tenant_id"
    }

    # Verify key binaries landed
    $expectedBins = @("quilrai-proxy.exe", "templating-engine.exe", "quilrai.exe", "bootstrap.exe", "email-discovery.exe")
    foreach ($bin in $expectedBins) {
        $binPath = Join-Path $InstallDir $bin
        if (Test-Path $binPath) {
            Write-InstallInfo "  Installed: $bin"
        } else {
            Write-InstallWarn "  Missing: $bin"
        }
    }

    # List all installed files
    $fileCount = (Get-ChildItem -Path $InstallDir -Recurse -File).Count
    Write-InstallInfo "  Total files installed: $fileCount"
    Write-Host ""

    # ── Install hooks to user profile ──
    # Mirrors macOS: hooks/ contents go to ~/.quilrai/
    #   - hook binaries land at $env:USERPROFILE\.quilrai\
    #   - scripts/ subdir lands at $env:USERPROFILE\.quilrai\scripts\
    $HooksSourceDir = Join-Path $InstallDir "hooks"
    $SentinelUserDir = Join-Path $env:LOCALAPPDATA ".quilrai"
    if (Test-Path $HooksSourceDir) {
        Write-InstallInfo "Installing hooks to $SentinelUserDir..."
        New-Item -ItemType Directory -Path $SentinelUserDir -Force | Out-Null
        Copy-Item (Join-Path $HooksSourceDir "*") -Destination $SentinelUserDir -Recurse -Force
        Write-InstallInfo "  Installed hook binaries and scripts/ to $SentinelUserDir"
        Remove-Item -Path $HooksSourceDir -Recurse -Force
        Write-InstallInfo "  Removed hooks/ from install directory"
    } else {
        Write-InstallWarn "hooks/ not found in package -- skipping hook installation."
    }
    Write-Host ""

    # Trust certificate (popup-free LocalMachine flow).
    # The MSI launcher pre-installs the Quilr CA chain to LocalMachine\Root/CA
    # before this runs, so machine-wide trust is already in place. Adding to
    # CurrentUser\Root (certutil -user) pops the Windows "install this
    # certificate?" dialog -- so we (a) skip if already trusted machine-wide,
    # and (b) otherwise add to LocalMachine\Root (silent, we're elevated)
    # instead of per-user.
    if ($TrustCert) {
        $certPath = Join-Path $InstallDir "cert.pem"
        if (Test-Path $certPath) {
            try {
                $c = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($certPath)
                $tp = $c.Thumbprint
                $trusted = $false
                foreach ($sn in @('Root','CA')) {
                    $st = New-Object System.Security.Cryptography.X509Certificates.X509Store(
                        $sn, [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
                    $st.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
                    foreach ($e in $st.Certificates) { if ($e.Thumbprint -eq $tp) { $trusted = $true; break } }
                    $st.Close()
                    if ($trusted) { break }
                }
                if ($trusted) {
                    Write-InstallInfo "Certificate already trusted machine-wide (LocalMachine) -- skipping add (no prompt)."
                } else {
                    & certutil -addstore -f Root "$certPath" | Out-Null
                    if ($LASTEXITCODE -eq 0) { Write-InstallInfo 'Certificate added to LocalMachine Root store (machine-wide, no prompt).' }
                    else { Write-InstallWarn "Failed to add certificate to LocalMachine Root store (exit $LASTEXITCODE)." }
                }
            } catch {
                Write-InstallWarn "Certificate trust check failed: $($_.Exception.Message)"
            }
        } else {
            Write-InstallWarn 'cert.pem not found in package -- skipping certificate trust.'
        }
        Write-Host ""
    }

    $nodeCertPath = Join-Path $InstallDir "cert.pem"
    Set-NodeCaEnv -CertPath $nodeCertPath

    # Compute RUST_LOG for the service registry and user environment.
    #
    # "info" is always the global default so every crate produces logs.
    # Without it, tracing-subscriber's EnvFilter only passes events that match an
    # explicit target directive — silencing all quilrai agent startup logs.
    #
    # $ServiceRustLog — written into the SCM service registry Environment value.
    #   Always "info" at minimum; adds the profiling entry when -EnableProfiling is set.
    #   Never derived from HKCU: stale user values must not bleed into the service process.
    #
    # $UserRustLog — written to HKCU and the current session. Mirrors the service value
    #   so terminal runs (sentinel_runner.bat standalone) behave the same as service mode.
    $ProfilingEntry = "sentinel_proxy::request_profiler=debug,sentinel_proxy=info"
    $BaseRustLog    = "info"

    $ServiceRustLog = if ($EnableProfiling) { "$BaseRustLog,$ProfilingEntry" } else { $BaseRustLog }
    $UserRustLog    = $ServiceRustLog

    # Register or unregister Windows service
    if ($RegisterAsService) {
        Write-Host ""
        Register-SentinelService -InstallDir $InstallDir -WorkEmail $WorkEmail `
            -DlpEndpoint $DlpEndpoint -BackendBaseUrl $BackendBaseUrl -RustLog $ServiceRustLog `
            -SentinelUserDir $SentinelUserDir -UnifiedDlpPolicy $EnableUnifiedDlpPolicy.IsPresent `
            -TenantId $TenantId

        # Start the service so the agent comes up immediately after install.
        # The rebranded agent self-updates from within the running service (its
        # internal scheduler + updater, core/src/scheduler + scripting/updater.rs),
        # so there is no separate Windows "update" scheduled task by design -- the
        # service running IS what keeps the agent updated.
        Start-QuilrService
    } else {
        # Remove existing service registration if present (standalone mode)
        $existingSvc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($existingSvc) {
            Write-Host ""
            Write-InstallInfo "Removing existing $ServiceName service (standalone mode)..."
            cmd /c "sc.exe delete $ServiceName" 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0) {
                Write-InstallInfo "$ServiceName service removed."
            } else {
                Write-InstallWarn "Failed to remove $ServiceName service (exit code $LASTEXITCODE)."
            }
        }
        Write-Host ""
        Write-InstallInfo "Service registration skipped (pass -RegisterAsService to register)."
    }

    # Persist override email for current user's shells regardless of service/standalone mode.
    # If no email was provided, remove any stale entry left by a previous install.
    if ($WorkEmail) {
        # 1. Current PowerShell session (process-scope) — works when script is invoked as .\installer.ps1
        $env:QUILRAI_OVERRIDE_EMAIL = $WorkEmail

        # 2. Future sessions — persists to HKCU via registry (equivalent to setx)
        [System.Environment]::SetEnvironmentVariable("QUILRAI_OVERRIDE_EMAIL", $WorkEmail, [System.EnvironmentVariableTarget]::User)

        Write-InstallInfo "QUILRAI_OVERRIDE_EMAIL configured: $WorkEmail"

        # 3. Write CMD helper silently — available at a known path if ever needed manually
        $cmdHelper = Join-Path $env:TEMP "sentinel_set_env.cmd"
        Set-Content -Path $cmdHelper -Value "@set QUILRAI_OVERRIDE_EMAIL=$WorkEmail" -Encoding ASCII
    } else {
        # No email provided — clear any stale value from a previous install.

        # 1. HKCU — future sessions
        [System.Environment]::SetEnvironmentVariable("QUILRAI_OVERRIDE_EMAIL", $null, [System.EnvironmentVariableTarget]::User)

        # 2. Current PowerShell session
        Remove-Item "Env:\QUILRAI_OVERRIDE_EMAIL" -ErrorAction SilentlyContinue

        # 3. Broadcast WM_SETTINGCHANGE so GUI applications (Explorer, etc.) that listen for
        #    environment change notifications refresh their env copy. CMD and PowerShell windows
        #    do not respond to this message — their env lives in each process's own memory and
        #    cannot be modified from outside; only a new terminal will pick up the clean state.
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
        } catch { }

        # 4. CMD helper — lets users clear the var in any open CMD window with one command
        $cmdHelper = Join-Path $env:TEMP "sentinel_clear_env.cmd"
        Set-Content -Path $cmdHelper -Value "@set QUILRAI_OVERRIDE_EMAIL=" -Encoding ASCII

        Write-InstallInfo "No work email provided -- QUILRAI_OVERRIDE_EMAIL cleared."
    }

    # Set environment endpoint vars — always applied regardless of service/standalone mode
    Write-Host ""
    Write-InstallInfo "Setting Quilr environment endpoint vars ($Env)..."
    $env:QUILR_DLP_ENDPOINT     = $DlpEndpoint
    $env:QUILR_BACKEND_BASE_URL = $BackendBaseUrl
    [System.Environment]::SetEnvironmentVariable("QUILR_DLP_ENDPOINT",     $DlpEndpoint,    [System.EnvironmentVariableTarget]::User)
    [System.Environment]::SetEnvironmentVariable("QUILR_BACKEND_BASE_URL", $BackendBaseUrl, [System.EnvironmentVariableTarget]::User)
    Write-InstallInfo "  QUILR_DLP_ENDPOINT     = $DlpEndpoint"
    Write-InstallInfo "  QUILR_BACKEND_BASE_URL = $BackendBaseUrl"

    $templateFileEnvPath = Join-Path $InstallDir "templates\app-discovery"
    $env:QUILRAI_TEMPLATE_DIR = $templateFileEnvPath
    [System.Environment]::SetEnvironmentVariable("QUILRAI_TEMPLATE_DIR", $templateFileEnvPath, [System.EnvironmentVariableTarget]::User)
    Write-InstallInfo "  QUILRAI_TEMPLATE_DIR = $templateFileEnvPath"

    $env:QUILRAI_INSTALLATION_PATH = $SentinelUserDir
    [System.Environment]::SetEnvironmentVariable("QUILRAI_INSTALLATION_PATH", $SentinelUserDir, [System.EnvironmentVariableTarget]::User)
    Write-InstallInfo "  QUILRAI_INSTALLATION_PATH = $SentinelUserDir"

    # ── Request profiling RUST_LOG ──
    Write-Host ""
    Write-InstallInfo "Configuring RUST_LOG for request profiling (enabled=$EnableProfiling)..."
    if ($UserRustLog) {
        $env:RUST_LOG = $UserRustLog
        [System.Environment]::SetEnvironmentVariable("RUST_LOG", $UserRustLog, [System.EnvironmentVariableTarget]::User)
        Write-InstallInfo "  RUST_LOG = $UserRustLog"
    } else {
        Remove-Item "Env:\RUST_LOG" -ErrorAction SilentlyContinue
        [System.Environment]::SetEnvironmentVariable("RUST_LOG", $null, [System.EnvironmentVariableTarget]::User)
        Write-InstallInfo "  RUST_LOG profiling entry cleared."
    }

    # ── Unified DLP+policy pipeline opt-in ──
    # When set to "1", the agent forwards --unified-dlp-policy to the proxy and the proxy
    # uses the unified backend pipeline (POST /v2/nonstreamdetect_for_endpoint_agent) in
    # place of the streaming DLP analyzer + local policy engine. Default off — unset/clear
    # to fall back to the legacy pipeline.
    Write-Host ""
    Write-InstallInfo "Configuring QUILRAI_UNIFIED_DLP_POLICY (enabled=$EnableUnifiedDlpPolicy)..."
    if ($EnableUnifiedDlpPolicy) {
        $env:QUILRAI_UNIFIED_DLP_POLICY = "1"
        [System.Environment]::SetEnvironmentVariable("QUILRAI_UNIFIED_DLP_POLICY", "1", [System.EnvironmentVariableTarget]::User)
        Write-InstallInfo "  QUILRAI_UNIFIED_DLP_POLICY = 1"
    } else {
        Remove-Item "Env:\QUILRAI_UNIFIED_DLP_POLICY" -ErrorAction SilentlyContinue
        [System.Environment]::SetEnvironmentVariable("QUILRAI_UNIFIED_DLP_POLICY", $null, [System.EnvironmentVariableTarget]::User)
        Write-InstallInfo "  QUILRAI_UNIFIED_DLP_POLICY cleared (legacy pipeline)."
    }

    # Write CMD helper — mirrors every HKCU env var the installer sets so users can
    # apply them to an already-open CMD window with a single command.
    $cmdQuilrHelper = Join-Path $env:TEMP "sentinel_set_quilr_env.cmd"
    $UnifiedDlpPolicyValue = if ($EnableUnifiedDlpPolicy) { "1" } else { "" }
    $cmdLines = @(
        "@set QUILR_DLP_ENDPOINT=$DlpEndpoint",
        "@set QUILR_BACKEND_BASE_URL=$BackendBaseUrl",
        "@set QUILRAI_TEMPLATE_DIR=$templateFileEnvPath",
        "@set QUILRAI_INSTALLATION_PATH=$SentinelUserDir",
        "@set RUST_LOG=$UserRustLog",
        "@set QUILRAI_UNIFIED_DLP_POLICY=$UnifiedDlpPolicyValue"
    )
    Set-Content -Path $cmdQuilrHelper -Value ($cmdLines -join "`r`n") -Encoding ASCII

    # Summary
    Write-Host ""
    Write-Host ("=" * 60) -ForegroundColor Cyan
    Write-InstallInfo "Installation Complete!"
    Write-Host ("=" * 60) -ForegroundColor Cyan
    Write-Host ""
    Write-InstallInfo "Install directory: $InstallDir"
    if ($RegisterAsService) {
        Write-InstallInfo "Start the agent:   Start-Service $ServiceName"
    } else {
        Write-InstallInfo "Run standalone:    & `"$PSScriptRoot\sentinel_runner.ps1`""
    }
    Write-Host ""
    Write-InstallWarn "If you invoked this script from a CMD window, environment variables are"
    Write-InstallWarn "NOT automatically inherited by the parent CMD session (OS limitation)."
    Write-InstallWarn "Run these once in your CMD window to apply them to the current session:"
    if ($WorkEmail) {
        Write-InstallWarn "  $cmdHelper"
    }
    Write-InstallWarn "  $cmdQuilrHelper"
    Write-Host ""

} catch {
    Write-InstallError "Installation failed: $_"
    exit 1
} finally {
    Set-Location $OriginalDir
}

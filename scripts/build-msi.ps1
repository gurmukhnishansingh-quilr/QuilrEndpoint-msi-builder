# build-msi.ps1
#
# Builds the Quilr Sentinel Endpoint MSI in one of two modes:
#
# SINGLE (default) -- one env-agnostic MSI; the env is resolved at install time
#   from the discovery service (by TENANTID). Agent binaries are identical
#   across environments, so a single package serves all.
#     .\scripts\build-msi.ps1                    # fetch agent ZIP + build single
#     .\scripts\build-msi.ps1 -Version 0.30.291  # pin the agent version
#     .\scripts\build-msi.ps1 -ZipFile <path>    # air-gap: use a pre-downloaded ZIP
#   Output: out\quilrai-endpoint-agent.msi
#
# PER-ENV -- env baked into each MSI at build time (legacy method).
#     .\scripts\build-msi.ps1 -Env uspoc         # one env
#     .\scripts\build-msi.ps1 -All               # every env
#   Output: out\quilrai-endpoint-agent-<env>-<version>.msi
#
# Common flags: -Force (re-download ZIP), -Clean (wipe staged payload).
#
# Prereq: WiX Toolset v3.11+, .NET Framework 4.x (csc). Network to the agent
# CDN at build time unless -ZipFile. The resulting MSI bundles the agent ZIP +
# cert bundle + vc_redist; in single mode only the discovery lookup needs
# network at install (override with ENVNAME= for air-gapped installs).

[CmdletBinding(DefaultParameterSetName='Single')]
param(
    [Parameter(ParameterSetName='PerEnv', Mandatory=$true)]
    [ValidateSet('quartz','preprod','usprod','uspoc','india-prod','india-poc','secure','qualtrix-secure')]
    [string]$Env,

    [Parameter(ParameterSetName='All', Mandatory=$true)]
    [switch]$All,

    [string]$Version,
    [string]$ZipFile,
    [string]$PackageZip,    # agent package to extract + bundle (default: signed v0.30.293)
    [switch]$Force,         # re-download the agent ZIP even if cached
    [switch]$Clean,
    # Use the launcher EXEs already in build\launchers\ AS-IS (do not recompile).
    # Drop your code-signed install-launcher.exe / uninstall-launcher.exe there
    # first, then build with -SignedLaunchers so the signature is preserved.
    [switch]$SignedLaunchers
)

# The agent ZIP is byte-identical across environments (verified: all env ZIPs
# share the same SHA-256), so SINGLE mode fetches it from one stable CDN path.
$AgentCdnBase = 'https://quilr-extensions.quilr.ai/endpoint-agent/preprod'

# Single-package UpgradeCode (env-agnostic). NEVER change.
$SingleUpgradeCode = '9F3B7C21-5D84-4A6E-B0C2-1E7A9D34F5B0'

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$ProgressPreference = 'SilentlyContinue'

# TLS 1.2 minimum -- the CDN endpoints reject older.
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

# --- Repo paths -------------------------------------------------------------
$repoRoot   = Split-Path -Parent $PSScriptRoot
$sourceDir  = Join-Path $repoRoot 'source'
$scriptsDir = Join-Path $repoRoot 'scripts'
$buildDir   = Join-Path $repoRoot 'build'
$payloadDir = Join-Path $repoRoot 'payload'
$outDir     = Join-Path $repoRoot 'out'
$wxs        = Join-Path $buildDir 'Product.wxs'

if (-not (Test-Path -LiteralPath $wxs)) { throw "Missing WiX source: $wxs" }
foreach ($d in @($outDir, $payloadDir)) {
    if (-not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Path $d | Out-Null }
}

# --- Env table --------------------------------------------------------------
# Keyed by the internal env name (what the agent writes to HKLM and what its
# scheduled updater switches on). PathSlug is the directory segment on the
# CDN side -- differs for india-* and secure (see source/sentinel-endpoint.ps1
# lines 522-572 for the source of truth).
# Stable per-env UpgradeCodes: never change. Re-running the same env over an
# existing install does a clean major-upgrade. Different envs deploy as
# separate products and can coexist if needed.
$EnvMap = [ordered]@{
    'quartz' = @{
        CdnBase     = 'https://quilr-extensions.quilr.ai/endpoint-agent/quartz'
        UpgradeCode = '2C9D3E5A-6F12-4E0B-9B6A-7F4A1D2E0001'
    }
    'preprod' = @{
        CdnBase     = 'https://quilr-extensions.quilr.ai/endpoint-agent/preprod'
        UpgradeCode = '2C9D3E5A-6F12-4E0B-9B6A-7F4A1D2E0002'
    }
    'usprod' = @{
        CdnBase     = 'https://quilr-extensions.quilr.ai/endpoint-agent/usprod'
        UpgradeCode = '2C9D3E5A-6F12-4E0B-9B6A-7F4A1D2E0003'
    }
    'uspoc' = @{
        CdnBase     = 'https://quilr-extensions.quilr.ai/endpoint-agent/uspoc'
        UpgradeCode = '2C9D3E5A-6F12-4E0B-9B6A-7F4A1D2E0004'
    }
    'india-prod' = @{
        CdnBase     = 'https://quilr-extensions.quilr.ai/endpoint-agent/indprod'
        UpgradeCode = '2C9D3E5A-6F12-4E0B-9B6A-7F4A1D2E0005'
    }
    'india-poc' = @{
        CdnBase     = 'https://quilr-extensions.quilr.ai/endpoint-agent/indpoc'
        UpgradeCode = '2C9D3E5A-6F12-4E0B-9B6A-7F4A1D2E0006'
    }
    'secure' = @{
        CdnBase     = 'https://quilr-hub.quilr.ai/endpoint-agent/prod'
        UpgradeCode = '2C9D3E5A-6F12-4E0B-9B6A-7F4A1D2E0007'
    }
    'qualtrix-secure' = @{
        CdnBase     = 'https://quilr-hub.s3.us-east-1.amazonaws.com/endpoint-agent/prod'
        UpgradeCode = '2C9D3E5A-6F12-4E0B-9B6A-7F4A1D2E0008'
    }
}

# --- Locate WiX -------------------------------------------------------------
function Find-WixTool {
    param([string]$Name)
    $cmd = Get-Command $Name -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    if ($env:WIX) {
        $candidate = Join-Path $env:WIX "bin\$Name"
        if (Test-Path -LiteralPath $candidate) { return $candidate }
    }
    $roots = @(
        "${env:ProgramFiles(x86)}\WiX Toolset v3.14\bin",
        "${env:ProgramFiles(x86)}\WiX Toolset v3.11\bin",
        "$env:ProgramFiles\WiX Toolset v3.14\bin",
        "$env:ProgramFiles\WiX Toolset v3.11\bin"
    )
    foreach ($r in $roots) {
        $candidate = Join-Path $r $Name
        if (Test-Path -LiteralPath $candidate) { return $candidate }
    }
    return $null
}

$candle = Find-WixTool 'candle.exe'
$light  = Find-WixTool 'light.exe'
if (-not $candle -or -not $light) {
    Write-Host ''
    Write-Host '*** WiX Toolset v3 not found.' -ForegroundColor Red
    Write-Host '*** Install from: https://wixtoolset.org/releases/' -ForegroundColor Red
    Write-Host '*** Then re-run this script.' -ForegroundColor Red
    exit 2
}
Write-Host "[+] candle: $candle"
Write-Host "[+] light:  $light"

# --- Locate C# compiler -----------------------------------------------------
function Find-Csc {
    $candidates = @(
        "$env:SystemRoot\Microsoft.NET\Framework64\v4.0.30319\csc.exe",
        "$env:SystemRoot\Microsoft.NET\Framework\v4.0.30319\csc.exe"
    )
    foreach ($c in $candidates) { if (Test-Path -LiteralPath $c) { return $c } }
    return $null
}
$csc = Find-Csc
if (-not $csc) { throw "csc.exe (.NET Framework 4.x) not found. Install .NET Framework or run on Windows 10+." }
Write-Host "[+] csc:    $csc"

# --- Source files (shared across envs) --------------------------------------
# Install and uninstall are both fully native (C# launchers); the MSI ships no
# PowerShell scripts.
$srcInstallLauncher  = Join-Path $scriptsDir 'InstallLauncher.cs'
$srcUninstallLauncher = Join-Path $scriptsDir 'UninstallLauncher.cs'

foreach ($p in @($srcInstallLauncher, $srcUninstallLauncher)) {
    if (-not (Test-Path -LiteralPath $p)) { throw "Missing required file: $p" }
}

# Agent package to bundle (extracted into the MSI, not as a ZIP). Override with
# -PackageZip. Default is the signed v0.30.293 india-poc quilrai package.
if (-not $PackageZip) {
    $PackageZip = 'C:\Users\nisha\Downloads\sentinel_win_v0.30.293_release_india-poc_signed\quilrai_package_v0.30.293_win_release.zip'
}
$heat = Find-WixTool 'heat.exe'
if (-not $heat) { throw 'heat.exe (WiX) not found.' }
Write-Host "[+] heat:   $heat"

# --- Build launcher EXEs once (shared across all env builds) ----------------
$launcherOutDir = Join-Path $buildDir 'launchers'
if (-not (Test-Path -LiteralPath $launcherOutDir)) { New-Item -ItemType Directory -Path $launcherOutDir | Out-Null }

function Compile-Launcher {
    param([string]$CsFile, [string]$ExeName)
    $exePath = Join-Path $launcherOutDir $ExeName

    # -SignedLaunchers: never recompile. Use the code-signed EXE verbatim so its
    # Authenticode signature is preserved. Looked up in build\launchers\Signed\
    # first (where the signed copies are dropped), falling back to build\launchers\.
    if ($SignedLaunchers) {
        $signed = Join-Path (Join-Path $launcherOutDir 'Signed') $ExeName
        $src = if (Test-Path -LiteralPath $signed) { $signed } else { $exePath }
        if (-not (Test-Path -LiteralPath $src)) {
            throw "-SignedLaunchers set but no $ExeName found in $launcherOutDir\Signed or $launcherOutDir. Place your signed EXE there first."
        }
        $sig = Get-AuthenticodeSignature -LiteralPath $src
        if ($sig.Status -eq 'Valid') {
            Write-Host "    signed:  $src  [$($sig.SignerCertificate.Subject)]"
        } else {
            Write-Host "    WARN: $src is '$($sig.Status)' (not validly signed) -- bundling as-is." -ForegroundColor Yellow
        }
        return $src
    }

    # Rebuild if source newer than exe, or exe missing
    $rebuild = $true
    if (Test-Path -LiteralPath $exePath) {
        $srcMtime = (Get-Item $CsFile).LastWriteTimeUtc
        $exeMtime = (Get-Item $exePath).LastWriteTimeUtc
        if ($exeMtime -gt $srcMtime) { $rebuild = $false }
    }
    if (-not $rebuild) {
        Write-Host "    cached:  $exePath"
        return $exePath
    }
    Write-Host "    compile: $CsFile -> $exePath"
    $cscArgs = @(
        '/nologo',
        '/target:winexe',                                  # Windows subsystem -- no console flash when spawned
        '/optimize+',
        '/platform:anycpu',
        '/reference:System.dll',
        '/reference:System.IO.Compression.dll',           # ZipFile lives here on .NET 4.5+
        '/reference:System.IO.Compression.FileSystem.dll', # ZipFile.ExtractToDirectory extension
        '/reference:System.Web.Extensions.dll',           # JavaScriptSerializer (discovery JSON)
        '/reference:System.ServiceProcess.dll',           # ServiceController (start/stop the agent service)
        '/reference:System.Management.dll',               # WMI Win32_NetworkAdapter (NDIS rebind on uninstall)
        "/out:$exePath",
        $CsFile
    )
    & $csc @cscArgs 2>&1 | ForEach-Object { Write-Host "      $_" }
    if ($LASTEXITCODE -ne 0) { throw "csc.exe failed for $CsFile (exit $LASTEXITCODE)" }
    return $exePath
}

Write-Host $(if ($SignedLaunchers) { '[*] Using pre-supplied (signed) launchers...' } else { '[*] Compiling launchers...' })
$installLauncherExe   = Compile-Launcher -CsFile $srcInstallLauncher   -ExeName 'install-launcher.exe'
$uninstallLauncherExe = Compile-Launcher -CsFile $srcUninstallLauncher -ExeName 'uninstall-launcher.exe'

# --- Helpers ----------------------------------------------------------------

function Get-LatestVersionFromCdn {
    param([string]$CdnBase)
    $manifestUrl = "$CdnBase/windows/64/update.json"
    Write-Host "    fetching: $manifestUrl"
    try {
        $resp = Invoke-WebRequest -Uri $manifestUrl -UseBasicParsing -TimeoutSec 30
        $manifest = $resp.Content | ConvertFrom-Json
        if (-not $manifest.version) { throw "manifest has no .version field" }
        return $manifest.version
    } catch {
        throw "Could not fetch / parse ${manifestUrl}: $($_.Exception.Message)"
    }
}

function Resolve-CertsBundle {
    # Returns the path to certs-bundle.zip used by the installer. The bundle
    # is the CA chain that the agent's HTTPS interceptor terminates against;
    # it gets shipped inside every per-env MSI and installed to LocalMachine\Root
    # / LocalMachine\CA at install time.
    #
    # Source of truth: payload\_shared\certs-bundle.zip. The operator pre-places
    # the file there (download it manually from the tools/certs-bundle CDN
    # path or copy from a peer machine). If absent, the build aborts -- we
    # never fetch from the network here so the build remains air-gappable
    # and unaffected by site-local download policies.
    $sharedDir = Join-Path $payloadDir '_shared'
    if (-not (Test-Path -LiteralPath $sharedDir)) {
        New-Item -ItemType Directory -Path $sharedDir | Out-Null
    }
    $dest = Join-Path $sharedDir 'certs-bundle.zip'
    if (Test-Path -LiteralPath $dest) {
        $sizeKb = [math]::Round((Get-Item $dest).Length / 1KB, 1)
        Write-Host "    certs:    $dest ($sizeKb KB)"
        return $dest
    }
    throw @"
Cert bundle not found at:
  $dest

Place certs-bundle.zip in that folder, then re-run the build.
The bundle is the issuing/intermediate CA chain the agent expects.
"@
}

function Resolve-VcRedist {
    # Returns the path to vc_redist.x64.exe bundled into every MSI. The agent's
    # native binaries need the MSVC 2015-2022 x64 runtime. Source of truth:
    # payload\_shared\vc_redist.x64.exe. If absent, fetch the official package
    # from aka.ms (curl follows the redirect); if that's blocked, abort with a
    # clear message so the operator can drop it in manually (keeps air-gappable).
    $sharedDir = Join-Path $payloadDir '_shared'
    if (-not (Test-Path -LiteralPath $sharedDir)) { New-Item -ItemType Directory -Path $sharedDir | Out-Null }
    $dest = Join-Path $sharedDir 'vc_redist.x64.exe'
    if (Test-Path -LiteralPath $dest) {
        $sizeMb = [math]::Round((Get-Item $dest).Length / 1MB, 1)
        Write-Host "    vcredist: $dest ($sizeMb MB)"
        return $dest
    }
    $url = 'https://aka.ms/vs/17/release/vc_redist.x64.exe'
    $curl = Join-Path $env:SystemRoot 'System32\curl.exe'
    if (Test-Path -LiteralPath $curl) {
        Write-Host "    fetching vc_redist.x64.exe from $url"
        $tmp = "$dest.partial"
        & $curl --silent --show-error --fail --location --max-time 180 --output $tmp $url 2>&1 | ForEach-Object { Write-Host "      $_" }
        if ($LASTEXITCODE -eq 0 -and (Test-Path -LiteralPath $tmp)) {
            Move-Item -LiteralPath $tmp -Destination $dest -Force
            return $dest
        }
        if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    }
    throw @"
vc_redist.x64.exe not found and could not be fetched automatically.
Place the Microsoft Visual C++ 2015-2022 x64 Redistributable at:
  $dest
(download from https://aka.ms/vs/17/release/vc_redist.x64.exe) then re-run.
"@
}

function Get-AgentZip {
    param(
        [string]$CdnBase,
        [string]$Version,
        [string]$DestDir,
        [switch]$Force
    )
    $zipName = "sentinel_package_v${Version}_win_release.zip"
    $zipUrl  = "$CdnBase/windows/64/$zipName"
    $zipPath = Join-Path $DestDir $zipName
    if ((Test-Path -LiteralPath $zipPath) -and -not $Force) {
        $sizeMb = [math]::Round((Get-Item $zipPath).Length / 1MB, 1)
        Write-Host "    cached:   $zipPath ($sizeMb MB)"
        return $zipPath
    }
    if (-not (Test-Path -LiteralPath $DestDir)) { New-Item -ItemType Directory -Path $DestDir | Out-Null }
    Write-Host "    download: $zipUrl"
    $tmp = "$zipPath.partial"
    try {
        Invoke-WebRequest -Uri $zipUrl -OutFile $tmp -UseBasicParsing -TimeoutSec 600
        Move-Item -LiteralPath $tmp -Destination $zipPath -Force
    } catch {
        if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
        throw "Download failed from ${zipUrl}: $($_.Exception.Message)"
    }
    $sizeMb = [math]::Round((Get-Item $zipPath).Length / 1MB, 1)
    Write-Host "    saved:    $zipPath ($sizeMb MB)"
    return $zipPath
}

function Build-Msi {
    param(
        [string]$EnvName,          # '' = single/discovery mode; else per-env (baked)
        [string]$UpgradeCode,
        [string]$ProductName,
        [string]$PackagePath,      # agent package ZIP to EXTRACT + bundle (files, not the zip)
        [string]$VersionOverride,
        [switch]$CleanStaging
    )
    $isPerEnv = -not [string]::IsNullOrEmpty($EnvName)
    $label = if ($isPerEnv) { "per-env: $EnvName" } else { 'single (discovery)' }
    $tag   = if ($isPerEnv) { $EnvName } else { 'single' }

    Write-Host ""
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host " Building MSI -- $label" -ForegroundColor Cyan
    Write-Host "================================================================" -ForegroundColor Cyan

    # 1. Resolve agent package + version (from the package filename).
    if (-not (Test-Path -LiteralPath $PackagePath)) { throw "Agent package not found: $PackagePath" }
    $pkgPath = (Resolve-Path -LiteralPath $PackagePath).Path
    $pkgName = [IO.Path]::GetFileName($pkgPath)
    if ($pkgName -match '_v(\d+\.\d+\.\d+(\.\d+)?)_') { $resolvedVersion = $Matches[1] }
    elseif ($VersionOverride)                        { $resolvedVersion = $VersionOverride }
    else { throw "Could not infer version from package filename '$pkgName'; pass -Version." }
    if ($resolvedVersion -notmatch '^\d+\.\d+\.\d+(\.\d+)?$') {
        throw "Invalid version '$resolvedVersion'; must be X.Y.Z or X.Y.Z.W."
    }
    Write-Host "    agent package: $pkgPath"
    Write-Host "    agent version: $resolvedVersion"

    # 2. Stage payload dir (per-mode so single & per-env don't collide)
    $stagedName = if ($isPerEnv) { "staged-payload-$EnvName" } else { 'staged-payload' }
    $stagedPayload = Join-Path $buildDir $stagedName
    if ($CleanStaging -and (Test-Path -LiteralPath $stagedPayload)) {
        Remove-Item -LiteralPath $stagedPayload -Recurse -Force
    }
    if (-not (Test-Path -LiteralPath $stagedPayload)) {
        New-Item -ItemType Directory -Path $stagedPayload | Out-Null
    }

    # Extract the agent package into agent\ (binaries live at the root of the
    # ZIP, so they end up directly under agent\). Always re-extract clean so a
    # changed -PackageZip can't leave stale files behind.
    $agentDir = Join-Path $stagedPayload 'agent'
    if (Test-Path -LiteralPath $agentDir) { Remove-Item -LiteralPath $agentDir -Recurse -Force }
    New-Item -ItemType Directory -Path $agentDir | Out-Null
    Write-Host "    extracting agent package -> $agentDir"
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [IO.Compression.ZipFile]::ExtractToDirectory($pkgPath, $agentDir)
    $agentFileCount = (Get-ChildItem -LiteralPath $agentDir -Recurse -File).Count
    Write-Host "    extracted $agentFileCount agent files"
    if (-not (Test-Path -LiteralPath (Join-Path $agentDir 'quilrai.exe'))) {
        throw "Agent package looks wrong: quilrai.exe not found at root of $agentDir"
    }

    # The MSI ships NO PowerShell at all: install-launcher.exe and
    # uninstall-launcher.exe perform install and teardown natively.
    Copy-Item -LiteralPath $installLauncherExe    -Destination (Join-Path $stagedPayload 'install-launcher.exe')              -Force
    Copy-Item -LiteralPath $uninstallLauncherExe  -Destination (Join-Path $stagedPayload 'uninstall-launcher.exe')            -Force
    Copy-Item -LiteralPath $certsBundlePath       -Destination (Join-Path $stagedPayload 'certs-bundle.zip')                  -Force
    Copy-Item -LiteralPath $vcRedistPath          -Destination (Join-Path $stagedPayload 'vc_redist.x64.exe')                 -Force

    # Quilr branding: ico for ARP entry + install-dialog logo (Quilr Logo Artwork).
    $brandIcoSrc = 'C:\Quilr\Quilr Logo Artwork\logo.ico'
    $brandIcoDst = Join-Path $stagedPayload 'quilr.ico'
    if (Test-Path -LiteralPath $brandIcoSrc) {
        Copy-Item -LiteralPath $brandIcoSrc -Destination $brandIcoDst -Force
    } else {
        Write-Host "    WARN: $brandIcoSrc missing -- MSI will be built without an ARP icon."
        if (Test-Path -LiteralPath $brandIcoDst) { Remove-Item -LiteralPath $brandIcoDst -Force }
    }

    $licenseRtf = Join-Path $stagedPayload 'License.rtf'
    if (-not (Test-Path -LiteralPath $licenseRtf)) {
        $minimalRtf = @"
{\rtf1\ansi\ansicpg1252\deff0\nouicompat\deflang1033{\fonttbl{\f0\fnil\fcharset0 Calibri;}}
\viewkind4\uc1\pard\sa200\sl276\slmult1\f0\fs22
Quilr Sentinel Endpoint Agent\par
\par
By installing this software you agree to the terms of your service contract with Quilr, Inc.\par
\par
Copyright (c) Quilr, Inc. All rights reserved.\par
}
"@
        Set-Content -LiteralPath $licenseRtf -Value $minimalRtf -Encoding ASCII
    }

    # 3. heat-harvest the extracted agent tree -> AgentFiles-<tag>.wxs.
    #    Files install DIRECTLY to C:\Program Files\QuilrAI (QUILRAIDIR) so MSI
    #    owns their removal. quilrai.exe is excluded via the XSLT transform and
    #    authored by hand in Product.wxs (it carries the ServiceInstall).
    #    -ag  auto-generate component GUIDs at compile (fine under MajorUpgrade)
    #    -srd suppress harvesting the root dir element (we author QUILRAIDIR)
    #    -sreg/-scom suppress registry+COM harvesting (binaries only)
    #    -sfrag emit a single fragment; -var var.AgentDir => Source="$(var.AgentDir)\.."
    #    -t   XSLT that drops the quilrai.exe component + its ComponentRef
    $agentWxs = Join-Path $buildDir "AgentFiles-$tag.wxs"
    $excludeXslt = Join-Path $buildDir 'exclude-quilrai-exe.xslt'
    $heatArgs = @(
        'dir', $agentDir,
        '-nologo', '-ag', '-srd', '-sreg', '-scom', '-sfrag',
        '-cg', 'AgentFiles',
        '-dr', 'QUILRAIDIR',
        '-var', 'var.AgentDir',
        '-t', $excludeXslt,
        '-out', $agentWxs
    )
    & $heat @heatArgs 2>&1 | ForEach-Object { Write-Host $_ }
    if ($LASTEXITCODE -ne 0) { throw "heat.exe failed ($tag, exit $LASTEXITCODE)" }

    # 4. candle (compile each wxs separately). PER-ENV adds -dDefaultEnv (bakes
    #    ENVNAME); SINGLE omits it (Product.wxs uses <?ifdef DefaultEnv?>).
    $productWixobj = Join-Path $buildDir "Product-$tag.wixobj"
    $agentWixobj   = Join-Path $buildDir "AgentFiles-$tag.wixobj"
    $candleArgs = @(
        '-nologo',
        "-dProductVersion=$resolvedVersion",
        "-dProductName=$ProductName",
        "-dUpgradeCode=$UpgradeCode",
        "-dPayloadDir=$stagedPayload",
        "-dAgentDir=$agentDir"
    )
    if ($isPerEnv) { $candleArgs += "-dDefaultEnv=$EnvName" }
    & $candle @candleArgs '-arch' 'x64' '-ext' 'WixUIExtension' '-out' $productWixobj $wxs 2>&1 | ForEach-Object { Write-Host $_ }
    if ($LASTEXITCODE -ne 0) { throw "candle.exe failed (Product, $tag, exit $LASTEXITCODE)" }
    & $candle @candleArgs '-arch' 'x64' '-out' $agentWixobj $agentWxs 2>&1 | ForEach-Object { Write-Host $_ }
    if ($LASTEXITCODE -ne 0) { throw "candle.exe failed (AgentFiles, $tag, exit $LASTEXITCODE)" }

    # 5. light (both wixobjs). Write to a unique temp file first, then move it
    #    into place. The canonical out\*.msi can be transiently locked (Defender
    #    scanning the prior 70+MB build, or a delete-pending zombie), which makes
    #    light fail at LayoutMedia with "Access denied". Building to temp + move
    #    sidesteps that; if the canonical name is still locked at move time, we
    #    keep a timestamped name so the operator always gets a usable artifact.
    $msiName = if ($isPerEnv) { "quilrai-endpoint-agent-$EnvName-$resolvedVersion.msi" } else { 'quilrai-endpoint-agent.msi' }
    $msiOut  = Join-Path $outDir $msiName
    $msiTmp  = Join-Path $outDir ("~build-$tag-{0}.msi" -f ([guid]::NewGuid().ToString('N')))
    $lightArgs = @('-nologo','-spdb','-ext','WixUIExtension','-cultures:en-us','-out',$msiTmp,$productWixobj,$agentWixobj)
    & $light @lightArgs 2>&1 | ForEach-Object { Write-Host $_ }
    if ($LASTEXITCODE -ne 0) { throw "light.exe failed ($tag, exit $LASTEXITCODE)" }

    $moved = $false
    for ($i = 0; $i -lt 5 -and -not $moved; $i++) {
        try {
            if (Test-Path -LiteralPath $msiOut) { Remove-Item -LiteralPath $msiOut -Force -ErrorAction Stop }
            Move-Item -LiteralPath $msiTmp -Destination $msiOut -Force -ErrorAction Stop
            $moved = $true
        } catch {
            Start-Sleep -Milliseconds 800
        }
    }
    if (-not $moved) {
        $fallback = Join-Path $outDir ("{0}-{1}.msi" -f [IO.Path]::GetFileNameWithoutExtension($msiName), (Get-Date -Format 'yyyyMMdd-HHmmss'))
        Move-Item -LiteralPath $msiTmp -Destination $fallback -Force
        Write-Host "    WARN: '$msiOut' is locked (Defender/open handle); wrote '$fallback' instead." -ForegroundColor Yellow
        $msiOut = $fallback
    }

    $size = (Get-Item -LiteralPath $msiOut).Length
    return [pscustomobject]@{
        Mode    = $label
        Version = $resolvedVersion
        Msi     = $msiOut
        SizeMb  = [math]::Round($size / 1MB, 2)
    }
}

# --- Main -------------------------------------------------------------------

Write-Host '[*] Resolving cert bundle...'
$certsBundlePath = Resolve-CertsBundle
Write-Host '[*] Resolving VC++ redist...'
$vcRedistPath = Resolve-VcRedist

$results = New-Object System.Collections.Generic.List[object]
$failed  = New-Object System.Collections.Generic.List[string]

# The agent package to extract + bundle. -ZipFile overrides -PackageZip (the
# default signed v0.30.293 package); both modes use the same env-agnostic files.
$pkgToBundle = if ($ZipFile) { $ZipFile } else { $PackageZip }

if ($PSCmdlet.ParameterSetName -eq 'Single') {
    # SINGLE (default): one env-agnostic MSI; env resolved from discovery.
    $r = Build-Msi -EnvName '' `
                   -UpgradeCode $SingleUpgradeCode `
                   -ProductName 'QuilrAI Endpoint Agent' `
                   -PackagePath $pkgToBundle `
                   -VersionOverride $Version `
                   -CleanStaging:$Clean
    $results.Add($r) | Out-Null
} else {
    # PER-ENV (legacy): env baked per MSI.
    $envsToBuild = if ($All) { @($EnvMap.Keys) } else { @($Env) }
    foreach ($e in $envsToBuild) {
        $entry = $EnvMap[$e]
        try {
            $r = Build-Msi -EnvName $e `
                           -UpgradeCode $entry.UpgradeCode `
                           -ProductName "QuilrAI Endpoint Agent ($e)" `
                           -PackagePath $pkgToBundle `
                           -VersionOverride $Version `
                           -CleanStaging:$Clean
            $results.Add($r) | Out-Null
        } catch {
            Write-Host "[!] $e FAILED: $($_.Exception.Message)" -ForegroundColor Red
            $failed.Add("${e}: $($_.Exception.Message)") | Out-Null
        }
    }
}

# --- Summary ----------------------------------------------------------------
Write-Host ""
Write-Host "================================================================" -ForegroundColor Green
Write-Host " Build summary" -ForegroundColor Green
Write-Host "================================================================" -ForegroundColor Green
if ($results.Count -gt 0) { $results | Format-Table -AutoSize Mode, Version, SizeMb, Msi | Out-Host }
if ($failed.Count -gt 0) {
    Write-Host "Failures:" -ForegroundColor Red
    $failed | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
    exit 1
}
Write-Host ""
if ($PSCmdlet.ParameterSetName -eq 'Single') {
    Write-Host "Single MSI -- env resolved from discovery via TENANTID:"
    Write-Host "  msiexec /i quilrai-endpoint-agent.msi /qn TENANTID=<your-id>"
    Write-Host "Air-gapped (pin the env, skip discovery):"
    Write-Host "  msiexec /i quilrai-endpoint-agent.msi /qn TENANTID=<your-id> ENVNAME=uspoc"
} else {
    Write-Host "Per-env MSI -- env baked in:"
    Write-Host "  msiexec /i quilrai-endpoint-agent-<env>-<version>.msi /qn TENANTID=<your-id>"
}

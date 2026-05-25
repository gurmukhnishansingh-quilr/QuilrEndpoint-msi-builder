# Quilr Sentinel Endpoint — MSI Installer

Wraps `sentinel-endpoint.ps1` / `sentinel-endpoint-uninstaller.ps1` into a
**per-environment Windows MSI** suitable for fully offline deployment via
Group Policy, Intune, SCCM, or `msiexec`.

The agent payload ZIP for the target environment is **bundled inside the
MSI**, so no network is required at install time. Each environment gets its
own MSI so the bundled ZIP and the env baked into the scheduled updater
match.

---

## 1. Environments

| Env name (`-Env`)   | CDN base URL                                                              |
|---------------------|---------------------------------------------------------------------------|
| `quartz`            | `https://quilr-extensions.quilr.ai/endpoint-agent/quartz`                 |
| `preprod`           | `https://quilr-extensions.quilr.ai/endpoint-agent/preprod`                |
| `usprod`            | `https://quilr-extensions.quilr.ai/endpoint-agent/usprod`                 |
| `uspoc`             | `https://quilr-extensions.quilr.ai/endpoint-agent/uspoc`                  |
| `india-prod`        | `https://quilr-extensions.quilr.ai/endpoint-agent/indprod`                |
| `india-poc`         | `https://quilr-extensions.quilr.ai/endpoint-agent/indpoc`                 |
| `secure`            | `https://quilr-hub.quilr.ai/endpoint-agent/prod`                          |
| `qualtrix-secure`   | `https://quilr-hub.s3.us-east-1.amazonaws.com/endpoint-agent/prod`        |

Env name semantics match the agent script's internal switch
(`sentinel-endpoint.ps1`). The MSI bakes the env in as the default
`ENVNAME` property; the install wrapper writes it to
`HKLM\SOFTWARE\Quilr\Sentinel\Env`, which is what the scheduled updater
reads to pick its CDN.

---

## 2. Repo layout

```
msi-installer-endpoint/
├── source/                          # Original PS1 scripts (don't edit)
│   ├── sentinel-endpoint.ps1
│   └── sentinel-endpoint-uninstaller.ps1
├── scripts/
│   ├── install-wrapper.ps1          # MSI deferred-CA bridge → install
│   ├── uninstall-wrapper.ps1        # MSI deferred-CA bridge → uninstall
│   └── build-msi.ps1                # One-shot build driver
├── build/
│   ├── Product.wxs                  # WiX source
│   └── staged-payload-<env>/        # Generated per env at build time
├── payload/
│   └── <env>/                       # ZIP cache, one folder per env
│       └── sentinel_package_v*_win_release.zip
├── out/
│   └── sentinel-endpoint-<env>-<version>.msi
└── README.md
```

---

## 3. Prerequisites

| What                  | Why                                | Where                                    |
|-----------------------|------------------------------------|------------------------------------------|
| WiX Toolset v3.11+    | Compiles `.wxs` → `.msi`           | <https://wixtoolset.org/releases/>       |
| .NET Framework 4.5+   | csc.exe compiles the launcher EXEs | Built-in on Windows 10+                  |
| Windows PowerShell 5+ | Runs the build script              | Built-in                                 |
| `certs-bundle.zip`    | Bundled CA chain (Root + Inter)    | Place at `payload\_shared\certs-bundle.zip` |
| Network at build time | Fetches the env-specific agent ZIP | Outbound HTTPS to the env's CDN          |

The build process needs network for the agent ZIP. The *resulting MSI* does not.

### Cert bundle

The MSI bundles `payload\_shared\certs-bundle.zip` (download once from
`https://quilr-extensions.quilr.ai/endpoint-agent/tools/certs-bundle/certs-bundle.zip`
and place it there). At install time the launcher:

* extracts the ZIP to a temp dir
* loads each `.cer / .crt / .pem / .der / .p7b / .p7c` file
* installs missing certs to:
  * `LocalMachine\Root` if self-signed (Subject == Issuer)
  * `LocalMachine\CA`   otherwise
* skips certs whose thumbprint already exists in the target store
* records installed thumbprints in `C:\ProgramData\Quilr\installed_certs.txt` so uninstall can remove exactly those

No interactive "Do you want to trust this CA?" prompt is shown — the operator already authorized machine-wide changes when they accepted UAC for the MSI. Per-user trust prompts are a separate (and incompatible) installation path.

---

## 4. Build

### Build one env
```powershell
.\scripts\build-msi.ps1 -Env preprod
# → out\sentinel-endpoint-preprod-<version>.msi
```

The latest version is read from `<cdn>/windows/64/update.json`; pin
with `-Version 0.30.291` if you need a specific build. The ZIP is cached
in `payload\<env>\` and reused on subsequent builds — pass `-Force` to
re-download.

### Build every env in one shot
```powershell
.\scripts\build-msi.ps1 -All
```

Builds for all 8 envs. Failures (e.g. one env's CDN is temporarily
unreachable) don't abort the run — the script reports a summary table
at the end and exits non-zero if any env failed.

### Air-gapped build (no network at build time)
```powershell
# Operator pre-downloaded the env's ZIP on another machine and transferred it:
.\scripts\build-msi.ps1 -Env preprod -ZipFile .\sentinel_package_v0.30.291_win_release.zip
```

### Cleanup helpers
```powershell
.\scripts\build-msi.ps1 -Env preprod -Clean    # wipe staged-payload-<env> first
.\scripts\build-msi.ps1 -Env preprod -Force    # re-fetch ZIP even if cached
```

---

## 5. Install (silent / scripted)

```powershell
msiexec /i sentinel-endpoint-preprod-0.30.291.msi /qn `
        /l*v %TEMP%\sentinel-msi.log `
        TENANTID=<your-tenant-id> `
        EMAIL=user@org.com
```

### MSI properties

| Property   | Required for silent install      | Effect                                                  |
|------------|----------------------------------|----------------------------------------------------------|
| `TENANTID` | **Yes** (unless pre-staged)      | Forwarded as `-TenantId` to `sentinel-endpoint.ps1`     |
| `EMAIL`    | No                               | Forwarded as `-Email`                                    |
| `ENVNAME`  | No (baked into MSI)              | Override the env baked at build time. Persisted to `HKLM\SOFTWARE\Quilr\Sentinel\Env`. |

### Alternative ways to supply `TENANTID`
For MDM/GPO flows where tenant ID is delivered out-of-band:

1. Machine env var **before** msiexec runs:
   ```powershell
   [Environment]::SetEnvironmentVariable('QUILR_TENANT_ID', '<id>', 'Machine')
   ```
2. Pre-staged tenant file:
   ```powershell
   New-Item -ItemType Directory C:\ProgramData\Sentinel -Force | Out-Null
   Set-Content -Path C:\ProgramData\Sentinel\tenant_id -Value '<id>' -NoNewline -Encoding ASCII
   ```

---

## 6. Uninstall

```powershell
msiexec /x sentinel-endpoint-preprod-0.30.291.msi /qn /l*v %TEMP%\sentinel-msi-uninstall.log
```

The deferred uninstall CA invokes `sentinel-endpoint-uninstaller.ps1`,
which has `Force` mode hard-coded on. Uninstall is best-effort: a
step failure in the underlying uninstaller does **not** trap the MSI.

---

## 7. Logs

| When             | Log                                                                  |
|------------------|----------------------------------------------------------------------|
| MSI machinery    | `%TEMP%\sentinel-msi.log` (when `/l*v` is passed)                    |
| Install wrapper  | `%TEMP%\sentinel-msi-install.log`                                    |
| Uninstall wrapper| `%TEMP%\sentinel-msi-uninstall.log`                                  |
| Agent installer  | `C:\ProgramData\Quilr\logs\sentinel-endpoint\sentinel_endpoint.log`  |
| Agent uninstall  | `%TEMP%\sentinel-endpoint-uninstaller.log`                           |

---

## 8. Upgrade and cross-env semantics

- Each env has its own stable `UpgradeCode` (see `EnvMap` in
  `scripts\build-msi.ps1`). Deploying a newer `sentinel-endpoint-preprod-*.msi`
  cleanly upgrades a previous `preprod` install via `MajorUpgrade`.
- **Different envs are different products**: installing `usprod.msi` on a box
  that already has `preprod.msi` will *not* uninstall preprod automatically.
  For an intentional env switch, uninstall the previous env's MSI first.
- Downgrades within the same env are blocked with an explicit error.

---

## 9. Offline guarantee

- All 5 files (2 source PS1s, 2 wrappers, env-specific ZIP) are embedded in
  a single CAB inside the MSI.
- The install wrapper invokes `sentinel-endpoint.ps1 -ZipPath <bundled-zip>`,
  bypassing the CDN entirely.
- No internet is needed at install time.
- Network *is* needed after install for the scheduled updater to fetch
  newer agent versions. To stay fully offline, re-deploy a newer MSI
  instead of relying on the updater.

---

## 10. Known caveats

- WiX v3 only. v4/v5 syntax is incompatible.
- The MSI installs to `C:\Program Files\Quilr\Sentinel-Installer\` (staging
  only). The actual agent installs itself to `C:\Program Files\Sentinel\`
  via `sentinel-endpoint.ps1` — the MSI does **not** manage that directory
  or the `SentinelAgent` service.
- The `License.rtf` shown in interactive installs is a placeholder generated
  at build time. Replace `build\staged-payload-<env>\License.rtf` (or
  pre-place a file there before building) with the real EULA before shipping.

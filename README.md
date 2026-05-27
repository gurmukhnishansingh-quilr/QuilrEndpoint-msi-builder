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

The single MSI is environment-agnostic. By default the launcher looks the
`TENANTID` up in the discovery service (`https://discover.quilrai.dev/discovery/<TENANTID>`)
and resolves the environment from the returned backend URL — e.g. tenant
`442e052d-4c60-4cdc-961e-bc9db74a40ca` resolves to backend `https://preprod.quilr.ai`,
i.e. env **`preprod`**.

```powershell
# Normal: env resolved automatically from the Tenant ID via discovery
msiexec /i quilrai-endpoint-agent.msi /qn `
        /l*v %TEMP%\quilrai-msi.log `
        TENANTID=442e052d-4c60-4cdc-961e-bc9db74a40ca
```

### Pinning the environment with `ENVNAME` (air-gapped / skip discovery)

Pass `ENVNAME` to skip the discovery call and pin the environment explicitly —
useful for air-gapped installs or to override what discovery would return. Use
the **same short env name** discovery resolves to (the value derived from the
backend URL, *not* the URL itself):

```powershell
# Pin to the env discovery shows for this tenant (preprod) -- no network needed
msiexec /i quilrai-endpoint-agent.msi /qn `
        TENANTID=442e052d-4c60-4cdc-961e-bc9db74a40ca `
        ENVNAME=preprod
```

Valid `ENVNAME` values (see §1 for the backend each maps to):
`quartz` · `preprod` · `usprod` · `uspoc` · `india-prod` · `india-poc` · `secure` · `qualtrix-secure`

| discovery `QUILR_BACKEND_BASE_URL` | `ENVNAME` |
|------------------------------------|-----------|
| `https://quartz.quilr.ai`          | `quartz`     |
| `https://preprod.quilr.ai`         | `preprod`    |
| `https://app.quilrai.com`          | `usprod`     |
| `https://app.quilr.ai`             | `uspoc`      |
| `https://platform.quilrai.com`     | `india-prod` |
| `https://platform.quilr.ai`        | `india-poc`  |
| `https://secure.quilr.ai`          | `secure`     |

### Fully offline / custom backend (`SKIPDISCOVERY`)

`ENVNAME` (above) skips discovery but only works for the **known** environments in
the built-in URL map. For a fully offline install — or a custom/self-hosted backend
that isn't in that map — pass `SKIPDISCOVERY=1`. The installer then **never contacts
discovery and never validates the tenant**; every agent variable must come from MSI
properties. It **fails fast** (before touching the system) if a required variable is
missing.

Required when `SKIPDISCOVERY=1`: `BACKENDURL` **and** `DLPURL` — *or* a known
`ENVNAME` whose URLs are derived automatically. Any other `endpoint_agent_env` key
(e.g. `OAUTH_PROVIDER`, `ENDPOINT_AGENT_CDN_BASE_MAC`) is passed via the generic
`AGENTENV` property as a `;`-separated `KEY=VALUE` list.

```powershell
# Fully offline, explicit URLs + extra keys -- no network at install time
msiexec /i quilrai-endpoint-agent.msi /qn `
        SKIPDISCOVERY=1 `
        TENANTID=442e052d-4c60-4cdc-961e-bc9db74a40ca `
        BACKENDURL=https://preprod.quilr.ai `
        DLPURL=https://dlppreprod.quilr.ai `
        AGENTENV="OAUTH_PROVIDER=microsoft;ENDPOINT_AGENT_CDN_BASE_MAC=https://quilr-extensions.quilr.ai/endpoint-agent/quilrai/preprod"
```

`AGENTENV` also works **without** `SKIPDISCOVERY` — its keys are merged as overrides
on top of whatever discovery returns.

### MSI properties

| Property   | Required for silent install | Effect                                                                 |
|------------|-----------------------------|------------------------------------------------------------------------|
| `TENANTID` | **Yes** (unless pre-staged) | Validated against discovery; binds the device and resolves the env     |
| `ENVNAME`  | No                          | Pin the env, skip discovery (see above)                                |
| `SKIPDISCOVERY` | No                     | `1` = never contact discovery / validate tenant; requires `BACKENDURL`+`DLPURL` (or known `ENVNAME`) |
| `AGENTENV` | No                          | Extra agent env vars as `KEY=VALUE;KEY=VALUE` (merged as overrides)     |
| `APIKEY`   | No                          | `x-api-key` for the discovery call (overrides the baked default)       |
| `DLPURL`        | No                     | Override `QUILR_DLP_ENDPOINT`        (else discovery → env switch)      |
| `BACKENDURL`    | No                     | Override `QUILR_BACKEND_BASE_URL`                                       |
| `TEMPLATEDIR`   | No                     | Override `QUILRAI_TEMPLATE_DIR`                                         |
| `INSTALLPATH`   | No                     | Override `QUILRAI_INSTALLATION_PATH`                                    |
| `WORKEMAIL`     | No                     | Override `QUILRAI_OVERRIDE_EMAIL`                                       |
| `UNIFIEDDLP`    | No                     | Override `QUILRAI_UNIFIED_DLP_POLICY`                                   |
| `RUSTLOG`       | No                     | Override `RUST_LOG`                                                     |

Precedence for the agent config vars: **explicit property > discovery > env switch**.

### Environment variables (from discovery)

The agent's runtime config comes from the discovery service's `endpoint_agent_env`.
For example, `GET https://discover.quilrai.dev/discovery/442e052d-4c60-4cdc-961e-bc9db74a40ca`
(with header `x-api-key: <key>`) returns:

```json
{
  "tenant_id": "442e052d-4c60-4cdc-961e-bc9db74a40ca",
  "endpoint_agent_env": {
    "QUILR_DLP_ENDPOINT": "https://dlpone.quilr.ai",
    "QUILR_BACKEND_BASE_URL": "https://preprod.quilr.ai",
    "QUILRAI_INSTALLATION_PATH": "C:\\Program Files\\QuilrAI",
    "QUILRAI_TEMPLATE_DIR": "C:\\Program Files\\QuilrAI\\templates\\app-discovery"
  }
}
```

`install-launcher.exe` applies these **verbatim** (discovery is authoritative) to both:

- **System environment variables** — `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment` (visible to every session)
- the **`QuilrAIAgent` service** environment block — `HKLM\SYSTEM\CurrentControlSet\Services\QuilrAIAgent\Environment` (REG_MULTI_SZ), which additionally gets `RUST_LOG=info` and `QUILR_TENANT_ID=<id>`

It also sets `NODE_EXTRA_CA_CERTS=C:\Program Files\QuilrAI\cert.pem` and `NODE_TLS_REJECT_UNAUTHORIZED=0`.

So after installing the tenant above, the machine ends up with:

```text
QUILR_DLP_ENDPOINT        = https://dlpone.quilr.ai
QUILR_BACKEND_BASE_URL    = https://preprod.quilr.ai
QUILRAI_INSTALLATION_PATH = C:\Program Files\QuilrAI
QUILRAI_TEMPLATE_DIR      = C:\Program Files\QuilrAI\templates\app-discovery
NODE_EXTRA_CA_CERTS       = C:\Program Files\QuilrAI\cert.pem
NODE_TLS_REJECT_UNAUTHORIZED = 0
```

Any key you also pass as an MSI property (e.g. `DLPURL=https://custom-dlp`) overrides the discovery value for that variable.

### Alternative ways to supply `TENANTID`
For MDM/GPO flows where the tenant ID is delivered out-of-band:

1. Machine env var **before** msiexec runs:
   ```powershell
   [Environment]::SetEnvironmentVariable('QUILR_TENANT_ID', '<id>', 'Machine')
   ```
2. Pre-staged tenant file:
   ```powershell
   New-Item -ItemType Directory C:\ProgramData\QuilrAI -Force | Out-Null
   Set-Content -Path C:\ProgramData\QuilrAI\tenant_id -Value '<id>' -NoNewline -Encoding ASCII
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

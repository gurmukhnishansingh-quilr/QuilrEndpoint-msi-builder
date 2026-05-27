// InstallLauncher.cs — MSI deferred-CA bridge that invokes sentinel-endpoint.ps1.
//
// Why a native exe (not a PowerShell wrapper):
//   * MSI deferred CAs run in Session 0 with no console attached. PowerShell
//     wrappers hit edge cases there (orphaned child PS processes, Start-Process
//     -Wait deadlocks when stdio is half-redirected, silent crashes in
//     ExecutionPolicy enforcement).
//   * A compiled exe is unambiguous to msiexec: clean PID, clean exit code,
//     no script-host indirection, no MOTW or ExecutionPolicy interference.
//
// Build:
//   csc.exe /target:exe /optimize+ /platform:anycpu /out:install-launcher.exe
//           /reference:System.dll InstallLauncher.cs
//
// MSI ExeCommand (set by WiX Product.wxs) -- the agent files + service are already
// installed by the MSI; this configures the runtime and starts the service:
//   "[#fil_InstallLauncherExe]" --tenant-id "[TENANTID]" --env-name "[ENVNAME]"
//        --api-key "[APIKEY]" --dlp ... --be ... --agent-env "[AGENTENV]"
//        --skip-discovery "[SKIPDISCOVERY]" --ver ... --uurl ... --auto ...
//
// Environment resolution (highest precedence first):
//   * SKIPDISCOVERY=1 -> never contact discovery, never validate the tenant. The
//       env label = ENVNAME (or "manual"); ALL required agent env vars must be
//       supplied via MSI properties (BACKENDURL + DLPURL, or a known ENVNAME whose
//       URLs are derived). Missing required vars => fail fast before any teardown.
//   * ENVNAME set (no SKIPDISCOVERY) -> pin the env, derive URLs from the built-in
//       map for the known envs; discovery validation skipped (air-gapped friendly).
//   * otherwise -> resolve + validate the tenant against discovery (online).
//
// Behavior:
//   1. install dir = C:\Program Files\<brand> (MSI installed the agent + service)
//   2. resolve env (above); merge MSI-property overrides + AGENTENV passthrough
//   3. remove any foreign CLI agent, write certs/env, configure + start the service
//   4. write the version file + register the auto-update scheduled task
//   Returns 1603 on any error so msiexec surfaces an unambiguous failure code.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Net;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.ServiceProcess;
using System.Text;
using System.Web.Script.Serialization;
using Microsoft.Win32;
using Win32Registry = Microsoft.Win32.Registry;
using Win32RegistryValueKind = Microsoft.Win32.RegistryValueKind;

internal static class InstallLauncher {
    private const int ERROR_INSTALL_FAILURE = 1603;

    private static string s_logPath;
    private static StreamWriter s_logWriter;

    private static int Main(string[] args) {
        // Log everything to %TEMP%\sentinel-msi-install.log. In a deferred CA
        // running as SYSTEM, %TEMP% is C:\Windows\Temp; under impersonation
        // it's the user's TEMP. Either way readable by admins.
        try {
            string temp = Environment.GetEnvironmentVariable("TEMP")
                          ?? Environment.GetEnvironmentVariable("TMP")
                          ?? @"C:\Windows\Temp";
            s_logPath = Path.Combine(temp, "sentinel-msi-install.log");
            s_logWriter = new StreamWriter(s_logPath, append: true, encoding: Encoding.UTF8) { AutoFlush = true };
        } catch {
            // Logging unavailable; continue silent.
            s_logWriter = null;
        }

        try {
            Log("================================================================");
            Log("Sentinel Endpoint MSI install launcher started (PID " + Process.GetCurrentProcess().Id + ")");

            // Parse named args. Trim every value: operators frequently paste a
            // Tenant ID with a leading/trailing space, which would otherwise be
            // sent verbatim to discovery (=> 404) and to the agent (=> bad id).
            var parsed = ParseArgs(args);
            string tenantId, envName, apiKeyArg;
            parsed.TryGetValue("tenant-id", out tenantId);  tenantId  = (tenantId  ?? "").Trim();
            parsed.TryGetValue("env-name",  out envName);   envName   = (envName   ?? "").Trim();
            parsed.TryGetValue("api-key",   out apiKeyArg); apiKeyArg = (apiKeyArg ?? "").Trim();
            // Stash the (optional) API-key override so the discovery call can use
            // it. Empty => fall back to the env var, then the baked default.
            s_apiKeyArg = apiKeyArg;

            // Optional agent-config overrides passed as MSI properties. Each maps a
            // CA flag to the env var it overrides. Highest precedence: these win over
            // discovery and over the env->URL switch. Empty values are ignored.
            var overrides = new Dictionary<string,string>(StringComparer.OrdinalIgnoreCase);
            CollectOverride(parsed, "dlp",   "QUILR_DLP_ENDPOINT",         overrides);  // DLPURL
            CollectOverride(parsed, "be",    "QUILR_BACKEND_BASE_URL",     overrides);  // BACKENDURL
            CollectOverride(parsed, "tdir",  B.TemplateDirVar,       overrides);  // TEMPLATEDIR
            CollectOverride(parsed, "ipath", B.InstallPathVar,  overrides);  // INSTALLPATH
            CollectOverride(parsed, "email", B.OverrideEmailVar,     overrides);  // WORKEMAIL
            CollectOverride(parsed, "udlp",  B.UnifiedDlpVar, overrides);  // UNIFIEDDLP
            CollectOverride(parsed, "rlog",  "RUST_LOG",                   overrides);  // RUSTLOG

            // Generic agent-env passthrough (MSI prop AGENTENV): "K1=v1;K2=v2;..."
            // lets operators supply ANY endpoint_agent_env key that has no dedicated
            // switch (OAUTH_PROVIDER, ENDPOINT_AGENT_CDN_BASE_*, ...). Merged into the
            // overrides map (highest precedence) so it works with or without discovery.
            string agentEnvArg; parsed.TryGetValue("agent-env", out agentEnvArg);
            MergeKvList(agentEnvArg, overrides);

            // SKIPDISCOVERY=1 -> never contact discovery and never validate the tenant
            // against it; the environment + all required agent env vars must be supplied
            // via MSI properties (validated below). Anything else => normal discovery.
            string skipArg; parsed.TryGetValue("skip-discovery", out skipArg);
            bool skipDiscovery = string.Equals((skipArg ?? "").Trim(), "1", StringComparison.Ordinal);

            // Auto-updater wiring (MSI props ProductVersion/UPDATEURL/UPDATEINTERVAL/AUTOUPDATE).
            string agentVersion; parsed.TryGetValue("ver",  out agentVersion); agentVersion = (agentVersion ?? "").Trim();
            string updTaskUrl;   parsed.TryGetValue("uurl", out updTaskUrl);   updTaskUrl   = (updTaskUrl   ?? "").Trim();
            string updInterval;  parsed.TryGetValue("uint", out updInterval);  updInterval  = (updInterval  ?? "").Trim();
            string autoUpdate;   parsed.TryGetValue("auto", out autoUpdate);   autoUpdate   = (autoUpdate   ?? "").Trim();

            Log("Env name: "  + (string.IsNullOrEmpty(envName)  ? "<empty>" : envName));
            Log("TenantId:  " + (string.IsNullOrEmpty(tenantId) ? "<empty>" : "<provided>"));
            if (overrides.Count > 0) Log("Property overrides supplied: " + string.Join(", ", new List<string>(overrides.Keys).ToArray()));

            // Launcher dir = dir containing this exe (INSTALLERDIR). The helper
            // payload (certs-bundle.zip, vc_redist.x64.exe) lives here.
            string exePath = Assembly.GetEntryAssembly().Location;
            string installerDir = Path.GetDirectoryName(exePath);
            Log("Installer (helper) dir: " + installerDir);

            // Brand config (quilrai vs sentinel) from the bundled brand.json.
            B = Brand.Load(installerDir);
            Log("Brand: service=" + B.ServiceName + " exe=" + B.ServiceExe + " dir=" + B.InstallDir);

            // The agent itself was installed by MSI directly to C:\Program Files\QuilrAI
            // (and the QuilrAIAgent service created via ServiceInstall). Confirm it landed.
            if (!File.Exists(Path.Combine(B.InstallDir, B.ServiceExe))) {
                LogError("Agent not found at " + B.InstallDir + "\\" + B.ServiceExe + " (MSI file install may have failed).");
                return ERROR_INSTALL_FAILURE;
            }
            Log("Agent install dir: " + B.InstallDir);

            // TenantId gating: must come from MSI arg, env var, or pre-staged file.
            if (string.IsNullOrEmpty(tenantId)) {
                string envTenant = Environment.GetEnvironmentVariable("QUILR_TENANT_ID");
                string preStaged = B.TenantFile;
                if (!string.IsNullOrEmpty(envTenant)) {
                    Log("TenantId will come from QUILR_TENANT_ID env var.");
                } else if (File.Exists(preStaged)) {
                    Log("TenantId will come from " + preStaged);
                } else {
                    LogError("TENANTID is required when installing via MSI.");
                    LogError("Pass it on the msiexec line: msiexec /i ... TENANTID=<id>");
                    return ERROR_INSTALL_FAILURE;
                }
            }

            // ── Resolve the environment (single-package model) ───────────────
            // This is one MSI for all environments. We don't bake the env at
            // build time; instead we ask the discovery service which env this
            // tenant belongs to and write HKLM\SOFTWARE\Quilr\Sentinel\Env
            // BEFORE the agent runs (the agent reads it at startup to pick its
            // DLP / Backend / CDN URLs). An explicit ENVNAME= on the msiexec
            // line overrides discovery (offline / air-gapped fallback).
            string effectiveTenant = tenantId;
            if (string.IsNullOrEmpty(effectiveTenant)) {
                string envTenant = Environment.GetEnvironmentVariable("QUILR_TENANT_ID");
                effectiveTenant = (envTenant ?? "").Trim();
                if (string.IsNullOrEmpty(effectiveTenant)) {
                    string preStaged = B.TenantFile;
                    if (File.Exists(preStaged)) { try { effectiveTenant = File.ReadAllText(preStaged).Trim(); } catch { } }
                }
            }
            Dictionary<string,string> discBrowserEnv = null, discEndpointEnv = null;
            string resolvedEnv;

            if (skipDiscovery) {
                // FULLY OFFLINE: never contact discovery, never validate the tenant.
                // The env label comes from ENVNAME if supplied (also used as a URL
                // fallback for the known envs); everything the agent needs must be
                // supplied via MSI properties. Validate the required vars are present
                // BEFORE any teardown so a missing var fails fast and harmlessly.
                resolvedEnv = string.IsNullOrEmpty(envName) ? "manual" : envName;
                Log("SKIPDISCOVERY=1 -- discovery + tenant validation skipped; using explicit MSI env config (env label '" + resolvedEnv + "').");
                var missing = MissingRequiredEnv(envName, overrides);
                if (missing.Count > 0) {
                    LogError("SKIPDISCOVERY=1 but required agent environment variable(s) were not supplied: " + string.Join(", ", missing.ToArray()));
                    LogError("Pass them on the msiexec line, e.g.:");
                    LogError("  BACKENDURL=https://<backend>  DLPURL=https://<dlp>");
                    LogError("  (or pin a known ENVNAME=<env> so the URLs are derived automatically).");
                    LogError("Extra keys can be passed via AGENTENV=\"OAUTH_PROVIDER=microsoft;KEY=VALUE\".");
                    return ERROR_INSTALL_FAILURE;
                }
            } else if (!string.IsNullOrEmpty(envName)) {
                // PER-ENV / explicit override: env is baked/pinned. Stay offline-
                // friendly -- no discovery requirement.
                resolvedEnv = envName;
                Log("Env pinned via ENVNAME='" + envName + "' (discovery validation skipped).");
            } else {
                // SINGLE mode: the Tenant ID MUST exist in discovery, and we
                // resolve the environment from it.
                if (string.IsNullOrEmpty(effectiveTenant)) {
                    LogError("No Tenant ID provided -- cannot validate against discovery or resolve the environment.");
                    LogError("Pass TENANTID=<id> (or ENVNAME=<env> for an air-gapped install).");
                    return ERROR_INSTALL_FAILURE;
                }
                string discStatus;
                resolvedEnv = ResolveEnvFromDiscovery(effectiveTenant, out discBrowserEnv, out discEndpointEnv, out discStatus);

                if (discStatus == "notfound") {
                    LogError("Tenant ID '" + effectiveTenant + "' is not registered in the discovery service.");
                    LogError("Verify the Tenant ID (Quilr admin console) and retry. Aborting install.");
                    return ERROR_INSTALL_FAILURE;
                }
                if (string.IsNullOrEmpty(resolvedEnv)) {
                    if (discStatus == "unreachable") {
                        LogError("Could not reach the discovery service to validate the Tenant ID / resolve the environment.");
                        LogError("Retry online, or pass ENVNAME=<env> to pin the environment for an air-gapped install.");
                    } else { // unmappable
                        LogError("Discovery returned a backend with no known environment mapping for this tenant.");
                        LogError("Pass ENVNAME=<env> to pin the environment explicitly.");
                    }
                    return ERROR_INSTALL_FAILURE;
                }
                Log("Tenant validated and environment resolved: " + resolvedEnv);
            }

            // Remove a NON-MSI (CLI) Sentinel install if present -- BEFORE we write
            // our config/certs (the foreign teardown removes shared Quilr CA certs +
            // env, which we then (re)establish below). MSI Sentinels were already
            // removed by the <Upgrade> cross-removal, so a Sentinel still on disk here
            // with a live proxy is the CLI install. Runs after discovery so the
            // teardown's NDIS reset can't disrupt our discovery call.
            try {
                RemoveForeignCliAgent(installerDir);
            } catch (Exception ex) {
                Log("WARN: foreign CLI agent removal threw: " + ex.Message);
            }

            WriteEnvToRegistry(resolvedEnv);

            // Browser-extension env vars go machine-wide here. The endpoint_agent_env
            // is applied inside ConfigureAndStartAgent so discovery stays authoritative
            // and isn't overwritten by the env->URL switch (see that method).
            ApplyEnvVarsToMachine(discBrowserEnv,  "browser_extension_env");

            // Ensure the VC++ 2015-2022 x64 runtime is present BEFORE starting
            // the agent -- its native binaries (quilrai.exe, WinDivert, etc.)
            // depend on it. vc_redist.x64.exe lives in the launcher's own dir.
            try {
                EnsureVcRedist(installerDir);
            } catch (Exception ex) {
                Log("WARN: VC++ redist step threw: " + ex.Message);
            }

            // Install the CA bundle to LocalMachine BEFORE starting the agent so
            // machine-wide trust is in place and the agent never pops a per-user
            // trust dialog. certs-bundle.zip lives in the launcher's own dir.
            try {
                InstallCertsBundle(installerDir);
            } catch (Exception ex) {
                Log("WARN: cert bundle install threw: " + ex.Message);
            }

            // ── Native runtime config + service start (no PowerShell) ─────────
            // MSI already installed the agent files to C:\Program Files\QuilrAI
            // and created the QuilrAIAgent service. This configures the runtime
            // bits MSI can't express -- discovery-resolved env block + tenant
            // binding, hooks, Node CA env, failure actions -- then starts the service.
            try {
                ConfigureAndStartAgent(resolvedEnv, effectiveTenant, discEndpointEnv, overrides);
            } catch (Exception ex) {
                LogError("Native agent configuration failed: " + ex);
                return ERROR_INSTALL_FAILURE;
            }

            // Record the installed version (so the updater can compare) and register
            // the auto-update scheduled task that runs update-launcher.exe.
            try { WriteVersionFile(agentVersion); } catch (Exception ex) { Log("WARN: version file: " + ex.Message); }
            if (!string.Equals(autoUpdate, "0", StringComparison.Ordinal)) {
                try { RegisterUpdaterTask(installerDir, updInterval, updTaskUrl); }
                catch (Exception ex) { Log("WARN: updater task registration: " + ex.Message); }
            } else {
                Log("Auto-update disabled (AUTOUPDATE=0) -- no scheduled task created.");
            }

            Log("QuilrAI MSI install launcher completed OK");
            return 0;
        } catch (Exception ex) {
            LogError("Unhandled exception: " + ex);
            return ERROR_INSTALL_FAILURE;
        } finally {
            if (s_logWriter != null) {
                try { s_logWriter.Flush(); s_logWriter.Dispose(); } catch { }
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    // Discovery-driven environment resolution (single-package model)
    // ─────────────────────────────────────────────────────────────────────
    private const string DiscoveryBase = "https://discover.quilrai.dev";

    // API key sent as the "x-api-key" header on discovery calls.
    // Resolution order (first non-empty wins):
    //   1. --api-key CA arg  (MSI property APIKEY=...; optional)
    //   2. QUILR_DISCOVERY_API_KEY machine env var (rotation without rebuild)
    //   3. baked default below
    private const string DefaultDiscoveryApiKey = "qd_live_0dX0_qSKMWwhsJL7AMvWF7YIChi263NE";
    private static string s_apiKeyArg;   // set in Main from --api-key
    private static string DiscoveryApiKey() {
        if (!string.IsNullOrEmpty(s_apiKeyArg)) return s_apiKeyArg;
        string k = Environment.GetEnvironmentVariable("QUILR_DISCOVERY_API_KEY");
        if (!string.IsNullOrEmpty(k)) return k;
        return DefaultDiscoveryApiKey;
    }

    // Inverse of sentinel-endpoint.ps1's switch($Env): backend base URL -> env.
    private static readonly Dictionary<string,string> BackendToEnv =
        new Dictionary<string,string>(StringComparer.OrdinalIgnoreCase) {
            { "https://app.quilr.ai",         "uspoc" },
            { "https://app.quilrai.com",      "usprod" },
            { "https://platform.quilrai.com", "india-prod" },
            { "https://platform.quilr.ai",    "india-poc" },
            { "https://quartz.quilr.ai",      "quartz" },
            { "https://preprod.quilr.ai",     "preprod" },
            { "https://secure.quilr.ai",      "secure" },
        };

    // Discovery resolution outcome, so the caller can validate the tenant id.
    //   "found"       -> tenant exists, env resolved (return value set)
    //   "notfound"    -> discovery returned HTTP 404: tenant id is NOT registered
    //   "unmappable"  -> tenant exists but its backend URL has no env mapping
    //   "unreachable" -> network/timeout/other; could not validate
    private static string ResolveEnvFromDiscovery(string tenantId,
            out Dictionary<string,string> browserEnv, out Dictionary<string,string> endpointEnv,
            out string status) {
        browserEnv = null; endpointEnv = null; status = "unreachable";
        try {
            try { ServicePointManager.SecurityProtocol |= SecurityProtocolType.Tls12; } catch { }
            string url = DiscoveryBase + "/discovery/" + Uri.EscapeDataString(tenantId);
            Log("Querying discovery: " + url);
            var req = (HttpWebRequest)WebRequest.Create(url);
            req.Method = "GET";
            req.Timeout = 30000;
            req.ReadWriteTimeout = 30000;
            req.UserAgent = "sentinel-msi-launcher";
            req.Accept = "application/json";
            // Authenticate to the discovery service. Key value is never logged.
            string apiKey = DiscoveryApiKey();
            string keySrc = !string.IsNullOrEmpty(s_apiKeyArg) ? "APIKEY arg"
                          : (!string.IsNullOrEmpty(Environment.GetEnvironmentVariable("QUILR_DISCOVERY_API_KEY")) ? "env var" : "baked default");
            if (!string.IsNullOrEmpty(apiKey)) {
                req.Headers.Add("x-api-key", apiKey);
                Log("Discovery auth: x-api-key from " + keySrc + ".");
            }
            string json;
            using (var resp = (HttpWebResponse)req.GetResponse())
            using (var sr = new StreamReader(resp.GetResponseStream())) {
                json = sr.ReadToEnd();
            }
            var ser = new JavaScriptSerializer();
            ser.MaxJsonLength = 8 * 1024 * 1024;
            var root = ser.DeserializeObject(json) as Dictionary<string,object>;
            if (root == null) { Log("WARN: discovery response was not a JSON object."); status = "unmappable"; return null; }
            endpointEnv = ToStringDict(root, "endpoint_agent_env");
            browserEnv  = ToStringDict(root, "browser_extension_env");

            string backend = null;
            if (endpointEnv != null && endpointEnv.ContainsKey("QUILR_BACKEND_BASE_URL"))
                backend = endpointEnv["QUILR_BACKEND_BASE_URL"];
            if (string.IsNullOrEmpty(backend)) {
                Log("WARN: discovery response had no QUILR_BACKEND_BASE_URL; cannot derive env.");
                status = "unmappable"; return null;
            }
            string norm = backend.Trim().TrimEnd('/');
            if (BackendToEnv.ContainsKey(norm)) {
                string e = BackendToEnv[norm];
                Log("Discovery resolved backend " + backend + " -> env '" + e + "' (tenant exists).");
                status = "found"; return e;
            }
            Log("WARN: backend URL '" + backend + "' is not in the env reverse-map; pass ENVNAME= to override.");
            status = "unmappable"; return null;
        } catch (WebException wex) {
            var http = wex.Response as HttpWebResponse;
            if (http != null && (int)http.StatusCode == 404) {
                Log("Discovery: tenant '" + tenantId + "' NOT FOUND (HTTP 404).");
                status = "notfound";
            } else {
                Log("WARN: discovery request failed: " + wex.Message
                    + (http != null ? " (HTTP " + (int)http.StatusCode + ")" : ""));
                status = "unreachable";
            }
            try { if (http != null) http.Close(); } catch { }
            return null;
        } catch (Exception ex) {
            Log("WARN: discovery resolution error: " + ex.Message);
            status = "unreachable";
            return null;
        }
    }

    private static Dictionary<string,string> ToStringDict(Dictionary<string,object> root, string key) {
        if (root == null || !root.ContainsKey(key)) return null;
        var inner = root[key] as Dictionary<string,object>;
        if (inner == null) return null;
        var d = new Dictionary<string,string>(StringComparer.OrdinalIgnoreCase);
        foreach (var kv in inner) { d[kv.Key] = (kv.Value == null) ? "" : kv.Value.ToString(); }
        return d;
    }

    private static void WriteEnvToRegistry(string env) {
        try {
            using (var k = Win32Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Quilr\Sentinel")) {
                if (k != null) k.SetValue("Env", env, Win32RegistryValueKind.String);
            }
            Log("Set Env=" + env + " in machine config store (before agent run).");
        } catch (Exception ex) {
            Log("WARN: could not write Env value: " + ex.Message);
        }
    }

    private static void ApplyEnvVarsToMachine(Dictionary<string,string> vars, string label) {
        if (vars == null) return;
        int n = 0;
        foreach (var kv in vars) {
            if (string.IsNullOrEmpty(kv.Key)) continue;
            SetMachineEnv(kv.Key, kv.Value); n++;   // registry-direct (no per-call broadcast)
        }
        Log("Applied " + n + " " + label + " var(s) at Machine scope from discovery.");
    }

    // ─────────────────────────────────────────────────────────────────────
    // VC++ 2015-2022 x64 runtime dependency
    // ─────────────────────────────────────────────────────────────────────
    //
    // The agent's native binaries link against the MSVC runtime. If it's not
    // present the service fails to start. We bundle vc_redist.x64.exe and run
    // it (quiet) only when the runtime is missing.
    private static void EnsureVcRedist(string installDir) {
        if (IsVcRedistInstalled()) {
            Log("VC++ 2015-2022 x64 runtime already present -- skipping.");
            return;
        }
        string vc = Path.Combine(installDir, "vc_redist.x64.exe");
        if (!File.Exists(vc)) {
            Log("WARN: VC++ runtime missing and vc_redist.x64.exe not bundled at " + vc + " -- agent may fail to start.");
            return;
        }
        Log("VC++ runtime missing -- installing " + vc + " (/install /quiet /norestart)");
        var psi = new ProcessStartInfo {
            FileName = vc,
            Arguments = "/install /quiet /norestart",
            UseShellExecute = false,
            CreateNoWindow = true
        };
        using (var p = Process.Start(psi)) {
            p.WaitForExit();
            int c = p.ExitCode;
            // 0 = ok, 3010 = ok (reboot required), 1638 = a newer version is already installed
            if (c == 0 || c == 3010 || c == 1638) {
                Log("VC++ redist install exit " + c + " (ok)");
            } else {
                Log("WARN: VC++ redist install returned exit " + c);
            }
        }
    }

    private static bool IsVcRedistInstalled() {
        // VC++ 2015-2022 x64 registers Installed=1 under VisualStudio\14.0\VC\
        // Runtimes\x64. Check both the 64-bit and 32-bit (WOW6432Node) views.
        foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 }) {
            try {
                using (var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view))
                using (var k = baseKey.OpenSubKey(@"SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64")) {
                    if (k != null) {
                        object installed = k.GetValue("Installed");
                        if (installed != null && Convert.ToInt32(installed) == 1) return true;
                    }
                }
            } catch { /* try next view */ }
        }
        return false;
    }


    // ─────────────────────────────────────────────────────────────────────
    // Certificate bundle install
    // ─────────────────────────────────────────────────────────────────────
    //
    // The MSI bundles certs-bundle.zip (downloaded at build time from
    // https://quilr-extensions.quilr.ai/endpoint-agent/tools/certs-bundle/).
    // We extract it, walk every cert file, and install each cert that isn't
    // already in the target machine store.
    //
    // Store selection:
    //   self-signed (Subject == Issuer)  → LocalMachine\Root
    //   otherwise                        → LocalMachine\CA (Intermediate)
    //
    // No UI prompts: MSI runs elevated, so admin consent for machine-store
    // writes is already given. Per-user "Do you want to trust this CA?"
    // dialogs only appear for CurrentUser\Root installs, which would be
    // out of scope here (MSI deferred CAs run as SYSTEM).
    //
    // Idempotent: re-installing the same MSI on a machine that already has
    // the certs is a no-op (we match by thumbprint).
    //
    // For symmetric uninstall, every installed cert is appended to a
    // thumbprint manifest at C:\ProgramData\Quilr\installed_certs.txt so
    // UninstallLauncher can remove exactly what was added.

    private const string InstalledCertsManifest = @"C:\ProgramData\Quilr\installed_certs.txt";

    private static void InstallCertsBundle(string installDir) {
        string bundleZip = Path.Combine(installDir, "certs-bundle.zip");
        if (!File.Exists(bundleZip)) {
            Log("INFO: certs-bundle.zip not present at " + bundleZip + " - skipping cert install.");
            return;
        }

        string extractDir = Path.Combine(Path.GetTempPath(), "sentinel-certs-" + Guid.NewGuid().ToString("N"));
        try {
            Directory.CreateDirectory(extractDir);
            ZipFile.ExtractToDirectory(bundleZip, extractDir);
            Log("Extracted cert bundle to " + extractDir);

            // Recognized cert file extensions. PKCS#7 (.p7b/.p7c) bundles
            // multiple certs in one file -- handled by Collection.Import.
            var validExts = new HashSet<string>(StringComparer.OrdinalIgnoreCase) {
                ".cer", ".crt", ".pem", ".der", ".p7b", ".p7c"
            };

            int installed = 0, alreadyPresent = 0, errors = 0;
            foreach (string p in Directory.GetFiles(extractDir, "*", SearchOption.AllDirectories)) {
                if (!validExts.Contains(Path.GetExtension(p))) continue;
                try {
                    var collection = new X509Certificate2Collection();
                    collection.Import(p);
                    if (collection.Count == 0) {
                        Log("WARN: no certs found in " + p);
                        continue;
                    }
                    foreach (X509Certificate2 cert in collection) {
                        try {
                            if (InstallSingleCert(cert)) installed++;
                            else alreadyPresent++;
                        } catch (Exception inner) {
                            errors++;
                            Log("WARN: failed to install cert from " + p
                                + " (subject=" + cert.Subject + ", thumbprint=" + cert.Thumbprint
                                + "): " + inner.Message);
                        }
                    }
                } catch (Exception ex) {
                    errors++;
                    Log("WARN: could not parse cert file " + p + ": " + ex.Message);
                }
            }

            Log(string.Format(
                "Cert bundle: {0} installed, {1} already present, {2} errors",
                installed, alreadyPresent, errors));
        } finally {
            try { if (Directory.Exists(extractDir)) Directory.Delete(extractDir, true); }
            catch (Exception ex) { Log("WARN: failed to clean " + extractDir + ": " + ex.Message); }
        }
    }

    private static bool InstallSingleCert(X509Certificate2 cert) {
        bool isSelfSigned = string.Equals(cert.SubjectName.Name, cert.IssuerName.Name,
                                          StringComparison.OrdinalIgnoreCase);
        StoreName  storeName = isSelfSigned ? StoreName.Root : StoreName.CertificateAuthority;
        string     label     = isSelfSigned ? "LocalMachine\\Root" : "LocalMachine\\CA";

        using (var store = new X509Store(storeName, StoreLocation.LocalMachine)) {
            store.Open(OpenFlags.ReadWrite);
            var existing = store.Certificates.Find(X509FindType.FindByThumbprint, cert.Thumbprint, false);
            if (existing.Count > 0) {
                Log("[cert] already trusted in " + label
                    + " - " + Shorten(cert.Subject) + " (tp " + cert.Thumbprint + ")");
                return false;
            }
            store.Add(cert);
            Log("[cert] installed to " + label
                + " - " + Shorten(cert.Subject) + " (tp " + cert.Thumbprint + ")");
            RecordInstalledThumbprint(cert.Thumbprint, label);
            return true;
        }
    }

    private static void RecordInstalledThumbprint(string thumbprint, string storeLabel) {
        try {
            string dir = Path.GetDirectoryName(InstalledCertsManifest);
            if (!Directory.Exists(dir)) Directory.CreateDirectory(dir);
            File.AppendAllText(InstalledCertsManifest,
                thumbprint + "\t" + storeLabel + "\t"
                + DateTime.UtcNow.ToString("o") + Environment.NewLine);
        } catch (Exception ex) {
            Log("WARN: could not record thumbprint to " + InstalledCertsManifest + ": " + ex.Message);
        }
    }

    private static string Shorten(string s) {
        if (string.IsNullOrEmpty(s) || s.Length <= 80) return s;
        return s.Substring(0, 77) + "...";
    }

    // ─────────────────────────────────────────────────────────────────────
    // Native runtime config + service start (MSI-managed-service model)
    // ─────────────────────────────────────────────────────────────────────
    //
    // MSI installs the agent files to C:\Program Files\QuilrAI and creates the
    // QuilrAIAgent service (ServiceInstall). This launcher fills in the bits MSI
    // can't express declaratively, then starts the service:
    //   1. persist the tenant id
    //   2. install hooks to %LOCALAPPDATA%\.quilrai
    //   3. set Node CA env + env-specific URLs (machine scope)
    //   4. write the service Environment block (discovery-resolved) + failure actions
    //   5. start the service and verify it reaches Running
    //
    // Mirrors the relevant parts of source/sentinel_installer.ps1 -- keep in sync.

    // Brand (paths/service/exe names) -- loaded from brand.json next to this exe
    // in Main. QuilrAI defaults until then. See Brand.cs.
    private static Brand B = new Brand();

    private static void ConfigureAndStartAgent(string env, string tenantId,
            Dictionary<string,string> discEndpointEnv, Dictionary<string,string> overrides) {
        string userDir = InstallHooks(B.InstallDir);   // returns the .quilrai dir

        // Build the effective agent config. Precedence, highest first:
        //   1. explicit MSI-property overrides (command line / GPO / Intune)
        //   2. discovery's endpoint_agent_env (authoritative)
        //   3. env->URL switch + computed paths (fallback / air-gapped)
        var cfg = BuildAgentConfig(env, userDir, discEndpointEnv);
        if (overrides != null) {
            foreach (var kv in overrides) cfg[kv.Key] = kv.Value;   // overrides win
        }

        string srcLabel = (overrides != null && overrides.Count > 0) ? "overrides+"
                        : "";
        srcLabel += (discEndpointEnv != null && discEndpointEnv.Count > 0) ? "discovery-authoritative" : "switch/computed fallback";
        Log("Effective agent config (" + srcLabel + "):");
        foreach (var kv in cfg) Log("  " + kv.Key + "=" + kv.Value);

        PersistTenant(tenantId);
        SetNodeCaEnv(B.InstallDir);

        // Publish the effective config at Machine scope (these are the values that
        // land in System env -- now exactly matching discovery / the overrides).
        foreach (var kv in cfg) SetMachineEnv(kv.Key, kv.Value);
        // These are only set when supplied (override) -- otherwise clear any stale value.
        if (!cfg.ContainsKey(B.OverrideEmailVar))    SetMachineEnv(B.OverrideEmailVar, null);
        if (!cfg.ContainsKey(B.UnifiedDlpVar)) SetMachineEnv(B.UnifiedDlpVar, null);
        // SetNodeCaEnv + the loop above wrote the registry directly (fast, no per-call
        // broadcast). Notify the system ONCE so new processes see the new env.
        BroadcastEnvChange();

        ConfigureServiceRuntime(tenantId, cfg);
        DisableIPv6();          // before starting the agent (uninstaller re-enables)
        StartAgentService();
        Log("Native config complete.");
    }

    // Disable IPv6 on the host so traffic is forced down the IPv4 path the agent's
    // WinDivert proxy intercepts (IPv6 would otherwise bypass it). Two parts:
    //   1. HKLM\...\Tcpip6\Parameters\DisabledComponents = 0xFF -- persistent across
    //      reboots; this is exactly what the uninstaller's EnableIPv6 step reverses.
    //   2. Disable the ms_tcpip6 binding on every adapter -- takes effect immediately
    //      (no reboot), via Disable-NetAdapterBinding.
    private static void DisableIPv6() {
        try {
            using (var k = Win32Registry.LocalMachine.CreateSubKey(@"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters")) {
                if (k != null) {
                    k.SetValue("DisabledComponents", unchecked((int)0xFF), Win32RegistryValueKind.DWord);
                    Log("IPv6: set Tcpip6 DisabledComponents=0xFF (disabled across reboots).");
                }
            }
        } catch (Exception ex) { Log("WARN: set DisabledComponents failed: " + ex.Message); }
        try {
            string psh = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),
                                      @"WindowsPowerShell\v1.0\powershell.exe");
            var psi = new ProcessStartInfo {
                FileName = psh,
                Arguments = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command " +
                            "\"Disable-NetAdapterBinding -Name '*' -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue\"",
                UseShellExecute = false, CreateNoWindow = true
            };
            using (var p = Process.Start(psi)) {
                if (!p.WaitForExit(60000)) Log("WARN: Disable-NetAdapterBinding(ms_tcpip6) timed out.");
                else Log("IPv6: disabled ms_tcpip6 binding on all adapters (immediate).");
            }
        } catch (Exception ex) { Log("WARN: per-adapter IPv6 disable failed: " + ex.Message); }
    }

    // Effective agent config = discovery's endpoint_agent_env (authoritative),
    // with the env->URL switch + computed paths only filling absent keys. (Explicit
    // MSI-property overrides are layered on top by the caller.)
    private static Dictionary<string,string> BuildAgentConfig(
            string env, string userDir, Dictionary<string,string> discEndpointEnv) {
        var cfg = new Dictionary<string,string>(StringComparer.OrdinalIgnoreCase);
        if (discEndpointEnv != null) {
            foreach (var kv in discEndpointEnv)
                if (!string.IsNullOrEmpty(kv.Key)) cfg[kv.Key] = kv.Value ?? "";
        }
        // Fallbacks for required keys discovery didn't provide.
        string dlp, backend;
        bool known = EnvUrls(env, out dlp, out backend);
        if (known) {
            if (!cfg.ContainsKey("QUILR_DLP_ENDPOINT"))     cfg["QUILR_DLP_ENDPOINT"] = dlp;
            if (!cfg.ContainsKey("QUILR_BACKEND_BASE_URL")) cfg["QUILR_BACKEND_BASE_URL"] = backend;
        } else if (!cfg.ContainsKey("QUILR_BACKEND_BASE_URL")) {
            Log("WARN: env '" + env + "' unknown and discovery gave no backend URL -- agent config may be incomplete.");
        }
        if (!cfg.ContainsKey(B.TemplateDirVar))
            cfg[B.TemplateDirVar] = Path.Combine(B.InstallDir, @"templates\app-discovery");
        if (!cfg.ContainsKey(B.InstallPathVar))
            cfg[B.InstallPathVar] = userDir;
        if (!cfg.ContainsKey("RUST_LOG"))
            cfg["RUST_LOG"] = "info";
        return cfg;
    }

    // Pull one --flag value from parsed args and, if non-empty, record it under
    // its real env-var name in the overrides map.
    private static void CollectOverride(Dictionary<string,string> parsed, string flag,
                                        string envVar, Dictionary<string,string> overrides) {
        string v;
        if (parsed.TryGetValue(flag, out v)) {
            v = (v ?? "").Trim();
            if (v.Length > 0) overrides[envVar] = v;
        }
    }

    // Inverse of the agent's env->URL switch (sentinel_installer.ps1 lines 315-325).
    private static bool EnvUrls(string env, out string dlp, out string backend) {
        dlp = null; backend = null;
        switch ((env ?? "").ToLowerInvariant()) {
            case "quartz":          dlp = "https://dlpone.quilr.ai";         backend = "https://quartz.quilr.ai";       return true;
            case "preprod":         dlp = "https://dlppreprod.quilr.ai";     backend = "https://preprod.quilr.ai";      return true;
            case "usprod":          dlp = "https://dlpone.quilrai.com";      backend = "https://app.quilrai.com";       return true;
            case "uspoc":           dlp = "https://dlpone.quilr.ai";         backend = "https://app.quilr.ai";          return true;
            case "india-prod":      dlp = "https://dlp-platform.quilrai.com"; backend = "https://platform.quilrai.com"; return true;
            case "india-poc":       dlp = "https://dlp-platform.quilr.ai";   backend = "https://platform.quilr.ai";     return true;
            case "secure":          dlp = "https://dlpone.quilr.ai";         backend = "https://secure.quilr.ai";       return true;
            case "qualtrix-secure": dlp = "https://dlpone.quilr.ai";         backend = "https://secure.quilr.ai";       return true;
            default: return false;
        }
    }

    // Parse a "K1=v1;K2=v2;..." list (AGENTENV) into the overrides map. Splits on
    // ';' then the first '=' (values may themselves contain '='). Blank/malformed
    // entries are skipped with a warning. Values are never logged (may be secrets).
    private static void MergeKvList(string s, Dictionary<string,string> dst) {
        if (string.IsNullOrEmpty(s)) return;
        foreach (string pair in s.Split(';')) {
            string p = (pair ?? "").Trim();
            if (p.Length == 0) continue;
            int eq = p.IndexOf('=');
            if (eq <= 0) { Log("WARN: ignoring malformed AGENTENV entry (expected KEY=VALUE): " + p); continue; }
            string k = p.Substring(0, eq).Trim();
            string v = p.Substring(eq + 1).Trim();
            if (k.Length > 0) { dst[k] = v; Log("AGENTENV: " + k + " supplied via MSI property."); }
        }
    }

    // For SKIPDISCOVERY mode: which REQUIRED agent env vars cannot be resolved from
    // the supplied overrides + the ENVNAME URL map. Required = backend + DLP endpoint
    // (without these the agent can't reach the platform). Every other key has a safe
    // default in BuildAgentConfig, so it is not required here.
    private static List<string> MissingRequiredEnv(string envName, Dictionary<string,string> overrides) {
        string dlp, backend;
        bool known = EnvUrls(envName, out dlp, out backend);
        var missing = new List<string>();
        if (!(known || HasNonEmpty(overrides, "QUILR_BACKEND_BASE_URL"))) missing.Add("QUILR_BACKEND_BASE_URL (BACKENDURL)");
        if (!(known || HasNonEmpty(overrides, "QUILR_DLP_ENDPOINT")))     missing.Add("QUILR_DLP_ENDPOINT (DLPURL)");
        return missing;
    }

    private static bool HasNonEmpty(Dictionary<string,string> d, string k) {
        string v; return d != null && d.TryGetValue(k, out v) && v != null && v.Trim().Length > 0;
    }

    private static void CopyDirContents(string src, string dest) {
        Directory.CreateDirectory(dest);
        foreach (string dir in Directory.GetDirectories(src, "*", SearchOption.AllDirectories)) {
            Directory.CreateDirectory(dir.Replace(src, dest));
        }
        foreach (string file in Directory.GetFiles(src, "*", SearchOption.AllDirectories)) {
            string target = file.Replace(src, dest);
            File.Copy(file, target, true);
        }
    }

    private static void PersistTenant(string tenantId) {
        if (string.IsNullOrEmpty(tenantId)) { Log("No tenant id to persist."); return; }
        if (!Directory.Exists(B.DataDir)) Directory.CreateDirectory(B.DataDir);
        File.WriteAllText(Path.Combine(B.DataDir, "tenant_id"), tenantId, new UTF8Encoding(false));
        Log("Tenant id persisted to " + B.DataDir + "\\tenant_id");
    }

    // Hooks: copy <install>\hooks\* -> %LOCALAPPDATA%\.quilrai. The hooks/ dir
    // under QuilrAI is MSI-owned (removed on uninstall), so we copy only -- we do
    // NOT delete it. Returns the .quilrai dir (also QUILRAI_INSTALLATION_PATH).
    // NOTE: running as SYSTEM, LOCALAPPDATA is the SYSTEM profile -- same as the
    // PS1's behaviour under the MSI.
    private static string InstallHooks(string installDir) {
        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string userDir = Path.Combine(localAppData, B.HooksDirName);
        string hooksSrc = Path.Combine(installDir, "hooks");
        if (Directory.Exists(hooksSrc)) {
            Log("Installing hooks -> " + userDir);
            CopyDirContents(hooksSrc, userDir);
        } else {
            Log("WARN: hooks/ not present under " + installDir + " -- skipping hook install.");
        }
        return userDir;
    }

    private static void SetNodeCaEnv(string installDir) {
        string cert = Path.Combine(installDir, "cert.pem");
        if (File.Exists(cert)) {
            SetMachineEnv("NODE_EXTRA_CA_CERTS", cert);
            SetMachineEnv("NODE_TLS_REJECT_UNAUTHORIZED", "0");
            Log("Set NODE_EXTRA_CA_CERTS + NODE_TLS_REJECT_UNAUTHORIZED (machine).");
        } else {
            Log("WARN: cert.pem not found at " + cert + " -- skipping Node CA env.");
        }
    }

    // Write (or, when value is null/empty, delete) a Machine-scope env var DIRECTLY
    // in the registry. We deliberately avoid Environment.SetEnvironmentVariable(Machine)
    // here: it broadcasts WM_SETTINGCHANGE on every call (each blocks up to ~1s per
    // unresponsive top-level window), which made setting ~8 vars take ~20s. Instead we
    // write the registry instantly and broadcast ONCE via BroadcastEnvChange() after
    // all vars are set (see ConfigureAndStartAgent).
    private const string MachineEnvKey = @"SYSTEM\CurrentControlSet\Control\Session Manager\Environment";
    private static void SetMachineEnv(string name, string value) {
        try {
            using (var k = Win32Registry.LocalMachine.OpenSubKey(MachineEnvKey, true)) {
                if (k == null) { Log("WARN: cannot open machine Environment key."); return; }
                if (string.IsNullOrEmpty(value)) {
                    if (k.GetValue(name) != null) k.DeleteValue(name, false);
                } else {
                    k.SetValue(name, value, Win32RegistryValueKind.String);
                }
            }
        } catch (Exception ex) { Log("WARN: set " + name + " (Machine) failed: " + ex.Message); }
    }

    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    private static extern IntPtr SendMessageTimeout(IntPtr hWnd, uint msg, IntPtr wParam,
        string lParam, uint flags, uint timeoutMs, out IntPtr result);
    private static void BroadcastEnvChange() {
        // One HWND_BROADCAST of WM_SETTINGCHANGE("Environment") so new processes pick
        // up the machine env without a logoff. SMTO_ABORTIFHUNG + 1s keeps it bounded.
        try {
            IntPtr res;
            SendMessageTimeout((IntPtr)0xFFFF, 0x001A, IntPtr.Zero, "Environment", 0x0002, 1000, out res);
        } catch { }
    }

    // Configure the MSI-created QuilrAIAgent service: failure-recovery policy and
    // the SCM Environment block (REG_MULTI_SZ "Environment" value on the service
    // key -- NOT a subkey). The agent config comes from `cfg` (discovery-authoritative,
    // built in BuildAgentConfig), so the service sees exactly the same values that
    // were published to System env. The service exists by now (After InstallServices).
    private static void ConfigureServiceRuntime(string tenantId, Dictionary<string,string> cfg) {
        if (FindService(B.ServiceName) == null) {
            Log("WARN: " + B.ServiceName + " not present (MSI ServiceInstall may have failed) -- skipping runtime config.");
            return;
        }

        // Failure recovery: restart 3x @5s, reset counter daily. Simple args, no quoting.
        RunExe("sc.exe", "failure " + B.ServiceName + " reset= 86400 actions= restart/5000/restart/5000/restart/5000");
        RunExe("sc.exe", "failureflag " + B.ServiceName + " 1");

        string logDir = Path.Combine(B.DataDir, "logs");
        if (!Directory.Exists(logDir)) Directory.CreateDirectory(logDir);

        string svcKey = @"SYSTEM\CurrentControlSet\Services\" + B.ServiceName;
        using (var k = Win32Registry.LocalMachine.OpenSubKey(svcKey, true)) {
            if (k == null) { Log("WARN: service key not found to write Environment."); return; }
            // Drop a stale Environment subkey from older installs (SCM never read it).
            try { if (k.OpenSubKey("Environment") != null) k.DeleteSubKeyTree("Environment", false); } catch { }

            // Base user/system context (SYSTEM profile under the MSI), then the
            // effective agent config (incl. RUST_LOG), then tenant binding.
            var lines = new List<string> {
                "USERPROFILE=" + (Environment.GetEnvironmentVariable("USERPROFILE") ?? ""),
                "APPDATA=" + (Environment.GetEnvironmentVariable("APPDATA") ?? ""),
                "LOCALAPPDATA=" + Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "USERNAME=" + (Environment.GetEnvironmentVariable("USERNAME") ?? "")
            };
            foreach (var kv in cfg) lines.Add(kv.Key + "=" + kv.Value);
            string dom = Environment.GetEnvironmentVariable("USERDNSDOMAIN");
            if (!string.IsNullOrEmpty(dom)) lines.Add("USERDNSDOMAIN=" + dom);
            if (!string.IsNullOrEmpty(tenantId)) lines.Add("QUILR_TENANT_ID=" + tenantId);

            k.SetValue("Environment", lines.ToArray(), Win32RegistryValueKind.MultiString);
            Log("Wrote service Environment block (" + lines.Count + " vars).");
        }
    }

    private static void StartAgentService() {
        var svc = FindService(B.ServiceName);
        if (svc == null) { Log("WARN: cannot start -- " + B.ServiceName + " not registered."); return; }
        try {
            if (svc.Status == ServiceControllerStatus.Running) { Log(B.ServiceName + " already running."); return; }
            Log("Starting " + B.ServiceName + " service...");
            svc.Start();
            svc.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(30));
            svc.Refresh();
            if (svc.Status == ServiceControllerStatus.Running) {
                Log(B.ServiceName + " is running.");
            } else {
                Log("WARN: " + B.ServiceName + " status after start: " + svc.Status);
            }
        } catch (Exception ex) {
            // Non-fatal: files are installed; surface why it didn't come up.
            Log("WARN: " + B.ServiceName + " did not reach Running: " + ex.Message);
            string q = RunExe("sc.exe", "query " + B.ServiceName);
            if (!string.IsNullOrEmpty(q)) {
                foreach (string l in q.Split('\n'))
                    if (l.IndexOf("EXIT_CODE", StringComparison.OrdinalIgnoreCase) >= 0) Log("  " + l.Trim());
            }
            string agentLog = Path.Combine(B.DataDir, "logs", Path.GetFileNameWithoutExtension(B.ServiceExe) + ".log");
            if (File.Exists(agentLog)) {
                try {
                    string[] all = File.ReadAllLines(agentLog);
                    int from = Math.Max(0, all.Length - 8);
                    Log("  Last agent log lines (" + agentLog + "):");
                    for (int i = from; i < all.Length; i++) Log("    " + all[i]);
                } catch { }
            }
            Log("  Retry: Start-Service " + B.ServiceName + "  (check " + agentLog + ")");
        } finally {
            svc.Close();
        }
    }

    private static ServiceController FindService(string name) {
        try {
            foreach (var sc in ServiceController.GetServices())
                if (string.Equals(sc.ServiceName, name, StringComparison.OrdinalIgnoreCase)) return sc;
        } catch (Exception ex) { Log("WARN: ServiceController.GetServices failed: " + ex.Message); }
        return null;
    }

    // ─────────────────────────────────────────────────────────────────────
    // Foreign (non-MSI / CLI) agent removal
    // ─────────────────────────────────────────────────────────────────────
    // If a CLI-installed Sentinel agent is present -- C:\Program Files\Sentinel
    // has sentinel.exe AND sentinel-proxy.exe is running -- run its own uninstaller
    // under C:\Program Files\Quilr\sentinel-endpoint\ (the CLI ships it as a PS1,
    // sentinel-endpoint-uninstaller.ps1, run via powershell.exe; .exe fallback) before
    // we start our agent. MSI Sentinels were already removed by the <Upgrade>
    // cross-removal, so a Sentinel still here is the non-MSI/CLI install.
    // Skipped if that dir IS our own install dir (don't remove ourselves).
    private static void RemoveForeignCliAgent(string installerDir) {
        string pf = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        string sentinelDir = Path.Combine(pf, "Sentinel");
        if (string.Equals(sentinelDir, B.InstallDir, StringComparison.OrdinalIgnoreCase)) {
            Log("Foreign-agent check skipped (Sentinel dir is this brand's install dir).");
            return;
        }
        // Present if the dir has sentinel.exe OR the SentinelAgent service is
        // registered. We do NOT require the proxy to be running: a stopped-but-
        // installed CLI agent is still a stale/conflicting install to remove.
        bool dirInstalled = File.Exists(Path.Combine(sentinelDir, "sentinel.exe"));
        bool svcExists = FindService("SentinelAgent") != null;
        if (!dirInstalled && !svcExists) {
            Log("No CLI Sentinel install present (sentinel.exe=" + dirInstalled + ", SentinelAgent service=" + svcExists + ").");
            return;
        }
        bool proxyRunning = false;
        try { proxyRunning = Process.GetProcessesByName("sentinel-proxy").Length > 0; } catch { }
        Log("CLI Sentinel install present (sentinel.exe=" + dirInstalled + ", service=" + svcExists + ", proxy running=" + proxyRunning + ") -- removing.");

        // Preferred: run the CLI install's OWN uninstaller (it ships a .ps1; the
        // .exe has no uninstall). Run via powershell.exe (.exe fallback).
        string dir = Path.Combine(pf, @"Quilr\sentinel-endpoint");
        string ps1 = Path.Combine(dir, "sentinel-endpoint-uninstaller.ps1");
        string exe = Path.Combine(dir, "sentinel-endpoint-uninstaller.exe");
        ProcessStartInfo psi = null;
        if (File.Exists(ps1)) {
            string psh = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),
                                      @"WindowsPowerShell\v1.0\powershell.exe");
            psi = new ProcessStartInfo {
                FileName = psh,
                Arguments = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"" + ps1 + "\"",
                UseShellExecute = false, CreateNoWindow = true
            };
            Log("CLI Sentinel install detected (" + sentinelDir + " + running sentinel-proxy). Running its uninstaller PS1: " + ps1);
        } else if (File.Exists(exe)) {
            psi = new ProcessStartInfo { FileName = exe, UseShellExecute = false, CreateNoWindow = true };
            Log("CLI Sentinel install detected. Running its uninstaller exe: " + exe);
        }

        if (psi != null) {
            try {
                using (var p = Process.Start(psi)) {
                    if (!p.WaitForExit(300000)) Log("WARN: CLI uninstaller still running after 300s -- continuing.");
                    else Log("CLI Sentinel uninstaller exit code: " + p.ExitCode);
                }
                // If it actually removed things, the service+proxy should be gone now.
                if (FindService("SentinelAgent") == null && Process.GetProcessesByName("sentinel-proxy").Length == 0) {
                    Log("CLI Sentinel removed by its own uninstaller."); return;
                }
                Log("CLI uninstaller ran but Sentinel agent still present -- using native fallback.");
            } catch (Exception ex) {
                Log("WARN: CLI uninstaller failed (" + ex.Message + ") -- using native fallback.");
            }
        } else {
            Log("CLI Sentinel install detected but no bundled uninstaller (.ps1/.exe) at " + dir + " -- using native fallback.");
        }

        // Fallback: no (working) CLI uninstaller -- tear it down with OUR native
        // uninstall-launcher.exe pointed at a Sentinel brand.json. This stops+deletes
        // SentinelAgent, kills sentinel* processes, unloads WinDivert, and removes
        // C:\Program Files\Sentinel + its data/hooks/certs/env, even with no CLI uninstaller.
        NativeForeignUninstall(installerDir);
    }

    // Sentinel brand for the native fallback (matches build-msi $BrandSentinel).
    private const string SentinelBrandJson =
        "{\"ServiceExe\":\"sentinel.exe\",\"ServiceName\":\"SentinelAgent\"," +
        "\"ServiceDisplay\":\"Sentinel Endpoint Agent\",\"InstallDir\":\"C:\\\\Program Files\\\\Sentinel\"," +
        "\"DataDir\":\"C:\\\\ProgramData\\\\Sentinel\",\"HooksDirName\":\".sentinel\",\"EnvPrefix\":\"SENTINEL_\"," +
        "\"PackagePrefix\":\"sentinel_package\",\"UpdaterTask\":\"Sentinel-Endpoint-Update\"," +
        "\"Processes\":[\"sentinel\",\"sentinel-proxy\",\"ipc-light-broker\",\"sentinel-diagnostics\"," +
        "\"templating-engine\",\"template-engine\",\"sentinel-monitor-v2\",\"email-discovery\"," +
        "\"sentinel-hook-client\",\"sentinel-claude-hook-client\"]}";

    private static void NativeForeignUninstall(string installerDir) {
        string uninstaller = Path.Combine(installerDir, "uninstall-launcher.exe");
        if (!File.Exists(uninstaller)) { Log("WARN: uninstall-launcher.exe not found at " + uninstaller + " -- cannot remove CLI agent."); return; }
        string brandDir = Path.Combine(Path.GetTempPath(), "quilr-foreign-brand-" + Guid.NewGuid().ToString("N"));
        try {
            Directory.CreateDirectory(brandDir);
            File.WriteAllText(Path.Combine(brandDir, "brand.json"), SentinelBrandJson, new UTF8Encoding(false));
            Log("Native fallback: running uninstall-launcher.exe (Sentinel brand) to remove the CLI install...");
            var psi = new ProcessStartInfo {
                FileName = uninstaller,
                Arguments = "--brand-dir \"" + brandDir + "\"",
                UseShellExecute = false, CreateNoWindow = true
            };
            using (var p = Process.Start(psi)) {
                if (!p.WaitForExit(300000)) Log("WARN: native foreign uninstall still running after 300s -- continuing.");
                else Log("Native foreign uninstall exit code: " + p.ExitCode);
            }
        } catch (Exception ex) {
            Log("WARN: native foreign uninstall failed: " + ex.Message);
        } finally {
            try { Directory.Delete(brandDir, true); } catch { }
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    // Auto-updater wiring
    // ─────────────────────────────────────────────────────────────────────
    // Record the installed version so update-launcher.exe can compare against
    // discovery's endpoint_agent_version_windows.
    private static void WriteVersionFile(string version) {
        if (string.IsNullOrEmpty(version)) { Log("No ProductVersion supplied -- skipping version file."); return; }
        if (!Directory.Exists(B.DataDir)) Directory.CreateDirectory(B.DataDir);
        File.WriteAllText(Path.Combine(B.DataDir, "version"), version, new UTF8Encoding(false));
        Log("Recorded installed version " + version + " (" + B.DataDir + "\\version).");
    }

    // Register the SYSTEM scheduled task that runs update-launcher.exe every
    // <interval> minutes. Uses schtasks /XML so the exe path + args need no shell
    // quoting. An UPDATE_URL override is baked into the task args; otherwise the
    // updater reads UPDATE_URL from discovery at run time.
    private static void RegisterUpdaterTask(string installerDir, string intervalStr, string updateUrlOverride) {
        string exe = Path.Combine(installerDir, "update-launcher.exe");
        if (!File.Exists(exe)) { Log("WARN: update-launcher.exe not found at " + exe + " -- skipping updater task."); return; }
        int interval; if (!int.TryParse(intervalStr, out interval) || interval < 5) interval = 30;
        string args = string.IsNullOrEmpty(updateUrlOverride) ? "" : ("--update-url \"" + updateUrlOverride + "\"");
        string startBoundary = DateTime.Now.AddMinutes(2).ToString("yyyy-MM-ddTHH:mm:ss");

        string xml = BuildTaskXml(exe, args, interval, startBoundary);
        string tmp = Path.Combine(Path.GetTempPath(), "quilrai-updater-task-" + Guid.NewGuid().ToString("N") + ".xml");
        try {
            File.WriteAllText(tmp, xml, new UnicodeEncoding(false, true));   // UTF-16 LE + BOM (Task Scheduler requires)
            string outp = RunExe("schtasks.exe", "/Create /TN \"" + B.UpdaterTask + "\" /XML \"" + tmp + "\" /F");
            string q = RunExe("schtasks.exe", "/Query /TN \"" + B.UpdaterTask + "\"");
            if (q.IndexOf(B.UpdaterTask, StringComparison.OrdinalIgnoreCase) >= 0)
                Log("Registered auto-updater task '" + B.UpdaterTask + "' (every " + interval + " min, SYSTEM).");
            else
                Log("WARN: updater task not present after create. schtasks: " + outp.Trim());
        } finally { try { File.Delete(tmp); } catch { } }
    }

    private static string BuildTaskXml(string command, string arguments, int intervalMin, string startBoundary) {
        string cmdEsc  = System.Security.SecurityElement.Escape(command);
        string argsEsc = System.Security.SecurityElement.Escape(arguments ?? "");
        string argsElem = string.IsNullOrEmpty(arguments) ? "" : ("<Arguments>" + argsEsc + "</Arguments>");
        return
"<?xml version=\"1.0\" encoding=\"UTF-16\"?>\r\n" +
"<Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">\r\n" +
"  <Triggers>\r\n" +
"    <TimeTrigger>\r\n" +
"      <Repetition><Interval>PT" + intervalMin + "M</Interval><StopAtDurationEnd>false</StopAtDurationEnd></Repetition>\r\n" +
"      <StartBoundary>" + startBoundary + "</StartBoundary>\r\n" +
"      <Enabled>true</Enabled>\r\n" +
"    </TimeTrigger>\r\n" +
"  </Triggers>\r\n" +
"  <Principals>\r\n" +
"    <Principal id=\"Author\"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal>\r\n" +
"  </Principals>\r\n" +
"  <Settings>\r\n" +
"    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>\r\n" +
"    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>\r\n" +
"    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>\r\n" +
"    <StartWhenAvailable>true</StartWhenAvailable>\r\n" +
"    <Enabled>true</Enabled>\r\n" +
"    <ExecutionTimeLimit>PT1H</ExecutionTimeLimit>\r\n" +
"  </Settings>\r\n" +
"  <Actions Context=\"Author\">\r\n" +
"    <Exec><Command>" + cmdEsc + "</Command>" + argsElem + "</Exec>\r\n" +
"  </Actions>\r\n" +
"</Task>";
    }

    // Run a native exe, capture combined output, log on non-zero exit. Used for
    // taskkill / sc.exe / schtasks calls whose args have NO ambiguous embedded
    // quoting (paths in %TEMP% / fixed names).
    private static string RunExe(string file, string args) {
        try {
            var psi = new ProcessStartInfo {
                FileName = file, Arguments = args,
                UseShellExecute = false, CreateNoWindow = true,
                RedirectStandardOutput = true, RedirectStandardError = true
            };
            using (var p = Process.Start(psi)) {
                string outp = p.StandardOutput.ReadToEnd();
                string err = p.StandardError.ReadToEnd();
                p.WaitForExit();
                string combined = (outp + err).Trim();
                if (p.ExitCode != 0)
                    Log("  [" + file + " " + args + "] exit=" + p.ExitCode + (combined.Length > 0 ? " : " + combined : ""));
                return combined;
            }
        } catch (Exception ex) {
            Log("WARN: exec '" + file + " " + args + "' threw: " + ex.Message);
            return "";
        }
    }

    private static Dictionary<string,string> ParseArgs(string[] args) {
        var d = new Dictionary<string,string>(StringComparer.OrdinalIgnoreCase);
        for (int i = 0; i < args.Length; i++) {
            string a = args[i];
            if (a.StartsWith("--")) {
                string key = a.Substring(2);
                string val = (i + 1 < args.Length) ? args[i + 1] : "";
                d[key] = val;
                i++;
            }
        }
        return d;
    }

    private static void Log(string msg) {
        string line = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ") + " [INFO]  " + msg;
        if (s_logWriter != null) {
            try { s_logWriter.WriteLine(line); } catch { }
        }
    }

    private static void LogError(string msg) {
        string line = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ") + " [ERROR] " + msg;
        if (s_logWriter != null) {
            try { s_logWriter.WriteLine(line); } catch { }
        }
        Console.Error.WriteLine(line);
    }
}

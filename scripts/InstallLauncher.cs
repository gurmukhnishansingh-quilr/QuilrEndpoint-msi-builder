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
// MSI ExeCommand (set by WiX Product.wxs):
//   "[#fil_InstallLauncherExe]" --tenant-id "[TENANTID]"
//                               --env-name "[ENVNAME]"  --api-key "[APIKEY]"
//
// Behavior:
//   1. install dir = directory containing this exe (the MSI staged it there)
//   2. agent ps1 = "<installDir>\sentinel-endpoint.ps1"  (rebranded QuilrAI installer)
//   3. agent dir = "<installDir>\agent"  (the extracted package, bundled by the MSI)
//   4. resolve env from discovery (by tenant id) unless --env-name pins it
//   5. Spawn powershell.exe with
//        -File <ps1> -SourceDir <agentDir> -Env <env> -TenantId <tid> -RegisterAsService
//      redirect stdio to a per-launch log.
//   6. Wait. Return that process's exit code, mapped to 1603 on any error so
//      msiexec surfaces an unambiguous failure code.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Net;
using System.Reflection;
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
            CollectOverride(parsed, "tdir",  "QUILRAI_TEMPLATE_DIR",       overrides);  // TEMPLATEDIR
            CollectOverride(parsed, "ipath", "QUILRAI_INSTALLATION_PATH",  overrides);  // INSTALLPATH
            CollectOverride(parsed, "email", "QUILRAI_OVERRIDE_EMAIL",     overrides);  // WORKEMAIL
            CollectOverride(parsed, "udlp",  "QUILRAI_UNIFIED_DLP_POLICY", overrides);  // UNIFIEDDLP
            CollectOverride(parsed, "rlog",  "RUST_LOG",                   overrides);  // RUSTLOG

            Log("Env name: "  + (string.IsNullOrEmpty(envName)  ? "<empty>" : envName));
            Log("TenantId:  " + (string.IsNullOrEmpty(tenantId) ? "<empty>" : "<provided>"));
            if (overrides.Count > 0) Log("Property overrides supplied: " + string.Join(", ", new List<string>(overrides.Keys).ToArray()));

            // Launcher dir = dir containing this exe (INSTALLERDIR). The helper
            // payload (certs-bundle.zip, vc_redist.x64.exe) lives here.
            string exePath = Assembly.GetEntryAssembly().Location;
            string installerDir = Path.GetDirectoryName(exePath);
            Log("Installer (helper) dir: " + installerDir);

            // The agent itself was installed by MSI directly to C:\Program Files\QuilrAI
            // (and the QuilrAIAgent service created via ServiceInstall). Confirm it landed.
            if (!File.Exists(Path.Combine(AgentInstallDir, "quilrai.exe"))) {
                LogError("Agent not found at " + AgentInstallDir + "\\quilrai.exe (MSI file install may have failed).");
                return ERROR_INSTALL_FAILURE;
            }
            Log("Agent install dir: " + AgentInstallDir);

            // TenantId gating: must come from MSI arg, env var, or pre-staged file.
            if (string.IsNullOrEmpty(tenantId)) {
                string envTenant = Environment.GetEnvironmentVariable("QUILR_TENANT_ID");
                string preStaged = @"C:\ProgramData\QuilrAI\tenant_id";
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
                    string preStaged = @"C:\ProgramData\QuilrAI\tenant_id";
                    if (File.Exists(preStaged)) { try { effectiveTenant = File.ReadAllText(preStaged).Trim(); } catch { } }
                }
            }
            Dictionary<string,string> discBrowserEnv = null, discEndpointEnv = null;
            string resolvedEnv;

            if (!string.IsNullOrEmpty(envName)) {
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
            try { Environment.SetEnvironmentVariable(kv.Key, kv.Value, EnvironmentVariableTarget.Machine); n++; }
            catch (Exception ex) { Log("WARN: set " + kv.Key + " (Machine) failed: " + ex.Message); }
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

    private const string AgentInstallDir = @"C:\Program Files\QuilrAI";
    private const string AgentServiceName = "QuilrAIAgent";
    private const string AgentDataDir = @"C:\ProgramData\QuilrAI";

    private static void ConfigureAndStartAgent(string env, string tenantId,
            Dictionary<string,string> discEndpointEnv, Dictionary<string,string> overrides) {
        string userDir = InstallHooks(AgentInstallDir);   // returns the .quilrai dir

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
        SetNodeCaEnv(AgentInstallDir);

        // Publish the effective config at Machine scope (these are the values that
        // land in System env -- now exactly matching discovery / the overrides).
        foreach (var kv in cfg) SetMachineEnv(kv.Key, kv.Value);
        // These are only set when supplied (override) -- otherwise clear any stale value.
        if (!cfg.ContainsKey("QUILRAI_OVERRIDE_EMAIL"))    SetMachineEnv("QUILRAI_OVERRIDE_EMAIL", null);
        if (!cfg.ContainsKey("QUILRAI_UNIFIED_DLP_POLICY")) SetMachineEnv("QUILRAI_UNIFIED_DLP_POLICY", null);

        ConfigureServiceRuntime(tenantId, cfg);
        StartAgentService();
        Log("Native config complete.");
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
        if (!cfg.ContainsKey("QUILRAI_TEMPLATE_DIR"))
            cfg["QUILRAI_TEMPLATE_DIR"] = Path.Combine(AgentInstallDir, @"templates\app-discovery");
        if (!cfg.ContainsKey("QUILRAI_INSTALLATION_PATH"))
            cfg["QUILRAI_INSTALLATION_PATH"] = userDir;
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
        if (!Directory.Exists(AgentDataDir)) Directory.CreateDirectory(AgentDataDir);
        File.WriteAllText(Path.Combine(AgentDataDir, "tenant_id"), tenantId, new UTF8Encoding(false));
        Log("Tenant id persisted to " + AgentDataDir + "\\tenant_id");
    }

    // Hooks: copy <install>\hooks\* -> %LOCALAPPDATA%\.quilrai. The hooks/ dir
    // under QuilrAI is MSI-owned (removed on uninstall), so we copy only -- we do
    // NOT delete it. Returns the .quilrai dir (also QUILRAI_INSTALLATION_PATH).
    // NOTE: running as SYSTEM, LOCALAPPDATA is the SYSTEM profile -- same as the
    // PS1's behaviour under the MSI.
    private static string InstallHooks(string installDir) {
        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string userDir = Path.Combine(localAppData, ".quilrai");
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

    private static void SetMachineEnv(string name, string value) {
        try { Environment.SetEnvironmentVariable(name, value, EnvironmentVariableTarget.Machine); }
        catch (Exception ex) { Log("WARN: set " + name + " (Machine) failed: " + ex.Message); }
    }

    // Configure the MSI-created QuilrAIAgent service: failure-recovery policy and
    // the SCM Environment block (REG_MULTI_SZ "Environment" value on the service
    // key -- NOT a subkey). The agent config comes from `cfg` (discovery-authoritative,
    // built in BuildAgentConfig), so the service sees exactly the same values that
    // were published to System env. The service exists by now (After InstallServices).
    private static void ConfigureServiceRuntime(string tenantId, Dictionary<string,string> cfg) {
        if (FindService(AgentServiceName) == null) {
            Log("WARN: " + AgentServiceName + " not present (MSI ServiceInstall may have failed) -- skipping runtime config.");
            return;
        }

        // Failure recovery: restart 3x @5s, reset counter daily. Simple args, no quoting.
        RunExe("sc.exe", "failure " + AgentServiceName + " reset= 86400 actions= restart/5000/restart/5000/restart/5000");
        RunExe("sc.exe", "failureflag " + AgentServiceName + " 1");

        string logDir = Path.Combine(AgentDataDir, "logs");
        if (!Directory.Exists(logDir)) Directory.CreateDirectory(logDir);

        string svcKey = @"SYSTEM\CurrentControlSet\Services\" + AgentServiceName;
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
        var svc = FindService(AgentServiceName);
        if (svc == null) { Log("WARN: cannot start -- " + AgentServiceName + " not registered."); return; }
        try {
            if (svc.Status == ServiceControllerStatus.Running) { Log(AgentServiceName + " already running."); return; }
            Log("Starting " + AgentServiceName + " service...");
            svc.Start();
            svc.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(30));
            svc.Refresh();
            if (svc.Status == ServiceControllerStatus.Running) {
                Log(AgentServiceName + " is running.");
            } else {
                Log("WARN: " + AgentServiceName + " status after start: " + svc.Status);
            }
        } catch (Exception ex) {
            // Non-fatal: files are installed; surface why it didn't come up.
            Log("WARN: " + AgentServiceName + " did not reach Running: " + ex.Message);
            string q = RunExe("sc.exe", "query " + AgentServiceName);
            if (!string.IsNullOrEmpty(q)) {
                foreach (string l in q.Split('\n'))
                    if (l.IndexOf("EXIT_CODE", StringComparison.OrdinalIgnoreCase) >= 0) Log("  " + l.Trim());
            }
            string agentLog = Path.Combine(AgentDataDir, @"logs\quilrai.log");
            if (File.Exists(agentLog)) {
                try {
                    string[] all = File.ReadAllLines(agentLog);
                    int from = Math.Max(0, all.Length - 8);
                    Log("  Last agent log lines (" + agentLog + "):");
                    for (int i = from; i < all.Length; i++) Log("    " + all[i]);
                } catch { }
            }
            Log("  Retry: Start-Service " + AgentServiceName + "  (check " + agentLog + ")");
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

    // Run a native exe, capture combined output, log on non-zero exit. Used for
    // taskkill / sc.exe calls whose args have NO embedded quotes (so a plain
    // Arguments string is unambiguous).
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

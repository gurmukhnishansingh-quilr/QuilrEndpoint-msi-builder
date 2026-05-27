// UpdateLauncher.cs — QuilrAI agent auto-updater.
//
// Run periodically by the "QuilrAI-Endpoint-Update" scheduled task (created by
// install-launcher.exe). It asks discovery for the latest agent version and, if
// it's newer than what's installed, downloads the new package and swaps the
// binaries in C:\Program Files\QuilrAI, then restarts the service.
//
// Contract (both come from discovery):
//   * latest version   = discovery field  endpoint_agent_version_windows
//   * download location = discovery field  endpoint_agent_update_url_windows
//                         (a direct package .zip URL); override with --update-url.
//                         Falls back to endpoint_agent_env["UPDATE_URL"] only for
//                         older discovery records without the dedicated field.
//       - if the URL ends in ".zip" it's used as the package URL directly
//       - otherwise it's treated as a base dir and the package name is derived:
//             <url>/quilrai_package_v<version>_win_release.zip
//
// Installed version is tracked in C:\ProgramData\QuilrAI\version (written by
// install-launcher at install time and by this updater after each update).
//
// Build:
//   csc /target:winexe /reference:System.dll;System.IO.Compression.dll;
//       System.IO.Compression.FileSystem.dll;System.Web.Extensions.dll;
//       System.ServiceProcess.dll UpdateLauncher.cs
//
// Best-effort: a failed check never harms the running agent. Exit 0 = up-to-date
// or updated OK or nothing to do; non-zero = download/apply error.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Net;
using System.Reflection;
using System.Runtime.InteropServices;
using System.ServiceProcess;
using System.Text;
using System.Web.Script.Serialization;

internal static class UpdateLauncher {
    // Brand (paths/service/package names) loaded from brand.json in Main. See Brand.cs.
    private static Brand B = new Brand();
    private const string DiscoveryBase = "https://discover.quilrai.dev";
    private const string DefaultDiscoveryApiKey = "qd_live_0dX0_qSKMWwhsJL7AMvWF7YIChi263NE";

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool MoveFileEx(string existing, string newName, int flags);
    private const int MOVEFILE_DELAY_UNTIL_REBOOT = 0x4;

    private static StreamWriter s_log;
    private static string s_apiKey;

    private const long LogMaxBytes = 2 * 1024 * 1024;   // rotate at 2 MB (one generation)

    private static int Main(string[] args) {
        try { B = Brand.Load(Path.GetDirectoryName(Assembly.GetEntryAssembly().Location)); } catch { }
        try {
            string logDir = Path.Combine(B.DataDir, "logs");
            Directory.CreateDirectory(logDir);
            string logPath = Path.Combine(logDir, "quilrai-update.log");
            // Rotate so a task running every 30 min doesn't grow the log forever.
            try {
                var fi = new FileInfo(logPath);
                if (fi.Exists && fi.Length > LogMaxBytes) {
                    string bak = logPath + ".1";
                    if (File.Exists(bak)) File.Delete(bak);
                    File.Move(logPath, bak);
                }
            } catch { }
            s_log = new StreamWriter(logPath, true, Encoding.UTF8) { AutoFlush = true };
        } catch { s_log = null; }

        try {
            Log("================================================================");
            Log("QuilrAI updater started (PID " + Process.GetCurrentProcess().Id + ")");

            var a = ParseArgs(args);
            string updateUrlArg = (Get(a, "update-url") ?? "").Trim();
            string apiKeyArg    = (Get(a, "api-key")    ?? "").Trim();
            string tenantArg    = (Get(a, "tenant-id")  ?? "").Trim();
            s_apiKey = !string.IsNullOrEmpty(apiKeyArg) ? apiKeyArg
                     : (Environment.GetEnvironmentVariable("QUILR_DISCOVERY_API_KEY") ?? DefaultDiscoveryApiKey);

            string installedVer = ReadInstalledVersion();
            Log("Installed version: " + (string.IsNullOrEmpty(installedVer) ? "<unknown>" : installedVer));

            string tenant = !string.IsNullOrEmpty(tenantArg) ? tenantArg : ReadTenant();
            if (string.IsNullOrEmpty(tenant)) { Log("No tenant id available -- nothing to do."); return 0; }

            // Discovery is the source of truth for BOTH the target version and
            // (unless overridden) the download location.
            string latestVer, discUpdateUrl;
            QueryDiscovery(tenant, out latestVer, out discUpdateUrl);
            if (string.IsNullOrEmpty(latestVer)) {
                Log("Discovery has no endpoint_agent_version_windows for this tenant -- nothing to do.");
                return 0;
            }
            Log("Latest version (discovery): " + latestVer);

            if (!string.IsNullOrEmpty(installedVer) && CompareVersions(latestVer, installedVer) <= 0) {
                Log("Already up to date (installed " + installedVer + " >= latest " + latestVer + ").");
                return 0;
            }

            bool urlFromArg = !string.IsNullOrEmpty(updateUrlArg);
            string updateUrl = urlFromArg ? updateUrlArg : (discUpdateUrl ?? "").Trim();
            if (string.IsNullOrEmpty(updateUrl)) {
                Log("Newer version " + latestVer + " available, but no UPDATE_URL configured (discovery/arg) -- cannot download.");
                return 0;
            }
            Log("UPDATE_URL (" + (urlFromArg ? "--update-url arg" : "discovery") + "): " + updateUrl);

            string pkgUrl = updateUrl.EndsWith(".zip", StringComparison.OrdinalIgnoreCase)
                ? updateUrl
                : DerivePackageUrl(updateUrl, latestVer);
            Log("Package URL: " + pkgUrl);

            string tmp = Path.Combine(Path.GetTempPath(), "quilrai_update_" + Guid.NewGuid().ToString("N") + ".zip");
            if (!Download(pkgUrl, tmp)) { Log("Download failed -- skipping."); return 1; }
            try {
                if (!LooksLikeZip(tmp)) { Log("Downloaded file is not a ZIP -- aborting (UPDATE_URL wrong?)."); return 1; }

                Log("Applying update " + (installedVer ?? "?") + " -> " + latestVer + " ...");
                StopAgent();
                if (!ExtractOver(tmp, B.InstallDir))
                    Log("WARN: some files were locked and scheduled for replace-on-reboot.");
                WriteInstalledVersion(latestVer);
                StartAgent();
                Log("Update applied: now at " + latestVer + ".");
                return 0;
            } finally {
                try { if (File.Exists(tmp)) File.Delete(tmp); } catch { }
            }
        } catch (Exception ex) {
            Log("ERROR: " + ex);
            return 1;
        } finally {
            if (s_log != null) { try { s_log.Flush(); s_log.Dispose(); } catch { } }
        }
    }

    // ── Discovery: latest version + UPDATE_URL ────────────────────────────────
    private static void QueryDiscovery(string tenant, out string version, out string updateUrl) {
        version = null; updateUrl = null;
        try {
            string json = HttpGetDiscovery(DiscoveryBase + "/discovery/" + Uri.EscapeDataString(tenant));
            if (json == null) return;
            var root = new JavaScriptSerializer { MaxJsonLength = 8 * 1024 * 1024 }.DeserializeObject(json) as Dictionary<string,object>;
            if (root == null) return;
            object v;
            if (root.TryGetValue("endpoint_agent_version_windows", out v) && v != null && v.ToString().Trim().Length > 0)
                version = v.ToString().Trim();
            // Update URL: use the DEDICATED top-level field endpoint_agent_update_url_windows
            // (a direct package .zip URL). Fall back to endpoint_agent_env["UPDATE_URL"]
            // only if the dedicated field is absent (older discovery records).
            object u;
            if (root.TryGetValue("endpoint_agent_update_url_windows", out u) && u != null && u.ToString().Trim().Length > 0) {
                updateUrl = u.ToString().Trim();
            } else {
                object envObj;
                if (root.TryGetValue("endpoint_agent_env", out envObj)) {
                    var env = envObj as Dictionary<string,object>;
                    object eu;
                    if (env != null && env.TryGetValue("UPDATE_URL", out eu) && eu != null && eu.ToString().Trim().Length > 0)
                        updateUrl = eu.ToString().Trim();
                }
            }
        } catch (Exception ex) { Log("WARN: discovery query failed: " + ex.Message); }
    }

    private static string HttpGetDiscovery(string url) {
        try {
            try { ServicePointManager.SecurityProtocol |= SecurityProtocolType.Tls12; } catch { }
            var req = (HttpWebRequest)WebRequest.Create(url);
            req.Method = "GET"; req.Timeout = 30000; req.ReadWriteTimeout = 30000;
            req.UserAgent = "quilrai-updater"; req.Accept = "application/json";
            if (!string.IsNullOrEmpty(s_apiKey)) req.Headers.Add("x-api-key", s_apiKey);
            using (var resp = (HttpWebResponse)req.GetResponse())
            using (var sr = new StreamReader(resp.GetResponseStream())) return sr.ReadToEnd();
        } catch (Exception ex) { Log("WARN: GET " + url + " failed: " + ex.Message); return null; }
    }

    // <UPDATE_URL base>/quilrai_package_v<version>_win_release.zip
    private static string DerivePackageUrl(string baseUrl, string version) {
        string b = baseUrl.TrimEnd('/');
        return b + "/" + B.PackagePrefix + "_v" + version + "_win_release.zip";
    }

    // ── Version tracking ─────────────────────────────────────────────────────
    private static string VersionFile { get { return Path.Combine(B.DataDir, "version"); } }
    private static string ReadInstalledVersion() {
        try { if (File.Exists(VersionFile)) return File.ReadAllText(VersionFile).Trim(); } catch { }
        return null;
    }
    private static void WriteInstalledVersion(string v) {
        try { Directory.CreateDirectory(B.DataDir); File.WriteAllText(VersionFile, v, new UTF8Encoding(false)); }
        catch (Exception ex) { Log("WARN: could not write version file: " + ex.Message); }
    }

    // >0 if a>b, 0 equal, <0 if a<b. Dotted numeric parts.
    private static int CompareVersions(string a, string b) {
        string[] pa = (a ?? "0").Split('.'), pb = (b ?? "0").Split('.');
        int n = Math.Max(pa.Length, pb.Length);
        for (int i = 0; i < n; i++) {
            int x = i < pa.Length ? ParseLeadingInt(pa[i]) : 0;
            int y = i < pb.Length ? ParseLeadingInt(pb[i]) : 0;
            if (x != y) return x.CompareTo(y);
        }
        return 0;
    }
    private static int ParseLeadingInt(string s) {
        int end = 0; while (end < s.Length && char.IsDigit(s[end])) end++;
        int n; return int.TryParse(s.Substring(0, end), out n) ? n : 0;
    }

    // ── Download ──────────────────────────────────────────────────────────────
    private static bool Download(string url, string dest) {
        try {
            try { ServicePointManager.SecurityProtocol |= SecurityProtocolType.Tls12; } catch { }
            var req = (HttpWebRequest)WebRequest.Create(url);
            req.Method = "GET"; req.Timeout = 60000; req.ReadWriteTimeout = 300000;
            req.UserAgent = "quilrai-updater";
            using (var resp = (HttpWebResponse)req.GetResponse())
            using (var rs = resp.GetResponseStream())
            using (var fs = File.Create(dest)) { rs.CopyTo(fs); }
            long len = new FileInfo(dest).Length;
            Log("Downloaded " + len + " bytes.");
            return len > 0;
        } catch (Exception ex) { Log("WARN: download failed: " + ex.Message); return false; }
    }

    private static bool LooksLikeZip(string path) {
        try {
            using (var fs = File.OpenRead(path)) {
                if (fs.Length < 4) return false;
                int b0 = fs.ReadByte(), b1 = fs.ReadByte();
                return b0 == 0x50 && b1 == 0x4B;   // "PK"
            }
        } catch { return false; }
    }

    // ── Apply (stop / extract / start) ───────────────────────────────────────
    private static void StopAgent() {
        var svc = FindService(B.ServiceName);
        if (svc != null) {
            try {
                RunExe("sc.exe", "failure " + B.ServiceName + " reset= 0 actions= \"\"");
                if (svc.Status != ServiceControllerStatus.Stopped) {
                    svc.Stop(); svc.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(30));
                }
            } catch (Exception ex) { Log("WARN: stop service: " + ex.Message); }
            finally { svc.Close(); }
        }
        foreach (string p in B.Processes) RunExe("taskkill.exe", "/F /IM " + p + ".exe");
        System.Threading.Thread.Sleep(2000);
        if (FindService("WinDivert") != null) {
            RunExe("sc.exe", "stop WinDivert");
            RunExe("sc.exe", "delete WinDivert");
            for (int i = 0; i < 10 && FindService("WinDivert") != null; i++) System.Threading.Thread.Sleep(1000);
        }
    }

    // Extract the package over the install dir. Returns false if any file had to
    // be scheduled for replace-on-reboot (locked, e.g. WinDivert64.sys).
    private static bool ExtractOver(string zip, string dest) {
        bool allOk = true;
        Directory.CreateDirectory(dest);
        using (var za = ZipFile.OpenRead(zip)) {
            foreach (var e in za.Entries) {
                if (string.IsNullOrEmpty(e.Name)) { Directory.CreateDirectory(Path.Combine(dest, e.FullName)); continue; }
                string target = Path.Combine(dest, e.FullName.Replace('/', '\\'));
                Directory.CreateDirectory(Path.GetDirectoryName(target));
                try {
                    e.ExtractToFile(target, true);
                } catch (IOException) {
                    try {
                        string staged = target + ".new";
                        e.ExtractToFile(staged, true);
                        if (MoveFileEx(staged, target, MOVEFILE_DELAY_UNTIL_REBOOT)) {
                            Log("  locked, scheduled replace-on-reboot: " + e.FullName); allOk = false;
                        }
                    } catch (Exception ex2) { Log("  WARN: could not stage " + e.FullName + ": " + ex2.Message); allOk = false; }
                }
            }
        }
        return allOk;
    }

    private static void StartAgent() {
        var svc = FindService(B.ServiceName);
        if (svc == null) { Log("WARN: " + B.ServiceName + " not present -- cannot start."); return; }
        try {
            RunExe("sc.exe", "failure " + B.ServiceName + " reset= 86400 actions= restart/5000/restart/5000/restart/5000");
            if (svc.Status != ServiceControllerStatus.Running) {
                svc.Start(); svc.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(30));
            }
            svc.Refresh();
            Log(B.ServiceName + " status: " + svc.Status);
        } catch (Exception ex) { Log("WARN: start service: " + ex.Message); }
        finally { svc.Close(); }
    }

    private static ServiceController FindService(string name) {
        try { foreach (var sc in ServiceController.GetServices())
                if (string.Equals(sc.ServiceName, name, StringComparison.OrdinalIgnoreCase)) return sc; }
        catch (Exception ex) { Log("WARN: GetServices: " + ex.Message); }
        return null;
    }

    private static string RunExe(string file, string args) {
        try {
            var psi = new ProcessStartInfo { FileName = file, Arguments = args, UseShellExecute = false,
                CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
            using (var p = Process.Start(psi)) {
                string o = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
                p.WaitForExit();
                return o;
            }
        } catch (Exception ex) { Log("WARN: exec " + file + ": " + ex.Message); return ""; }
    }

    private static string ReadTenant() {
        try { string f = Path.Combine(B.DataDir, "tenant_id"); if (File.Exists(f)) return File.ReadAllText(f).Trim(); } catch { }
        return Environment.GetEnvironmentVariable("QUILR_TENANT_ID");
    }

    private static Dictionary<string,string> ParseArgs(string[] args) {
        var d = new Dictionary<string,string>(StringComparer.OrdinalIgnoreCase);
        for (int i = 0; i < args.Length; i++)
            if (args[i].StartsWith("--")) d[args[i].Substring(2)] = (i + 1 < args.Length) ? args[++i] : "";
        return d;
    }
    private static string Get(Dictionary<string,string> d, string k) { string v; return d.TryGetValue(k, out v) ? v : null; }

    private static void Log(string msg) {
        string line = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ") + " " + msg;
        if (s_log != null) { try { s_log.WriteLine(line); } catch { } }
    }
}

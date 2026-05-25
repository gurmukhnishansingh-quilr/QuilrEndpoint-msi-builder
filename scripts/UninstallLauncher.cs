// UninstallLauncher.cs — native MSI uninstall (no PowerShell).
//
// MSI deferred CA (Session 0, SYSTEM). Performs the full agent teardown in
// C#, mirroring source/sentinel-endpoint-uninstaller.ps1 minus the cosmetic
// console diagnostics (banners, event-log dumps, network snapshots) that are
// pointless in a headless Session-0 context. Order:
//   1. stop + delete the QuilrAIAgent service and kill agent processes
//   2. remove the Quilr CA certs (manifest from install, plus a subject sweep)
//   3. unload + delete the WinDivert driver (so its .sys can be removed)
//   4. delete install dir / hooks / data, with reboot-delete fallback for
//      anything still locked (WinDivert64.sys held by the kernel)
//   5. clear env vars, QUIC browser policies, re-enable IPv6, NDIS rebind
//
// Best-effort throughout: every step is wrapped so a single failure never traps
// MSI removal. Always returns 0. Keep in sync with the uninstaller PS1.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Management;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.ServiceProcess;
using System.Text;
using System.Threading;
using Microsoft.Win32;

internal static class UninstallLauncher {
    private const string InstallDir = @"C:\Program Files\QuilrAI";
    private const string ServiceName = "QuilrAIAgent";
    private const string DataDir = @"C:\ProgramData\QuilrAI";
    private const string QuilrProgramData = @"C:\ProgramData\Quilr";
    private const string InstalledCertsManifest = @"C:\ProgramData\Quilr\installed_certs.txt";
    private const string LegacyUpdaterTask = "Sentinel-Endpoint-Update";

    // Agent process base names (no .exe). quilrai-proxy holds the WinDivert
    // handle; legacy sentinel* names are harmless to include (skipped if absent).
    private static readonly string[] ProcessNames = {
        "quilrai", "quilrai-proxy", "ipc-light-broker", "quilrai-diagnostics",
        "templating-engine", "template-engine", "quilrai-monitor-v2", "email-discovery",
        "quilrai-hook-client", "quilrai-claude-hook-client",
        "sentinel", "sentinel-proxy", "sentinel-endpoint"
    };
    private static readonly string[] WinDivertServices = { "WinDivert", "WinDivert14" };
    private static readonly string[] WinDivertHolders = { "quilrai-proxy", "quilrai", "sentinel-proxy", "sentinel" };
    private static readonly string[] CertSubjects = {
        "Quilr EA Root CA", "Quilr EA Intermediate CA", "Quilr Proxy Root CA"
    };
    private static readonly string[] EnvVars = {
        "NODE_EXTRA_CA_CERTS", "NODE_TLS_REJECT_UNAUTHORIZED",
        "QUILR_DLP_ENDPOINT", "QUILR_BACKEND_BASE_URL",
        "QUILRAI_TEMPLATE_DIR", "QUILRAI_INSTALLATION_PATH", "QUILRAI_OVERRIDE_EMAIL", "QUILRAI_UNIFIED_DLP_POLICY",
        "QUILR_TENANT_ID",
        // legacy Sentinel-named vars from older builds
        "SENTINEL_OVERRIDE_EMAIL", "SENTINEL_TEMPLATE_DIR", "SENTINEL_INSTALLATION_PATH", "SENTINEL_UNIFIED_DLP_POLICY"
    };
    private static readonly string[] QuicPolicyKeys = {
        @"SOFTWARE\Policies\Google\Chrome",
        @"SOFTWARE\Policies\Microsoft\Edge"
    };

    private static StreamWriter s_log;
    private static bool s_rebootNeeded;

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool MoveFileEx(string existing, string newName, int flags);
    private const int MOVEFILE_DELAY_UNTIL_REBOOT = 0x4;

    private static int Main(string[] args) {
        try {
            string temp = Environment.GetEnvironmentVariable("TEMP")
                          ?? Environment.GetEnvironmentVariable("TMP")
                          ?? @"C:\Windows\Temp";
            s_log = new StreamWriter(Path.Combine(temp, "sentinel-msi-uninstall.log"), append: true, encoding: Encoding.UTF8) { AutoFlush = true };
        } catch { s_log = null; }

        try {
            Log("================================================================");
            Log("QuilrAI MSI uninstall launcher started (PID " + Process.GetCurrentProcess().Id + ")");

            Step("stop service + processes", StopServiceAndProcesses);
            Step("remove certificates",      RemoveCerts);
            Step("remove WinDivert driver",  RemoveWinDivert);
            Step("remove files",             RemoveFiles);
            Step("remove env vars",          RemoveEnvVars);
            Step("remove QUIC policies",     RemoveQuicPolicies);
            Step("re-enable IPv6",           EnableIPv6);
            Step("reset network adapters",   ResetNetworkAdapters);
            Step("remove legacy updater task", RemoveLegacyUpdaterTask);

            if (s_rebootNeeded)
                Log("NOTE: some locked items (e.g. WinDivert64.sys) are scheduled for deletion on next reboot.");
            Log("QuilrAI MSI uninstall launcher completed");
            return 0;
        } catch (Exception ex) {
            Log("ERROR: unhandled exception: " + ex);
            return 0;   // Best-effort: never trap MSI removal.
        } finally {
            if (s_log != null) { try { s_log.Flush(); s_log.Dispose(); } catch { } }
        }
    }

    private static void Step(string label, Action action) {
        Log("[step] " + label + " ...");
        try { action(); Log("[step] " + label + " done."); }
        catch (Exception ex) { Log("WARN: step '" + label + "' threw (continuing): " + ex.Message); }
    }

    // ── 1. Service + processes ───────────────────────────────────────────────
    // MSI's <ServiceControl> stops + removes the QuilrAIAgent service during the
    // StopServices/DeleteServices actions, which precede this CA. So the service
    // is normally already gone here; we just clear failure-recovery + stop it if
    // it somehow lingers, then kill any orphaned child processes (quilrai-proxy
    // etc.) so the WinDivert handle is released for the driver unload below.
    private static void StopServiceAndProcesses() {
        if (FindService(ServiceName) != null) {
            RunExe("sc.exe", "failure " + ServiceName + " reset= 0 actions= \"\"");
            RunExe("sc.exe", "stop " + ServiceName);
        } else {
            Log("  " + ServiceName + " service already removed (by MSI ServiceControl) or absent.");
        }

        foreach (string p in ProcessNames)
            RunExe("taskkill.exe", "/F /IM " + p + ".exe");
        Thread.Sleep(2000);
        // Service deletion is owned by MSI ServiceControl -- not done here.
    }

    // ── 2. Certificates ──────────────────────────────────────────────────────
    private static void RemoveCerts() {
        RemoveInstalledCertsFromManifest();
        RemoveCertsBySubject();
    }

    private static void RemoveInstalledCertsFromManifest() {
        if (!File.Exists(InstalledCertsManifest)) { Log("  no cert manifest at " + InstalledCertsManifest); return; }
        int removed = 0, missing = 0, errors = 0;
        foreach (string raw in File.ReadAllLines(InstalledCertsManifest)) {
            string line = raw.Trim();
            if (line.Length == 0) continue;
            string[] parts = line.Split('\t');
            if (parts.Length < 2) continue;
            string thumb = parts[0].Trim();
            string label = parts[1].Trim();
            StoreName sn = label.IndexOf("Root", StringComparison.OrdinalIgnoreCase) >= 0
                ? StoreName.Root : StoreName.CertificateAuthority;
            try {
                using (var store = new X509Store(sn, StoreLocation.LocalMachine)) {
                    store.Open(OpenFlags.ReadWrite);
                    var hit = store.Certificates.Find(X509FindType.FindByThumbprint, thumb, false);
                    if (hit.Count == 0) { missing++; continue; }
                    foreach (X509Certificate2 c in hit) store.Remove(c);
                    removed++;
                    Log("  [cert] removed from " + label + " (tp " + thumb + ")");
                }
            } catch (Exception ex) { errors++; Log("  WARN: remove tp=" + thumb + " from " + label + ": " + ex.Message); }
        }
        Log("  manifest certs: " + removed + " removed, " + missing + " absent, " + errors + " errors");
        try { File.Delete(InstalledCertsManifest); } catch { }
    }

    // CN sweep -- covers certs added outside the manifest (legacy installs,
    // CurrentUser\Root from the agent's own trust step, rotations). As SYSTEM in
    // Session 0 there's no interactive session, so no "delete root cert" dialog.
    private static void RemoveCertsBySubject() {
        foreach (string subj in CertSubjects) {
            foreach (StoreLocation loc in new[] { StoreLocation.CurrentUser, StoreLocation.LocalMachine }) {
                foreach (StoreName sn in new[] { StoreName.Root, StoreName.CertificateAuthority }) {
                    try {
                        using (var store = new X509Store(sn, loc)) {
                            store.Open(OpenFlags.ReadWrite);
                            var hits = store.Certificates.Find(X509FindType.FindBySubjectName, subj, false);
                            int n = 0;
                            foreach (X509Certificate2 c in hits) {
                                // FindBySubjectName is a substring match on CN; confirm the CN token.
                                if (c.Subject.IndexOf("CN=" + subj, StringComparison.OrdinalIgnoreCase) < 0) continue;
                                store.Remove(c); n++;
                            }
                            if (n > 0) Log("  [cert] CN='" + subj + "' removed " + n + " from " + loc + "\\" + sn);
                        }
                    } catch (Exception ex) { Log("  WARN: CN='" + subj + "' " + loc + "\\" + sn + ": " + ex.Message); }
                }
            }
        }
    }

    // ── 3. WinDivert driver ──────────────────────────────────────────────────
    private static void RemoveWinDivert() {
        string sys = Path.Combine(InstallDir, "WinDivert64.sys");
        foreach (string drv in WinDivertServices) {
            if (FindService(drv) == null) continue;
            Log("  WinDivert driver '" + drv + "' present -- unloading...");
            // Kill the handle holders so 'sc stop' can actually unload the driver.
            foreach (string h in WinDivertHolders) RunExe("taskkill.exe", "/F /IM " + h + ".exe");
            RunExe("sc.exe", "stop " + drv);

            // Drive the unload: deleting WinDivert64.sys succeeds the moment the
            // kernel releases the image -- so this both confirms unload AND removes
            // the file, no reboot needed in the common case. Poll up to ~20s.
            bool unloaded = false;
            for (int i = 0; i < 20; i++) {
                if (!File.Exists(sys)) { unloaded = true; break; }
                try { File.Delete(sys); unloaded = true; break; } catch { Thread.Sleep(1000); }
            }
            RunExe("sc.exe", "delete " + drv);
            if (unloaded) Log("  WinDivert '" + drv + "' unloaded and image removed.");
            else Log("  WARN: WinDivert '" + drv + "' image still locked -- will be scheduled for reboot-delete in file cleanup.");
        }
    }

    // ── 4. Files (with reboot-delete fallback for locked residue) ─────────────
    private static void RemoveFiles() {
        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        RemoveDirSafe(InstallDir, "install dir");
        RemoveDirSafe(Path.Combine(localAppData, ".quilrai"), "hooks dir");
        RemoveDirSafe(DataDir, "data dir");
        RemoveDirSafe(QuilrProgramData, "Quilr ProgramData");
        // legacy dirs from older Sentinel builds
        RemoveDirSafe(Path.Combine(localAppData, "Sentinel"), "legacy Sentinel user dir");
        RemoveDirSafe(Path.Combine(localAppData, "Quilr"), "legacy Quilr user dir");
    }

    private static void RemoveDirSafe(string path, string label) {
        if (!Directory.Exists(path)) { Log("  not found (" + label + "): " + path); return; }
        try { Directory.Delete(path, true); Log("  removed " + label + ": " + path); return; }
        catch (Exception ex) { Log("  " + label + " locked; scheduling residue for reboot-delete (" + ex.Message + ")"); }

        // Residue survived (usually WinDivert64.sys held by the kernel). Schedule
        // each surviving file (deepest-first) then dirs then the root for delete
        // on next reboot via MoveFileEx(MOVEFILE_DELAY_UNTIL_REBOOT).
        try {
            var files = new List<string>(Directory.GetFiles(path, "*", SearchOption.AllDirectories));
            files.Sort((a, b) => b.Length.CompareTo(a.Length));
            foreach (string f in files) {
                try { File.Delete(f); }
                catch { if (MoveFileEx(f, null, MOVEFILE_DELAY_UNTIL_REBOOT)) s_rebootNeeded = true; }
            }
            var dirs = new List<string>(Directory.GetDirectories(path, "*", SearchOption.AllDirectories));
            dirs.Sort((a, b) => b.Length.CompareTo(a.Length));
            foreach (string d in dirs) {
                try { Directory.Delete(d, false); }
                catch { if (MoveFileEx(d, null, MOVEFILE_DELAY_UNTIL_REBOOT)) s_rebootNeeded = true; }
            }
            try { Directory.Delete(path, false); }
            catch { if (MoveFileEx(path, null, MOVEFILE_DELAY_UNTIL_REBOOT)) s_rebootNeeded = true; }
        } catch (Exception ex) { Log("  WARN: enumerating residue in " + path + " failed: " + ex.Message); }
    }

    // ── 5a. Environment variables ─────────────────────────────────────────────
    private static void RemoveEnvVars() {
        foreach (string v in EnvVars) {
            try { Environment.SetEnvironmentVariable(v, null, EnvironmentVariableTarget.Machine); } catch { }
            try { Environment.SetEnvironmentVariable(v, null, EnvironmentVariableTarget.User); } catch { }
        }
        Log("  cleared " + EnvVars.Length + " env var(s) at Machine+User scope.");
        // The Env marker the install launcher wrote (single-package model).
        try { Win32RegistryDelete(@"SOFTWARE\Quilr\Sentinel"); Log("  removed HKLM\\SOFTWARE\\Quilr\\Sentinel"); }
        catch (Exception ex) { Log("  WARN: remove HKLM\\SOFTWARE\\Quilr\\Sentinel: " + ex.Message); }
    }

    // ── 5b. QUIC browser policies ─────────────────────────────────────────────
    private static void RemoveQuicPolicies() {
        foreach (string key in QuicPolicyKeys) {
            try {
                using (var k = Registry.LocalMachine.OpenSubKey(key, true)) {
                    if (k == null) continue;
                    if (k.GetValue("QuicAllowed") != null) {
                        k.DeleteValue("QuicAllowed", false);
                        Log("  removed QuicAllowed from HKLM\\" + key);
                    }
                }
            } catch (Exception ex) { Log("  WARN: QUIC cleanup @ " + key + ": " + ex.Message); }
        }
    }

    // ── 5c. Re-enable IPv6 (drop our DisabledComponents=0xFF override) ─────────
    private static void EnableIPv6() {
        const string key = @"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters";
        try {
            using (var k = Registry.LocalMachine.OpenSubKey(key, true)) {
                if (k == null) return;
                object v = k.GetValue("DisabledComponents");
                if (v == null) return;
                int cur = Convert.ToInt32(v);
                if (cur == 0xFF) { k.DeleteValue("DisabledComponents", false); Log("  removed Tcpip6 DisabledComponents=0xFF (IPv6 re-enabled across reboots)."); }
                else Log("  Tcpip6 DisabledComponents=0x" + cur.ToString("X") + " is not our override -- left untouched.");
            }
        } catch (Exception ex) { Log("  WARN: IPv6 registry cleanup: " + ex.Message); }
    }

    // ── 5d. NDIS rebind: bounce physical adapters after WinDivert removal ─────
    // WinDivert is an NDIS filter; removing it at runtime can leave an adapter
    // connected at L2 but unable to pass IP until NDIS re-binds. A disable/enable
    // forces the rebind, avoiding a "connected but no internet" state pre-reboot.
    private static void ResetNetworkAdapters() {
        RunExe("ipconfig.exe", "/flushdns");
        try {
            using (var searcher = new ManagementObjectSearcher(
                       @"root\cimv2",
                       "SELECT DeviceID, NetConnectionID FROM Win32_NetworkAdapter WHERE PhysicalAdapter=TRUE AND NetEnabled=TRUE")) {
                foreach (ManagementObject nic in searcher.Get()) {
                    string name = (nic["NetConnectionID"] ?? "?").ToString();
                    try {
                        nic.InvokeMethod("Disable", null);
                        Thread.Sleep(800);
                        nic.InvokeMethod("Enable", null);
                        Log("  reset adapter: " + name);
                    } catch (Exception ex) { Log("  WARN: reset adapter '" + name + "': " + ex.Message); }
                }
            }
        } catch (Exception ex) { Log("  WARN: adapter enumeration failed: " + ex.Message); }
    }

    // ── 5e. Legacy updater scheduled task (older heavyweight installer) ───────
    private static void RemoveLegacyUpdaterTask() {
        RunExe("schtasks.exe", "/Delete /TN \"" + LegacyUpdaterTask + "\" /F");
    }

    // ── Helpers ───────────────────────────────────────────────────────────────
    private static void Win32RegistryDelete(string subkey) {
        // Delete a subkey tree under HKLM if present.
        using (var parent = Registry.LocalMachine.OpenSubKey(Path.GetDirectoryName(subkey), true)) {
            if (parent == null) return;
            string leaf = Path.GetFileName(subkey);
            if (parent.OpenSubKey(leaf) != null) parent.DeleteSubKeyTree(leaf, false);
        }
    }

    private static ServiceController FindService(string name) {
        try {
            foreach (var sc in ServiceController.GetServices())
                if (string.Equals(sc.ServiceName, name, StringComparison.OrdinalIgnoreCase)) return sc;
        } catch (Exception ex) { Log("  WARN: ServiceController.GetServices: " + ex.Message); }
        return null;
    }

    // Run a native exe whose args contain no ambiguous embedded quoting.
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
                if (p.ExitCode != 0 && combined.Length > 0)
                    Log("  [" + file + " " + args + "] exit=" + p.ExitCode + " : " + combined);
                return combined;
            }
        } catch (Exception ex) {
            Log("  WARN: exec '" + file + " " + args + "' threw: " + ex.Message);
            return "";
        }
    }

    private static void Log(string msg) {
        string line = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ") + " " + msg;
        if (s_log != null) { try { s_log.WriteLine(line); } catch { } }
    }
}

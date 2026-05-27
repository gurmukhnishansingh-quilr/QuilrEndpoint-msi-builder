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
    // Brand (paths/service/process names) loaded from brand.json in Main.
    // QuilrAI defaults until then. See Brand.cs.
    private static Brand B = new Brand();
    private const string QuilrProgramData = @"C:\ProgramData\Quilr";
    private const string InstalledCertsManifest = @"C:\ProgramData\Quilr\installed_certs.txt";
    private const string LegacyUpdaterTask = "Sentinel-Endpoint-Update";

    private static readonly string[] WinDivertServices = { "WinDivert", "WinDivert14" };
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

    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    private static extern IntPtr SendMessageTimeout(IntPtr hWnd, uint msg, IntPtr wParam,
        string lParam, uint flags, uint timeoutMs, out IntPtr result);
    private const int HWND_BROADCAST = 0xFFFF;
    private const uint WM_SETTINGCHANGE = 0x001A;
    private const uint SMTO_ABORTIFHUNG = 0x0002;

    private static int Main(string[] args) {
        try {
            string temp = Environment.GetEnvironmentVariable("TEMP")
                          ?? Environment.GetEnvironmentVariable("TMP")
                          ?? @"C:\Windows\Temp";
            s_log = new StreamWriter(Path.Combine(temp, "sentinel-msi-uninstall.log"), append: true, encoding: Encoding.UTF8) { AutoFlush = true };
        } catch { s_log = null; }

        try {
            Log("================================================================");
            Log("MSI uninstall launcher started (PID " + Process.GetCurrentProcess().Id + ")");
            // --brand-dir <dir> lets a caller (install-launcher tearing down a CLI
            // install of ANOTHER brand) point us at a brand.json other than our own.
            string brandDir = null;
            for (int i = 0; i < args.Length; i++)
                if (string.Equals(args[i], "--brand-dir", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length) brandDir = args[i + 1];
            if (string.IsNullOrEmpty(brandDir)) brandDir = Path.GetDirectoryName(Assembly.GetEntryAssembly().Location);
            try { B = Brand.Load(brandDir); } catch { }
            Log("Brand: service=" + B.ServiceName + " dir=" + B.InstallDir + " (brandDir=" + brandDir + ")");

            Step("stop service + processes", StopServiceAndProcesses);
            Step("remove certificates",      RemoveCerts);
            Step("remove WinDivert driver",  RemoveWinDivert);
            Step("remove files",             RemoveFiles);
            Step("remove env vars",          RemoveEnvVars);
            Step("remove QUIC policies",     RemoveQuicPolicies);
            Step("re-enable IPv6",           EnableIPv6);
            Step("reset network adapters",   ResetNetworkAdapters);
            Step("remove updater task(s)",   RemoveUpdaterTasks);

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
    // Under MSI uninstall, <ServiceControl> has usually already removed the
    // service before this CA; but when run STANDALONE (e.g. install-launcher
    // invoking us with --brand-dir to tear down a CLI install of another brand)
    // nothing else removes it -- so we stop AND delete it here. sc delete is
    // idempotent (1060 = already gone), so it's safe in both cases.
    private static void StopServiceAndProcesses() {
        if (FindService(B.ServiceName) != null) {
            RunExe("sc.exe", "failure " + B.ServiceName + " reset= 0 actions= \"\"");
            RunExe("sc.exe", "stop " + B.ServiceName);
        } else {
            Log("  " + B.ServiceName + " service already removed or absent.");
        }

        foreach (string p in B.Processes)
            RunExe("taskkill.exe", "/F /IM " + p + ".exe");
        Thread.Sleep(2000);
        RunExe("sc.exe", "delete " + B.ServiceName);   // idempotent; needed for standalone removal
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
        string sys = Path.Combine(B.InstallDir, "WinDivert64.sys");
        foreach (string drv in WinDivertServices) {
            if (FindService(drv) == null) continue;
            Log("  WinDivert driver '" + drv + "' present -- unloading...");
            // Kill the handle holders so 'sc stop' can actually unload the driver.
            foreach (string h in B.Processes) RunExe("taskkill.exe", "/F /IM " + h + ".exe");
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
        RemoveDirSafe(B.InstallDir, "install dir");
        RemoveDirSafe(Path.Combine(localAppData, B.HooksDirName), "hooks dir");
        RemoveDirSafe(B.DataDir, "data dir");
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
    // Delete the values DIRECTLY from the registry, then broadcast WM_SETTINGCHANGE
    // ONCE. We do NOT use Environment.SetEnvironmentVariable(...,Machine/User): that
    // broadcasts on every call, and each broadcast blocks up to ~1s per unresponsive
    // top-level window -- with ~26 calls under appwiz.cpl that added ~60s to the
    // uninstall. Registry deletes are instant.
    private const string MachineEnvKey = @"SYSTEM\CurrentControlSet\Control\Session Manager\Environment";
    private static void RemoveEnvVars() {
        int n = 0;
        using (var m = Registry.LocalMachine.OpenSubKey(MachineEnvKey, true))
        using (var u = Registry.CurrentUser.OpenSubKey("Environment", true)) {
            foreach (string v in EnvVars) {
                try { if (m != null && m.GetValue(v) != null) { m.DeleteValue(v, false); n++; } }
                catch (Exception ex) { Log("  WARN: del Machine " + v + ": " + ex.Message); }
                try { if (u != null && u.GetValue(v) != null) { u.DeleteValue(v, false); n++; } }
                catch (Exception ex) { Log("  WARN: del User " + v + ": " + ex.Message); }
            }
        }
        BroadcastEnvChange();
        Log("  removed " + n + " env var value(s) from registry (Machine+User), broadcast once.");
        // The Env marker the install launcher wrote (single-package model).
        try { Win32RegistryDelete(@"SOFTWARE\Quilr\Sentinel"); Log("  removed HKLM\\SOFTWARE\\Quilr\\Sentinel"); }
        catch (Exception ex) { Log("  WARN: remove HKLM\\SOFTWARE\\Quilr\\Sentinel: " + ex.Message); }
    }

    private static void BroadcastEnvChange() {
        try {
            IntPtr res;
            SendMessageTimeout((IntPtr)HWND_BROADCAST, WM_SETTINGCHANGE, IntPtr.Zero,
                "Environment", SMTO_ABORTIFHUNG, 1000, out res);
        } catch { /* best-effort: a logoff/reboot picks up the change regardless */ }
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

    // ── 5e. Updater scheduled tasks ──────────────────────────────────────────
    // Remove the auto-updater task this MSI created, plus the legacy task from
    // the older heavyweight installer (no-op if absent).
    private static void RemoveUpdaterTasks() {
        RunExe("schtasks.exe", "/Delete /TN \"" + B.UpdaterTask + "\" /F");
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

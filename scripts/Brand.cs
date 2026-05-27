// Brand.cs — brand configuration shared by all three launcher exes.
//
// The launchers are brand-agnostic CODE: at startup they call Brand.Load(<dir>)
// to read brand.json (bundled next to the exe by build-msi.ps1). If brand.json
// is absent, the QuilrAI defaults below apply. This lets ONE signed set of
// launchers serve both the QuilrAI and Sentinel MSIs — brand is data, not code.
//
// build-msi.ps1 detects the brand from the agent package (quilrai.exe vs
// sentinel.exe at the package root) and writes the matching brand.json.

using System;
using System.Collections.Generic;
using System.IO;
using System.Web.Script.Serialization;

internal sealed class Brand {
    // ---- QuilrAI defaults (used when brand.json is absent) ----
    public string ServiceExe         = "quilrai.exe";
    public string ServiceName        = "QuilrAIAgent";
    public string ServiceDisplay     = "QuilrAI Endpoint Agent";
    public string InstallDir         = @"C:\Program Files\QuilrAI";
    public string DataDir            = @"C:\ProgramData\QuilrAI";
    public string HooksDirName       = ".quilrai";          // under %LOCALAPPDATA%
    public string EnvPrefix          = "QUILRAI_";          // TEMPLATE_DIR / INSTALLATION_PATH / OVERRIDE_EMAIL / UNIFIED_DLP_POLICY
    public string PackagePrefix      = "quilrai_package";   // updater package filename prefix
    public string UpdaterTask        = "QuilrAI-Endpoint-Update";
    public string[] Processes = {
        "quilrai", "quilrai-proxy", "ipc-light-broker", "quilrai-diagnostics",
        "templating-engine", "template-engine", "quilrai-monitor-v2", "email-discovery",
        "quilrai-hook-client", "quilrai-claude-hook-client"
    };

    // Derived env var names (brand-prefixed). QUILR_DLP_ENDPOINT /
    // QUILR_BACKEND_BASE_URL / RUST_LOG / NODE_* are brand-NEUTRAL and stay literal.
    public string TemplateDirVar   { get { return EnvPrefix + "TEMPLATE_DIR"; } }
    public string InstallPathVar   { get { return EnvPrefix + "INSTALLATION_PATH"; } }
    public string OverrideEmailVar { get { return EnvPrefix + "OVERRIDE_EMAIL"; } }
    public string UnifiedDlpVar    { get { return EnvPrefix + "UNIFIED_DLP_POLICY"; } }
    public string ServiceExePath   { get { return Path.Combine(InstallDir, ServiceExe); } }
    public string LogsDir          { get { return Path.Combine(DataDir, "logs"); } }
    public string TenantFile       { get { return Path.Combine(DataDir, "tenant_id"); } }
    public string VersionFile      { get { return Path.Combine(DataDir, "version"); } }

    public static Brand Load(string dir) {
        var b = new Brand();
        try {
            string p = Path.Combine(dir ?? ".", "brand.json");
            if (!File.Exists(p)) return b;
            var m = new JavaScriptSerializer().DeserializeObject(File.ReadAllText(p)) as Dictionary<string, object>;
            if (m == null) return b;
            b.ServiceExe     = S(m, "ServiceExe", b.ServiceExe);
            b.ServiceName    = S(m, "ServiceName", b.ServiceName);
            b.ServiceDisplay = S(m, "ServiceDisplay", b.ServiceDisplay);
            b.InstallDir     = S(m, "InstallDir", b.InstallDir);
            b.DataDir        = S(m, "DataDir", b.DataDir);
            b.HooksDirName   = S(m, "HooksDirName", b.HooksDirName);
            b.EnvPrefix      = S(m, "EnvPrefix", b.EnvPrefix);
            b.PackagePrefix  = S(m, "PackagePrefix", b.PackagePrefix);
            b.UpdaterTask    = S(m, "UpdaterTask", b.UpdaterTask);
            object procs;
            if (m.TryGetValue("Processes", out procs)) {
                var arr = procs as object[];
                if (arr != null) {
                    var list = new List<string>();
                    foreach (var o in arr) if (o != null) list.Add(o.ToString());
                    if (list.Count > 0) b.Processes = list.ToArray();
                }
            }
        } catch { /* fall back to defaults */ }
        return b;
    }

    private static string S(Dictionary<string, object> m, string k, string dflt) {
        object v; return (m.TryGetValue(k, out v) && v != null && v.ToString().Length > 0) ? v.ToString() : dflt;
    }
}

namespace ScanSysDefence.Core.Models;

public enum StartupLocationType
{
    RegistryRun,
    RegistryRunOnce,
    RegistryPolicies,
    StartupFolderUser,
    StartupFolderAllUsers,
    TaskScheduler,
    Services,
    Winlogon,
    AppInitDlls,
    ImageFileExecutionOptions,
    BrowserHelperObjects,
    ShellExtensions,
    ContextMenuHandlers,
    WinlogonNotify,
    LsaProviders,
    SecurityProviders,
    NetworkProviders,
    PrintMonitors,
    WmiEventSubscriptions,
    Unknown
}

public class StartupItem : ScanItemBase
{
    public StartupLocationType LocationType { get; set; } = StartupLocationType.Unknown;
    public string LocationPath { get; set; } = string.Empty;
    public string Command { get; set; } = string.Empty;
    public string Arguments { get; set; } = string.Empty;
    public string WorkingDirectory { get; set; } = string.Empty;
    public bool IsEnabled { get; set; } = true;
    public bool Hidden { get; set; }
    public string RunAsUser { get; set; } = string.Empty;
    public string TaskSchedulerXml { get; set; } = string.Empty;
    public DateTime? LastRunTime { get; set; }
    public DateTime? NextRunTime { get; set; }
    public int? TaskSchedulerId { get; set; }

    public override string Name => string.IsNullOrWhiteSpace(base.Name) 
        ? (string.IsNullOrWhiteSpace(Command) ? "Unknown" : System.IO.Path.GetFileNameWithoutExtension(Command.Split(' ')[0].Trim('"'))) 
        : base.Name;

    public override string Path => Command;

    public bool IsSuspiciousLocation => LocationType switch
    {
        StartupLocationType.AppInitDlls => true,
        StartupLocationType.ImageFileExecutionOptions => true,
        StartupLocationType.WinlogonNotify => true,
        StartupLocationType.LsaProviders => true,
        StartupLocationType.SecurityProviders => true,
        StartupLocationType.WmiEventSubscriptions => true,
        _ => false
    };

    public bool IsSuspiciousCommand => IsCommandSuspicious(Command);

    private bool IsCommandSuspicious(string cmd)
    {
        if (string.IsNullOrWhiteSpace(cmd)) return true;
        var lower = cmd.ToLowerInvariant();
        var suspiciousPatterns = new[]
        {
            "powershell -enc", "powershell -encodedcommand",
            "cmd /c", "wscript ", "cscript ", "mshta ",
            "rundll32 ", "regsvr32 ", "certutil ", "bitsadmin ",
            "schtasks /create", "at ", "sc create",
            "invoke-expression", "iex ", "downloadstring",
            "webclient", "invoke-webrequest", "curl ", "wget ",
            "base64", "frombase64string", "bypass", "executionpolicy",
            "hidden", "windowstyle hidden", "-w hidden"
        };
        return suspiciousPatterns.Any(p => lower.Contains(p));
    }

    public static StartupLocationType ParseLocationType(string path)
    {
        var lower = path.ToLowerInvariant();
        if (lower.Contains("\\run\\") || lower.Contains("\\runonce\\")) return StartupLocationType.RegistryRun;
        if (lower.Contains("\\policies\\")) return StartupLocationType.RegistryPolicies;
        if (lower.Contains("startup") && lower.Contains("programs")) return StartupLocationType.StartupFolderUser;
        if (lower.Contains("programdata") && lower.Contains("startup")) return StartupLocationType.StartupFolderAllUsers;
        if (lower.Contains("tasks") || lower.Contains("task scheduler")) return StartupLocationType.TaskScheduler;
        if (lower.Contains("winlogon")) return StartupLocationType.Winlogon;
        if (lower.Contains("appinit")) return StartupLocationType.AppInitDlls;
        if (lower.Contains("image file execution options")) return StartupLocationType.ImageFileExecutionOptions;
        if (lower.Contains("browser helper objects")) return StartupLocationType.BrowserHelperObjects;
        if (lower.Contains("contextmenuhandlers")) return StartupLocationType.ContextMenuHandlers;
        if (lower.Contains("shell extensions")) return StartupLocationType.ShellExtensions;
        if (lower.Contains("winlogon\\notify")) return StartupLocationType.WinlogonNotify;
        if (lower.Contains("lsa") || lower.Contains("securityproviders")) return StartupLocationType.SecurityProviders;
        if (lower.Contains("networkproviders")) return StartupLocationType.NetworkProviders;
        if (lower.Contains("printmonitors")) return StartupLocationType.PrintMonitors;
        if (lower.Contains("wmi") || lower.Contains("eventsubscription")) return StartupLocationType.WmiEventSubscriptions;
        return StartupLocationType.Unknown;
    }
}
namespace ScanSysDefence.Core.Models;

using System.Text.RegularExpressions;

public class ProcessInfo : ScanItemBase
{
    public int ProcessId { get; set; }
    public int ParentProcessId { get; set; }
    public string CommandLine { get; set; } = string.Empty;
    public string CurrentDirectory { get; set; } = string.Empty;
    public string UserName { get; set; } = string.Empty;
    public string SessionId { get; set; } = string.Empty;
    public DateTime StartTime { get; set; }
    public TimeSpan TotalProcessorTime { get; set; }
    public long WorkingSet64 { get; set; }
    public long PrivateMemorySize64 { get; set; }
    public long VirtualMemorySize64 { get; set; }
    public int ThreadCount { get; set; }
    public int HandleCount { get; set; }
    public bool IsElevated { get; set; }
    public bool IsWow64 { get; set; }
    public string IntegrityLevel { get; set; } = string.Empty;
    public List<ModuleInfo> Modules { get; set; } = new();
    public List<NetworkConnection> NetworkConnections { get; set; } = new();
    public List<string> OpenHandles { get; set; } = new();
    public string CompanyName { get; set; } = string.Empty;
    public string FileDescription { get; set; } = string.Empty;
    public string ProductName { get; set; } = string.Empty;
    public string OriginalFilename { get; set; } = string.Empty;
    public string FileVersion { get; set; } = string.Empty;
    public bool IsPacked { get; set; }
    public bool IsDotNet { get; set; }
    public string[] CommandLineArgs { get; set; } = Array.Empty<string>();

    public override string Name => string.IsNullOrWhiteSpace(base.Name) ? ProcessName : base.Name;
    public string ProcessName { get; set; } = string.Empty;

    public bool IsUnsigned => !IsSigned;
    public bool IsSuspiciousName => IsNameSuspicious(ProcessName);
    public bool IsSuspiciousPath => IsPathSuspicious(Path);
    public bool IsSuspiciousCommandLine => IsCommandLineSuspicious(CommandLine);
    public bool HasNoPublisher => string.IsNullOrWhiteSpace(Publisher);
    public bool IsRunningFromTemp => IsRunningFromTempPath(Path);
    public bool IsMasquerading => IsProcessMasquerading();

    private bool IsNameSuspicious(string name)
    {
        if (string.IsNullOrWhiteSpace(name)) return true;
        var lower = name.ToLowerInvariant();
        var suspiciousNames = new[]
        {
            "svhost", "svch0st", "scvhost", "serv1ce", "system32",
            "winlogon.exe", "csrss.exe", "lsass.exe", "smss.exe",
            "services.exe", "spoolsv.exe", "taskhost.exe",
            "conhost.exe", "dwm.exe", "explorer.exe", "wininit.exe"
        };
        return suspiciousNames.Any(s => lower.Contains(s) && lower != s.Replace(".exe", "")) ||
               lower.EndsWith(".exe.exe") ||
               lower.Contains("..") ||
               Regex.IsMatch(lower, @"^[a-z]{1,4}\.exe$");
    }

    private bool IsPathSuspicious(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) return true;
        var lower = path.ToLowerInvariant();
        var systemPaths = new[] { "c:\\windows\\system32\\", "c:\\windows\\syswow64\\", "c:\\windows\\winsxs\\", "c:\\program files\\", "c:\\program files (x86)\\" };
        var suspiciousPaths = new[] { "\\temp\\", "\\tmp\\", "\\appdata\\", "\\programdata\\", "\\users\\public\\", "\\recycler\\", "\\$recycle.bin\\", "\\system volume information\\", "\\windows\\temp\\", "\\windows\\tasks\\", "\\windows\\debug\\" };
        
        if (suspiciousPaths.Any(p => lower.Contains(p))) return true;
        if (systemPaths.Any(p => lower.StartsWith(p))) return false;
        return !lower.StartsWith("c:\\") || lower.Contains("..");
    }

    private bool IsCommandLineSuspicious(string cmd)
    {
        if (string.IsNullOrWhiteSpace(cmd)) return false;
        var lower = cmd.ToLowerInvariant();
        var suspicious = new[]
        {
            "-enc", "-encodedcommand", "-ep bypass", "bypass",
            "invoke-expression", "iex ", "downloadstring",
            "webclient", "invoke-webrequest", "curl.exe", "wget.exe",
            "certutil -decode", "certutil -urlcache", "bitsadmin /transfer",
            "mshta ", "rundll32 ", "regsvr32 ", "regasm ",
            "installutil ", "msbuild ", "csc.exe ", "vbc.exe ",
            "wmic ", "schtasks ", "at ", "sc create", "sc start",
            "net user", "net localgroup", "whoami", "systeminfo",
            "tasklist", "taskkill", "wmic process", "get-process",
            "stop-process", "kill", "invoke-mimikatz", "sekurlsa",
            "procdump", "comsvcs.dll", "sqldumper", "adplus",
            "hidden", "windowstyle hidden", "-w hidden", "nologo"
        };
        return suspicious.Any(s => lower.Contains(s));
    }

    private bool IsRunningFromTempPath(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) return false;
        var lower = path.ToLowerInvariant();
        return lower.Contains("\\temp\\") || lower.Contains("\\tmp\\") ||
               lower.Contains("\\appdata\\local\\temp") ||
               lower.Contains("\\windows\\temp\\");
    }

    private bool IsProcessMasquerading()
    {
        var systemProcesses = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["svchost.exe"] = "c:\\windows\\system32\\",
            ["lsass.exe"] = "c:\\windows\\system32\\",
            ["csrss.exe"] = "c:\\windows\\system32\\",
            ["winlogon.exe"] = "c:\\windows\\system32\\",
            ["services.exe"] = "c:\\windows\\system32\\",
            ["smss.exe"] = "c:\\windows\\system32\\",
            ["wininit.exe"] = "c:\\windows\\system32\\",
            ["spoolsv.exe"] = "c:\\windows\\system32\\",
            ["taskhostw.exe"] = "c:\\windows\\system32\\",
            ["dwm.exe"] = "c:\\windows\\system32\\",
            ["conhost.exe"] = "c:\\windows\\system32\\",
            ["explorer.exe"] = "c:\\windows\\",
            ["runtimebroker.exe"] = "c:\\windows\\system32\\",
            ["sihost.exe"] = "c:\\windows\\system32\\",
            ["taskhost.exe"] = "c:\\windows\\system32\\",
            ["fontdrvhost.exe"] = "c:\\windows\\system32\\",
            ["audiodg.exe"] = "c:\\windows\\system32\\",
            ["dllhost.exe"] = "c:\\windows\\system32\\",
            ["wmiprvse.exe"] = "c:\\windows\\system32\\wbem\\",
            ["searchindexer.exe"] = "c:\\windows\\system32\\",
            ["searchprotocolhost.exe"] = "c:\\windows\\system32\\",
            ["searchfilterhost.exe"] = "c:\\windows\\system32\\"
        };

        if (systemProcesses.TryGetValue(ProcessName, out var expectedPath))
        {
            var actualPath = Path.ToLowerInvariant();
            return !actualPath.StartsWith(expectedPath.ToLowerInvariant());
        }
        return false;
    }
}

public class ModuleInfo
{
    public string Name { get; set; } = string.Empty;
    public string Path { get; set; } = string.Empty;
    public long BaseAddress { get; set; }
    public int ModuleMemorySize { get; set; }
    public string FileVersion { get; set; } = string.Empty;
    public bool IsSigned { get; set; }
    public string Publisher { get; set; } = string.Empty;
    public bool IsSuspicious { get; set; }
}

public class NetworkConnection
{
    public string LocalAddress { get; set; } = string.Empty;
    public int LocalPort { get; set; }
    public string RemoteAddress { get; set; } = string.Empty;
    public int RemotePort { get; set; }
    public string State { get; set; } = string.Empty;
    public string Protocol { get; set; } = string.Empty;
    public int ProcessId { get; set; }
    public bool IsSuspicious => IsConnectionSuspicious();

    private bool IsConnectionSuspicious()
    {
        if (RemoteAddress == "127.0.0.1" || RemoteAddress == "::1" || RemoteAddress == "0.0.0.0") return false;
        var suspiciousPorts = new[] { 4444, 5555, 6666, 7777, 8888, 9999, 1234, 31337, 1337, 6667, 6668, 6669, 3128, 8080, 8888 };
        if (suspiciousPorts.Contains(RemotePort)) return true;
        return false;
    }
}

public class ScheduledTaskInfo : ScanItemBase
{
    public string TaskName { get; set; } = string.Empty;
    public string TaskPath { get; set; } = string.Empty;
    public override string Description { get; set; } = string.Empty;
    public string Author { get; set; } = string.Empty;
    public string UserId { get; set; } = string.Empty;
    public bool Enabled { get; set; }
    public bool Hidden { get; set; }
    public bool RunOnlyIfNetworkAvailable { get; set; }
    public bool AllowDemandStart { get; set; }
    public bool StartWhenAvailable { get; set; }
    public bool RunOnlyIfIdle { get; set; }
    public bool DisallowStartIfOnBatteries { get; set; }
    public bool StopIfGoingOnBatteries { get; set; }
    public DateTime? NextRunTime { get; set; }
    public DateTime? LastRunTime { get; set; }
    public int LastTaskResult { get; set; }
    public List<TaskAction> Actions { get; set; } = new();
    public List<TaskTrigger> Triggers { get; set; } = new();
    public TaskSettings Settings { get; set; } = new();
    public string Xml { get; set; } = string.Empty;

    public override string Name => TaskName;
    public override string Path => Actions.FirstOrDefault()?.Path ?? string.Empty;

    public bool IsHidden => Hidden;
    public bool IsSuspicious => IsTaskSuspicious();

    private bool IsTaskSuspicious()
    {
        if (Hidden) return true;
        if (Actions.Any(a => a.IsSuspicious)) return true;
        if (Triggers.Any(t => t.IsSuspicious)) return true;
        if (Author != "Microsoft Corporation" && !string.IsNullOrWhiteSpace(Author)) return true;
        return false;
    }
}

public class TaskAction
{
    public string Type { get; set; } = string.Empty;
    public string Path { get; set; } = string.Empty;
    public string Arguments { get; set; } = string.Empty;
    public string WorkingDirectory { get; set; } = string.Empty;
    public string Id { get; set; } = string.Empty;

    public bool IsSuspicious => IsActionSuspicious();

    private bool IsActionSuspicious()
    {
        var suspiciousPaths = new[] { "powershell", "cmd", "wscript", "cscript", "mshta", "rundll32", "regsvr32", "certutil", "bitsadmin", "schtasks", "at", "sc", "net", "wmic", "python", "perl", "ruby", "php", "node", "bash", "sh" };
        var lowerPath = Path.ToLowerInvariant();
        var lowerArgs = Arguments.ToLowerInvariant();
        
        if (suspiciousPaths.Any(p => lowerPath.EndsWith(p + ".exe") || lowerPath.Contains("\\" + p + ".exe"))) return true;
        if (lowerArgs.Contains("-enc") || lowerArgs.Contains("bypass") || lowerArgs.Contains("downloadstring") || lowerArgs.Contains("iex ")) return true;
        return false;
    }
}

public class TaskTrigger
{
    public string Type { get; set; } = string.Empty;
    public DateTime? StartBoundary { get; set; }
    public DateTime? EndBoundary { get; set; }
    public string RepetitionInterval { get; set; } = string.Empty;
    public string RepetitionDuration { get; set; } = string.Empty;
    public bool Enabled { get; set; } = true;
    public string Id { get; set; } = string.Empty;

    public bool IsSuspicious => Type == "Boot" || Type == "Logon" || Type == "Idle" || (RepetitionInterval != null && TimeSpan.TryParse(RepetitionInterval, out var ts) && ts.TotalMinutes < 60);
}

public class TaskSettings
{
    public bool AllowHardTerminate { get; set; } = true;
    public bool RunOnlyIfNetworkAvailable { get; set; }
    public bool AllowDemandStart { get; set; } = true;
    public bool StartWhenAvailable { get; set; }
    public bool RunOnlyIfIdle { get; set; }
    public bool DisallowStartIfOnBatteries { get; set; } = true;
    public bool StopIfGoingOnBatteries { get; set; } = true;
    public string IdleSettings { get; set; } = string.Empty;
    public bool DeleteExpiredTaskAfter { get; set; }
    public string ExecutionTimeLimit { get; set; } = "PT72H";
    public int Priority { get; set; } = 7;
    public bool RestartOnFailure { get; set; }
    public string RestartInterval { get; set; } = string.Empty;
    public int RestartCount { get; set; }
}
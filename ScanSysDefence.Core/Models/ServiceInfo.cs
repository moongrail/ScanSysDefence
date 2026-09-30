namespace ScanSysDefence.Core.Models;

public enum ServiceStartType
{
    Boot = 0,
    System = 1,
    Auto = 2,
    Manual = 3,
    Disabled = 4,
    Unknown = 99
}

public enum ServiceState
{
    Stopped = 1,
    StartPending = 2,
    StopPending = 3,
    Running = 4,
    ContinuePending = 5,
    PausePending = 6,
    Paused = 7,
    Unknown = 99
}

public enum ServiceType
{
    KernelDriver = 1,
    FileSystemDriver = 2,
    Adapter = 4,
    RecognizerDriver = 8,
    OwnProcess = 16,
    ShareProcess = 32,
    InteractiveProcess = 256,
    Unknown = 99
}

public class ServiceInfo : ScanItemBase
{
    public string DisplayName { get; set; } = string.Empty;
    public string ServiceName { get; set; } = string.Empty;
    public ServiceStartType StartType { get; set; } = ServiceStartType.Unknown;
    public ServiceState CurrentState { get; set; } = ServiceState.Unknown;
    public ServiceType ServiceType { get; set; } = ServiceType.Unknown;
    public string BinaryPath { get; set; } = string.Empty;
    public string LoadOrderGroup { get; set; } = string.Empty;
    public string[] Dependencies { get; set; } = Array.Empty<string>();
    public string[] DependentServices { get; set; } = Array.Empty<string>();
    public string StartAccount { get; set; } = string.Empty;
    public string ErrorControl { get; set; } = string.Empty;
    public int ProcessId { get; set; }
    public bool IsRunning => CurrentState == ServiceState.Running;
    public bool IsEnabled => StartType != ServiceStartType.Disabled;
    public bool IsSuspiciousPath => IsPathSuspicious(BinaryPath);
    public bool HasNoDescription => string.IsNullOrWhiteSpace(Description);
    public bool IsInteractive => ServiceType.HasFlag((ServiceType)256);

    public override string Name => ServiceName;
    public override string Path => BinaryPath;

    private bool IsPathSuspicious(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) return true;
        var lower = path.ToLowerInvariant();
        var suspiciousPaths = new[]
        {
            "\\temp\\", "\\tmp\\", "\\appdata\\", "\\programdata\\",
            "\\users\\public\\", "\\windows\\temp\\", "\\recycler\\",
            "\\system volume information\\", "\\$recycle.bin\\"
        };
        return suspiciousPaths.Any(p => lower.Contains(p)) ||
               (!lower.StartsWith("c:\\windows\\system32\\") &&
                !lower.StartsWith("c:\\windows\\syswow64\\") &&
                !lower.StartsWith("c:\\program files\\") &&
                !lower.StartsWith("c:\\program files (x86)\\\\"));
    }

    public static ServiceStartType ParseStartType(string value) => value?.ToLowerInvariant() switch
    {
        "boot" => ServiceStartType.Boot,
        "system" => ServiceStartType.System,
        "auto" => ServiceStartType.Auto,
        "automatic" => ServiceStartType.Auto,
        "manual" => ServiceStartType.Manual,
        "demand" => ServiceStartType.Manual,
        "disabled" => ServiceStartType.Disabled,
        _ => ServiceStartType.Unknown
    };

    public static ServiceState ParseState(string value) => value?.ToLowerInvariant() switch
    {
        "stopped" => ServiceState.Stopped,
        "start pending" => ServiceState.StartPending,
        "stop pending" => ServiceState.StopPending,
        "running" => ServiceState.Running,
        "continue pending" => ServiceState.ContinuePending,
        "pause pending" => ServiceState.PausePending,
        "paused" => ServiceState.Paused,
        _ => ServiceState.Unknown
    };

    public static ServiceType ParseType(uint value)
    {
        var type = ServiceType.Unknown;
        if ((value & 1) != 0) type |= ServiceType.KernelDriver;
        if ((value & 2) != 0) type |= ServiceType.FileSystemDriver;
        if ((value & 4) != 0) type |= ServiceType.Adapter;
        if ((value & 8) != 0) type |= ServiceType.RecognizerDriver;
        if ((value & 16) != 0) type |= ServiceType.OwnProcess;
        if ((value & 32) != 0) type |= ServiceType.ShareProcess;
        if ((value & 256) != 0) type |= ServiceType.InteractiveProcess;
        return type;
    }
}
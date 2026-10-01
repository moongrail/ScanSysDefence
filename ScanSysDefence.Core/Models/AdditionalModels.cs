namespace ScanSysDefence.Core.Models;

public class DriverInfo : ScanItemBase
{
    public string DisplayName { get; set; } = string.Empty;
    public string DriverName { get; set; } = string.Empty;
    public string BinaryPath { get; set; } = string.Empty;
    public string DriverType { get; set; } = string.Empty;
    public string StartType { get; set; } = string.Empty;
    public string State { get; set; } = string.Empty;
    public string ErrorControl { get; set; } = string.Empty;
    public string LoadOrderGroup { get; set; } = string.Empty;
    public string[] Dependencies { get; set; } = Array.Empty<string>();
    public bool IsKernelMode { get; set; }
    public bool IsBootDriver { get; set; }
    public bool IsSystemDriver { get; set; }

    public override string Name => DriverName;
    public override string Path => BinaryPath;

    public bool IsSuspiciousPath =>
        !string.IsNullOrWhiteSpace(BinaryPath) &&
        (BinaryPath.Contains("\\temp\\", StringComparison.OrdinalIgnoreCase) ||
         BinaryPath.Contains("\\appdata\\", StringComparison.OrdinalIgnoreCase) ||
         BinaryPath.Contains("\\users\\public\\", StringComparison.OrdinalIgnoreCase) ||
         !BinaryPath.StartsWith("c:\\windows\\", StringComparison.OrdinalIgnoreCase));

    public bool IsSuspicious => IsDriverSuspicious();

    private bool IsDriverSuspicious()
    {
        if (!IsSigned) return true;
        if (IsSuspiciousPath) return true;
        if (string.IsNullOrWhiteSpace(Description) && !IsSystemDriver) return true;
        return false;
    }
}

public class WmiSubscriptionInfo : ScanItemBase
{
    public string SubscriptionName { get; set; } = string.Empty;
    public string FilterQuery { get; set; } = string.Empty;
    public string ConsumerType { get; set; } = string.Empty;
    public string ConsumerCommand { get; set; } = string.Empty;
    public string Creator { get; set; } = string.Empty;
    public bool IsActive { get; set; }
    public string Namespace { get; set; } = string.Empty;

    public override string Name => SubscriptionName;
    public override string Path => ConsumerCommand;

    public bool IsSuspicious => IsSubscriptionSuspicious();

    private bool IsSubscriptionSuspicious()
    {
        var suspiciousQueries = new[] { "targetinstance isa \"win32_process\"", "targetinstance isa \"win32_service\"", "__instancecreationevent", "__instancemodificationevent", "__instancedeletionevent" };
        var lowerQuery = FilterQuery.ToLowerInvariant();
        if (suspiciousQueries.Any(q => lowerQuery.Contains(q))) return true;
        
        var suspiciousConsumers = new[] { "commandlineeventconsumer", "active_script_event_consumer", "nt_event_log_event_consumer", "smtp_event_consumer" };
        if (suspiciousConsumers.Any(c => ConsumerType.ToLowerInvariant().Contains(c))) return true;
        
        return false;
    }
}

public class BrowserExtensionInfo : ScanItemBase
{
    public string Browser { get; set; } = string.Empty;
    public string ExtensionId { get; set; } = string.Empty;
    public string ExtensionName { get; set; } = string.Empty;
    public override string Version { get; set; } = string.Empty;
    public string InstallPath { get; set; } = string.Empty;
    public bool IsEnabled { get; set; }
    public string Permissions { get; set; } = string.Empty;
    public string UpdateUrl { get; set; } = string.Empty;
    public string HomepageUrl { get; set; } = string.Empty;
    public bool IsFromStore { get; set; }

    public override string Name => ExtensionName;
    public override string Path => InstallPath;

    public bool IsSuspicious => IsExtensionSuspicious();

    private bool IsExtensionSuspicious()
    {
        if (!IsFromStore && !string.IsNullOrWhiteSpace(InstallPath)) return true;
        if (Permissions.Contains("all_urls") || Permissions.Contains("<all_urls>")) return true;
        return false;
    }
}

public class ScanResult
{
    public string ScanId { get; set; } = Guid.NewGuid().ToString();
    public DateTime StartedAt { get; set; }
    public DateTime? CompletedAt { get; set; }
    public ScanStatus Status { get; set; } = ScanStatus.Pending;
    public TimeSpan Duration => CompletedAt.HasValue ? CompletedAt.Value - StartedAt : DateTime.Now - StartedAt;
    
    public List<ServiceInfo> Services { get; set; } = new();
    public List<StartupItem> StartupItems { get; set; } = new();
    public List<ProcessInfo> Processes { get; set; } = new();
    public List<DriverInfo> Drivers { get; set; } = new();
    public List<ScheduledTaskInfo> ScheduledTasks { get; set; } = new();
    public List<WmiSubscriptionInfo> WmiSubscriptions { get; set; } = new();
    public List<BrowserExtensionInfo> BrowserExtensions { get; set; } = new();
    
    public int TotalItems => Services.Count + StartupItems.Count + Processes.Count + Drivers.Count + ScheduledTasks.Count + WmiSubscriptions.Count + BrowserExtensions.Count;
    public int SuspiciousCount => AllItems.Count(i => i.RiskAssessment.Level >= RiskLevel.Medium);
    public int CriticalCount => AllItems.Count(i => i.RiskAssessment.Level == RiskLevel.Critical);
    public int HighCount => AllItems.Count(i => i.RiskAssessment.Level == RiskLevel.High);
    
    public IEnumerable<ScanItemBase> AllItems => Services.Cast<ScanItemBase>()
        .Concat(StartupItems)
        .Concat(Processes)
        .Concat(Drivers)
        .Concat(ScheduledTasks)
        .Concat(WmiSubscriptions)
        .Concat(BrowserExtensions);

    public Dictionary<RiskLevel, int> RiskDistribution => AllItems
        .GroupBy(i => i.RiskAssessment.Level)
        .ToDictionary(g => g.Key, g => g.Count());
}

public enum ScanStatus
{
    Pending,
    Running,
    Completed,
    Cancelled,
    Failed
}

public class ScanProgress
{
    public string ScanId { get; set; } = string.Empty;
    public ScanPhase CurrentPhase { get; set; }
    public int CurrentPhaseProgress { get; set; }
    public int TotalPhases { get; set; } = 7;
    public string CurrentItem { get; set; } = string.Empty;
    public int ItemsScanned { get; set; }
    public int SuspiciousFound { get; set; }
    public string StatusMessage { get; set; } = string.Empty;
    public bool IsCancellationRequested { get; set; }
}

public enum ScanPhase
{
    Initializing = 0,
    ScanningServices = 1,
    ScanningStartup = 2,
    ScanningProcesses = 3,
    ScanningDrivers = 4,
    ScanningTasks = 5,
    ScanningWmi = 6,
    ScanningBrowsers = 7,
    Analyzing = 8,
    Finalizing = 9
}
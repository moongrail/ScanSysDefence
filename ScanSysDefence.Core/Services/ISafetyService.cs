using ScanSysDefence.Core.Models;
using ScanSysDefence.Core.Remediation;

namespace ScanSysDefence.Core.Services;

public interface ISafetyService
{
    Task<SafetyCheckResult> ValidateActionAsync(RemediationAction action, ScanItemBase target);
    Task<SafetyCheckResult> ValidateBatchAsync(List<RemediationAction> actions, IEnumerable<ScanItemBase> targets);
    Task<SystemHealthSnapshot> CaptureSystemHealthAsync();
    Task<SystemHealthComparison> CompareSystemHealthAsync(SystemHealthSnapshot before);
    Task<bool> IsSystemCriticalAsync(ScanItemBase item);
    Task<List<string>> GetDependenciesAsync(ScanItemBase item);
    Task<RollbackToken> CreateRollbackPointAsync(string description);
    Task<RollbackResult> RollbackAsync(RollbackToken token);
    Task<List<RollbackToken>> GetAvailableRollbacksAsync();
    Task<bool> IsActionReversibleAsync(RemediationAction action);
    Task<SimulationResult> SimulateActionAsync(RemediationAction action, ScanItemBase target);
}

public class SafetyCheckResult
{
    public bool IsSafe { get; set; }
    public SafetyLevel Level { get; set; }
    public List<SafetyViolation> Violations { get; set; } = new();
    public List<SafetyWarning> Warnings { get; set; } = new();
    public List<SafetyRecommendation> Recommendations { get; set; } = new();
    public bool RequiresElevation { get; set; }
    public bool RequiresUserConfirmation { get; set; }
    public bool RequiresRestorePoint { get; set; }
    public string Summary { get; set; } = string.Empty;
}

public enum SafetyLevel
{
    Safe = 0,
    Caution = 1,
    Warning = 2,
    Dangerous = 3,
    Critical = 4,
    Blocked = 5
}

public class SafetyViolation
{
    public string Code { get; set; } = string.Empty;
    public string Message { get; set; } = string.Empty;
    public string MessageRu { get; set; } = string.Empty;
    public SafetyLevel Severity { get; set; }
    public string AffectedComponent { get; set; } = string.Empty;
    public string Remediation { get; set; } = string.Empty;
    public bool IsBlocking { get; set; }
}

public class SafetyWarning
{
    public string Code { get; set; } = string.Empty;
    public string Message { get; set; } = string.Empty;
    public string MessageRu { get; set; } = string.Empty;
    public SafetyLevel Severity { get; set; }
    public string AffectedComponent { get; set; } = string.Empty;
}

public class SafetyRecommendation
{
    public string Code { get; set; } = string.Empty;
    public string Message { get; set; } = string.Empty;
    public string MessageRu { get; set; } = string.Empty;
    public SafetyAction Action { get; set; }
}

public enum SafetyAction
{
    CreateRestorePoint,
    BackupFile,
    QuarantineInsteadOfDelete,
    DisableInsteadOfDelete,
    StopServiceBeforeDisable,
    CheckDependenciesFirst,
    RunInSafeMode,
    RequireManualVerification,
    SkipAction
}

public class SystemHealthSnapshot
{
    public string Id { get; set; } = Guid.NewGuid().ToString();
    public DateTime Timestamp { get; set; } = DateTime.Now;
    public string Description { get; set; } = string.Empty;
    public Dictionary<string, object> Metrics { get; set; } = new();
    public List<string> RunningCriticalServices { get; set; } = new();
    public List<string> LoadedCriticalDrivers { get; set; } = new();
    public long AvailableMemory { get; set; }
    public int ProcessCount { get; set; }
    public int ServiceCount { get; set; }
    public bool IsSystemStable { get; set; } = true;
}

public class SystemHealthComparison
{
    public bool IsHealthy { get; set; }
    public List<string> DegradedServices { get; set; } = new();
    public List<string> StoppedCriticalServices { get; set; } = new();
    public List<string> NewErrors { get; set; } = new();
    public List<string> Warnings { get; set; } = new();
    public string Summary { get; set; } = string.Empty;
}

public class RollbackToken
{
    public string Id { get; set; } = Guid.NewGuid().ToString();
    public DateTime CreatedAt { get; set; } = DateTime.Now;
    public string Description { get; set; } = string.Empty;
    public List<RollbackAction> Actions { get; set; } = new();
    public string BackupPath { get; set; } = string.Empty;
    public bool IsUsed { get; set; }
    public DateTime? UsedAt { get; set; }
    public string ActionType { get; set; } = string.Empty;
    public string TargetIdentifier { get; set; } = string.Empty;
}

public class RollbackAction
{
    public RollbackActionType Type { get; set; }
    public string Target { get; set; } = string.Empty;
    public string OriginalValue { get; set; } = string.Empty;
    public string NewValue { get; set; } = string.Empty;
    public Dictionary<string, object> Metadata { get; set; } = new();
}

public enum RollbackActionType
{
    RestoreFile,
    RestoreRegistryKey,
    RestoreRegistryValue,
    EnableService,
    StartService,
    RestoreStartupEntry,
    RestoreScheduledTask,
    RestoreWmiSubscription,
    LoadDriver,
    RestoreFileFromQuarantine,
    RestoreFromBackup
}

public class RollbackResult
{
    public bool Success { get; set; }
    public string TokenId { get; set; } = string.Empty;
    public int ActionsRolledBack { get; set; }
    public int ActionsFailed { get; set; }
    public List<string> Errors { get; set; } = new();
    public TimeSpan Duration { get; set; }
}

public class SimulationResult
{
    public bool IsSafe { get; set; }
    public SafetyLevel PredictedRisk { get; set; }
    public List<string> PredictedEffects { get; set; } = new();
    public List<string> AffectedComponents { get; set; } = new();
    public List<string> Warnings { get; set; } = new();
    public string Summary { get; set; } = string.Empty;
    public string SummaryRu { get; set; } = string.Empty;
}
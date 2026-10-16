using ScanSysDefence.Core.Models;

namespace ScanSysDefence.Core.Remediation;

public enum RemediationActionType
{
    StopProcess,
    StopService,
    DisableService,
    RemoveStartupEntry,
    DeleteFile,
    QuarantineFile,
    DisableScheduledTask,
    DeleteScheduledTask,
    RemoveWmiSubscription,
    RemoveBrowserExtension,
    UnloadDriver,
    CleanupDisk
}

public class RemediationAction
{
    public string Id { get; set; } = Guid.NewGuid().ToString();
    public RemediationActionType Type { get; set; }
    public string TargetId { get; set; } = string.Empty;
    public string TargetName { get; set; } = string.Empty;
    public string TargetPath { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public bool RequiresElevation { get; set; } = true;
    public bool RequiresRestorePointPrompt { get; set; } = true; // Changed: prompt user instead of auto
    public DateTime CreatedAt { get; set; } = DateTime.Now;
    public Dictionary<string, object> Parameters { get; set; } = new();
}

public class RemediationResult
{
    public string ActionId { get; set; } = string.Empty;
    public bool Success { get; set; }
    public string Message { get; set; } = string.Empty;
    public string Error { get; set; } = string.Empty;
    public DateTime ExecutedAt { get; set; } = DateTime.Now;
    public TimeSpan Duration { get; set; }
    public bool RestorePointCreated { get; set; }
    public string RestorePointSequenceNumber { get; set; } = string.Empty;
    public string BackupPath { get; set; } = string.Empty;
    public object? OutputData { get; set; }
}

public class RestorePointPromptContext
{
    public string ActionDescription { get; set; } = string.Empty;
    public List<string> AffectedItems { get; set; } = new();
    public bool IsDestructive { get; set; } = true;
    public string RecommendedDescription { get; set; } = string.Empty;
}

public interface IRemediationService
{
    Task<RemediationResult> ExecuteActionAsync(RemediationAction action, RestorePointPromptContext? promptContext = null, CancellationToken cancellationToken = default);
    
    // Individual actions
    Task<RemediationResult> StopProcessAsync(int processId, string processName, bool promptForRestorePoint = false);
    Task<RemediationResult> ForceKillProcessAsync(int processId, string processName);
    Task<RemediationResult> StopServiceAsync(string serviceName, bool promptForRestorePoint = false);
    Task<RemediationResult> DisableServiceAsync(string serviceName, bool promptForRestorePoint = false);
    Task<RemediationResult> RemoveStartupEntryAsync(StartupItem item, bool promptForRestorePoint = false);
    Task<RemediationResult> DeleteFileAsync(string filePath, bool createBackup = true, bool promptForRestorePoint = false);
    Task<RemediationResult> QuarantineFileAsync(string filePath, bool promptForRestorePoint = false);
    Task<RemediationResult> DisableScheduledTaskAsync(string taskName, string taskPath, bool promptForRestorePoint = false);
    Task<RemediationResult> DeleteScheduledTaskAsync(string taskName, string taskPath, bool promptForRestorePoint = false);
    Task<RemediationResult> RemoveWmiSubscriptionAsync(string subscriptionName, bool promptForRestorePoint = false);
    Task<RemediationResult> UnloadDriverAsync(string driverName, bool promptForRestorePoint = false);

    // Quarantine management
    Task<List<QuarantineEntry>> GetQuarantineEntriesAsync();
    Task<RemediationResult> RestoreFromQuarantineAsync(string quarantinePath, string? targetPath = null);
    Task<RemediationResult> DeleteFromQuarantineAsync(string quarantinePath);
    string QuarantineFolderPath { get; }
    
    // Batch operations
    Task<RemediationResult> ExecuteBatchAsync(List<RemediationAction> actions, RestorePointPromptContext? promptContext = null, CancellationToken cancellationToken = default);
}

public interface IRestorePointPromptService
{
    Task<RestorePointPromptResult> PromptUserAsync(RestorePointPromptContext context);
    void SetUserPreference(bool alwaysCreate, bool neverCreate);
    (bool alwaysCreate, bool neverCreate) GetUserPreference();
}

public class RestorePointPromptResult
{
    public bool ShouldCreateRestorePoint { get; set; }
    public string Description { get; set; } = string.Empty;
    public bool RememberChoice { get; set; }
    public RestorePointPromptAction Action { get; set; }
}

public enum RestorePointPromptAction
{
    CreateAndContinue,
    SkipAndContinue,
    Cancel
}
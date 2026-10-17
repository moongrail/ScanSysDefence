namespace ScanSysDefence.Core.Services;

public enum RegistryIssueType
{
    OrphanedUninstallEntry,
    BrokenSharedDll,
    InvalidStartupEntry,
    BrokenComRegistration,
    BrokenFileAssociation,
    EmptyKey
}

public class RegistryIssue : System.ComponentModel.INotifyPropertyChanged
{
    private bool _isSelected = true;

    public event System.ComponentModel.PropertyChangedEventHandler? PropertyChanged;

    public string Id { get; set; } = Guid.NewGuid().ToString();
    public RegistryIssueType Type { get; set; }
    public string Hive { get; set; } = string.Empty;
    public string KeyPath { get; set; } = string.Empty;
    public string ValueName { get; set; } = string.Empty;
    public string Target { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string DescriptionRu { get; set; } = string.Empty;
    public string RecommendationRu { get; set; } = string.Empty;
    public Models.RiskLevel RiskLevel { get; set; } = Models.RiskLevel.Low;
    public bool CanRepair { get; set; } = true;
    public bool RequiresKeyDeletion { get; set; }

    /// <summary>Исправление = удаление значения «по умолчанию» (битая ассоциация файла).</summary>
    public bool DeleteDefaultValue { get; set; }

    public bool IsSelected
    {
        get => _isSelected;
        set
        {
            if (_isSelected == value) return;
            _isSelected = value;
            PropertyChanged?.Invoke(this, new System.ComponentModel.PropertyChangedEventArgs(nameof(IsSelected)));
        }
    }
}

public class RegistryBackup
{
    public string Id { get; set; } = Guid.NewGuid().ToString();
    public string FilePath { get; set; } = string.Empty;
    public DateTime CreatedAt { get; set; } = DateTime.Now;
    public int IssueCount { get; set; }
    public string Description { get; set; } = string.Empty;
    public long FileSize { get; set; }
}

public class RegistryScanProgress
{
    public string CurrentArea { get; set; } = string.Empty;
    public int KeysScanned { get; set; }
    public int IssuesFound { get; set; }
    public int ProgressPercent { get; set; }
    public string StatusMessage { get; set; } = string.Empty;
}

public class RegistryRepairProgress
{
    public int CurrentIndex { get; set; }
    public int Total { get; set; }
    public string CurrentTarget { get; set; } = string.Empty;
    public int ProgressPercent { get; set; }
    public string StatusMessage { get; set; } = string.Empty;
}

public class RegistryScanResult
{
    public DateTime ScanTime { get; set; } = DateTime.Now;
    public TimeSpan Duration { get; set; }
    public List<RegistryIssue> Issues { get; set; } = new();
    public int TotalKeysScanned { get; set; }
    public Dictionary<RegistryIssueType, int> ByType => Issues.GroupBy(i => i.Type).ToDictionary(g => g.Key, g => g.Count());
}

public class RegistryRepairResult
{
    public bool Success { get; set; }
    public int Repaired { get; set; }
    public int Failed { get; set; }
    public bool BackupCreated { get; set; }
    public string BackupPath { get; set; } = string.Empty;
    public List<string> Errors { get; set; } = new();
    public TimeSpan Duration { get; set; }
    public string Message { get; set; } = string.Empty;
}

public interface IRegistryRepairService
{
    Task<RegistryScanResult> ScanAsync(IProgress<RegistryScanProgress>? progress = null, CancellationToken cancellationToken = default);
    Task<RegistryRepairResult> RepairAsync(List<RegistryIssue> issues, bool createBackup, IProgress<RegistryRepairProgress>? progress = null, CancellationToken cancellationToken = default);
    Task<RegistryRepairResult> RestoreBackupAsync(string backupFilePath);
    Task<List<RegistryBackup>> GetBackupsAsync();
}

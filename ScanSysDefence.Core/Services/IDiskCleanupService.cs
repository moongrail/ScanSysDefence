using ScanSysDefence.Core.Models;

namespace ScanSysDefence.Core.Services;

public interface IDiskCleanupService
{
    Task<List<DriveInfo>> GetDrivesAsync();
    Task<DiskCleanupScanResult> ScanAsync(string driveLetter, CleanupScanSettings settings, IProgress<CleanupScanProgress>? progress = null, CancellationToken cancellationToken = default);
    Task<CleanupResult> CleanAsync(List<CleanupItem> itemsToClean, bool createRestorePoint, IProgress<CleanupProgress>? progress = null, CancellationToken cancellationToken = default);
    Task<List<CleanupCategory>> GetCategoriesAsync();
}

public class DriveInfo
{
    public string Letter { get; set; } = string.Empty;
    public string Label { get; set; } = string.Empty;
    public string FileSystem { get; set; } = string.Empty;
    public long TotalSize { get; set; }
    public long FreeSpace { get; set; }
    public long UsedSpace => TotalSize - FreeSpace;
    public double UsagePercent => TotalSize > 0 ? (double)UsedSpace / TotalSize * 100 : 0;
    public DriveType DriveType { get; set; }
    public bool IsSystemDrive { get; set; }
    public bool IsReady { get; set; }
}

public class CleanupScanSettings
{
    public bool IncludeSystemTemp { get; set; } = true;
    public bool IncludeUserTemp { get; set; } = true;
    public bool IncludeWindowsUpdate { get; set; } = true;
    public bool IncludePrefetch { get; set; } = true;
    public bool IncludeThumbnails { get; set; } = true;
    public bool IncludeRecycleBin { get; set; } = true;
    public bool IncludeMemoryDumps { get; set; } = true;
    public bool IncludeDeliveryOptimization { get; set; } = true;
    public bool IncludeDriverStore { get; set; } = false; // Requires admin, careful
    public bool IncludeBrowserCache { get; set; } = true;
    public bool IncludeAppCaches { get; set; } = true;
    public bool IncludeDefenderCache { get; set; } = true;
    public bool IncludeOldChkdsk { get; set; } = true;
    public bool IncludeLogs { get; set; } = true;
    public int MinFileAgeDays { get; set; } = 7; // Only files older than N days
    public bool IncludeSubdirectories { get; set; } = true;
    public long MaxFileSize { get; set; } = 0; // 0 = no limit
    public List<string> ExcludedPaths { get; set; } = new();
    public bool SkipFilesInUse { get; set; } = true;
    public bool MoveToRecycleBin { get; set; } = true; // Safer than permanent delete
}

public class CleanupCategory : System.ComponentModel.INotifyPropertyChanged
{
    private bool _isSelectedByDefault = true;

    public event System.ComponentModel.PropertyChangedEventHandler? PropertyChanged;

    public string Id { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string DescriptionRu { get; set; } = string.Empty;
    public bool RequiresAdmin { get; set; }
    public RiskLevel RiskLevel { get; set; } = RiskLevel.Low;
    public List<string> Paths { get; set; } = new();

    public bool IsSelectedByDefault
    {
        get => _isSelectedByDefault;
        set
        {
            if (_isSelectedByDefault == value) return;
            _isSelectedByDefault = value;
            PropertyChanged?.Invoke(this, new System.ComponentModel.PropertyChangedEventArgs(nameof(IsSelectedByDefault)));
        }
    }
}

public class CleanupItem : System.ComponentModel.INotifyPropertyChanged
{
    private bool _isSelected = true;

    public event System.ComponentModel.PropertyChangedEventHandler? PropertyChanged;

    public string Id { get; set; } = Guid.NewGuid().ToString();
    public string CategoryId { get; set; } = string.Empty;
    public string CategoryName { get; set; } = string.Empty;
    public string FilePath { get; set; } = string.Empty;
    public string FileName { get; set; } = string.Empty;
    public long Size { get; set; }
    public DateTime LastAccessTime { get; set; }
    public DateTime LastWriteTime { get; set; }
    public DateTime CreationTime { get; set; }
    public FileAttributes Attributes { get; set; }
    public bool CanDelete { get; set; } = true;
    public string CannotDeleteReason { get; set; } = string.Empty;
    public bool IsInUse { get; set; }
    public bool IsSystemFile { get; set; }
    public bool MoveToRecycleBin { get; set; } = true;
    public string DescriptionRu { get; set; } = string.Empty;
    public RiskLevel RiskLevel { get; set; } = RiskLevel.Low;

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

public class DiskCleanupScanResult
{
    public string DriveLetter { get; set; } = string.Empty;
    public DateTime ScanTime { get; set; } = DateTime.Now;
    public TimeSpan ScanDuration { get; set; }
    public List<CleanupItem> Items { get; set; } = new();
    public List<CleanupCategorySummary> CategorySummaries { get; set; } = new();
    public long TotalSize { get; set; }
    public int TotalFiles { get; set; }
    public long SelectedSize => Items.Where(i => i.IsSelected && i.CanDelete).Sum(i => i.Size);
    public int SelectedFiles => Items.Count(i => i.IsSelected && i.CanDelete);
    public Dictionary<string, long> SizeByCategory => Items
        .Where(i => i.CanDelete)
        .GroupBy(i => i.CategoryId)
        .ToDictionary(g => g.Key, g => g.Sum(i => i.Size));
}

public class CleanupCategorySummary
{
    public string CategoryId { get; set; } = string.Empty;
    public string CategoryName { get; set; } = string.Empty;
    public long TotalSize { get; set; }
    public int FileCount { get; set; }
    public long SelectedSize { get; set; }
    public int SelectedFiles { get; set; }
    public bool IsExpanded { get; set; } = true;
}

public class CleanupScanProgress
{
    public string CurrentCategory { get; set; } = string.Empty;
    public string CurrentPath { get; set; } = string.Empty;
    public int FilesScanned { get; set; }
    public long BytesScanned { get; set; }
    public int ProgressPercent { get; set; }
    public string StatusMessage { get; set; } = string.Empty;
}

public class CleanupProgress
{
    public int CurrentFileIndex { get; set; }
    public int TotalFiles { get; set; }
    public string CurrentFile { get; set; } = string.Empty;
    public long BytesCleaned { get; set; }
    public long TotalBytesToClean { get; set; }
    public int ProgressPercent { get; set; }
    public string StatusMessage { get; set; } = string.Empty;
    public List<string> Errors { get; set; } = new();
}

public class CleanupResult
{
    public bool Success { get; set; }
    public int FilesDeleted { get; set; }
    public int FilesFailed { get; set; }
    public long BytesFreed { get; set; }
    public TimeSpan Duration { get; set; }
    public bool RestorePointCreated { get; set; }
    public string RestorePointSequenceNumber { get; set; } = string.Empty;
    public List<CleanupError> Errors { get; set; } = new();
    public List<string> DeletedFiles { get; set; } = new();
    public List<string> FailedFiles { get; set; } = new();
}

public class CleanupError
{
    public string FilePath { get; set; } = string.Empty;
    public string Error { get; set; } = string.Empty;
    public Exception? Exception { get; set; }
}
namespace ScanSysDefence.Core.Services;

public interface IRestorePointService
{
    Task<bool> CreateRestorePointAsync(string description);
    Task<bool> IsSystemRestoreEnabledAsync();
    Task<List<RestorePointInfo>> GetRestorePointsAsync();
    Task<bool> DeleteRestorePointAsync(string sequenceNumber);
}

public class RestorePointInfo
{
    public string SequenceNumber { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public DateTime CreationTime { get; set; }
    public RestorePointType Type { get; set; }
    public int EventType { get; set; }
}

public enum RestorePointType
{
    ApplicationInstall = 0,
    ApplicationUninstall = 1,
    DeviceDriverInstall = 10,
    ModifySettings = 12,
    CancelledOperation = 13
}
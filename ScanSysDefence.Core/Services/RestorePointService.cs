using System.Management;

namespace ScanSysDefence.Core.Services;

public class RestorePointService : IRestorePointService
{
    private readonly ILogger _logger;

    public RestorePointService(ILogger logger)
    {
        _logger = logger;
    }

    public async Task<bool> CreateRestorePointAsync(string description = "ScanSysDefence Restore Point")
    {
        try
        {
            _logger.Information("Creating system restore point: {Description}", description);

            var enabled = await IsSystemRestoreEnabledAsync();
            if (!enabled)
            {
                _logger.Warning("System Restore is disabled, cannot create restore point");
                return false;
            }

            var result = await Task.Run(() => CreateRestorePointNative(description));
            
            if (result)
            {
                _logger.Information("Restore point created successfully");
            }
            else
            {
                _logger.Error("Failed to create restore point");
            }

            return result;
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Exception creating restore point");
            return false;
        }
    }

    private bool CreateRestorePointNative(string description)
    {
        try
        {
            var scope = new ManagementScope(@"\\.\root\default");
            scope.Connect();

            using var classInstance = new ManagementClass(scope, new ManagementPath("SystemRestore"), null);
            using var inParams = classInstance.GetMethodParameters("CreateRestorePoint");
            
            inParams["Description"] = description;
            inParams["RestorePointType"] = (int)RestorePointType.ModifySettings;
            inParams["EventType"] = 100; // BEGIN_SYSTEM_CHANGE

            using var outParams = classInstance.InvokeMethod("CreateRestorePoint", inParams, null);
            
            var returnValue = Convert.ToUInt32(outParams["ReturnValue"]);
            return returnValue == 0;
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Native restore point creation failed");
            return false;
        }
    }

    public async Task<bool> IsSystemRestoreEnabledAsync()
    {
        return await Task.Run(() =>
        {
            try
            {
                var scope = new ManagementScope(@"\\.\root\default");
                scope.Connect();

                using var searcher = new ManagementObjectSearcher(scope, new ObjectQuery("SELECT * FROM SystemRestore"));
                foreach (ManagementObject obj in searcher.Get())
                {
                    var disabled = obj["RPSessionId"] == null || Convert.ToUInt32(obj["RPSessionId"]) == 0;
                    return !disabled;
                }
                return false;
            }
            catch
            {
                return false;
            }
        });
    }

    public async Task<List<RestorePointInfo>> GetRestorePointsAsync()
    {
        return await Task.Run(() =>
        {
            var points = new List<RestorePointInfo>();
            try
            {
                var scope = new ManagementScope(@"\\.\root\default");
                scope.Connect();

                using var searcher = new ManagementObjectSearcher(scope, new ObjectQuery("SELECT * FROM SystemRestore"));
                foreach (ManagementObject obj in searcher.Get())
                {
                    points.Add(new RestorePointInfo
                    {
                        SequenceNumber = obj["SequenceNumber"]?.ToString() ?? string.Empty,
                        Description = obj["Description"]?.ToString() ?? string.Empty,
                        CreationTime = ManagementDateTimeConverter.ToDateTime(obj["CreationTime"]?.ToString() ?? string.Empty),
                        Type = (RestorePointType)Convert.ToInt32(obj["RestorePointType"] ?? 0),
                        EventType = Convert.ToInt32(obj["EventType"] ?? 0)
                    });
                }
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Failed to get restore points");
            }
            return points.OrderByDescending(p => p.CreationTime).ToList();
        });
    }

    public Task<bool> DeleteRestorePointAsync(string sequenceNumber)
    {
        try
        {
            _logger.Information("Deleting restore point: {SequenceNumber}", sequenceNumber);
            
            var scope = new ManagementScope(@"\\.\root\default");
            scope.Connect();

            using var classInstance = new ManagementClass(scope, new ManagementPath("SystemRestore"), null);
            using var inParams = classInstance.GetMethodParameters("DeleteRestorePoint");
            
            inParams["SequenceNumber"] = sequenceNumber;

            using var outParams = classInstance.InvokeMethod("DeleteRestorePoint", inParams, null);
            
            var returnValue = Convert.ToUInt32(outParams["ReturnValue"]);
            return Task.FromResult(returnValue == 0);
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Failed to delete restore point");
            return Task.FromResult(false);
        }
    }
}
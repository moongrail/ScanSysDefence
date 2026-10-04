using System.Management;
using ScanSysDefence.Core.Analysis;
using ScanSysDefence.Core.Models;
using ScanSysDefence.Core.Services;
using ScanSysDefence.Core.Utils;

namespace ScanSysDefence.Core.Scanners;

public class DriverScanner : IScanner
{
    public string Name => "Kernel Drivers";
    public ScanPhase Phase => ScanPhase.ScanningDrivers;

    private readonly ILogger _logger;
    private readonly IDigitalSignatureService _signatureService;

    public DriverScanner(ILogger logger, IDigitalSignatureService signatureService)
    {
        _logger = logger;
        _signatureService = signatureService;
    }

    public async Task<IEnumerable<ScanItemBase>> ScanAsync(ScanContext context, CancellationToken cancellationToken = default)
    {
        var drivers = new List<DriverInfo>();

        if (!context.Settings.ScanDrivers)
        {
            _logger.Information("Driver scanning disabled in settings");
            return drivers;
        }

        try
        {
            context.Progress?.Report(new ScanProgress
            {
                CurrentPhase = Phase,
                StatusMessage = "Перечисление драйверов ядра..."
            });

            var scope = new ManagementScope(@"\\.\root\cimv2");
            scope.Connect();

            using var searcher = new ManagementObjectSearcher(scope, new ObjectQuery(
                "SELECT * FROM Win32_SystemDriver"));
            
            var allDrivers = searcher.Get().Cast<ManagementObject>().ToList();
            var total = Math.Max(1, allDrivers.Count);
            var processed = 0;

            foreach (var drv in allDrivers)
            {
                cancellationToken.ThrowIfCancellationRequested();

                var driver = await ParseDriverAsync(drv, context.Settings);
                if (driver != null)
                {
                    drivers.Add(driver);
                }

                processed++;
                if (processed % 10 == 0 || processed == total)
                {
                    context.Progress?.Report(new ScanProgress
                    {
                        CurrentPhase = Phase,
                        CurrentPhaseProgress = (int)((double)processed / total * 100),
                        ItemsScanned = processed,
                        StatusMessage = $"Сканирование драйвера: {driver?.DriverName ?? "..."}"
                    });
                }
            }

            _logger.Information("Driver scan completed: {Count} drivers found", drivers.Count);
        }
        catch (OperationCanceledException)
        {
            _logger.Warning("Driver scan cancelled");
            throw;
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Driver scan failed");
        }

        return drivers;
    }

    private async Task<DriverInfo?> ParseDriverAsync(ManagementObject drv, ScanSettings settings)
    {
        try
        {
            var name = WmiSafe.Str(drv, "Name");
            if (string.IsNullOrWhiteSpace(name)) return null;

            var displayName = WmiSafe.Str(drv, "DisplayName");
            var path = WmiSafe.Str(drv, "PathName");
            var startType = WmiSafe.Str(drv, "StartMode");
            var state = WmiSafe.Str(drv, "State");
            var driverTypeRaw = WmiSafe.Str(drv, "ServiceType");
            var driverTypeValue = WmiSafe.UInt32(drv, "ServiceType");
            var driverType = driverTypeValue switch
            {
                1 => "Kernel Driver",
                2 => "File System Driver",
                4 => "Adapter",
                8 => "Recognizer Driver",
                _ => driverTypeRaw
            };
            var errorControl = WmiSafe.Str(drv, "ErrorControl");
            var loadOrderGroup = WmiSafe.Str(drv, "LoadOrderGroup");
            var description = WmiSafe.Str(drv, "Description");

            var dependencies = new List<string>();
            try
            {
                using var depSearcher = new ManagementObjectSearcher(
                    $"ASSOCIATORS OF {{Win32_SystemDriver.Name='{name}'}} WHERE AssocClass=Win32_DependentService Role=Antecedent");
                foreach (ManagementObject dep in depSearcher.Get())
                {
                    var depName = WmiSafe.Str(dep, "Name");
                    if (!string.IsNullOrWhiteSpace(depName)) dependencies.Add(depName);
                }
            }
            catch { }

            var cleanPath = ExtractBinaryPath(path);
            var signature = await _signatureService.VerifySignatureAsync(cleanPath);
            
            var isMicrosoftSigned = signature.IsValid && IsMicrosoftPublisher(signature.Publisher);
            if (!settings.IncludeMicrosoftSigned && isMicrosoftSigned) return null;

            var isSystemDriver = IsSystemDriver(name, cleanPath, signature.Publisher);
            var isBootDriver = startType.Equals("Boot", StringComparison.OrdinalIgnoreCase);

            var driver = new DriverInfo
            {
                DriverName = name,
                DisplayName = string.IsNullOrWhiteSpace(displayName) ? name : displayName,
                Description = description,
                BinaryPath = cleanPath,
                DriverType = driverType,
                StartType = startType,
                State = state,
                ErrorControl = errorControl,
                LoadOrderGroup = loadOrderGroup,
                Dependencies = dependencies.ToArray(),
                IsKernelMode = driverType.Contains("Kernel", StringComparison.OrdinalIgnoreCase) || driverType.Contains("FileSystem", StringComparison.OrdinalIgnoreCase) || driverType.Contains("File System", StringComparison.OrdinalIgnoreCase),
                IsBootDriver = isBootDriver,
                IsSystemDriver = isSystemDriver,
                IsSigned = signature.IsSigned,
                SignatureValid = signature.IsValid,
                Publisher = signature.Publisher,
                SignatureDetails = signature.RawDetails,
                IsSystemItem = isSystemDriver,
                CanStop = state.Equals("Running", StringComparison.OrdinalIgnoreCase) && !isSystemDriver,
                CanDisable = !startType.Equals("Disabled", StringComparison.OrdinalIgnoreCase) && !isSystemDriver,
                CanDelete = !isSystemDriver,
                Metadata = new Dictionary<string, object>
                {
                    ["OriginalPath"] = path,
                    ["ServiceTypeValue"] = driverTypeValue,
                    ["RawStartMode"] = startType,
                    ["RawState"] = state
                }
            };

            driver.RiskAssessment = await RiskAnalyzer.AnalyzeDriverAsync(driver, _signatureService);
            return driver;
        }
        catch (Exception ex)
        {
            _logger.Debug("Failed to parse driver: {Message}", ex.Message);
            return null;
        }
    }

    private string ExtractBinaryPath(string rawPath)
    {
        if (string.IsNullOrWhiteSpace(rawPath)) return string.Empty;
        
        var path = rawPath.Trim();
        if (path.StartsWith("\"") && path.IndexOf("\"", 1) > 0)
        {
            path = path.Substring(1, path.IndexOf("\"", 1) - 1);
        }
        else if (path.Contains(" "))
        {
            path = path.Split(' ')[0];
        }
        
        return Environment.ExpandEnvironmentVariables(path);
    }

    private bool IsSystemDriver(string name, string path, string publisher)
    {
        var systemDrivers = new[] { "ntoskrnl", "hal", "kdcom", "mcupdate", "pshed", "clfs", "tpm", "volmgr", "volmgrx", "mountmgr", "partmgr", "volsnap", "rdyboost", "rdpencdd", "rdprefmp", "rdpvideominiport", "msahci", "storahci", "nvme", "iastor", "iaStorV", "nvraid", "nvstor", "amd_sata", "amd_xata", "mvs91xx", "jraid", "arcsas", "arc", "megasas", "megasr", "lsi_sas", "lsi_sas2", "lsi_sas3", "lsi_fc", "lsi_scsi", "mpt2sas", "mpt3sas", "qla2xxx", "qla4xxx", "ql2300", "ql40xx", "bfa", "lpfc", "elxstor", "hpsa", "cciss", "aacraid", "arcmsr", "hptiop", "rr232x", "rr2340", "rr172x", "rr174x", "hptmv", "hptmv6", "hptmv7", "nvgts", "nvgts7", "nvgts8", "nvgts9", "nvgts10" };
        
        var lowerName = name.ToLowerInvariant();
        var lowerPath = path.ToLowerInvariant();
        
        if (systemDrivers.Any(d => lowerName.Contains(d))) return true;
        if (lowerPath.StartsWith(@"c:\windows\system32\drivers\")) return true;
        if (IsMicrosoftPublisher(publisher)) return true;
        
        return false;
    }

    private bool IsMicrosoftPublisher(string publisher)
    {
        if (string.IsNullOrWhiteSpace(publisher)) return false;
        var lower = publisher.ToLowerInvariant();
        return lower.Contains("microsoft") || lower.Contains("windows publisher") || lower.Contains("windows");
    }
}

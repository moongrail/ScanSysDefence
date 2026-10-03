using System.Management;
using ScanSysDefence.Core.Analysis;
using ScanSysDefence.Core.Models;
using ScanSysDefence.Core.Services;
using ScanSysDefence.Core.Utils;

namespace ScanSysDefence.Core.Scanners;

public class ServiceScanner : IScanner
{
    public string Name => "Services";
    public ScanPhase Phase => ScanPhase.ScanningServices;

    private readonly ILogger _logger;
    private readonly IDigitalSignatureService _signatureService;

    public ServiceScanner(ILogger logger, IDigitalSignatureService signatureService)
    {
        _logger = logger;
        _signatureService = signatureService;
    }

    public async Task<IEnumerable<ScanItemBase>> ScanAsync(ScanContext context, CancellationToken cancellationToken = default)
    {
        var services = new List<ServiceInfo>();
        
        try
        {
            context.Progress?.Report(new ScanProgress 
            { 
                CurrentPhase = Phase, 
                StatusMessage = "Перечисление служб Windows..." 
            });

            var scope = new ManagementScope(@"\\.\root\cimv2");
            scope.Connect();

            using var searcher = new ManagementObjectSearcher(scope, new ObjectQuery(
                "SELECT * FROM Win32_Service"));
            
            var allServices = searcher.Get().Cast<ManagementObject>().ToList();
            var total = Math.Max(1, allServices.Count);
            var processed = 0;

            foreach (var svc in allServices)
            {
                cancellationToken.ThrowIfCancellationRequested();
                
                var service = await ParseServiceAsync(svc, context.Settings);
                if (service != null)
                {
                    services.Add(service);
                }

                processed++;
                context.Progress?.Report(new ScanProgress 
                { 
                    CurrentPhase = Phase, 
                    CurrentPhaseProgress = (int)((double)processed / total * 100),
                    ItemsScanned = processed,
                    StatusMessage = $"Сканирование службы: {service?.ServiceName ?? "..."}"
                });
            }

            _logger.Information("Service scan completed: {Count} services found", services.Count);
        }
        catch (OperationCanceledException)
        {
            _logger.Warning("Service scan cancelled");
            throw;
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Service scan failed");
        }

        return services;
    }

    private async Task<ServiceInfo?> ParseServiceAsync(ManagementObject svc, ScanSettings settings)
    {
        try
        {
            var serviceName = WmiSafe.Str(svc, "Name");
            if (string.IsNullOrWhiteSpace(serviceName)) return null;

            var displayName = WmiSafe.Str(svc, "DisplayName");
            var binaryPath = WmiSafe.Str(svc, "PathName");
            var startType = WmiSafe.Str(svc, "StartMode");
            var state = WmiSafe.Str(svc, "State");
            var serviceType = WmiSafe.UInt32(svc, "ServiceType");
            var description = WmiSafe.Str(svc, "Description");
            var startAccount = WmiSafe.Str(svc, "StartName");
            var processId = WmiSafe.Int32(svc, "ProcessId");
            var errorControl = WmiSafe.Str(svc, "ErrorControl");
            var loadOrderGroup = WmiSafe.Str(svc, "LoadOrderGroup");

            var dependencies = new List<string>();
            var dependentServices = new List<string>();

            try
            {
                using var depSearcher = new ManagementObjectSearcher(
                    $"ASSOCIATORS OF {{Win32_Service.Name='{serviceName}'}} WHERE AssocClass=Win32_DependentService Role=Antecedent");
                foreach (ManagementObject dep in depSearcher.Get())
                {
                    var depName = WmiSafe.Str(dep, "Name");
                    if (!string.IsNullOrWhiteSpace(depName)) dependencies.Add(depName);
                }
            }
            catch { }

            try
            {
                using var depSearcher = new ManagementObjectSearcher(
                    $"ASSOCIATORS OF {{Win32_Service.Name='{serviceName}'}} WHERE AssocClass=Win32_DependentService Role=Dependent");
                foreach (ManagementObject dep in depSearcher.Get())
                {
                    var depName = WmiSafe.Str(dep, "Name");
                    if (!string.IsNullOrWhiteSpace(depName)) dependentServices.Add(depName);
                }
            }
            catch { }

            var cleanPath = ExtractBinaryPath(binaryPath);
            var signature = await _signatureService.VerifySignatureAsync(cleanPath);
            
            var isSystem = IsSystemService(serviceName, startAccount, cleanPath);
            var isMicrosoftSigned = signature.IsValid && IsMicrosoftPublisher(signature.Publisher);

            if (!settings.IncludeSystemServices && isSystem) return null;
            if (!settings.IncludeMicrosoftSigned && isMicrosoftSigned) return null;

            var service = new ServiceInfo
            {
                ServiceName = serviceName,
                DisplayName = string.IsNullOrWhiteSpace(displayName) ? serviceName : displayName,
                Description = description,
                BinaryPath = cleanPath,
                StartType = ServiceInfo.ParseStartType(startType),
                CurrentState = ServiceInfo.ParseState(state),
                ServiceType = ServiceInfo.ParseType(serviceType),
                StartAccount = startAccount,
                ErrorControl = errorControl,
                LoadOrderGroup = loadOrderGroup,
                Dependencies = dependencies.ToArray(),
                DependentServices = dependentServices.ToArray(),
                ProcessId = processId,
                IsSigned = signature.IsSigned,
                SignatureValid = signature.IsValid,
                Publisher = signature.Publisher,
                SignatureDetails = signature.RawDetails,
                IsSystemItem = isSystem,
                CanStop = processId > 0 && ServiceInfo.ParseState(state) == ServiceState.Running,
                CanDisable = ServiceInfo.ParseStartType(startType) != ServiceStartType.Disabled,
                CanDelete = !isSystem,
                Metadata = new Dictionary<string, object>
                {
                    ["OriginalPath"] = binaryPath,
                    ["ServiceTypeValue"] = serviceType,
                    ["ErrorControlValue"] = errorControl,
                    ["RawStartMode"] = startType,
                    ["RawState"] = state
                }
            };

            service.RiskAssessment = await RiskAnalyzer.AnalyzeServiceAsync(service, _signatureService);
            return service;
        }
        catch (Exception ex)
        {
            _logger.Debug("Failed to parse service: {Message}", ex.Message);
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

    private bool IsSystemService(string name, string account, string path)
    {
        var systemAccounts = new[] { "localsystem", "nt authority\\system", "nt service\\", "local service", "network service" };
        var systemPaths = new[] { "c:\\windows\\system32\\", "c:\\windows\\syswow64\\", "c:\\windows\\winsxs\\" };
        
        var lowerAccount = account.ToLowerInvariant();
        var lowerPath = path.ToLowerInvariant();
        
        return systemAccounts.Any(a => lowerAccount.Contains(a)) ||
               systemPaths.Any(p => lowerPath.StartsWith(p));
    }

    private bool IsMicrosoftPublisher(string publisher)
    {
        if (string.IsNullOrWhiteSpace(publisher)) return false;
        var lower = publisher.ToLowerInvariant();
        return lower.Contains("microsoft") || lower.Contains("windows") || lower.Contains("windows publisher");
    }
}

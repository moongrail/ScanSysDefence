using System.Diagnostics;
using System.Management;
using ScanSysDefence.Core.Models;
using ScanSysDefence.Core.Remediation;

namespace ScanSysDefence.Core.Services;

public class SafetyService : ISafetyService
{
    private readonly ILogger _logger;
    private readonly List<RollbackToken> _rollbackTokens = new();
    private readonly object _lock = new();

    // Critical system components that should never be touched
    private static readonly HashSet<string> CriticalSystemServices = new(StringComparer.OrdinalIgnoreCase)
    {
        "winlogon", "csrss", "smss", "lsass", "services", "svchost",
        "wininit", "fontdrvhost", "dwm", "taskhostw", "explorer",
        "spoolsv", "schedule", "eventlog", "eventsystem", "rpcss",
        "dcomlaunch", "plugplay", "power", "wmiprvse", "searchindexer",
        "msiserver", "trustedinstaller", "wuauserv", "bits", "cryptsvc",
        "appidsvc", "audiosrv", "dhcp", "dnsapi", "fdphost", "fdrespub",
        "hidserv", "ikeext", "iphlpsvc", "lanmanserver", "lanmanworkstation",
        "mpssvc", "netlogon", "nlasvc", "nsi", "p2pimsvc", "pnrpauto",
        "pnrpsvc", "policyagent", "profsvc", "rasauto", "rasman", "remoteaccess",
        "samss", "scardsvr", "seclogon", "sens", "sessionenv", "shellhwdetection",
        "snmp", "sppsvc", "ssdpsrv", "stisvc", "swprv", "sysmain", "tapiserver",
        "termservice", "themes", "thrdsrv", "trkwks", "upnphost", "userdata",
        "vds", "vss", "w32time", "wbengine", "wcncsvc", "wcsplugplay", "wdi",
        "webclnt", "wercplsupport", "wersvc", "winhttpautoproxysvc", "wlanautoconfig",
        "wmiapsrv", "wmipath", "wncol", "wscsvc", "wuauserv", "wudfsvc", "w32time"
    };

    private static readonly HashSet<string> CriticalSystemPaths = new(StringComparer.OrdinalIgnoreCase)
    {
        @"C:\Windows\System32\",
        @"C:\Windows\SysWOW64\",
        @"C:\Windows\WinSxS\",
        @"C:\Windows\System32\drivers\",
        @"C:\Windows\System32\wbem\",
        @"C:\Windows\System32\config\",
        @"C:\Windows\System32\catroot\",
        @"C:\Windows\System32\catroot2\",
        @"C:\Windows\Boot\",
        @"C:\Windows\Fonts\",
        @"C:\Windows\Inf\",
        @"C:\Windows\Installer\",
        @"C:\Windows\Logs\",
        @"C:\Windows\Minidump\",
        @"C:\Windows\Panther\",
        @"C:\Windows\Performance\",
        @"C:\Windows\Prefetch\",
        @"C:\Windows\Registration\",
        @"C:\Windows\Resources\",
        @"C:\Windows\Schema\",
        @"C:\Windows\Security\",
        @"C:\Windows\ServiceProfiles\",
        @"C:\Windows\Servicing\",
        @"C:\Windows\Setup\",
        @"C:\Windows\SoftwareDistribution\",
        @"C:\Windows\System\",
        @"C:\Windows\System32\Tasks\",
        @"C:\Windows\System32\Tasks_Migrated\",
        @"C:\Windows\Temp\",
        @"C:\Windows\WinSxS\",
        @"C:\Windows\Winsxs\"
    };

    private static readonly HashSet<string> CriticalProcessNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "system", "registry", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
        "services.exe", "lsass.exe", "lsm.exe", "svchost.exe", "spoolsv.exe",
        "taskhost.exe", "taskhostw.exe", "dwm.exe", "explorer.exe", "conhost.exe",
        "fontdrvhost.exe", "sihost.exe", "startmenuexperiencehost.exe", "textinputhost.exe",
        "searchindexer.exe", "searchprotocolhost.exe", "searchfilterhost.exe",
        "runtimebroker.exe", "shellexperiencehost.exe", "applicationframehost.exe",
        "winstore.app.exe", "msedge.exe", "chrome.exe" // Browser processes can be critical for user session
    };

    public SafetyService(ILogger logger)
    {
        _logger = logger;
    }

    public async Task<SafetyCheckResult> ValidateActionAsync(RemediationAction action, ScanItemBase target)
    {
        var result = new SafetyCheckResult
        {
            IsSafe = true,
            Level = SafetyLevel.Safe,
            RequiresElevation = action.RequiresElevation,
            RequiresUserConfirmation = true,
            RequiresRestorePoint = action.RequiresRestorePointPrompt
        };

        var violations = new List<SafetyViolation>();
        var warnings = new List<SafetyWarning>();
        var recommendations = new List<SafetyRecommendation>();

        // Check if target is critical system component
        var criticalCheck = await IsSystemCriticalAsync(target);
        if (criticalCheck)
        {
            violations.Add(new SafetyViolation
            {
                Code = "CRITICAL_SYSTEM_COMPONENT",
                Message = $"Target is a critical system component: {target.Name}",
                MessageRu = $"Цель является критическим системным компонентом: {target.Name}",
                Severity = SafetyLevel.Blocked,
                AffectedComponent = target.Name,
                Remediation = "This action is blocked to prevent system instability",
                IsBlocking = true
            });
            result.IsSafe = false;
            result.Level = SafetyLevel.Blocked;
        }

        // Check dependencies
        var dependencies = await GetDependenciesAsync(target);
        if (dependencies.Any())
        {
            warnings.Add(new SafetyWarning
            {
                Code = "HAS_DEPENDENCIES",
                Message = $"Target has {dependencies.Count} dependent components",
                MessageRu = $"У цели есть {dependencies.Count} зависимых компонентов",
                Severity = SafetyLevel.Warning,
                AffectedComponent = target.Name
            });
            recommendations.Add(new SafetyRecommendation
            {
                Code = "CHECK_DEPENDENCIES",
                Message = "Check dependent services/processes before proceeding",
                MessageRu = "Проверьте зависимые службы/процессы перед продолжением",
                Action = SafetyAction.CheckDependenciesFirst
            });
        }

        // Check if action is reversible
        var reversible = await IsActionReversibleAsync(action);
        if (!reversible)
        {
            warnings.Add(new SafetyWarning
            {
                Code = "IRREVERSIBLE_ACTION",
                Message = "This action may not be easily reversible",
                MessageRu = "Это действие может быть необратимым",
                Severity = SafetyLevel.Dangerous,
                AffectedComponent = target.Name
            });
            recommendations.Add(new SafetyRecommendation
            {
                Code = "CREATE_RESTORE_POINT",
                Message = "Strongly recommended to create a restore point",
                MessageRu = "Настоятельно рекомендуется создать точку восстановления",
                Action = SafetyAction.CreateRestorePoint
            });
            result.RequiresRestorePoint = true;
        }

        // Action-specific checks
        switch (action.Type)
        {
            case RemediationActionType.DeleteFile:
                ValidateFileDeletion(target, violations, warnings, recommendations);
                break;
            case RemediationActionType.StopService:
            case RemediationActionType.DisableService:
                ValidateServiceAction(target, violations, warnings, recommendations);
                break;
            case RemediationActionType.StopProcess:
                ValidateProcessAction(target, violations, warnings, recommendations);
                break;
            case RemediationActionType.RemoveStartupEntry:
                ValidateStartupRemoval(target, violations, warnings, recommendations);
                break;
        }

        // Determine overall safety level
        if (violations.Any(v => v.IsBlocking))
        {
            result.Level = SafetyLevel.Blocked;
            result.IsSafe = false;
        }
        else if (violations.Any(v => v.Severity >= SafetyLevel.Dangerous))
        {
            result.Level = SafetyLevel.Dangerous;
            result.IsSafe = false;
        }
        else if (violations.Any(v => v.Severity >= SafetyLevel.Warning) || warnings.Any(w => w.Severity >= SafetyLevel.Warning))
        {
            result.Level = SafetyLevel.Warning;
        }
        else if (warnings.Any())
        {
            result.Level = SafetyLevel.Caution;
        }

        result.Violations = violations;
        result.Warnings = warnings;
        result.Recommendations = recommendations;
        result.Summary = GenerateSummary(result);
        
        return result;
    }

    private void ValidateFileDeletion(ScanItemBase target, List<SafetyViolation> violations, List<SafetyWarning> warnings, List<SafetyRecommendation> recommendations)
    {
        if (string.IsNullOrWhiteSpace(target.Path)) return;

        var path = target.Path.ToLowerInvariant();

        // Check if in critical system path
        foreach (var criticalPath in CriticalSystemPaths)
        {
            if (path.StartsWith(criticalPath.ToLowerInvariant()))
            {
                violations.Add(new SafetyViolation
                {
                    Code = "CRITICAL_SYSTEM_PATH",
                    Message = $"File is in critical system directory: {target.Path}",
                    MessageRu = $"Файл находится в критической системной директории: {target.Path}",
                    Severity = SafetyLevel.Blocked,
                    AffectedComponent = target.Path,
                    Remediation = "Deleting files from system directories can break Windows",
                    IsBlocking = true
                });
                return;
            }
        }

        // Check file extension
        var ext = Path.GetExtension(target.Path).ToLowerInvariant();
        var criticalExtensions = new[] { ".sys", ".dll", ".exe", ".msi", ".cat", ".inf" };
        if (criticalExtensions.Contains(ext))
        {
            warnings.Add(new SafetyWarning
            {
                Code = "CRITICAL_FILE_EXTENSION",
                Message = $"File has critical extension: {ext}",
                MessageRu = $"Файл имеет критическое расширение: {ext}",
                Severity = SafetyLevel.Warning,
                AffectedComponent = target.Path
            });
            recommendations.Add(new SafetyRecommendation
            {
                Code = "QUARANTINE_INSTEAD",
                Message = "Consider quarantine instead of deletion",
                MessageRu = "Рассмотрите карантин вместо удаления",
                Action = SafetyAction.QuarantineInsteadOfDelete
            });
        }

        // Check if file is digitally signed by Microsoft
        if (target.IsSigned && target.SignatureValid && IsMicrosoftPublisher(target.Publisher))
        {
            violations.Add(new SafetyViolation
            {
                Code = "MICROSOFT_SIGNED_FILE",
                Message = "File is digitally signed by Microsoft",
                MessageRu = "Файл цифрово подписан Microsoft",
                Severity = SafetyLevel.Blocked,
                AffectedComponent = target.Path,
                Remediation = "Do not delete Microsoft-signed system files",
                IsBlocking = true
            });
        }
    }

    private void ValidateServiceAction(ScanItemBase target, List<SafetyViolation> violations, List<SafetyWarning> warnings, List<SafetyRecommendation> recommendations)
    {
        if (target is not ServiceInfo service) return;

        if (CriticalSystemServices.Contains(service.ServiceName))
        {
            violations.Add(new SafetyViolation
            {
                Code = "CRITICAL_SYSTEM_SERVICE",
                Message = $"Service is critical for system operation: {service.ServiceName}",
                MessageRu = $"Служба критична для работы системы: {service.ServiceName}",
                Severity = SafetyLevel.Blocked,
                AffectedComponent = service.ServiceName,
                Remediation = "Stopping/disabling this service will cause system instability",
                IsBlocking = true
            });
            return;
        }

        if (service.IsSystemItem)
        {
            warnings.Add(new SafetyWarning
            {
                Code = "SYSTEM_SERVICE",
                Message = "This is a system service",
                MessageRu = "Это системная служба",
                Severity = SafetyLevel.Warning,
                AffectedComponent = service.ServiceName
            });
            recommendations.Add(new SafetyRecommendation
            {
                Code = "DISABLE_INSTEAD",
                Message = "Consider disabling instead of stopping",
                MessageRu = "Рассмотрите отключение вместо остановки",
                Action = SafetyAction.DisableInsteadOfDelete
            });
        }

        if (service.Dependencies.Length > 0)
        {
            warnings.Add(new SafetyWarning
            {
                Code = "SERVICE_HAS_DEPENDENCIES",
                Message = $"Service has {service.Dependencies.Length} dependencies",
                MessageRu = $"У службы {service.Dependencies.Length} зависимостей",
                Severity = SafetyLevel.Warning,
                AffectedComponent = service.ServiceName
            });
        }
    }

    private void ValidateProcessAction(ScanItemBase target, List<SafetyViolation> violations, List<SafetyWarning> warnings, List<SafetyRecommendation> recommendations)
    {
        if (target is not ProcessInfo process) return;

        if (CriticalProcessNames.Contains(process.ProcessName))
        {
            violations.Add(new SafetyViolation
            {
                Code = "CRITICAL_SYSTEM_PROCESS",
                Message = $"Process is critical for system operation: {process.ProcessName}",
                MessageRu = $"Процесс критичен для работы системы: {process.ProcessName}",
                Severity = SafetyLevel.Blocked,
                AffectedComponent = process.ProcessName,
                Remediation = "Stopping this process will cause system instability or crash",
                IsBlocking = true
            });
            return;
        }

        if (process.IsElevated && process.IsSystemItem)
        {
            warnings.Add(new SafetyWarning
            {
                Code = "ELEVATED_SYSTEM_PROCESS",
                Message = "Process is running elevated as system",
                MessageRu = "Процесс запущен с повышенными правами от системы",
                Severity = SafetyLevel.Warning,
                AffectedComponent = process.ProcessName
            });
        }
    }

    private void ValidateStartupRemoval(ScanItemBase target, List<SafetyViolation> violations, List<SafetyWarning> warnings, List<SafetyRecommendation> recommendations)
    {
        if (target is not StartupItem startup) return;

        if (startup.IsSystemItem || IsMicrosoftPublisher(startup.Publisher))
        {
            warnings.Add(new SafetyWarning
            {
                Code = "SYSTEM_STARTUP_ITEM",
                Message = "This appears to be a system startup entry",
                MessageRu = "Это похоже на системную запись автозапуска",
                Severity = SafetyLevel.Caution,
                AffectedComponent = startup.Name
            });
        }
    }

    public async Task<SafetyCheckResult> ValidateBatchAsync(List<RemediationAction> actions, IEnumerable<ScanItemBase> targets)
    {
        var combinedResult = new SafetyCheckResult
        {
            IsSafe = true,
            Level = SafetyLevel.Safe,
            RequiresElevation = actions.Any(a => a.RequiresElevation),
            RequiresUserConfirmation = true,
            RequiresRestorePoint = actions.Any(a => a.RequiresRestorePointPrompt)
        };

        var allViolations = new List<SafetyViolation>();
        var allWarnings = new List<SafetyWarning>();
        var allRecommendations = new List<SafetyRecommendation>();

        foreach (var action in actions)
        {
            var target = targets.FirstOrDefault(t => t.Id == action.TargetId || t.Name == action.TargetName);
            if (target != null)
            {
                var result = await ValidateActionAsync(action, target);
                allViolations.AddRange(result.Violations);
                allWarnings.AddRange(result.Warnings);
                allRecommendations.AddRange(result.Recommendations);
                
                if (!result.IsSafe)
                {
                    combinedResult.IsSafe = false;
                }
                if (result.Level > combinedResult.Level)
                {
                    combinedResult.Level = result.Level;
                }
            }
        }

        combinedResult.Violations = allViolations;
        combinedResult.Warnings = allWarnings;
        combinedResult.Recommendations = allRecommendations.DistinctBy(r => r.Code).ToList();
        combinedResult.Summary = GenerateSummary(combinedResult);

        return combinedResult;
    }

    public async Task<bool> IsSystemCriticalAsync(ScanItemBase item)
    {
        return await Task.Run(() =>
        {
            if (item is ServiceInfo service)
            {
                return CriticalSystemServices.Contains(service.ServiceName) ||
                       (service.IsSystemItem && service.StartType == ServiceStartType.Boot);
            }

            if (item is ProcessInfo process)
            {
                return CriticalProcessNames.Contains(process.ProcessName) ||
                       (process.IsSystemItem && process.IntegrityLevel == "System");
            }

            if (item is StartupItem startup)
            {
                return startup.IsSystemItem || IsMicrosoftPublisher(startup.Publisher);
            }

            if (item is DriverInfo driver)
            {
                return driver.IsSystemDriver || driver.IsBootDriver;
            }

            // Check path
            if (!string.IsNullOrWhiteSpace(item.Path))
            {
                var path = item.Path.ToLowerInvariant();
                return CriticalSystemPaths.Any(cp => path.StartsWith(cp.ToLowerInvariant()));
            }

            return false;
        });
    }

    public async Task<List<string>> GetDependenciesAsync(ScanItemBase item)
    {
        return await Task.Run(() =>
        {
            var deps = new List<string>();

            if (item is ServiceInfo service)
            {
                deps.AddRange(service.Dependencies);
                deps.AddRange(service.DependentServices);
            }

            if (item is ProcessInfo process)
            {
                // Could enumerate child processes here
            }

            return deps.Distinct().ToList();
        });
    }

    public async Task<RollbackToken> CreateRollbackPointAsync(string description)
    {
        var token = new RollbackToken
        {
            Description = description,
            ActionType = "Unknown"
        };

        // Capture current state for rollback
        // This would capture registry keys, service states, file backups, etc.

        lock (_lock)
        {
            _rollbackTokens.Add(token);
        }

        return await Task.FromResult(token);
    }

    public async Task<RollbackResult> RollbackAsync(RollbackToken token)
    {
        var result = new RollbackResult
        {
            TokenId = token.Id,
            Success = true
        };

        try
        {
            foreach (var action in token.Actions)
            {
                // Execute rollback actions
                // This would restore files, registry keys, service states, etc.
                result.ActionsRolledBack++;
            }

            token.IsUsed = true;
            token.UsedAt = DateTime.Now;
        }
        catch (Exception ex)
        {
            result.Success = false;
            result.Errors.Add(ex.Message);
            _logger.Error(ex, "Rollback failed for token {TokenId}", token.Id);
        }

        return await Task.FromResult(result);
    }

    public Task<List<RollbackToken>> GetAvailableRollbacksAsync()
    {
        lock (_lock)
        {
            return Task.FromResult(_rollbackTokens.Where(t => !t.IsUsed).ToList());
        }
    }

    public async Task<bool> IsActionReversibleAsync(RemediationAction action)
    {
        return await Task.Run(() =>
        {
            return action.Type switch
            {
                RemediationActionType.StopProcess => true, // Can restart
                RemediationActionType.StopService => true, // Can restart
                RemediationActionType.DisableService => true, // Can re-enable
                RemediationActionType.RemoveStartupEntry => true, // Can re-add
                RemediationActionType.DeleteFile => false, // May not be recoverable
                RemediationActionType.QuarantineFile => true, // Can restore from quarantine
                RemediationActionType.DisableScheduledTask => true, // Can re-enable
                RemediationActionType.DeleteScheduledTask => false, // XML lost unless backed up
                RemediationActionType.RemoveWmiSubscription => false, // Complex to recreate
                RemediationActionType.UnloadDriver => true, // Can reload
                _ => false
            };
        });
    }

    public async Task<SimulationResult> SimulateActionAsync(RemediationAction action, ScanItemBase target)
    {
        return await Task.Run(() =>
        {
            var result = new SimulationResult();
            var effects = new List<string>();
            var affected = new List<string>();
            var warnings = new List<string>();

            // Simulate the action
            switch (action.Type)
            {
                case RemediationActionType.StopService:
                    effects.Add($"Service '{target.Name}' will stop");
                    affected.Add(target.Name);
                    if (target is ServiceInfo svc && svc.DependentServices.Length > 0)
                    {
                        effects.Add($"Dependent services may stop: {string.Join(", ", svc.DependentServices)}");
                        affected.AddRange(svc.DependentServices);
                    }
                    break;

                case RemediationActionType.DisableService:
                    effects.Add($"Service '{target.Name}' will be disabled (won't start on boot)");
                    affected.Add(target.Name);
                    break;

                case RemediationActionType.DeleteFile:
                    effects.Add($"File '{target.Path}' will be permanently deleted");
                    affected.Add(target.Path);
                    warnings.Add("Cannot be undone without backup");
                    break;

                case RemediationActionType.QuarantineFile:
                    effects.Add($"File '{target.Path}' will be moved to quarantine");
                    affected.Add(target.Path);
                    effects.Add("Can be restored from quarantine");
                    break;

                case RemediationActionType.StopProcess:
                    effects.Add($"Process '{target.Name}' (PID: {(target as ProcessInfo)?.ProcessId}) will be terminated");
                    affected.Add(target.Name);
                    if (target is ProcessInfo proc && proc.ProcessId > 0)
                    {
                        warnings.Add("Unsaved data in the process will be lost");
                    }
                    break;
            }

            result.PredictedEffects = effects;
            result.AffectedComponents = affected;
            result.Warnings = warnings;
            result.Summary = $"Simulated {action.Type}: {effects.Count} effects, {warnings.Count} warnings";
            result.SummaryRu = $"Симуляция {action.Type}: {effects.Count} последствий, {warnings.Count} предупреждений";
            result.IsSafe = !warnings.Any(w => w.Contains("critical", StringComparison.OrdinalIgnoreCase) || w.Contains("irreversible", StringComparison.OrdinalIgnoreCase));
            result.PredictedRisk = result.IsSafe ? SafetyLevel.Caution : SafetyLevel.Warning;

            return result;
        });
    }

    public async Task<SystemHealthSnapshot> CaptureSystemHealthAsync()
    {
        return await Task.Run(() =>
        {
            var snapshot = new SystemHealthSnapshot
            {
                Description = $"Pre-action snapshot {DateTime.Now:yyyy-MM-dd HH:mm:ss}",
                ProcessCount = Process.GetProcesses().Length,
                AvailableMemory = GC.GetTotalMemory(false)
            };

            // Capture critical services
            var scope = new ManagementScope(@"\\.\root\cimv2");
            scope.Connect();
            using var searcher = new ManagementObjectSearcher(scope, new ObjectQuery(
                "SELECT Name, State FROM Win32_Service WHERE StartMode='Auto' AND State='Running'"));
            
            foreach (ManagementObject svc in searcher.Get())
            {
                var name = svc["Name"]?.ToString() ?? "";
                if (CriticalSystemServices.Contains(name))
                {
                    snapshot.RunningCriticalServices.Add(name);
                }
            }

            snapshot.IsSystemStable = true;
            return snapshot;
        });
    }

    public async Task<SystemHealthComparison> CompareSystemHealthAsync(SystemHealthSnapshot before)
    {
        var after = await CaptureSystemHealthAsync();
        
        var comparison = new SystemHealthComparison
        {
            IsHealthy = true
        };

        var stoppedServices = before.RunningCriticalServices.Except(after.RunningCriticalServices).ToList();
        if (stoppedServices.Any())
        {
            comparison.StoppedCriticalServices = stoppedServices;
            comparison.IsHealthy = false;
        }

        if (after.AvailableMemory < before.AvailableMemory * 0.9)
        {
            comparison.Warnings.Add("Significant memory decrease detected");
        }

        comparison.Summary = comparison.IsHealthy 
            ? "System health appears normal" 
            : $"System health degraded: {stoppedServices.Count} critical services stopped";

        return comparison;
    }

    private bool IsMicrosoftPublisher(string publisher)
    {
        if (string.IsNullOrWhiteSpace(publisher)) return false;
        var lower = publisher.ToLowerInvariant();
        return lower.Contains("microsoft") || lower.Contains("windows publisher") || lower.Contains("windows");
    }

    private string GenerateSummary(SafetyCheckResult result)
    {
        var parts = new List<string>();
        if (result.Violations.Any(v => v.IsBlocking)) parts.Add($"{result.Violations.Count(v => v.IsBlocking)} блокирующих");
        if (result.Violations.Any(v => !v.IsBlocking)) parts.Add($"{result.Violations.Count(v => !v.IsBlocking)} нарушений");
        if (result.Warnings.Any()) parts.Add($"{result.Warnings.Count} предупреждений");
        if (result.Recommendations.Any()) parts.Add($"{result.Recommendations.Count} рекомендаций");
        
        return parts.Any() ? string.Join(", ", parts) : "Проверка пройдена, проблем не обнаружено";
    }
}
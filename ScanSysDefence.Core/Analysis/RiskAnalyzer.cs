using ScanSysDefence.Core.Models;
using ScanSysDefence.Core.Services;

namespace ScanSysDefence.Core.Analysis;

public static class RiskAnalyzer
{
    private static readonly HashSet<string> KnownMicrosoftPublishers = new(StringComparer.OrdinalIgnoreCase)
    {
        "Microsoft Corporation", "Microsoft Windows", "Windows Publisher",
        "Microsoft Windows Component Publisher", "Microsoft Corporation (Windows)"
    };

    private static readonly HashSet<string> TrustedPublishers = new(StringComparer.OrdinalIgnoreCase)
    {
        "Google LLC", "Mozilla Corporation", "Adobe Inc.", "Oracle Corporation",
        "Amazon.com, Inc.", "Citrix Systems, Inc.", "VMware, Inc.",
        "Docker Inc.", "GitHub, Inc.", "Slack Technologies, Inc.",
        "Zoom Video Communications, Inc.", "TeamViewer Germany GmbH"
    };

    /// <summary>Известные службы телеметрии/диагностики Windows, которые можно отключить для снижения нагрузки.</summary>
    private static readonly HashSet<string> TelemetryServices = new(StringComparer.OrdinalIgnoreCase)
    {
        "DiagTrack",
        "dmwappushservice",
        "diagnosticshub.standardcollector.service",
        "PcaSvc",
        "WerSvc",
        "WdiServiceHost",
        "WdiSystemHost"
    };

    public static Task<RiskAssessment> AnalyzeServiceAsync(ServiceInfo service, IDigitalSignatureService signatureService)
    {
        var assessment = new RiskAssessment();
        var factors = new List<RiskFactor>();

        // Signature checks
        if (!service.IsSigned)
        {
            factors.Add(new RiskFactor
            {
                Id = "SVC_UNSIGNED",
                Category = "Signature",
                Description = "Service binary is not digitally signed",
                Score = 30,
                Severity = RiskSeverity.High,
                Evidence = $"File: {service.BinaryPath}",
                Recommendation = "Verify the legitimacy of this service. Unsigned services are common in malware."
            });
        }
        else if (!service.SignatureValid)
        {
            factors.Add(new RiskFactor
            {
                Id = "SVC_INVALID_SIG",
                Category = "Signature",
                Description = "Service binary has invalid or corrupted digital signature",
                Score = 40,
                Severity = RiskSeverity.Critical,
                Evidence = service.SignatureDetails,
                Recommendation = "This is a strong indicator of tampering or malware. Investigate immediately."
            });
        }
        else if (IsMicrosoftPublisher(service.Publisher))
        {
            factors.Add(new RiskFactor
            {
                Id = "SVC_MS_SIGNED",
                Category = "Signature",
                Description = "Digitally signed by Microsoft",
                Score = -20,
                Severity = RiskSeverity.None,
                Evidence = $"Publisher: {service.Publisher}",
                Recommendation = "Legitimate Microsoft service."
            });
        }
        else if (IsTrustedPublisher(service.Publisher))
        {
            factors.Add(new RiskFactor
            {
                Id = "SVC_TRUSTED_SIGNED",
                Category = "Signature",
                Description = "Signed by trusted publisher",
                Score = -10,
                Severity = RiskSeverity.None,
                Evidence = $"Publisher: {service.Publisher}",
                Recommendation = "Likely legitimate third-party software."
            });
        }

        // Path analysis
        if (service.IsSuspiciousPath)
        {
            factors.Add(new RiskFactor
            {
                Id = "SVC_SUSPICIOUS_PATH",
                Category = "Location",
                Description = "Service binary located in suspicious directory",
                Score = 25,
                Severity = RiskSeverity.High,
                Evidence = $"Path: {service.BinaryPath}",
                Recommendation = "Services should run from System32, Program Files, or other standard locations."
            });
        }

        // No description
        if (service.HasNoDescription && !service.IsSystemItem)
        {
            factors.Add(new RiskFactor
            {
                Id = "SVC_NO_DESC",
                Category = "Metadata",
                Description = "Service has no description",
                Score = 10,
                Severity = RiskSeverity.Low,
                Evidence = "Description field is empty",
                Recommendation = "Legitimate services typically have descriptions. Verify this service."
            });
        }

        // Interactive service (potential for shatter attacks)
        if (service.IsInteractive)
        {
            factors.Add(new RiskFactor
            {
                Id = "SVC_INTERACTIVE",
                Category = "Behavior",
                Description = "Service runs as interactive process",
                Score = 15,
                Severity = RiskSeverity.Medium,
                Evidence = "Service type includes InteractiveProcess flag",
                Recommendation = "Interactive services are deprecated and can be security risks."
            });
        }

        // Start type vs state mismatch
        if (service.StartType == ServiceStartType.Disabled && service.IsRunning)
        {
            factors.Add(new RiskFactor
            {
                Id = "SVC_DISABLED_RUNNING",
                Category = "Configuration",
                Description = "Service is disabled but currently running",
                Score = 20,
                Severity = RiskSeverity.Medium,
                Evidence = $"StartType: Disabled, State: Running (PID: {service.ProcessId})",
                Recommendation = "This indicates the service was started manually or by another process. Investigate."
            });
        }

        // Auto-start service not running
        if (service.StartType == ServiceStartType.Auto && !service.IsRunning && service.IsSystemItem)
        {
            factors.Add(new RiskFactor
            {
                Id = "SVC_AUTO_NOT_RUNNING",
                Category = "Configuration",
                Description = "System service set to auto-start but not running",
                Score = 15,
                Severity = RiskSeverity.Medium,
                Evidence = $"Service: {service.ServiceName}",
                Recommendation = "Critical system services should be running. May indicate system issues or malware interference."
            });
        }

        // Running from temp
        if (service.BinaryPath.Contains("\\Temp\\", StringComparison.OrdinalIgnoreCase) ||
            service.BinaryPath.Contains("\\AppData\\Local\\Temp", StringComparison.OrdinalIgnoreCase))
        {
            factors.Add(new RiskFactor
            {
                Id = "SVC_FROM_TEMP",
                Category = "Location",
                Description = "Service running from temporary directory",
                Score = 50,
                Severity = RiskSeverity.Critical,
                Evidence = $"Path: {service.BinaryPath}",
                Recommendation = "This is a common malware technique. Immediate investigation required."
            });
        }

        // Телеметрия Windows: известные службы, которые можно отключить
        if (TelemetryServices.Contains(service.ServiceName))
        {
            factors.Add(new RiskFactor
            {
                Id = "SVC_TELEMETRY",
                Category = "Телеметрия",
                Description = "Служба телеметрии Windows нагружает систему",
                Score = 15,
                Severity = RiskSeverity.Informational,
                Evidence = $"Служба: {service.ServiceName} ({service.DisplayName})",
                Recommendation = "Службу телеметрии можно остановить и отключить для снижения нагрузки: «Остановить», затем «Отключить»."
            });
        }

        assessment.Factors = factors;
        assessment.TotalScore = Math.Max(0, Math.Min(100, factors.Sum(f => f.Score)));
        assessment.Level = CalculateRiskLevel(assessment.TotalScore);
        
        return Task.FromResult(assessment);
    }

    public static Task<RiskAssessment> AnalyzeStartupItemAsync(StartupItem item, IDigitalSignatureService signatureService)
    {
        var assessment = new RiskAssessment();
        var factors = new List<RiskFactor>();

        // Signature checks
        if (!item.IsSigned)
        {
            factors.Add(new RiskFactor
            {
                Id = "STARTUP_UNSIGNED",
                Category = "Signature",
                Description = "Startup item target is not digitally signed",
                Score = 25,
                Severity = RiskSeverity.Medium,
                Evidence = $"Target: {item.Command}",
                Recommendation = "Unsigned startup items are common but should be verified."
            });
        }
        else if (!item.SignatureValid)
        {
            factors.Add(new RiskFactor
            {
                Id = "STARTUP_INVALID_SIG",
                Category = "Signature",
                Description = "Startup item has invalid digital signature",
                Score = 40,
                Severity = RiskSeverity.Critical,
                Evidence = item.SignatureDetails,
                Recommendation = "Strong indicator of tampering."
            });
        }
        else if (IsMicrosoftPublisher(item.Publisher) || IsTrustedPublisher(item.Publisher))
        {
            factors.Add(new RiskFactor
            {
                Id = "STARTUP_TRUSTED_SIGNED",
                Category = "Signature",
                Description = "Signed by trusted publisher",
                Score = -15,
                Severity = RiskSeverity.None,
                Evidence = $"Publisher: {item.Publisher}",
                Recommendation = "Likely legitimate."
            });
        }

        // Suspicious location
        if (item.IsSuspiciousLocation)
        {
            factors.Add(new RiskFactor
            {
                Id = "STARTUP_SUSPICIOUS_LOC",
                Category = "Persistence",
                Description = "Startup from suspicious persistence location",
                Score = 30,
                Severity = RiskSeverity.High,
                Evidence = $"Location: {item.LocationPath} ({item.LocationType})",
                Recommendation = "These locations are commonly abused by malware for persistence."
            });
        }

        // Suspicious command
        if (item.IsSuspiciousCommand)
        {
            factors.Add(new RiskFactor
            {
                Id = "STARTUP_SUSPICIOUS_CMD",
                Category = "Command",
                Description = "Startup command contains suspicious patterns",
                Score = 35,
                Severity = RiskSeverity.High,
                Evidence = $"Command: {item.Command}",
                Recommendation = "Command contains patterns commonly used by malware (encoded PowerShell, downloaders, etc.)"
            });
        }

        // Hidden/disabled but present
        if (!item.IsEnabled)
        {
            factors.Add(new RiskFactor
            {
                Id = "STARTUP_DISABLED",
                Category = "Configuration",
                Description = "Startup item is disabled but present",
                Score = 5,
                Severity = RiskSeverity.Informational,
                Evidence = "Item exists but is disabled",
                Recommendation = "May be legitimate disabled software. Verify if you recognize it."
            });
        }

        // Task Scheduler specific
        if (item.LocationType == StartupLocationType.TaskScheduler)
        {
            if (item.Hidden)
            {
                factors.Add(new RiskFactor
                {
                    Id = "STARTUP_HIDDEN_TASK",
                    Category = "Persistence",
                    Description = "Hidden scheduled task",
                    Score = 25,
                    Severity = RiskSeverity.High,
                    Evidence = "Task is marked as hidden",
                    Recommendation = "Hidden tasks are often used by malware to avoid detection."
                });
            }
        }

        assessment.Factors = factors;
        assessment.TotalScore = Math.Max(0, Math.Min(100, factors.Sum(f => f.Score)));
        assessment.Level = CalculateRiskLevel(assessment.TotalScore);
        
        return Task.FromResult(assessment);
    }

    public static Task<RiskAssessment> AnalyzeProcessAsync(ProcessInfo process, IDigitalSignatureService signatureService)
    {
        var assessment = new RiskAssessment();
        var factors = new List<RiskFactor>();

        // Signature checks
        if (!process.IsSigned)
        {
            factors.Add(new RiskFactor
            {
                Id = "PROC_UNSIGNED",
                Category = "Signature",
                Description = "Process binary is not digitally signed",
                Score = 25,
                Severity = RiskSeverity.Medium,
                Evidence = $"File: {process.Path}",
                Recommendation = "Unsigned executables are higher risk. Verify legitimacy."
            });
        }
        else if (!process.SignatureValid)
        {
            factors.Add(new RiskFactor
            {
                Id = "PROC_INVALID_SIG",
                Category = "Signature",
                Description = "Process binary has invalid digital signature",
                Score = 45,
                Severity = RiskSeverity.Critical,
                Evidence = process.SignatureDetails,
                Recommendation = "Critical indicator of tampering or malware."
            });
        }
        else if (IsMicrosoftPublisher(process.Publisher) || IsTrustedPublisher(process.Publisher))
        {
            factors.Add(new RiskFactor
            {
                Id = "PROC_TRUSTED_SIGNED",
                Category = "Signature",
                Description = "Signed by trusted publisher",
                Score = -15,
                Severity = RiskSeverity.None,
                Evidence = $"Publisher: {process.Publisher}",
                Recommendation = "Likely legitimate."
            });
        }

        // Process masquerading
        if (process.IsMasquerading)
        {
            factors.Add(new RiskFactor
            {
                Id = "PROC_MASQUERADING",
                Category = "Behavior",
                Description = "Process name masquerading as system process",
                Score = 50,
                Severity = RiskSeverity.Critical,
                Evidence = $"Process: {process.ProcessName}, Path: {process.Path}",
                Recommendation = "This is a classic malware technique (e.g., svchost.exe from non-system path). IMMEDIATE ACTION REQUIRED."
            });
        }

        // Suspicious name
        if (process.IsSuspiciousName)
        {
            factors.Add(new RiskFactor
            {
                Id = "PROC_SUSPICIOUS_NAME",
                Category = "Naming",
                Description = "Process name appears suspicious",
                Score = 20,
                Severity = RiskSeverity.Medium,
                Evidence = $"Name: {process.ProcessName}",
                Recommendation = "Name resembles system processes or uses random characters."
            });
        }

        // Suspicious path
        if (process.IsSuspiciousPath)
        {
            factors.Add(new RiskFactor
            {
                Id = "PROC_SUSPICIOUS_PATH",
                Category = "Location",
                Description = "Process running from suspicious location",
                Score = 30,
                Severity = RiskSeverity.High,
                Evidence = $"Path: {process.Path}",
                Recommendation = "Processes should run from standard locations (System32, Program Files)."
            });
        }

        // Running from temp
        if (process.IsRunningFromTemp)
        {
            factors.Add(new RiskFactor
            {
                Id = "PROC_FROM_TEMP",
                Category = "Location",
                Description = "Process running from temporary directory",
                Score = 50,
                Severity = RiskSeverity.Critical,
                Evidence = $"Path: {process.Path}",
                Recommendation = "Very common malware behavior. Investigate immediately."
            });
        }

        // Suspicious command line
        if (process.IsSuspiciousCommandLine)
        {
            factors.Add(new RiskFactor
            {
                Id = "PROC_SUSPICIOUS_CMDLINE",
                Category = "Command",
                Description = "Command line contains suspicious patterns",
                Score = 35,
                Severity = RiskSeverity.High,
                Evidence = $"CommandLine: {process.CommandLine}",
                Recommendation = "Contains encoded commands, downloaders, or bypass techniques."
            });
        }

        // No publisher info
        if (process.HasNoPublisher)
        {
            factors.Add(new RiskFactor
            {
                Id = "PROC_NO_PUBLISHER",
                Category = "Metadata",
                Description = "No publisher information available",
                Score = 10,
                Severity = RiskSeverity.Low,
                Evidence = "File version info lacks publisher",
                Recommendation = "Legitimate software typically includes publisher info."
            });
        }

        // Elevated process
        if (process.IsElevated && !process.IsSystemItem)
        {
            factors.Add(new RiskFactor
            {
                Id = "PROC_ELEVATED",
                Category = "Privilege",
                Description = "Non-system process running with elevated privileges",
                Score = 15,
                Severity = RiskSeverity.Medium,
                Evidence = $"Process: {process.ProcessName} (PID: {process.ProcessId})",
                Recommendation = "Elevated non-system processes should be verified."
            });
        }

        // Network connections
        if (process.NetworkConnections.Any(c => c.IsSuspicious))
        {
            var suspiciousConns = process.NetworkConnections.Where(c => c.IsSuspicious).ToList();
            factors.Add(new RiskFactor
            {
                Id = "PROC_SUSPICIOUS_NETWORK",
                Category = "Network",
                Description = "Process has suspicious network connections",
                Score = 30,
                Severity = RiskSeverity.High,
                Evidence = $"{suspiciousConns.Count} suspicious connection(s)",
                Recommendation = "Connections to suspicious ports or IPs may indicate C2 communication."
            });
        }

        // Packed executable
        if (process.IsPacked)
        {
            factors.Add(new RiskFactor
            {
                Id = "PROC_PACKED",
                Category = "Analysis",
                Description = "Executable appears to be packed/obfuscated",
                Score = 20,
                Severity = RiskSeverity.Medium,
                Evidence = "Entropy analysis or packer detection",
                Recommendation = "Packed executables are commonly used to evade detection."
            });
        }

        // .NET assembly (additional analysis possible)
        if (process.IsDotNet)
        {
            factors.Add(new RiskFactor
            {
                Id = "PROC_DOTNET",
                Category = "Analysis",
                Description = "Process is a .NET assembly",
                Score = 0,
                Severity = RiskSeverity.Informational,
                Evidence = "Detected .NET runtime",
                Recommendation = ".NET assemblies can be decompiled for further analysis."
            });
        }

        assessment.Factors = factors;
        assessment.TotalScore = Math.Max(0, Math.Min(100, factors.Sum(f => f.Score)));
        assessment.Level = CalculateRiskLevel(assessment.TotalScore);
        
        return Task.FromResult(assessment);
    }

    public static Task<RiskAssessment> AnalyzeDriverAsync(DriverInfo driver, IDigitalSignatureService signatureService)
    {
        var assessment = new RiskAssessment();
        var factors = new List<RiskFactor>();

        if (!driver.IsSigned)
        {
            factors.Add(new RiskFactor
            {
                Id = "DRV_UNSIGNED",
                Category = "Signature",
                Description = "Kernel driver is not signed",
                Score = 50,
                Severity = RiskSeverity.Critical,
                Evidence = $"Driver: {driver.BinaryPath}",
                Recommendation = "Unsigned kernel drivers cannot load on modern Windows with Driver Signature Enforcement. If present, DSE may be disabled."
            });
        }
        else if (!driver.SignatureValid)
        {
            factors.Add(new RiskFactor
            {
                Id = "DRV_INVALID_SIG",
                Category = "Signature",
                Description = "Driver has invalid signature",
                Score = 50,
                Severity = RiskSeverity.Critical,
                Evidence = driver.SignatureDetails,
                Recommendation = "Invalid driver signature is a critical security issue."
            });
        }

        if (driver.IsSuspiciousPath)
        {
            factors.Add(new RiskFactor
            {
                Id = "DRV_SUSPICIOUS_PATH",
                Category = "Location",
                Description = "Driver loaded from suspicious location",
                Score = 40,
                Severity = RiskSeverity.Critical,
                Evidence = $"Path: {driver.BinaryPath}",
                Recommendation = "Kernel drivers should only load from System32/drivers."
            });
        }

        assessment.Factors = factors;
        assessment.TotalScore = Math.Max(0, Math.Min(100, factors.Sum(f => f.Score)));
        assessment.Level = CalculateRiskLevel(assessment.TotalScore);
        
        return Task.FromResult(assessment);
    }

    public static Task<RiskAssessment> AnalyzeScheduledTaskAsync(ScheduledTaskInfo task, IDigitalSignatureService signatureService)
    {
        var assessment = new RiskAssessment();
        var factors = new List<RiskFactor>();

        if (task.Hidden)
        {
            factors.Add(new RiskFactor
            {
                Id = "TASK_HIDDEN",
                Category = "Persistence",
                Description = "Scheduled task is hidden",
                Score = 25,
                Severity = RiskSeverity.High,
                Evidence = "Task marked as hidden in Task Scheduler",
                Recommendation = "Hidden tasks are a common malware persistence technique."
            });
        }

        if (task.Actions.Any(a => a.IsSuspicious))
        {
            factors.Add(new RiskFactor
            {
                Id = "TASK_SUSPICIOUS_ACTION",
                Category = "Behavior",
                Description = "Task executes suspicious command",
                Score = 35,
                Severity = RiskSeverity.High,
                Evidence = $"Action: {task.Actions.First(a => a.IsSuspicious).Path} {task.Actions.First(a => a.IsSuspicious).Arguments}",
                Recommendation = "Task runs suspicious executables or commands."
            });
        }

        if (task.Triggers.Any(t => t.IsSuspicious))
        {
            factors.Add(new RiskFactor
            {
                Id = "TASK_SUSPICIOUS_TRIGGER",
                Category = "Persistence",
                Description = "Task has suspicious trigger configuration",
                Score = 20,
                Severity = RiskSeverity.Medium,
                Evidence = "Boot/Logon triggers or very frequent repetition",
                Recommendation = "Malware often uses boot/logon triggers for persistence."
            });
        }

        if (!string.IsNullOrWhiteSpace(task.Author) && !IsMicrosoftPublisher(task.Author) && !IsTrustedPublisher(task.Author))
        {
            factors.Add(new RiskFactor
            {
                Id = "TASK_UNKNOWN_AUTHOR",
                Category = "Attribution",
                Description = "Task created by unknown author",
                Score = 15,
                Severity = RiskSeverity.Medium,
                Evidence = $"Author: {task.Author}",
                Recommendation = "Verify if you recognize this software author."
            });
        }

        assessment.Factors = factors;
        assessment.TotalScore = Math.Max(0, Math.Min(100, factors.Sum(f => f.Score)));
        assessment.Level = CalculateRiskLevel(assessment.TotalScore);
        
        return Task.FromResult(assessment);
    }

    private static bool IsMicrosoftPublisher(string publisher)
    {
        if (string.IsNullOrWhiteSpace(publisher)) return false;
        return KnownMicrosoftPublishers.Any(p => publisher.Contains(p, StringComparison.OrdinalIgnoreCase));
    }

    private static bool IsTrustedPublisher(string publisher)
    {
        if (string.IsNullOrWhiteSpace(publisher)) return false;
        return TrustedPublishers.Any(p => publisher.Contains(p, StringComparison.OrdinalIgnoreCase));
    }

    private static RiskLevel CalculateRiskLevel(int score)
    {
        return score switch
        {
            >= 80 => RiskLevel.Critical,
            >= 60 => RiskLevel.High,
            >= 40 => RiskLevel.Medium,
            >= 20 => RiskLevel.Low,
            _ => RiskLevel.Informational
        };
    }
}
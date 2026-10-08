using System.Management;
using ScanSysDefence.Core.Analysis;
using ScanSysDefence.Core.Models;
using ScanSysDefence.Core.Services;
using ScanSysDefence.Core.Utils;

namespace ScanSysDefence.Core.Scanners;

public class WmiSubscriptionScanner : IScanner
{
    public string Name => "WMI Subscriptions";
    public ScanPhase Phase => ScanPhase.ScanningWmi;

    private readonly ILogger _logger;
    private readonly IDigitalSignatureService _signatureService;

    public WmiSubscriptionScanner(ILogger logger, IDigitalSignatureService signatureService)
    {
        _logger = logger;
        _signatureService = signatureService;
    }

    public async Task<IEnumerable<ScanItemBase>> ScanAsync(ScanContext context, CancellationToken cancellationToken = default)
    {
        var subscriptions = new List<WmiSubscriptionInfo>();

        if (!context.Settings.ScanWmiSubscriptions)
        {
            _logger.Information("WMI subscription scanning disabled in settings");
            return subscriptions;
        }

        try
        {
            context.Progress?.Report(new ScanProgress
            {
                CurrentPhase = Phase,
                StatusMessage = "Сканирование WMI-подписок..."
            });

            var scope = new ManagementScope(@"\\.\root\subscription");
            scope.Connect();

            // Query for __FilterToConsumerBinding
            using var bindingSearcher = new ManagementObjectSearcher(scope, new ObjectQuery("SELECT * FROM __FilterToConsumerBinding"));
            var bindings = bindingSearcher.Get().Cast<ManagementObject>().ToList();
            var total = Math.Max(1, bindings.Count);
            var processed = 0;

            foreach (var binding in bindings)
            {
                cancellationToken.ThrowIfCancellationRequested();

                var subscription = await ParseSubscriptionAsync(binding, scope);
                if (subscription != null)
                {
                    subscriptions.Add(subscription);
                }

                processed++;
                context.Progress?.Report(new ScanProgress
                {
                    CurrentPhase = Phase,
                    CurrentPhaseProgress = (int)((double)processed / total * 100),
                    ItemsScanned = processed,
                    StatusMessage = $"Сканирование WMI-подписки: {subscription?.SubscriptionName ?? "..."}"
                });
            }

            _logger.Information("WMI subscription scan completed: {Count} subscriptions found", subscriptions.Count);
        }
        catch (OperationCanceledException)
        {
            _logger.Warning("WMI subscription scan cancelled");
            throw;
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "WMI subscription scan failed");
        }

        return subscriptions;
    }

    private async Task<WmiSubscriptionInfo?> ParseSubscriptionAsync(ManagementObject binding, ManagementScope scope)
    {
        try
        {
            var filterRef = WmiSafe.Str(binding, "Filter");
            var consumerRef = WmiSafe.Str(binding, "Consumer");

            if (string.IsNullOrWhiteSpace(filterRef) || string.IsNullOrWhiteSpace(consumerRef))
                return null;

            // Parse filter
            var filterPath = new ManagementPath(filterRef);
            using var filter = new ManagementObject(scope, filterPath, null);
            var filterQuery = WmiSafe.Str(filter, "Query");
            var filterName = WmiSafe.Str(filter, "Name");
            if (string.IsNullOrWhiteSpace(filterName)) filterName = filterPath.ToString();

            // Parse consumer
            var consumerPath = new ManagementPath(consumerRef);
            using var consumer = new ManagementObject(scope, consumerPath, null);
            var consumerType = consumer.ClassPath.ClassName;
            var consumerCommand = GetConsumerCommand(consumer);

            var signature = new DigitalSignatureInfo();
            if (!string.IsNullOrWhiteSpace(consumerCommand) && File.Exists(consumerCommand))
            {
                signature = await _signatureService.VerifySignatureAsync(consumerCommand);
            }

            var subscription = new WmiSubscriptionInfo
            {
                SubscriptionName = filterName,
                FilterQuery = filterQuery,
                ConsumerType = consumerType,
                ConsumerCommand = consumerCommand,
                Creator = string.Empty,
                IsActive = true,
                Namespace = filterPath.NamespacePath,
                IsSigned = signature.IsSigned,
                SignatureValid = signature.IsValid,
                Publisher = signature.Publisher,
                SignatureDetails = signature.RawDetails,
                IsSystemItem = IsSystemSubscription(filterName, consumerCommand, signature.Publisher),
                CanStop = false,
                CanDisable = true,
                CanDelete = !IsSystemSubscription(filterName, consumerCommand, signature.Publisher),
                Metadata = new Dictionary<string, object>
                {
                    ["FilterPath"] = filterRef,
                    ["ConsumerPath"] = consumerRef,
                    ["ConsumerClass"] = consumerType
                }
            };

            subscription.RiskAssessment = AnalyzeSubscription(subscription);
            return subscription;
        }
        catch (Exception ex)
        {
            _logger.Debug("Failed to parse WMI subscription: {Message}", ex.Message);
            return null;
        }
    }

    private string GetConsumerCommand(ManagementObject consumer)
    {
        var type = consumer.ClassPath.ClassName;
        
        return type switch
        {
            "CommandLineEventConsumer" => WmiSafe.Str(consumer, "CommandLineTemplate"),
            "ActiveScriptEventConsumer" => WmiSafe.Str(consumer, "ScriptText"),
            "NTEventLogEventConsumer" => "Event Log: " + WmiSafe.Str(consumer, "LogFileName"),
            "SMTPEventConsumer" => "Email: " + WmiSafe.Str(consumer, "ToLine"),
            _ => string.Empty
        };
    }

    private bool IsSystemSubscription(string filterName, string consumerCommand, string publisher)
    {
        var systemFilters = new[] { "Win32_ProcessStartTrace", "Win32_ProcessStopTrace", "Win32_ThreadStartTrace", "Win32_ThreadStopTrace" };
        if (systemFilters.Any(f => filterName.Contains(f, StringComparison.OrdinalIgnoreCase))) return true;
        
        if (IsMicrosoftPublisher(publisher)) return true;
        
        return false;
    }

    private RiskAssessment AnalyzeSubscription(WmiSubscriptionInfo sub)
    {
        var assessment = new RiskAssessment();
        var factors = new List<RiskFactor>();

        // Check for suspicious queries
        var suspiciousQueries = new[]
        {
            "targetinstance isa \"win32_process\"",
            "targetinstance isa \"win32_service\"",
            "__instancecreationevent",
            "__instancemodificationevent",
            "__instancedeletionevent",
            "within"
        };

        var lowerQuery = sub.FilterQuery.ToLowerInvariant();
        foreach (var pattern in suspiciousQueries)
        {
            if (lowerQuery.Contains(pattern))
            {
                factors.Add(new RiskFactor
                {
                    Id = "WMI_SUSPICIOUS_QUERY",
                    Category = "Query",
                    Description = "WMI-фильтр отслеживает создание/изменение процессов и служб",
                    Score = 30,
                    Severity = RiskSeverity.High,
                    Evidence = $"Запрос: {sub.FilterQuery}",
                    Recommendation = "Такой шаблон часто используется вредоносным ПО для скрытого закрепления и обхода защиты."
                });
                break;
            }
        }

        // Check for suspicious consumers
        var suspiciousConsumers = new[]
        {
            "commandlineeventconsumer",
            "active_script_event_consumer",
            "nt_event_log_event_consumer",
            "smtp_event_consumer"
        };

        var lowerConsumer = sub.ConsumerType.ToLowerInvariant();
        foreach (var pattern in suspiciousConsumers)
        {
            if (lowerConsumer.Contains(pattern))
            {
                factors.Add(new RiskFactor
                {
                    Id = "WMI_SUSPICIOUS_CONSUMER",
                    Category = "Consumer",
                    Description = "WMI-потребитель может выполнять код или сценарии",
                    Score = 35,
                    Severity = RiskSeverity.High,
                    Evidence = $"Consumer: {sub.ConsumerType}, Команда: {sub.ConsumerCommand}",
                    Recommendation = "CommandLineEventConsumer и ActiveScriptEventConsumer часто используются вредоносным ПО."
                });
                break;
            }
        }

        // Check if unsigned
        if (!sub.IsSigned && !string.IsNullOrWhiteSpace(sub.ConsumerCommand) && File.Exists(sub.ConsumerCommand))
        {
            factors.Add(new RiskFactor
            {
                Id = "WMI_UNSIGNED_CONSUMER",
                Category = "Signature",
                Description = "Исполняемый файл WMI-потребителя не имеет цифровой подписи",
                Score = 25,
                Severity = RiskSeverity.Medium,
                Evidence = $"Файл: {sub.ConsumerCommand}",
                Recommendation = "Неподписанные исполняемые файлы, запускаемые по событиям WMI, подозрительны."
            });
        }

        assessment.Factors = factors;
        assessment.TotalScore = Math.Max(0, Math.Min(100, factors.Sum(f => f.Score)));
        assessment.Level = CalculateRiskLevel(assessment.TotalScore);
        
        return assessment;
    }

    private RiskLevel CalculateRiskLevel(int score)
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

    private bool IsMicrosoftPublisher(string publisher)
    {
        if (string.IsNullOrWhiteSpace(publisher)) return false;
        var lower = publisher.ToLowerInvariant();
        return lower.Contains("microsoft") || lower.Contains("windows publisher") || lower.Contains("windows");
    }
}

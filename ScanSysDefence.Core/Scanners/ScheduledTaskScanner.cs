using System.Diagnostics;
using ScanSysDefence.Core.Analysis;
using ScanSysDefence.Core.Models;
using ScanSysDefence.Core.Services;

namespace ScanSysDefence.Core.Scanners;

public class ScheduledTaskScanner : IScanner
{
    public string Name => "Scheduled Tasks";
    public ScanPhase Phase => ScanPhase.ScanningTasks;

    private readonly ILogger _logger;
    private readonly IDigitalSignatureService _signatureService;

    public ScheduledTaskScanner(ILogger logger, IDigitalSignatureService signatureService)
    {
        _logger = logger;
        _signatureService = signatureService;
    }

    public async Task<IEnumerable<ScanItemBase>> ScanAsync(ScanContext context, CancellationToken cancellationToken = default)
    {
        var tasks = new List<ScheduledTaskInfo>();

        if (!context.Settings.ScanScheduledTasks)
        {
            _logger.Information("Task Scheduler scanning disabled in settings");
            return tasks;
        }

        try
        {
            context.Progress?.Report(new ScanProgress
            {
                CurrentPhase = Phase,
                StatusMessage = "Перечисление задач планировщика..."
            });

            var schedulerType = Type.GetTypeFromProgID("Schedule.Service");
            if (schedulerType == null)
            {
                _logger.Warning("Task Scheduler COM object not available");
                return tasks;
            }

            dynamic scheduler = Activator.CreateInstance(schedulerType)
                ?? throw new InvalidOperationException("Task Scheduler COM not available");
            scheduler.Connect();

            // Важно: аргумент статически типизирован как object, иначе вызов
            // диспатчится динамически и .ToList() (метод-расширение) не находится
            // (RuntimeBinderException: does not contain a definition for 'ToList').
            object rootFolder = scheduler.GetFolder("\\");
            var allTasks = new List<object>();
            CollectTasksRecursive(rootFolder, allTasks);
            var total = Math.Max(1, allTasks.Count);
            var processed = 0;

            foreach (var task in allTasks)
            {
                cancellationToken.ThrowIfCancellationRequested();

                var taskInfo = await ParseTaskAsync(task, context.Settings);
                if (taskInfo != null)
                {
                    tasks.Add(taskInfo);
                }

                processed++;
                if (processed % 20 == 0 || processed == total)
                {
                    context.Progress?.Report(new ScanProgress
                    {
                        CurrentPhase = Phase,
                        CurrentPhaseProgress = (int)((double)processed / total * 100),
                        ItemsScanned = processed,
                        StatusMessage = $"Сканирование задачи: {taskInfo?.TaskName ?? "..."}"
                    });
                }
            }

            _logger.Information("Task Scheduler scan completed: {Count} tasks found", tasks.Count);
        }
        catch (OperationCanceledException)
        {
            _logger.Warning("Task Scheduler scan cancelled");
            throw;
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Task Scheduler scan failed");
        }

        return tasks;
    }

    /// <summary>
    /// Собирает все задачи рекурсивно. Важно: COM-коллекции планировщика нельзя
    /// перебирать через foreach по dynamic — COM-объекты не реализуют IEnumerable
    /// для C# dynamic (перечисление молча падает), поэтому используем Count + Item(i)
    /// (нумерация COM-коллекций с 1). Найдено при тестировании в чистой Windows 10.
    /// </summary>
    private static void CollectTasksRecursive(object folder, List<object> sink)
    {
        dynamic dynFolder = folder;

        dynamic tasks = dynFolder.GetTasks(1); // 1 = TASK_ENUM_HIDDEN
        var taskCount = 0;
        try { taskCount = (int)tasks.Count; } catch { }
        for (var i = 1; i <= taskCount; i++)
        {
            sink.Add((object)tasks.Item(i));
        }

        dynamic subFolders = dynFolder.GetFolders(0);
        var folderCount = 0;
        try { folderCount = (int)subFolders.Count; } catch { }
        for (var i = 1; i <= folderCount; i++)
        {
            CollectTasksRecursive((object)subFolders.Item(i), sink);
        }
    }

    private async Task<ScheduledTaskInfo?> ParseTaskAsync(dynamic task, ScanSettings settings)
    {
        try
        {
            var definition = task.Definition;
            var registrationInfo = definition.RegistrationInfo;
            var settingsObj = definition.Settings;
            var triggers = definition.Triggers;
            var actions = definition.Actions;

            var taskName = task.Name;
            var taskPath = task.Path;
            var author = TryGetValue(() => (string?)registrationInfo.Author ?? string.Empty, string.Empty);
            var description = TryGetValue(() => (string?)registrationInfo.Description ?? string.Empty, string.Empty);
            var userId = TryGetValue(() => (string?)definition.Principal.UserId ?? string.Empty, string.Empty);
            var xmlText = TryGetValue(() => (string?)definition.XmlText ?? string.Empty, string.Empty);
            var enabled = task.Enabled;
            var hidden = settingsObj.Hidden;
            var runOnlyIfNetworkAvailable = settingsObj.RunOnlyIfNetworkAvailable;
            var allowDemandStart = settingsObj.AllowDemandStart;
            var startWhenAvailable = settingsObj.StartWhenAvailable;
            var runOnlyIfIdle = settingsObj.RunOnlyIfIdle;
            var disallowStartIfOnBatteries = settingsObj.DisallowStartIfOnBatteries;
            var stopIfGoingOnBatteries = settingsObj.StopIfGoingOnBatteries;

            var taskActions = new List<TaskAction>();
            var actionCount = TryGetValue(() => (int)actions.Count, 0);
            for (var ai = 1; ai <= actionCount; ai++)
            {
                try
                {
                    dynamic action = actions.Item(ai);
                    if (action.Type == 0) // TASK_ACTION_EXEC (в COM-API свойство называется Type, не ActionType!)
                    {
                        var path = action.Path ?? string.Empty;
                        var arguments = action.Arguments ?? string.Empty;
                        var workingDir = action.WorkingDirectory ?? string.Empty;
                        var id = action.Id ?? string.Empty;

                        if (!string.IsNullOrWhiteSpace(path))
                        {
                            var actionSignature = await _signatureService.VerifySignatureAsync(path);
                            var isMicrosoftSigned = actionSignature.IsValid && IsMicrosoftPublisher(actionSignature.Publisher);
                            if (!settings.IncludeMicrosoftSigned && isMicrosoftSigned) continue;

                            taskActions.Add(new TaskAction
                            {
                                Type = "Exec",
                                Path = path,
                                Arguments = arguments,
                                WorkingDirectory = workingDir,
                                Id = id
                            });
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.Debug("Skipped task action: {Message}", ex.Message);
                }
            }

            if (!taskActions.Any()) return null;

            var taskTriggers = new List<TaskTrigger>();
            var triggerCount = TryGetValue(() => (int)triggers.Count, 0);
            for (var ti = 1; ti <= triggerCount; ti++)
            {
                try
                {
                    dynamic trigger = triggers.Item(ti);
                    DateTime? start = null;
                    DateTime? end = null;
                    try { var sb = (DateTime)trigger.StartBoundary; if (sb != DateTime.MinValue) start = sb; } catch { }
                    try { var eb = (DateTime)trigger.EndBoundary; if (eb != DateTime.MinValue) end = eb; } catch { }

                    string repInterval = string.Empty;
                    string repDuration = string.Empty;
                    try { repInterval = trigger.Repetition?.Interval ?? string.Empty; } catch { }
                    try { repDuration = trigger.Repetition?.Duration ?? string.Empty; } catch { }

                    bool trigEnabled = true;
                    try { trigEnabled = trigger.Enabled; } catch { }

                    string trigId = string.Empty;
                    try { trigId = trigger.Id ?? string.Empty; } catch { }

                    taskTriggers.Add(new TaskTrigger
                    {
                        Type = GetTriggerTypeName(trigger),
                        StartBoundary = start,
                        EndBoundary = end,
                        RepetitionInterval = repInterval,
                        RepetitionDuration = repDuration,
                        Enabled = trigEnabled,
                        Id = trigId
                    });
                }
                catch (Exception ex)
                {
                    _logger.Debug("Skipped task trigger: {Message}", ex.Message);
                }
            }

            var taskSettings = new TaskSettings
            {
                AllowHardTerminate = TryGetValue(() => (bool)settingsObj.AllowHardTerminate, true),
                RunOnlyIfNetworkAvailable = runOnlyIfNetworkAvailable,
                AllowDemandStart = allowDemandStart,
                StartWhenAvailable = startWhenAvailable,
                RunOnlyIfIdle = runOnlyIfIdle,
                DisallowStartIfOnBatteries = disallowStartIfOnBatteries,
                StopIfGoingOnBatteries = stopIfGoingOnBatteries,
                ExecutionTimeLimit = TryGetValue(() => (string?)settingsObj.ExecutionTimeLimit ?? "PT72H", "PT72H"),
                Priority = TryGetValue(() => (int)settingsObj.Priority, 7),
                // В COM-API нет свойства RestartOnFailure: перезапуск при сбое задаётся
                // парой RestartCount / RestartInterval (в XML — элемент RestartOnFailure).
                RestartOnFailure = TryGetValue(() => (int)settingsObj.RestartCount, 0) > 0,
                RestartInterval = TryGetValue(() => (string?)settingsObj.RestartInterval ?? string.Empty, string.Empty),
                RestartCount = TryGetValue(() => (int)settingsObj.RestartCount, 0)
            };

            var firstAction = taskActions.First();
            var signature = await _signatureService.VerifySignatureAsync(firstAction.Path);
            
            var taskInfo = new ScheduledTaskInfo
            {
                TaskName = taskName,
                TaskPath = taskPath,
                Description = description,
                Author = author,
                UserId = userId,
                Enabled = enabled,
                Hidden = hidden,
                RunOnlyIfNetworkAvailable = runOnlyIfNetworkAvailable,
                AllowDemandStart = allowDemandStart,
                StartWhenAvailable = startWhenAvailable,
                RunOnlyIfIdle = runOnlyIfIdle,
                DisallowStartIfOnBatteries = disallowStartIfOnBatteries,
                StopIfGoingOnBatteries = stopIfGoingOnBatteries,
                NextRunTime = TryGetDateTime(task, "NextRunTime"),
                LastRunTime = TryGetDateTime(task, "LastRunTime"),
                LastTaskResult = task.LastTaskResult,
                Actions = taskActions,
                Triggers = taskTriggers,
                Settings = taskSettings,
                Xml = xmlText,
                IsSigned = signature.IsSigned,
                SignatureValid = signature.IsValid,
                Publisher = signature.Publisher,
                SignatureDetails = signature.RawDetails,
                Version = GetFileVersion(firstAction.Path),
                IsSystemItem = IsSystemTask(taskName, author, signature.Publisher),
                CanStop = false,
                CanDisable = true,
                CanDelete = !IsSystemTask(taskName, author, signature.Publisher),
                Metadata = new Dictionary<string, object>
                {
                    ["TaskDefinition"] = xmlText
                }
            };

            taskInfo.RiskAssessment = await RiskAnalyzer.AnalyzeScheduledTaskAsync(taskInfo, _signatureService);
            return taskInfo;
        }
        catch (Exception ex)
        {
            _logger.Debug("Failed to parse task: {Message}", ex.Message);
            return null;
        }
    }

    private static T TryGetValue<T>(Func<T> getter, T fallback)
    {
        try { return getter(); } catch { return fallback; }
    }

    private static DateTime? TryGetDateTime(dynamic task, string property)
    {
        try
        {
            var value = (DateTime)task[property];
            return value == DateTime.MinValue ? null : value;
        }
        catch
        {
            return null;
        }
    }

    private string GetTriggerTypeName(dynamic trigger)
    {
        try
        {
            int type = (int)trigger.Type;
            return type switch
            {
                1 => "Event",
                2 => "Time",
                3 => "Daily",
                4 => "Weekly",
                5 => "Monthly",
                6 => "MonthlyDOW",
                7 => "Idle",
                8 => "Registration",
                9 => "Boot",
                10 => "Logon",
                11 => "SessionStateChange",
                12 => "Custom",
                _ => "Type" + type
            };
        }
        catch
        {
            try { return trigger.GetType().Name.Replace("Trigger", ""); }
            catch { return "Unknown"; }
        }
    }

    private string GetFileVersion(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                return FileVersionInfo.GetVersionInfo(path).FileVersion ?? string.Empty;
            }
        }
        catch { }
        return string.Empty;
    }

    private bool IsSystemTask(string name, string author, string publisher)
    {
        if (name.StartsWith("Microsoft", StringComparison.OrdinalIgnoreCase)) return true;
        if (name.StartsWith("Windows", StringComparison.OrdinalIgnoreCase)) return true;
        if (IsMicrosoftPublisher(author)) return true;
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

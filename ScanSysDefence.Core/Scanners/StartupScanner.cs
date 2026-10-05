using Microsoft.Win32;
using System.Diagnostics;
using System.Management;
using ScanSysDefence.Core.Analysis;
using ScanSysDefence.Core.Models;
using ScanSysDefence.Core.Services;

namespace ScanSysDefence.Core.Scanners;

public class StartupScanner : IScanner
{
    public string Name => "Startup Items";
    public ScanPhase Phase => ScanPhase.ScanningStartup;

    private readonly ILogger _logger;
    private readonly IDigitalSignatureService _signatureService;

    public StartupScanner(ILogger logger, IDigitalSignatureService signatureService)
    {
        _logger = logger;
        _signatureService = signatureService;
    }

    public async Task<IEnumerable<ScanItemBase>> ScanAsync(ScanContext context, CancellationToken cancellationToken = default)
    {
        var items = new List<StartupItem>();

        try
        {
            context.Progress?.Report(new ScanProgress
            {
                CurrentPhase = Phase,
                StatusMessage = "Scanning Registry Run keys..."
            });

            // Registry Run keys
            items.AddRange(await ScanRegistryRunKeysAsync(context.Settings, cancellationToken));

            context.Progress?.Report(new ScanProgress
            {
                CurrentPhase = Phase,
                StatusMessage = "Scanning Startup folders..."
            });

            // Startup folders
            items.AddRange(await ScanStartupFoldersAsync(context.Settings, cancellationToken));

            context.Progress?.Report(new ScanProgress
            {
                CurrentPhase = Phase,
                StatusMessage = "Scanning Task Scheduler..."
            });

            // Task Scheduler
            items.AddRange(await ScanTaskSchedulerAsync(context.Settings, cancellationToken));

            context.Progress?.Report(new ScanProgress
            {
                CurrentPhase = Phase,
                StatusMessage = "Scanning other persistence locations..."
            });

            // Other persistence locations
            items.AddRange(await ScanOtherPersistenceAsync(context.Settings, cancellationToken));

            _logger.Information("Startup scan completed: {Count} items found", items.Count);
        }
        catch (OperationCanceledException)
        {
            _logger.Warning("Startup scan cancelled");
            throw;
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Startup scan failed");
        }

        return items;
    }

    private async Task<List<StartupItem>> ScanRegistryRunKeysAsync(ScanSettings settings, CancellationToken cancellationToken)
    {
        var items = new List<StartupItem>();
        var runKeys = new[]
        {
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
            @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\RunOnce"
        };

        foreach (var keyPath in runKeys)
        {
            cancellationToken.ThrowIfCancellationRequested();
            
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(keyPath);
                if (key != null)
                {
                    foreach (var valueName in key.GetValueNames())
                    {
                        var command = key.GetValue(valueName)?.ToString() ?? string.Empty;
                        if (string.IsNullOrWhiteSpace(command)) continue;

                        var item = await CreateStartupItemAsync(valueName, command, keyPath, StartupLocationType.RegistryRun, settings);
                        if (item != null) items.Add(item);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Error scanning registry key {KeyPath}", keyPath);
            }
        }

        // Current User keys
        var userRunKeys = new[]
        {
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
        };

        foreach (var keyPath in userRunKeys)
        {
            cancellationToken.ThrowIfCancellationRequested();
            
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(keyPath);
                if (key != null)
                {
                    foreach (var valueName in key.GetValueNames())
                    {
                        var command = key.GetValue(valueName)?.ToString() ?? string.Empty;
                        if (string.IsNullOrWhiteSpace(command)) continue;

                        var item = await CreateStartupItemAsync(valueName, command, keyPath, StartupLocationType.RegistryRun, settings);
                        if (item != null) items.Add(item);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Error scanning user registry key {KeyPath}", keyPath);
            }
        }

        return items;
    }

    private async Task<StartupItem?> CreateStartupItemAsync(string name, string command, string location, StartupLocationType locationType, ScanSettings settings)
    {
        try
        {
            var cleanPath = ExtractPathFromCommand(command);
            if (string.IsNullOrWhiteSpace(cleanPath)) return null;

            var signature = await _signatureService.VerifySignatureAsync(cleanPath);
            
            var isMicrosoftSigned = signature.IsValid && IsMicrosoftPublisher(signature.Publisher);
            if (!settings.IncludeMicrosoftSigned && isMicrosoftSigned) return null;

            var item = new StartupItem
            {
                Name = name,
                Command = command,
                LocationPath = location,
                LocationType = locationType,
                Arguments = ExtractArguments(command),
                WorkingDirectory = ExtractWorkingDirectory(cleanPath),
                IsEnabled = true,
                IsSigned = signature.IsSigned,
                SignatureValid = signature.IsValid,
                Publisher = signature.Publisher,
                SignatureDetails = signature.RawDetails,
                Version = GetFileVersion(cleanPath),
                Description = GetFileDescription(cleanPath),
                IsSystemItem = IsSystemStartupItem(cleanPath, signature.Publisher),
                CanStop = false,
                CanDisable = true,
                CanDelete = !IsSystemStartupItem(cleanPath, signature.Publisher),
                Metadata = new Dictionary<string, object>
                {
                    ["RegistryKey"] = location,
                    ["ValueName"] = name
                }
            };

            item.RiskAssessment = await RiskAnalyzer.AnalyzeStartupItemAsync(item, _signatureService);
            return item;
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Failed to create startup item for {Name}", name);
            return null;
        }
    }

    private async Task<List<StartupItem>> ScanStartupFoldersAsync(ScanSettings settings, CancellationToken cancellationToken)
    {
        var items = new List<StartupItem>();
        var folders = new[]
        {
            (Environment.GetFolderPath(Environment.SpecialFolder.Startup), StartupLocationType.StartupFolderUser),
            (Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup), StartupLocationType.StartupFolderAllUsers)
        };

        foreach (var (folder, locationType) in folders)
        {
            cancellationToken.ThrowIfCancellationRequested();
            
            if (!Directory.Exists(folder)) continue;

            try
            {
                var files = Directory.GetFiles(folder, "*.*", SearchOption.AllDirectories)
                    .Where(f => f.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase) ||
                               f.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ||
                               f.EndsWith(".bat", StringComparison.OrdinalIgnoreCase) ||
                               f.EndsWith(".cmd", StringComparison.OrdinalIgnoreCase) ||
                               f.EndsWith(".ps1", StringComparison.OrdinalIgnoreCase));

                foreach (var file in files)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    
                    var name = Path.GetFileNameWithoutExtension(file);
                    var targetPath = file;

                    // Resolve shortcut
                    if (file.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase))
                    {
                        targetPath = ResolveShortcut(file);
                    }

                    if (string.IsNullOrWhiteSpace(targetPath) || !File.Exists(targetPath)) continue;

                    var signature = await _signatureService.VerifySignatureAsync(targetPath);
                    var isMicrosoftSigned = signature.IsValid && IsMicrosoftPublisher(signature.Publisher);
                    if (!settings.IncludeMicrosoftSigned && isMicrosoftSigned) continue;

                    var item = new StartupItem
                    {
                        Name = name,
                        Command = targetPath,
                        LocationPath = folder,
                        LocationType = locationType,
                        IsEnabled = true,
                        IsSigned = signature.IsSigned,
                        SignatureValid = signature.IsValid,
                        Publisher = signature.Publisher,
                        SignatureDetails = signature.RawDetails,
                        Version = GetFileVersion(targetPath),
                        Description = GetFileDescription(targetPath),
                        IsSystemItem = IsSystemStartupItem(targetPath, signature.Publisher),
                        CanDisable = true,
                        CanDelete = true,
                        Metadata = new Dictionary<string, object>
                        {
                            ["ShortcutPath"] = file,
                            ["TargetPath"] = targetPath
                        }
                    };

                    item.RiskAssessment = await RiskAnalyzer.AnalyzeStartupItemAsync(item, _signatureService);
                    items.Add(item);
                }
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Error scanning startup folder {Folder}", folder);
            }
        }

        return items;
    }

    private async Task<List<StartupItem>> ScanTaskSchedulerAsync(ScanSettings settings, CancellationToken cancellationToken)
    {
        var items = new List<StartupItem>();

        try
        {
            // Use COM interface for Task Scheduler
            var schedulerType = Type.GetTypeFromProgID("Schedule.Service");
            if (schedulerType == null) return items;

            dynamic scheduler = Activator.CreateInstance(schedulerType)
                ?? throw new InvalidOperationException("Task Scheduler COM not available");
            scheduler.Connect();

            var rootFolder = scheduler.GetFolder("\\");
            var tasks = GetTasksRecursive(rootFolder);

            foreach (var task in tasks)
            {
                cancellationToken.ThrowIfCancellationRequested();

                try
                {
                    if (task.State == 4) continue; // Disabled

                    var definition = task.Definition;
                    var actions = definition.Actions;

                    var actionCount = 0;
                    try { actionCount = (int)actions.Count; } catch { }
                    for (var ai = 1; ai <= actionCount; ai++)
                    {
                        dynamic action = actions.Item(ai);
                        if (action.Type == 0) // TASK_ACTION_EXEC (в COM-API свойство называется Type, не ActionType!)
                        {
                            var path = action.Path ?? string.Empty;
                            var arguments = action.Arguments ?? string.Empty;
                            var workingDir = action.WorkingDirectory ?? string.Empty;

                            if (string.IsNullOrWhiteSpace(path)) continue;

                            var fullCommand = $"\"{path}\" {arguments}".Trim();
                            var signature = await _signatureService.VerifySignatureAsync(path);
                            var isMicrosoftSigned = signature.IsValid && IsMicrosoftPublisher(signature.Publisher);
                            if (!settings.IncludeMicrosoftSigned && isMicrosoftSigned) continue;

                            var item = new StartupItem
                            {
                                Name = task.Name,
                                Command = fullCommand,
                                LocationPath = task.Path,
                                LocationType = StartupLocationType.TaskScheduler,
                                Arguments = arguments,
                                WorkingDirectory = workingDir,
                                IsEnabled = task.Enabled,
                                Hidden = definition.Settings.Hidden,
                                TaskSchedulerXml = definition.XmlText,
                                LastRunTime = task.LastRunTime != DateTime.MinValue ? task.LastRunTime : null,
                                NextRunTime = task.NextRunTime != DateTime.MinValue ? task.NextRunTime : null,
                                IsSigned = signature.IsSigned,
                                SignatureValid = signature.IsValid,
                                Publisher = signature.Publisher,
                                SignatureDetails = signature.RawDetails,
                                Version = GetFileVersion(path),
                                Description = GetFileDescription(path),
                                IsSystemItem = IsSystemStartupItem(path, signature.Publisher) || task.Name.StartsWith("Microsoft", StringComparison.OrdinalIgnoreCase),
                                CanDisable = true,
                                CanDelete = true,
                                Metadata = new Dictionary<string, object>
                                {
                                    ["TaskName"] = task.Name,
                                    ["TaskPath"] = task.Path,
                                    ["Author"] = definition.RegistrationInfo.Author ?? string.Empty,
                                    ["Description"] = definition.RegistrationInfo.Description ?? string.Empty
                                }
                            };

                            item.RiskAssessment = await RiskAnalyzer.AnalyzeStartupItemAsync(item, _signatureService);
                            items.Add(item);
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.Error(ex, "Error scanning task {TaskName}", task.Name);
                }
            }
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Task Scheduler scan failed");
        }

        return items;
    }

    private static IEnumerable<dynamic> GetTasksRecursive(dynamic folder)
    {
        // Count + Item(i), т.к. foreach по COM-коллекциям через dynamic в C# молча падает
        dynamic tasks = folder.GetTasks(1); // 1 = TASK_ENUM_HIDDEN
        var taskCount = 0;
        try { taskCount = (int)tasks.Count; } catch { }
        for (var i = 1; i <= taskCount; i++)
        {
            yield return (dynamic)tasks.Item(i);
        }

        dynamic subFolders = folder.GetFolders(0);
        var folderCount = 0;
        try { folderCount = (int)subFolders.Count; } catch { }
        for (var i = 1; i <= folderCount; i++)
        {
            foreach (var task in GetTasksRecursive((dynamic)(object)subFolders.Item(i)))
            {
                yield return task;
            }
        }
    }

    private async Task<List<StartupItem>> ScanOtherPersistenceAsync(ScanSettings settings, CancellationToken cancellationToken)
    {
        var items = new List<StartupItem>();

        // Winlogon
        items.AddRange(await ScanRegistryValuesAsync(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", 
            new[] { "Userinit", "Shell", "System" }, StartupLocationType.Winlogon, settings, cancellationToken));

        // AppInit_DLLs
        items.AddRange(await ScanRegistryValuesAsync(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
            new[] { "AppInit_DLLs" }, StartupLocationType.AppInitDlls, settings, cancellationToken));

        // Image File Execution Options (IFEO)
        items.AddRange(await ScanIfeoAsync(settings, cancellationToken));

        // Services (already scanned by ServiceScanner, but check for suspicious ones)
        // Browser Helper Objects
        items.AddRange(await ScanRegistrySubKeysAsync(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects",
            StartupLocationType.BrowserHelperObjects, settings, cancellationToken));

        // Shell Extensions
        items.AddRange(await ScanRegistrySubKeysAsync(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved",
            StartupLocationType.ShellExtensions, settings, cancellationToken));

        // Context Menu Handlers
        items.AddRange(await ScanRegistrySubKeysAsync(@"*\shellex\ContextMenuHandlers",
            StartupLocationType.ContextMenuHandlers, settings, cancellationToken, Registry.ClassesRoot));

        return items;
    }

    private async Task<List<StartupItem>> ScanRegistryValuesAsync(string keyPath, string[] valueNames, StartupLocationType locationType, ScanSettings settings, CancellationToken cancellationToken)
    {
        var items = new List<StartupItem>();

        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(keyPath);
            if (key == null) return items;

            foreach (var valueName in valueNames)
            {
                cancellationToken.ThrowIfCancellationRequested();
                
                var value = key.GetValue(valueName)?.ToString() ?? string.Empty;
                if (string.IsNullOrWhiteSpace(value)) continue;

                // Parse multiple paths separated by spaces/commas
                var paths = value.Split(new[] { ' ', ',', ';' }, StringSplitOptions.RemoveEmptyEntries);
                
                foreach (var path in paths)
                {
                    var cleanPath = ExtractPathFromCommand(path);
                    if (string.IsNullOrWhiteSpace(cleanPath) || !File.Exists(cleanPath)) continue;

                    var signature = await _signatureService.VerifySignatureAsync(cleanPath);
                    var isMicrosoftSigned = signature.IsValid && IsMicrosoftPublisher(signature.Publisher);
                    if (!settings.IncludeMicrosoftSigned && isMicrosoftSigned) continue;

                    var item = new StartupItem
                    {
                        Name = $"{valueName}: {Path.GetFileName(cleanPath)}",
                        Command = path,
                        LocationPath = keyPath,
                        LocationType = locationType,
                        IsEnabled = true,
                        IsSigned = signature.IsSigned,
                        SignatureValid = signature.IsValid,
                        Publisher = signature.Publisher,
                        SignatureDetails = signature.RawDetails,
                        Version = GetFileVersion(cleanPath),
                        Description = GetFileDescription(cleanPath),
                        IsSystemItem = IsSystemStartupItem(cleanPath, signature.Publisher),
                        CanDisable = true,
                        CanDelete = true,
                        Metadata = new Dictionary<string, object>
                        {
                            ["RegistryKey"] = keyPath,
                            ["ValueName"] = valueName,
                            ["OriginalValue"] = value
                        }
                    };

                    item.RiskAssessment = await RiskAnalyzer.AnalyzeStartupItemAsync(item, _signatureService);
                    items.Add(item);
                }
            }
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Error scanning registry values at {KeyPath}", keyPath);
        }

        return items;
    }

    private async Task<List<StartupItem>> ScanIfeoAsync(ScanSettings settings, CancellationToken cancellationToken)
    {
        var items = new List<StartupItem>();

        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options");
            if (key == null) return items;

            foreach (var subKeyName in key.GetSubKeyNames())
            {
                cancellationToken.ThrowIfCancellationRequested();
                
                using var subKey = key.OpenSubKey(subKeyName);
                if (subKey == null) continue;

                var debugger = subKey.GetValue("Debugger")?.ToString() ?? string.Empty;
                if (string.IsNullOrWhiteSpace(debugger)) continue;

                var cleanPath = ExtractPathFromCommand(debugger);
                if (string.IsNullOrWhiteSpace(cleanPath) || !File.Exists(cleanPath)) continue;

                var signature = await _signatureService.VerifySignatureAsync(cleanPath);
                var isMicrosoftSigned = signature.IsValid && IsMicrosoftPublisher(signature.Publisher);
                if (!settings.IncludeMicrosoftSigned && isMicrosoftSigned) continue;

                var item = new StartupItem
                {
                    Name = $"IFEO: {subKeyName} -> {Path.GetFileName(cleanPath)}",
                    Command = debugger,
                    LocationPath = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\" + subKeyName,
                    LocationType = StartupLocationType.ImageFileExecutionOptions,
                    IsEnabled = true,
                    IsSigned = signature.IsSigned,
                    SignatureValid = signature.IsValid,
                    Publisher = signature.Publisher,
                    SignatureDetails = signature.RawDetails,
                    Version = GetFileVersion(cleanPath),
                    Description = GetFileDescription(cleanPath),
                    IsSystemItem = IsSystemStartupItem(cleanPath, signature.Publisher),
                    CanDisable = true,
                    CanDelete = true,
                    Metadata = new Dictionary<string, object>
                    {
                        ["TargetExecutable"] = subKeyName,
                        ["DebuggerValue"] = debugger
                    }
                };

                item.RiskAssessment = await RiskAnalyzer.AnalyzeStartupItemAsync(item, _signatureService);
                items.Add(item);
            }
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "IFEO scan failed");
        }

        return items;
    }

    private async Task<List<StartupItem>> ScanRegistrySubKeysAsync(string keyPath, StartupLocationType locationType, ScanSettings settings, CancellationToken cancellationToken, RegistryKey? rootKey = null)
    {
        var items = new List<StartupItem>();
        rootKey ??= Registry.LocalMachine;

        try
        {
            using var key = rootKey.OpenSubKey(keyPath);
            if (key == null) return items;

            foreach (var subKeyName in key.GetSubKeyNames())
            {
                cancellationToken.ThrowIfCancellationRequested();
                
                using var subKey = key.OpenSubKey(subKeyName);
                if (subKey == null) continue;

                // Get default value or specific values
                var value = subKey.GetValue("")?.ToString() ?? subKey.GetValue("Command")?.ToString() ?? string.Empty;
                if (string.IsNullOrWhiteSpace(value)) continue;

                var cleanPath = ExtractPathFromCommand(value);
                if (string.IsNullOrWhiteSpace(cleanPath) || !File.Exists(cleanPath)) continue;

                var signature = await _signatureService.VerifySignatureAsync(cleanPath);
                var isMicrosoftSigned = signature.IsValid && IsMicrosoftPublisher(signature.Publisher);
                if (!settings.IncludeMicrosoftSigned && isMicrosoftSigned) continue;

                var item = new StartupItem
                {
                    Name = subKeyName,
                    Command = value,
                    LocationPath = keyPath + "\\" + subKeyName,
                    LocationType = locationType,
                    IsEnabled = true,
                    IsSigned = signature.IsSigned,
                    SignatureValid = signature.IsValid,
                    Publisher = signature.Publisher,
                    SignatureDetails = signature.RawDetails,
                    Version = GetFileVersion(cleanPath),
                    Description = GetFileDescription(cleanPath),
                    IsSystemItem = IsSystemStartupItem(cleanPath, signature.Publisher),
                    CanDisable = true,
                    CanDelete = true
                };

                item.RiskAssessment = await RiskAnalyzer.AnalyzeStartupItemAsync(item, _signatureService);
                items.Add(item);
            }
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Error scanning registry subkeys at {KeyPath}", keyPath);
        }

        return items;
    }

    private string ExtractPathFromCommand(string command)
    {
        if (string.IsNullOrWhiteSpace(command)) return string.Empty;

        command = command.Trim();
        
        // Handle quoted paths
        if (command.StartsWith("\""))
        {
            var endQuote = command.IndexOf('"', 1);
            if (endQuote > 0)
            {
                return Environment.ExpandEnvironmentVariables(command.Substring(1, endQuote - 1));
            }
        }

        // Handle unquoted paths (take first part before space)
        var parts = command.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length > 0)
        {
            return Environment.ExpandEnvironmentVariables(parts[0]);
        }

        return string.Empty;
    }

    private string ExtractArguments(string command)
    {
        if (string.IsNullOrWhiteSpace(command)) return string.Empty;

        command = command.Trim();
        
        if (command.StartsWith("\""))
        {
            var endQuote = command.IndexOf('"', 1);
            if (endQuote > 0 && endQuote + 1 < command.Length)
            {
                return command.Substring(endQuote + 1).Trim();
            }
        }
        else
        {
            var parts = command.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length > 1)
            {
                return string.Join(" ", parts.Skip(1));
            }
        }

        return string.Empty;
    }

    private string ExtractWorkingDirectory(string path)
    {
        try
        {
            return Path.GetDirectoryName(path) ?? string.Empty;
        }
        catch
        {
            return string.Empty;
        }
    }

    private string ResolveShortcut(string shortcutPath)
    {
        try
        {
            var shellType = Type.GetTypeFromProgID("Shell.Application");
            if (shellType == null) return string.Empty;

            var shellObj = Activator.CreateInstance(shellType);
            if (shellObj == null) return string.Empty;
            dynamic shell = shellObj;

            var dir = Path.GetDirectoryName(shortcutPath);
            if (string.IsNullOrEmpty(dir)) return string.Empty;

            dynamic folder = shell.NameSpace(dir);
            if (folder == null) return string.Empty;

            dynamic item = folder.ParseName(Path.GetFileName(shortcutPath));
            if (item == null) return string.Empty;

            dynamic link = item.GetLink;
            if (link == null) return string.Empty;

            return link.Path ?? string.Empty;
        }
        catch
        {
            return string.Empty;
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

    private string GetFileDescription(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                return FileVersionInfo.GetVersionInfo(path).FileDescription ?? string.Empty;
            }
        }
        catch { }
        return string.Empty;
    }

    private bool IsSystemStartupItem(string path, string publisher)
    {
        var lowerPath = path.ToLowerInvariant();
        var systemPaths = new[] { @"c:\windows\system32\", @"c:\windows\syswow64\", @"c:\windows\winsxs\" };
        
        if (systemPaths.Any(p => lowerPath.StartsWith(p))) return true;
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
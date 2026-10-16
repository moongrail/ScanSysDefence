using System.Diagnostics;
using System.IO;
using System.Management;
using System.Security.AccessControl;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text.Json;
using Microsoft.Win32;
using ScanSysDefence.Core.Models;
using ScanSysDefence.Core.Services;

namespace ScanSysDefence.Core.Remediation;

public class RemediationService : IRemediationService
{
    private readonly ILogger _logger;
    private readonly IRestorePointService _restorePointService;
    private readonly IRestorePointPromptService _promptService;
    private readonly ISafetyService _safetyService;
    private readonly string _quarantineFolder;

    public RemediationService(
        ILogger logger,
        IRestorePointService restorePointService,
        IRestorePointPromptService promptService,
        ISafetyService safetyService)
    {
        _logger = logger;
        _restorePointService = restorePointService;
        _promptService = promptService;
        _safetyService = safetyService;
        _quarantineFolder = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "ScanSysDefence", "Quarantine");
        Directory.CreateDirectory(_quarantineFolder);
    }

    public async Task<RemediationResult> ExecuteActionAsync(RemediationAction action, RestorePointPromptContext? promptContext = null, CancellationToken ct = default)
    {
        var stopwatch = Stopwatch.StartNew();
        var result = new RemediationResult { ActionId = action.Id };

        try
        {
            if (action.RequiresRestorePointPrompt && promptContext != null)
            {
                var promptResult = await _promptService.PromptUserAsync(promptContext);
                if (promptResult.Action == RestorePointPromptAction.Cancel)
                {
                    result.Message = "Действие отменено пользователем";
                    result.Success = false;
                    return result;
                }

                if (promptResult.ShouldCreateRestorePoint)
                {
                    var rpCreated = await _restorePointService.CreateRestorePointAsync(promptResult.Description);
                    result.RestorePointCreated = rpCreated;
                    _logger.Information("Restore point created: {Result}", rpCreated);
                }
            }

            result = action.Type switch
            {
                RemediationActionType.StopProcess => await StopProcessAsync(Convert.ToInt32(action.TargetId), action.TargetName, ct),
                RemediationActionType.StopService => await StopServiceInternalAsync(action.TargetId, ct),
                RemediationActionType.DisableService => await DisableServiceInternalAsync(action.TargetId, ct),
                RemediationActionType.RemoveStartupEntry => await RemoveStartupEntryInternalAsync(action, ct),
                RemediationActionType.DeleteFile => await DeleteFileInternalAsync(action.TargetPath, true, ct),
                RemediationActionType.QuarantineFile => await QuarantineFileInternalAsync(action.TargetPath, ct),
                RemediationActionType.DisableScheduledTask => await DisableScheduledTaskInternalAsync(action.TargetName, action.TargetPath, ct),
                RemediationActionType.DeleteScheduledTask => await DeleteScheduledTaskInternal(action.TargetName, action.TargetPath, ct),
                RemediationActionType.RemoveWmiSubscription => await RemoveWmiSubscriptionInternalAsync(action.TargetId, ct),
                _ => new RemediationResult { ActionId = action.Id, Success = false, Error = "Неизвестный тип действия" }
            };

            result.ActionId = action.Id;
            stopwatch.Stop();
            result.Duration = stopwatch.Elapsed;

            _logger.Information("Remediation {Type} on {Target}: {Success} in {Duration}",
                action.Type, action.TargetName, result.Success, result.Duration);

            return result;
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Remediation failed for {Action}", action.Type);
            stopwatch.Stop();
            return new RemediationResult
            {
                ActionId = action.Id,
                Success = false,
                Error = ex.Message,
                Duration = stopwatch.Elapsed
            };
        }
    }

    public async Task<RemediationResult> StopProcessAsync(int processId, string processName, bool promptForRestorePoint = false)
    {
        return await StopProcessAsync(processId, processName, CancellationToken.None);
    }

    private async Task<RemediationResult> StopProcessAsync(int processId, string processName, CancellationToken ct)
    {
        var result = new RemediationResult();
        try
        {
            await Task.Run(() =>
            {
                using var proc = Process.GetProcessById(processId);
                if (proc.MainWindowHandle != IntPtr.Zero)
                {
                    // Пытаемся закрыть приложение корректно
                    proc.CloseMainWindow();
                    if (!proc.WaitForExit(3000))
                    {
                        proc.Kill(true);
                        proc.WaitForExit(5000);
                    }
                }
                else
                {
                    proc.Kill(true);
                    proc.WaitForExit(5000);
                }
            }, ct);

            var alive = await IsProcessAliveAsync(processId, ct);
            result.Success = !alive;
            result.Message = alive
                ? $"Процесс «{processName}» (PID: {processId}) всё ещё работает — используйте «Убить процесс»."
                : $"Процесс «{processName}» (PID: {processId}) остановлен.";
            if (alive) result.Error = "Процесс не завершился после запроса остановки.";
        }
        catch (ArgumentException)
        {
            result.Success = true;
            result.Message = $"Процесс «{processName}» (PID: {processId}) уже не запущен.";
        }
        catch (Exception ex)
        {
            result.Success = false;
            result.Error = $"Не удалось остановить процесс: {ex.Message}";
        }
        return result;
    }

    public async Task<RemediationResult> ForceKillProcessAsync(int processId, string processName)
    {
        var result = new RemediationResult();
        try
        {
            await Task.Run(() =>
            {
                try
                {
                    using var proc = Process.GetProcessById(processId);
                    proc.Kill(true);
                    proc.WaitForExit(3000);
                }
                catch
                {
                    // Резервный путь: WMI Terminate (срабатывает там, где .NET Kill отказал)
                    try
                    {
                        using var mo = new ManagementObject($"Win32_Process.Handle=\"{processId}\"");
                        mo.InvokeMethod("Terminate", null);
                    }
                    catch
                    {
                        // Игнорируем — проверка ниже определит результат
                    }
                }
            });

            var alive = await IsProcessAliveAsync(processId, CancellationToken.None);
            result.Success = !alive;
            result.Message = alive
                ? $"Не удалось убить процесс «{processName}» (PID: {processId}) — доступ запрещён или процесс защищён системой."
                : $"Процесс «{processName}» (PID: {processId}) принудительно убит.";
            if (alive) result.Error = "Процесс всё ещё работает (возможно, защищённый системный процесс).";
        }
        catch (Exception ex)
        {
            result.Success = false;
            result.Error = $"Не удалось убить процесс: {ex.Message}";
        }
        return result;
    }

    private static async Task<bool> IsProcessAliveAsync(int processId, CancellationToken ct)
    {
        for (int attempt = 0; attempt < 8; attempt++)
        {
            try
            {
                using var proc = Process.GetProcessById(processId);
                if (proc.HasExited) return false;
            }
            catch (ArgumentException)
            {
                return false;
            }
            catch
            {
                return true; // Доступ запрещён — процесс существует
            }
            await Task.Delay(250, ct);
        }
        return true;
    }

    public async Task<RemediationResult> StopServiceAsync(string serviceName, bool promptForRestorePoint = false)
    {
        return await StopServiceInternalAsync(serviceName, CancellationToken.None);
    }

    private async Task<RemediationResult> StopServiceInternalAsync(string serviceName, CancellationToken ct)
    {
        var result = new RemediationResult();
        try
        {
            await Task.Run(() =>
            {
                using var service = new ServiceController(serviceName);
                if (service.Status == ServiceControllerStatus.Running ||
                    service.Status == ServiceControllerStatus.StartPending)
                {
                    service.Stop();
                    service.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(30));
                }
            }, ct);

            using (var check = new ServiceController(serviceName))
            {
                check.Refresh();
                var stopped = check.Status == ServiceControllerStatus.Stopped;
                result.Success = stopped;
                result.Message = stopped
                    ? $"Служба «{serviceName}» остановлена (текущее состояние: Остановлена)."
                    : $"Служба «{serviceName}» не остановилась — текущее состояние: {TranslateStatus(check.Status)}.";
                if (!stopped) result.Error = $"Текущее состояние службы: {TranslateStatus(check.Status)}";
            }
        }
        catch (InvalidOperationException ex)
        {
            result.Success = false;
            result.Error = $"Служба не найдена или недоступна: {ex.Message}";
        }
        catch (Exception ex)
        {
            result.Success = false;
            result.Error = $"Не удалось остановить службу: {ex.Message}";
        }
        return result;
    }

    private static string TranslateStatus(ServiceControllerStatus status) => status switch
    {
        ServiceControllerStatus.Stopped => "Остановлена",
        ServiceControllerStatus.StartPending => "Запускается",
        ServiceControllerStatus.StopPending => "Останавливается",
        ServiceControllerStatus.Running => "Работает",
        ServiceControllerStatus.ContinuePending => "Возобновляется",
        ServiceControllerStatus.PausePending => "Приостанавливается",
        ServiceControllerStatus.Paused => "Приостановлена",
        _ => status.ToString()
    };

    public async Task<RemediationResult> DisableServiceAsync(string serviceName, bool promptForRestorePoint = false)
    {
        return await DisableServiceInternalAsync(serviceName, CancellationToken.None);
    }

    private async Task<RemediationResult> DisableServiceInternalAsync(string serviceName, CancellationToken ct)
    {
        var result = new RemediationResult();
        try
        {
            string? startValue = null;
            string? writeError = null;

            await Task.Run(() =>
            {
                try
                {
                    using var service = new ServiceController(serviceName);
                    if (service.Status == ServiceControllerStatus.Running ||
                        service.Status == ServiceControllerStatus.StartPending)
                    {
                        try
                        {
                            service.Stop();
                            service.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(30));
                        }
                        catch (Exception stopEx)
                        {
                            // Останавливаем, но продолжаем отключение даже если стоп не удался
                            writeError = $"служба не остановилась ({stopEx.Message}); ";
                        }
                    }
                }
                catch (InvalidOperationException)
                {
                    // Служба может отсутствовать в SCM — пробуем только реестр
                }

                var regPath = $@"SYSTEM\CurrentControlSet\Services\{serviceName}";
                using (var key = Registry.LocalMachine.OpenSubKey(regPath, true))
                {
                    if (key != null)
                    {
                        key.SetValue("Start", 4, RegistryValueKind.DWord);
                    }
                    else
                    {
                        // Fallback: sc.exe config
                        var psi = new ProcessStartInfo("sc.exe", $"config \"{serviceName}\" start= disabled")
                        {
                            CreateNoWindow = true,
                            UseShellExecute = false,
                            RedirectStandardOutput = true,
                            RedirectStandardError = true
                        };
                        using var proc = Process.Start(psi);
                        proc?.WaitForExit(10000);
                    }
                }

                using var check = Registry.LocalMachine.OpenSubKey(regPath, false);
                startValue = check?.GetValue("Start")?.ToString();
            }, ct);

            var disabled = startValue == "4";
            result.Success = disabled;
            result.Message = disabled
                ? $"Служба «{serviceName}» отключена (запуск запрещён, Start=4)."
                : $"Служба «{serviceName}»: не удалось подтвердить отключение (Start={startValue ?? "?"}).";
            if (!disabled)
            {
                result.Error = (writeError ?? string.Empty) + "Не удалось установить Start=4 (нужны права администратора).";
            }
            else if (!string.IsNullOrEmpty(writeError))
            {
                result.Message += " " + writeError;
            }
        }
        catch (Exception ex)
        {
            result.Success = false;
            result.Error = $"Не удалось отключить службу: {ex.Message}";
        }
        return result;
    }

    public async Task<RemediationResult> RemoveStartupEntryAsync(StartupItem item, bool promptForRestorePoint = false)
    {
        var action = new RemediationAction
        {
            Type = RemediationActionType.RemoveStartupEntry,
            TargetId = item.Id,
            TargetName = item.Name,
            TargetPath = item.Command
        };
        return await RemoveStartupEntryInternalAsync(action, CancellationToken.None);
    }

    private async Task<RemediationResult> RemoveStartupEntryInternalAsync(RemediationAction action, CancellationToken ct)
    {
        var result = new RemediationResult();
        try
        {
            await Task.Run(async () =>
            {
                switch (action.Parameters.TryGetValue("LocationType", out var locObj) ? locObj?.ToString() : "")
                {
                    case nameof(StartupLocationType.RegistryRun):
                    case nameof(StartupLocationType.RegistryRunOnce):
                        RemoveRegistryStartup(action);
                        break;
                    case nameof(StartupLocationType.TaskScheduler):
                        await DeleteScheduledTaskInternal(action.TargetName, action.TargetPath, ct);
                        break;
                    default:
                        result.Success = false;
                        result.Error = "Неизвестный тип расположения автозапуска";
                        break;
                }
            }, ct);

            result.Success = true;
            result.Message = $"Запись автозапуска «{action.TargetName}» удалена.";
        }
        catch (Exception ex)
        {
            result.Success = false;
            result.Error = $"Не удалось удалить запись автозапуска: {ex.Message}";
        }
        return result;
    }

    private void RemoveRegistryStartup(RemediationAction action)
    {
        var keyPath = action.Parameters.TryGetValue("RegistryKey", out var kpObj) ? kpObj?.ToString() ?? "" : "";
        var valueName = action.Parameters.TryGetValue("ValueName", out var vnObj) ? vnObj?.ToString() ?? "" : "";

        if (string.IsNullOrEmpty(keyPath) || string.IsNullOrEmpty(valueName)) return;

        using var key = Registry.LocalMachine.OpenSubKey(keyPath, true)
            ?? Registry.CurrentUser.OpenSubKey(keyPath, true);
        key?.DeleteValue(valueName, false);
    }

    public async Task<RemediationResult> DeleteFileAsync(string filePath, bool createBackup = true, bool promptForRestorePoint = false)
    {
        return await DeleteFileInternalAsync(filePath, createBackup, CancellationToken.None);
    }

    private async Task<RemediationResult> DeleteFileInternalAsync(string filePath, bool createBackup, CancellationToken ct)
    {
        var result = new RemediationResult();
        try
        {
            await Task.Run(() =>
            {
                if (!File.Exists(filePath))
                {
                    result.Success = false;
                    result.Error = "Файл не найден";
                    return;
                }

                if (createBackup)
                {
                    var backupPath = Path.Combine(_quarantineFolder, $"{Path.GetFileName(filePath)}.{DateTime.Now:yyyyMMdd_HHmmss}.bak");
                    File.Copy(filePath, backupPath, true);
                    result.BackupPath = backupPath;
                }

                var fileAttrs = File.GetAttributes(filePath);
                if (fileAttrs.HasFlag(FileAttributes.ReadOnly))
                {
                    File.SetAttributes(filePath, fileAttrs & ~FileAttributes.ReadOnly);
                }

                File.Delete(filePath);
            }, ct);

            result.Success = true;
            result.Message = $"Файл «{Path.GetFileName(filePath)}» удалён.";
        }
        catch (Exception ex)
        {
            result.Success = false;
            result.Error = $"Не удалось удалить файл: {ex.Message}";
        }
        return result;
    }

    public async Task<RemediationResult> QuarantineFileAsync(string filePath, bool promptForRestorePoint = false)
    {
        return await QuarantineFileInternalAsync(filePath, CancellationToken.None);
    }

    private async Task<RemediationResult> QuarantineFileInternalAsync(string filePath, CancellationToken ct)
    {
        var result = new RemediationResult();
        try
        {
            await Task.Run(() =>
            {
                if (!File.Exists(filePath))
                {
                    result.Success = false;
                    result.Error = "Файл не найден";
                    return;
                }

                long size = 0;
                try { size = new FileInfo(filePath).Length; } catch { }

                var quarantinePath = Path.Combine(_quarantineFolder,
                    $"{Path.GetFileNameWithoutExtension(filePath)}.{Guid.NewGuid():N}.quarantined");
                File.Move(filePath, quarantinePath, true);

                // Encrypt quarantined file
                EncryptFile(quarantinePath);
                SaveQuarantineMeta(quarantinePath, new QuarantineMeta
                {
                    OriginalPath = filePath,
                    Reason = "Помещён в карантин из ScanSysDefence",
                    QuarantinedAt = DateTime.Now,
                    SizeBytes = size
                });

                result.BackupPath = quarantinePath;
            }, ct);

            result.Success = true;
            result.Message = $"Файл «{Path.GetFileName(filePath)}» перемещён в карантин (восстановление — во вкладке «Карантин»).";
        }
        catch (Exception ex)
        {
            result.Success = false;
            result.Error = $"Не удалось поместить файл в карантин: {ex.Message}";
        }
        return result;
    }

    private void EncryptFile(string path)
    {
        try
        {
            var bytes = File.ReadAllBytes(path);
            for (int i = 0; i < bytes.Length; i++)
            {
                bytes[i] = (byte)(bytes[i] ^ 0x5A);
            }
            File.WriteAllBytes(path, bytes);
            File.SetAttributes(path, File.GetAttributes(path) | FileAttributes.Hidden | FileAttributes.System);
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Failed to encrypt quarantined file {Path}", path);
        }
    }

    public string QuarantineFolderPath => _quarantineFolder;

    public Task<List<QuarantineEntry>> GetQuarantineEntriesAsync()
    {
        return Task.Run(() =>
        {
            var entries = new List<QuarantineEntry>();
            try
            {
                if (!Directory.Exists(_quarantineFolder)) return entries;

                foreach (var file in Directory.EnumerateFiles(_quarantineFolder))
                {
                    var ext = Path.GetExtension(file);
                    var isQuarantined = ext.Equals(".quarantined", StringComparison.OrdinalIgnoreCase);
                    var isBackup = ext.Equals(".bak", StringComparison.OrdinalIgnoreCase);
                    if (!isQuarantined && !isBackup) continue;

                    var info = new FileInfo(file);
                    var meta = isQuarantined ? LoadQuarantineMeta(file) : null;

                    entries.Add(new QuarantineEntry
                    {
                        QuarantinePath = file,
                        FileName = info.Name,
                        OriginalPath = meta?.OriginalPath ?? string.Empty,
                        Reason = meta?.Reason ?? (isBackup ? "Резервная копия (создана при удалении файла)" : string.Empty),
                        QuarantinedAt = meta?.QuarantinedAt ?? info.LastWriteTime,
                        SizeBytes = meta?.SizeBytes ?? info.Length,
                        IsBackup = isBackup
                    });
                }
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Failed to enumerate quarantine entries");
            }

            return entries.OrderByDescending(e => e.QuarantinedAt).ToList();
        });
    }

    public async Task<RemediationResult> RestoreFromQuarantineAsync(string quarantinePath, string? targetPath = null)
    {
        var result = new RemediationResult();
        try
        {
            if (!File.Exists(quarantinePath))
            {
                result.Success = false;
                result.Error = "Файл карантина не найден";
                return result;
            }

            var meta = LoadQuarantineMeta(quarantinePath);
            var target = !string.IsNullOrWhiteSpace(targetPath)
                ? targetPath!
                : meta?.OriginalPath ?? string.Empty;

            if (string.IsNullOrWhiteSpace(target))
            {
                result.Success = false;
                result.Error = "Исходный путь неизвестен — восстановление невозможно";
                return result;
            }

            await Task.Run(() =>
            {
                var dir = Path.GetDirectoryName(target);
                if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);

                // Не перезаписываем существующий файл: добавляем суффикс
                if (File.Exists(target))
                {
                    var name = Path.GetFileNameWithoutExtension(target);
                    var ext = Path.GetExtension(target);
                    target = Path.Combine(dir ?? string.Empty, $"{name}.restored_{DateTime.Now:yyyyMMdd_HHmmss}{ext}");
                }

                var bytes = File.ReadAllBytes(quarantinePath);
                for (int i = 0; i < bytes.Length; i++) bytes[i] = (byte)(bytes[i] ^ 0x5A);

                try { File.SetAttributes(quarantinePath, FileAttributes.Normal); } catch { }
                File.WriteAllBytes(target, bytes);
                try { File.SetAttributes(target, FileAttributes.Normal); } catch { }

                try { File.Delete(quarantinePath); } catch { }
                var metaPath = quarantinePath + ".meta.json";
                if (File.Exists(metaPath)) { try { File.Delete(metaPath); } catch { } }

                result.BackupPath = target;
            });

            result.Success = true;
            result.Message = $"Файл восстановлен: {target}";
        }
        catch (Exception ex)
        {
            result.Success = false;
            result.Error = $"Не удалось восстановить файл: {ex.Message}";
        }
        return result;
    }

    public async Task<RemediationResult> DeleteFromQuarantineAsync(string quarantinePath)
    {
        var result = new RemediationResult();
        try
        {
            await Task.Run(() =>
            {
                if (File.Exists(quarantinePath))
                {
                    try { File.SetAttributes(quarantinePath, FileAttributes.Normal); } catch { }
                    File.Delete(quarantinePath);
                }
                var metaPath = quarantinePath + ".meta.json";
                if (File.Exists(metaPath)) File.Delete(metaPath);
            });

            result.Success = true;
            result.Message = $"Файл «{Path.GetFileName(quarantinePath)}» удалён из карантина безвозвратно.";
        }
        catch (Exception ex)
        {
            result.Success = false;
            result.Error = $"Не удалось удалить файл из карантина: {ex.Message}";
        }
        return result;
    }

    private void SaveQuarantineMeta(string quarantinePath, QuarantineMeta meta)
    {
        try
        {
            var json = JsonSerializer.Serialize(meta);
            File.WriteAllText(quarantinePath + ".meta.json", json);
        }
        catch (Exception ex)
        {
            _logger.Debug("Failed to save quarantine meta: {Message}", ex.Message);
        }
    }

    private QuarantineMeta? LoadQuarantineMeta(string quarantinePath)
    {
        try
        {
            var metaPath = quarantinePath + ".meta.json";
            if (!File.Exists(metaPath)) return null;
            var json = File.ReadAllText(metaPath);
            return JsonSerializer.Deserialize<QuarantineMeta>(json);
        }
        catch
        {
            return null;
        }
    }

    public async Task<RemediationResult> DisableScheduledTaskAsync(string taskName, string taskPath, bool promptForRestorePoint = false)
    {
        return await DisableScheduledTaskInternalAsync(taskName, taskPath, CancellationToken.None);
    }

    private async Task<RemediationResult> DisableScheduledTaskInternalAsync(string taskName, string taskPath, CancellationToken ct)
    {
        var result = new RemediationResult();
        try
        {
            await Task.Run(() =>
            {
                var schedulerType = Type.GetTypeFromProgID("Schedule.Service");
                if (schedulerType == null) throw new InvalidOperationException("Task Scheduler COM not available");

                dynamic scheduler = Activator.CreateInstance(schedulerType)
                    ?? throw new InvalidOperationException("Task Scheduler COM not available");
                scheduler.Connect();
                dynamic folder = scheduler.GetFolder(Path.GetDirectoryName(taskPath));
                dynamic task = folder.GetTask(Path.GetFileName(taskPath));
                task.Enabled = false;
            }, ct);

            result.Success = true;
            result.Message = $"Задача «{taskName}» отключена.";
        }
        catch (Exception ex)
        {
            result.Success = false;
            result.Error = $"Не удалось отключить задачу: {ex.Message}";
        }
        return result;
    }

    public async Task<RemediationResult> DeleteScheduledTaskAsync(string taskName, string taskPath, bool promptForRestorePoint = false)
    {
        return await DeleteScheduledTaskInternal(taskName, taskPath, CancellationToken.None);
    }

    private async Task<RemediationResult> DeleteScheduledTaskInternal(string taskName, string taskPath, CancellationToken ct)
    {
        var result = new RemediationResult();
        try
        {
            await Task.Run(() =>
            {
                var schedulerType = Type.GetTypeFromProgID("Schedule.Service");
                if (schedulerType == null) throw new InvalidOperationException("Task Scheduler COM not available");

                dynamic scheduler = Activator.CreateInstance(schedulerType)
                    ?? throw new InvalidOperationException("Task Scheduler COM not available");
                scheduler.Connect();
                dynamic folder = scheduler.GetFolder(Path.GetDirectoryName(taskPath));
                folder.DeleteTask(Path.GetFileName(taskPath), 0);
            }, ct);

            result.Success = true;
            result.Message = $"Задача «{taskName}» удалена.";
        }
        catch (Exception ex)
        {
            result.Success = false;
            result.Error = $"Не удалось удалить задачу: {ex.Message}";
        }
        return result;
    }

    public async Task<RemediationResult> RemoveWmiSubscriptionAsync(string subscriptionName, bool promptForRestorePoint = false)
    {
        return await RemoveWmiSubscriptionInternalAsync(subscriptionName, CancellationToken.None);
    }

    private async Task<RemediationResult> RemoveWmiSubscriptionInternalAsync(string subscriptionName, CancellationToken ct)
    {
        var result = new RemediationResult();
        try
        {
            await Task.Run(() =>
            {
                var scope = new ManagementScope(@"\\.\root\subscription");
                scope.Connect();

                using var searcher = new ManagementObjectSearcher(scope,
                    new ObjectQuery($"SELECT * FROM __FilterToConsumerBinding WHERE Filter LIKE '%{subscriptionName}%'"));
                foreach (ManagementObject binding in searcher.Get())
                {
                    binding.Delete();
                }

                using var filterSearcher = new ManagementObjectSearcher(scope,
                    new ObjectQuery($"SELECT * FROM __EventFilter WHERE Name='{subscriptionName}'"));
                foreach (ManagementObject filter in filterSearcher.Get())
                {
                    filter.Delete();
                }
            }, ct);

            result.Success = true;
            result.Message = $"WMI-подписка «{subscriptionName}» удалена.";
        }
        catch (Exception ex)
        {
            result.Success = false;
            result.Error = $"Не удалось удалить WMI-подписку: {ex.Message}";
        }
        return result;
    }

    public async Task<RemediationResult> UnloadDriverAsync(string driverName, bool promptForRestorePoint = false)
    {
        var result = new RemediationResult();
        try
        {
            await Task.Run(() =>
            {
                using var service = new ServiceController(driverName);
                if (service.Status == ServiceControllerStatus.Running)
                {
                    service.Stop();
                    service.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(30));
                }
            });

            result.Success = true;
            result.Message = $"Драйвер «{driverName}» остановлен.";
        }
        catch (Exception ex)
        {
            result.Success = false;
            result.Error = $"Не удалось остановить драйвер: {ex.Message}";
        }
        return result;
    }

    public async Task<RemediationResult> ExecuteBatchAsync(List<RemediationAction> actions, RestorePointPromptContext? promptContext = null, CancellationToken ct = default)
    {
        var result = new RemediationResult();
        var stopwatch = Stopwatch.StartNew();

        if (promptContext != null)
        {
            var promptResult = await _promptService.PromptUserAsync(promptContext);
            if (promptResult.Action == RestorePointPromptAction.Cancel)
            {
                result.Message = "Пакетное действие отменено пользователем";
                result.Success = false;
                return result;
            }
            if (promptResult.ShouldCreateRestorePoint)
            {
                result.RestorePointCreated = await _restorePointService.CreateRestorePointAsync(promptResult.Description);
            }
        }

        var successCount = 0;
        var failCount = 0;
        var errors = new List<string>();

        foreach (var action in actions)
        {
            ct.ThrowIfCancellationRequested();

            var actionResult = await ExecuteActionAsync(action, null, ct);
            if (actionResult.Success) successCount++;
            else { failCount++; errors.Add($"{action.TargetName}: {actionResult.Error}"); }
        }

        stopwatch.Stop();
        result.Success = failCount == 0;
        result.Message = $"Выполнено: {successCount}, ошибок: {failCount}";
        result.Error = string.Join("; ", errors);
        result.Duration = stopwatch.Elapsed;

        return result;
    }
}
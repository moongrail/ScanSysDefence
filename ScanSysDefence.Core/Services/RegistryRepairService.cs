using System.Diagnostics;
using System.IO;
using Microsoft.Win32;
using ScanSysDefence.Native.Win32;

namespace ScanSysDefence.Core.Services;

public class RegistryRepairService : IRegistryRepairService
{
    private readonly ILogger _logger;
    private readonly string _backupFolder;

    private static readonly string[] UninstallRoots =
    {
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        @"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
    };

    private static readonly string[] RunKeys =
    {
        @"Software\Microsoft\Windows\CurrentVersion\Run",
        @"Software\Microsoft\Windows\CurrentVersion\RunOnce",
        @"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
    };

    public RegistryRepairService(ILogger logger)
    {
        _logger = logger;
        _backupFolder = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "ScanSysDefence", "RegistryBackups");
        Directory.CreateDirectory(_backupFolder);
    }

    public async Task<RegistryScanResult> ScanAsync(IProgress<RegistryScanProgress>? progress = null, CancellationToken ct = default)
    {
        return await Task.Run(() =>
        {
            var sw = Stopwatch.StartNew();
            var result = new RegistryScanResult();
            int keysScanned = 0;

            void Report(string area, string message)
            {
                progress?.Report(new RegistryScanProgress
                {
                    CurrentArea = area,
                    KeysScanned = keysScanned,
                    IssuesFound = result.Issues.Count,
                    ProgressPercent = Math.Min(95, result.Issues.Count + keysScanned / 100),
                    StatusMessage = message
                });
            }

            try
            {
                Report("Uninstall", "Проверка записей установщика...");
                ScanUninstallEntries(Registry.LocalMachine, result, ref keysScanned, ct);
                ScanUninstallEntries(Registry.CurrentUser, result, ref keysScanned, ct);

                Report("SharedDLLs", "Проверка SharedDLLs...");
                ScanSharedDlls(Registry.LocalMachine, result, ref keysScanned, ct);

                Report("Startup", "Проверка автозагрузки...");
                ScanRunKeys(Registry.CurrentUser, result, ref keysScanned, ct);
                ScanRunKeys(Registry.LocalMachine, result, ref keysScanned, ct);

                Report("COM", "Проверка COM-регистраций (CLSID)...");
                ScanComRegistration(Registry.ClassesRoot, string.Empty, "HKCR", result, ref keysScanned, ct);
                ScanComRegistration(Registry.CurrentUser, @"Software\Classes", "HKCU", result, ref keysScanned, ct);

                Report("Associations", "Проверка файловых ассоциаций...");
                ScanFileAssociations(Registry.CurrentUser, @"Software\Classes", "HKCU", result, ref keysScanned, ct);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Registry scan failed");
            }

            sw.Stop();
            result.Duration = sw.Elapsed;
            result.TotalKeysScanned = keysScanned;
            result.Issues = result.Issues
                .GroupBy(i => (i.Hive, i.KeyPath, i.ValueName))
                .Select(g => g.First())
                .ToList();

            _logger.Information("Registry scan finished: {Issues} issues, {Keys} keys in {Duration}",
                result.Issues.Count, keysScanned, sw.Elapsed);
            return result;
        }, ct);
    }

    private void ScanUninstallEntries(RegistryKey root, RegistryScanResult result, ref int keysScanned, CancellationToken ct)
    {
        foreach (var subRoot in UninstallRoots)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                using var key = root.OpenSubKey(subRoot);
                if (key == null) continue;

                foreach (var name in key.GetSubKeyNames())
                {
                    ct.ThrowIfCancellationRequested();
                    keysScanned++;
                    try
                    {
                        using var sub = key.OpenSubKey(name);
                        if (sub == null) continue;

                        var displayName = sub.GetValue("DisplayName") as string ?? name;
                        var icon = sub.GetValue("DisplayIcon") as string;
                        var uninstall = sub.GetValue("UninstallString") as string;
                        var installLoc = sub.GetValue("InstallLocation") as string;

                        string? path = ExtractFilePath(icon)
                                       ?? ExtractFilePath(uninstall)
                                       ?? NormalizeDir(installLoc);

                        if (path == null) continue;
                        if (path.Contains("MsiExec", StringComparison.OrdinalIgnoreCase)) continue;
                        if (!Path.IsPathRooted(path)) continue;
                        if (File.Exists(path) || Directory.Exists(path)) continue;

                        result.Issues.Add(new RegistryIssue
                        {
                            Type = RegistryIssueType.OrphanedUninstallEntry,
                            Hive = root.Name.StartsWith("HKEY_CURRENT_USER") ? "HKCU" : "HKLM",
                            KeyPath = $@"{subRoot}\{name}",
                            Target = path,
                            Description = $"Orphaned uninstall entry '{displayName}' points to missing file",
                            DescriptionRu = $"Остаток установщика «{displayName}»: файл {path} отсутствует",
                            RecommendationRu = "Запись не удалена программой-удалителём. Запись можно безопасно удалить.",
                            RiskLevel = Models.RiskLevel.Low,
                            RequiresKeyDeletion = true
                        });
                    }
                    catch (OperationCanceledException) { throw; }
                    catch { /* skip unreadable */ }
                }
            }
            catch (OperationCanceledException) { throw; }
            catch { /* skip unreadable root */ }
        }
    }

    private void ScanSharedDlls(RegistryKey root, RegistryScanResult result, ref int keysScanned, CancellationToken ct)
    {
        var paths = new[] { @"SOFTWARE\Microsoft\Windows\CurrentVersion\SharedDLLs" };
        foreach (var path in paths)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                using var key = root.OpenSubKey(path);
                if (key == null) continue;
                keysScanned++;

                foreach (var valueName in key.GetValueNames())
                {
                    ct.ThrowIfCancellationRequested();
                    if (!Path.IsPathRooted(valueName)) continue;
                    if (File.Exists(valueName)) continue;

                    result.Issues.Add(new RegistryIssue
                    {
                        Type = RegistryIssueType.BrokenSharedDll,
                        Hive = root.Name.StartsWith("HKEY_CURRENT_USER") ? "HKCU" : "HKLM",
                        KeyPath = path,
                        ValueName = valueName,
                        Target = valueName,
                        Description = "SharedDLL counter references a missing file",
                        DescriptionRu = $"Счётчик SharedDLL указывает на отсутствующий файл: {valueName}",
                        RecommendationRu = "Файл удалён, но счётчик остался. Запись значения можно удалить.",
                        RiskLevel = Models.RiskLevel.Informational
                    });
                }
            }
            catch (OperationCanceledException) { throw; }
            catch { /* skip */ }
        }
    }

    private void ScanRunKeys(RegistryKey root, RegistryScanResult result, ref int keysScanned, CancellationToken ct)
    {
        foreach (var runKey in RunKeys)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                using var key = root.OpenSubKey(runKey);
                if (key == null) continue;
                keysScanned++;

                foreach (var valueName in key.GetValueNames())
                {
                    ct.ThrowIfCancellationRequested();
                    var command = key.GetValue(valueName) as string;
                    if (string.IsNullOrWhiteSpace(command)) continue;

                    var filePath = ExtractFilePath(command);
                    if (filePath == null) continue;
                    if (!Path.IsPathRooted(filePath)) continue;
                    if (File.Exists(filePath)) continue;

                    var isUser = root.Name.StartsWith("HKEY_CURRENT_USER");
                    result.Issues.Add(new RegistryIssue
                    {
                        Type = RegistryIssueType.InvalidStartupEntry,
                        Hive = isUser ? "HKCU" : "HKLM",
                        KeyPath = runKey,
                        ValueName = valueName,
                        Target = filePath,
                        Description = $"Startup entry '{valueName}' points to missing file",
                        DescriptionRu = $"Автозагрузка «{valueName}» указывает на несуществующий файл: {filePath}",
                        RecommendationRu = "Программа удалена, запись автозапуска осталась. Запись можно удалить.",
                        RiskLevel = Models.RiskLevel.Medium
                    });
                }
            }
            catch (OperationCanceledException) { throw; }
            catch { /* skip */ }
        }
    }

    private void ScanComRegistration(RegistryKey root, string relativePath, string hiveLabel, RegistryScanResult result, ref int keysScanned, CancellationToken ct)
    {
        try
        {
            using var clsid = string.IsNullOrEmpty(relativePath)
                ? root.OpenSubKey("CLSID")
                : root.OpenSubKey(relativePath + @"\CLSID");
            if (clsid == null) return;

            foreach (var clsidName in clsid.GetSubKeyNames())
            {
                ct.ThrowIfCancellationRequested();
                keysScanned++;
                if (result.Issues.Count > 500) return;

                try
                {
                    using var sub = clsid.OpenSubKey(clsidName);
                    using var server = sub?.OpenSubKey("InprocServer32") ?? sub?.OpenSubKey("LocalServer32");
                    var serverPath = server?.GetValue(null) as string;
                    if (string.IsNullOrWhiteSpace(serverPath)) continue;

                    var filePath = ExtractFilePath(serverPath);
                    if (filePath == null || !Path.IsPathRooted(filePath)) continue;
                    if (File.Exists(filePath)) continue;

                    var friendly = sub?.GetValue(null) as string ?? clsidName;
                    result.Issues.Add(new RegistryIssue
                    {
                        Type = RegistryIssueType.BrokenComRegistration,
                        Hive = hiveLabel,
                        KeyPath = string.IsNullOrEmpty(relativePath) ? $@"CLSID\{clsidName}" : $@"{relativePath}\CLSID\{clsidName}",
                        Target = filePath,
                        Description = $"COM class '{friendly}' references missing server {filePath}",
                        DescriptionRu = $"COM-класс «{friendly}» ссылается на отсутствующую библиотеку: {filePath}",
                        RecommendationRu = "Класс не зарегистрирован в системе. Удаление безопасно, если программа не используется.",
                        RiskLevel = Models.RiskLevel.Medium,
                        RequiresKeyDeletion = true,
                        IsSelected = false
                    });
                }
                catch (OperationCanceledException) { throw; }
                catch { /* skip */ }
            }
        }
        catch (OperationCanceledException) { throw; }
        catch { /* skip */ }
    }

    private void ScanFileAssociations(RegistryKey root, string relativePath, string hiveLabel, RegistryScanResult result, ref int keysScanned, CancellationToken ct)
    {
        try
        {
            using var classes = root.OpenSubKey(relativePath);
            if (classes == null) return;

            foreach (var ext in classes.GetSubKeyNames())
            {
                ct.ThrowIfCancellationRequested();
                keysScanned++;
                if (result.Issues.Count > 600) return;
                if (!ext.StartsWith(".")) continue;
                if (ext.Length < 2) continue;

                try
                {
                    using var extKey = classes.OpenSubKey(ext);
                    var progId = extKey?.GetValue(null) as string;
                    if (string.IsNullOrWhiteSpace(progId)) continue;

                    using var handler = classes.OpenSubKey($@"{progId}\shell\open\command");
                    if (handler != null) continue;

                    result.Issues.Add(new RegistryIssue
                    {
                        Type = RegistryIssueType.BrokenFileAssociation,
                        Hive = hiveLabel,
                        KeyPath = $@"{relativePath}\{ext}",
                        Target = progId,
                        Description = $"Extension '{ext}' references missing handler '{progId}'",
                        DescriptionRu = $"Расширение {ext} привязано к несуществующему обработчику «{progId}»",
                        RecommendationRu = "Ассоциация битая. Исправление сбросит привязку — Windows снова предложит выбрать программу для открытия таких файлов.",
                        RiskLevel = Models.RiskLevel.Low,
                        CanRepair = true,
                        DeleteDefaultValue = true,
                        IsSelected = false
                    });
                }
                catch (OperationCanceledException) { throw; }
                catch { /* skip */ }
            }
        }
        catch (OperationCanceledException) { throw; }
        catch { /* skip */ }
    }

    public async Task<RegistryRepairResult> RepairAsync(List<RegistryIssue> issues, bool createBackup, IProgress<RegistryRepairProgress>? progress = null, CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();
        var result = new RegistryRepairResult();

        var repairable = issues.Where(i => i.CanRepair && i.IsSelected).ToList();
        if (repairable.Count == 0)
        {
            return new RegistryRepairResult { Success = true, Message = "Нет выбранных проблем для исправления" };
        }

        if (createBackup)
        {
            var backup = await CreateBackupAsync(repairable, ct);
            result.BackupCreated = backup != null;
            result.BackupPath = backup ?? string.Empty;
            if (backup == null)
            {
                _logger.Warning("Registry backup failed, aborting repair");
                return new RegistryRepairResult
                {
                    Success = false,
                    Message = "Не удалось создать резервную копию — исправление отменено",
                    Duration = sw.Elapsed
                };
            }
        }

        int done = 0;
        foreach (var issue in repairable)
        {
            ct.ThrowIfCancellationRequested();
            done++;
            progress?.Report(new RegistryRepairProgress
            {
                CurrentIndex = done,
                Total = repairable.Count,
                CurrentTarget = string.IsNullOrEmpty(issue.ValueName) ? issue.KeyPath : $"{issue.KeyPath}\\{issue.ValueName}",
                ProgressPercent = done * 100 / repairable.Count,
                StatusMessage = $"Исправление: {issue.DescriptionRu}"
            });

            try
            {
                ApplyFix(issue);
                result.Repaired++;
            }
            catch (OperationCanceledException) { throw; }
            catch (UnauthorizedAccessException)
            {
                result.Failed++;
                result.Errors.Add($"{issue.KeyPath}: доступ запрещён — нужны права администратора");
                _logger.Warning("Access denied repairing {Key}", issue.KeyPath);
            }
            catch (System.Security.SecurityException)
            {
                result.Failed++;
                result.Errors.Add($"{issue.KeyPath}: доступ запрещён системой — нужны права администратора");
                _logger.Warning("Security exception repairing {Key}", issue.KeyPath);
            }
            catch (Exception ex)
            {
                result.Failed++;
                result.Errors.Add($"{issue.KeyPath}: {ex.Message}");
                _logger.Warning("Failed to repair {Key}: {Error}", issue.KeyPath, ex.Message);
            }
        }

        sw.Stop();
        result.Duration = sw.Elapsed;
        result.Success = result.Failed == 0;
        result.Message = $"Исправлено {result.Repaired}, ошибок {result.Failed}" +
                         (result.BackupCreated ? $". Резервная копия: {Path.GetFileName(result.BackupPath)}" : string.Empty);
        if (result.Errors.Count > 0)
        {
            result.Message += " Причины: " + string.Join("; ", result.Errors.Take(3));
        }

        _logger.Information("Registry repair finished: {Repaired} repaired, {Failed} failed", result.Repaired, result.Failed);
        return result;
    }

    private void ApplyFix(RegistryIssue issue)
    {
        try
        {
            ApplyFixCore(issue);
            return;
        }
        catch (UnauthorizedAccessException)
        {
            // Ключ защищён (владелец — TrustedInstaller): берём владение, как это делает regedit
        }
        catch (System.Security.SecurityException)
        {
        }

        _logger.Information("Repair hit protected key, taking ownership: {Hive}\\{Path}", issue.Hive, issue.KeyPath);
        TryTakeOwnershipRecursive(issue.Hive, issue.KeyPath);
        ApplyFixCore(issue);
    }

    private void ApplyFixCore(RegistryIssue issue)
    {
        var hive = OpenHive(issue.Hive);
        using var key = hive.OpenSubKey(issue.KeyPath, writable: true);
        if (key == null)
            throw new InvalidOperationException($"Ключ не найден: {issue.KeyPath}");

        if (issue.RequiresKeyDeletion)
        {
            var parentPath = ParentPath(issue.KeyPath);
            var leaf = LeafName(issue.KeyPath);
            using var parent = hive.OpenSubKey(parentPath, writable: true);
            if (parent == null)
                throw new InvalidOperationException($"Родительский ключ не найден: {parentPath}");

            TryTakeOwnershipRecursive(issue.Hive, issue.KeyPath);
            parent.DeleteSubKeyTree(leaf, throwOnMissingSubKey: false);
        }
        else if (!string.IsNullOrEmpty(issue.ValueName))
        {
            key.DeleteValue(issue.ValueName, throwOnMissingValue: false);
        }
        else if (issue.DeleteDefaultValue)
        {
            // Сброс битой ассоциации: удаляем значение «по умолчанию» у ключа расширения
            key.DeleteValue(string.Empty, throwOnMissingValue: false);
        }
        else
        {
            throw new InvalidOperationException("Не определено, что именно исправлять");
        }
    }

    /// <summary>Делает администратора владельцем ключа и всех вложенных ключей (для защищённых CLSID).</summary>
    private void TryTakeOwnershipRecursive(string hive, string keyPath)
    {
        var paths = new List<string> { keyPath };
        try
        {
            CollectSubKeyPaths(OpenHive(hive), keyPath, paths, 0);
        }
        catch (Exception ex)
        {
            _logger.Debug("Subkey enumeration failed for {Path}: {Message}", keyPath, ex.Message);
        }

        foreach (var path in paths)
        {
            if (RegistryNative.TryTakeOwnership(hive, path, out var error))
            {
                _logger.Information("Ownership taken: {Hive}\\{Path}", hive, path);
            }
            else
            {
                _logger.Warning("Failed to take ownership {Hive}\\{Path}: {Error}", hive, path, error);
            }
        }
    }

    private static void CollectSubKeyPaths(RegistryKey hive, string path, List<string> paths, int depth)
    {
        if (depth >= 6) return;
        try
        {
            using var key = hive.OpenSubKey(path);
            if (key == null) return;

            foreach (var name in key.GetSubKeyNames())
            {
                var childPath = $@"{path}\{name}";
                paths.Add(childPath);
                CollectSubKeyPaths(hive, childPath, paths, depth + 1);
            }
        }
        catch
        {
            // Нет доступа к поддереву — остальные ключи всё равно обработаем
        }
    }

    private async Task<string?> CreateBackupAsync(List<RegistryIssue> issues, CancellationToken ct)
    {
        try
        {
            var fileName = $"registry_backup_{DateTime.Now:yyyyMMdd_HHmmss}.reg";
            var filePath = Path.Combine(_backupFolder, fileName);

            var exportKeys = issues
                .Select(i => new { i.Hive, Path = BackupKeyPath(i) })
                .Distinct()
                .OrderBy(x => x.Path.Length)
                .ToList();

            var sections = new List<string>();
            foreach (var exportKey in exportKeys)
            {
                ct.ThrowIfCancellationRequested();
                var regPath = ToRegPath(exportKey.Hive, exportKey.Path);
                var tempFile = Path.Combine(Path.GetTempPath(), $"wss_export_{Guid.NewGuid():N}.reg");

                var psi = new ProcessStartInfo
                {
                    FileName = "reg.exe",
                    Arguments = $"export \"{regPath}\" \"{tempFile}\" /y",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };

                using var proc = Process.Start(psi);
                if (proc == null) continue;
                await proc.WaitForExitAsync(ct);

                if (proc.ExitCode == 0 && File.Exists(tempFile))
                {
                    var content = File.ReadAllText(tempFile);
                    var lines = content.Replace("\r\n", "\n").Split('\n');
                    // strip "Windows Registry Editor Version 5.00" header from subsequent sections
                    var startIndex = 0;
                    if (sections.Count > 0)
                    {
                        startIndex = lines.Length > 0 && lines[0].Contains("Registry Editor") ? 1 : 0;
                        while (startIndex < lines.Length && string.IsNullOrWhiteSpace(lines[startIndex])) startIndex++;
                    }
                    sections.Add(string.Join(Environment.NewLine, lines.Skip(startIndex)));
                    File.Delete(tempFile);
                }
                else
                {
                    _logger.Warning("reg export failed for {Key}", regPath);
                }
            }

            if (sections.Count == 0) return null;

            const string header = "Windows Registry Editor Version 5.00";
            var all = header + Environment.NewLine + Environment.NewLine +
                      string.Join(Environment.NewLine + Environment.NewLine, sections);

            await File.WriteAllTextAsync(filePath, all, System.Text.Encoding.Unicode, ct);
            _logger.Information("Registry backup created: {Path}", filePath);
            return filePath;
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            _logger.Error(ex, "Failed to create registry backup");
            return null;
        }
    }

    public async Task<RegistryRepairResult> RestoreBackupAsync(string backupFilePath)
    {
        var sw = Stopwatch.StartNew();
        if (!File.Exists(backupFilePath))
        {
            return new RegistryRepairResult { Success = false, Message = $"Файл не найден: {backupFilePath}" };
        }

        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "reg.exe",
                Arguments = $"import \"{backupFilePath}\"",
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };

            using var proc = Process.Start(psi);
            if (proc == null)
                return new RegistryRepairResult { Success = false, Message = "Не удалось запустить reg.exe" };

            var stderr = await proc.StandardError.ReadToEndAsync();
            await proc.WaitForExitAsync();
            sw.Stop();

            var success = proc.ExitCode == 0;
            _logger.Information("Registry import from {File}: exit {Code}", backupFilePath, proc.ExitCode);

            return new RegistryRepairResult
            {
                Success = success,
                Repaired = success ? 1 : 0,
                BackupPath = backupFilePath,
                Duration = sw.Elapsed,
                Message = success ? "Резервная копия восстановлена" : $"Ошибка импорта: {stderr}"
            };
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Registry import failed");
            return new RegistryRepairResult { Success = false, Message = ex.Message, Duration = sw.Elapsed };
        }
    }

    public Task<List<RegistryBackup>> GetBackupsAsync()
    {
        var backups = new List<RegistryBackup>();
        try
        {
            if (Directory.Exists(_backupFolder))
            {
                foreach (var file in Directory.GetFiles(_backupFolder, "*.reg").OrderByDescending(f => f))
                {
                    var info = new FileInfo(file);
                    backups.Add(new RegistryBackup
                    {
                        FilePath = file,
                        CreatedAt = info.CreationTime,
                        FileSize = info.Length,
                        Description = info.Name
                    });
                }
            }
        }
        catch (Exception ex)
        {
            _logger.Warning("Failed to enumerate registry backups: {Error}", ex.Message);
        }
        return Task.FromResult(backups);
    }

    private static RegistryKey OpenHive(string hive) => hive switch
    {
        "HKCU" => Registry.CurrentUser,
        "HKCR" => Registry.ClassesRoot,
        _ => Registry.LocalMachine
    };

    private static string BackupKeyPath(RegistryIssue issue)
    {
        // For value-level fixes export the parent key; for key deletions export the key itself
        return issue.RequiresKeyDeletion || string.IsNullOrEmpty(issue.ValueName)
            ? issue.KeyPath
            : ParentPath(issue.KeyPath);
    }

    private static string ToRegPath(string hive, string keyPath)
    {
        var root = hive switch
        {
            "HKCU" => "HKCU",
            "HKCR" => "HKCR",
            _ => "HKLM"
        };
        return keyPath.Contains('\\') ? $@"{root}\{keyPath}" : root;
    }

    private static string ParentPath(string keyPath)
    {
        var idx = keyPath.LastIndexOf('\\');
        return idx > 0 ? keyPath.Substring(0, idx) : keyPath;
    }

    private static string LeafName(string keyPath)
    {
        var idx = keyPath.LastIndexOf('\\');
        return idx > 0 ? keyPath.Substring(idx + 1) : keyPath;
    }

    private static string? ExtractFilePath(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return null;
        var value = raw.Trim();

        if (value.StartsWith("\""))
        {
            var end = value.IndexOf('"', 1);
            return end > 1 ? value.Substring(1, end - 1) : null;
        }

        // strip trailing ,0 icon index and arguments
        var comma = value.IndexOf(',');
        if (comma > 0 && !value.Substring(0, comma).EndsWith("\\"))
        {
            var candidate = value.Substring(0, comma).Trim();
            if (candidate.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ||
                candidate.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) ||
                candidate.EndsWith(".ocx", StringComparison.OrdinalIgnoreCase) ||
                candidate.EndsWith(".sys", StringComparison.OrdinalIgnoreCase))
                return candidate;
        }

        var space = value.IndexOf(' ');
        if (space > 0 && File.Exists(value.Substring(0, space)))
            return value.Substring(0, space);

        return File.Exists(value) ? value : (Path.IsPathRooted(value) && !value.Contains(' ') ? value : null);
    }

    private static string? NormalizeDir(string? dir)
    {
        if (string.IsNullOrWhiteSpace(dir)) return null;
        dir = dir.Trim().Trim('"');
        if (!Path.IsPathRooted(dir)) return null;
        if (!Directory.Exists(dir)) return dir;
        try
        {
            var exe = Directory.GetFiles(dir, "*.exe").FirstOrDefault();
            return exe ?? dir;
        }
        catch
        {
            return dir;
        }
    }
}

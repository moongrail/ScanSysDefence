using System.IO;
using System.Management;
using ScanSysDefence.Core.Models;
using ScanSysDefence.Core.Services;

namespace ScanSysDefence.Core.Services;

public class DiskCleanupService : IDiskCleanupService
{
    private readonly ILogger _logger;
    private readonly ISafetyService _safetyService;

    public DiskCleanupService(ILogger logger, ISafetyService safetyService)
    {
        _logger = logger;
        _safetyService = safetyService;
    }

    public async Task<List<DriveInfo>> GetDrivesAsync()
    {
        return await Task.Run(() =>
        {
            var drives = new List<DriveInfo>();
            foreach (var drive in System.IO.DriveInfo.GetDrives())
            {
                if (!drive.IsReady) continue;
                
                drives.Add(new DriveInfo
                {
                    Letter = drive.Name.TrimEnd('\\'),
                    Label = drive.VolumeLabel,
                    FileSystem = drive.DriveFormat,
                    TotalSize = drive.TotalSize,
                    FreeSpace = drive.AvailableFreeSpace,
                    DriveType = drive.DriveType,
                    IsSystemDrive = drive.Name.StartsWith(Environment.GetEnvironmentVariable("SystemDrive") ?? "C:", StringComparison.OrdinalIgnoreCase),
                    IsReady = drive.IsReady
                });
            }
            return drives;
        });
    }

    public async Task<List<CleanupCategory>> GetCategoriesAsync()
    {
        return await Task.Run(() => new List<CleanupCategory>
        {
            new CleanupCategory
            {
                Id = "SystemTemp",
                Name = "System Temporary Files",
                Description = "Windows system temporary files",
                DescriptionRu = "Системные временные файлы Windows",
                IsSelectedByDefault = true,
                RequiresAdmin = true,
                RiskLevel = RiskLevel.Low,
                Paths = new() { @"C:\Windows\Temp", @"C:\Windows\Prefetch" }
            },
            new CleanupCategory
            {
                Id = "UserTemp",
                Name = "User Temporary Files",
                Description = "Current user temporary files",
                DescriptionRu = "Временные файлы текущего пользователя",
                IsSelectedByDefault = true,
                RequiresAdmin = false,
                RiskLevel = RiskLevel.Low,
                Paths = new() { Environment.GetEnvironmentVariable("TEMP") ?? @"C:\Temp" }
            },
            new CleanupCategory
            {
                Id = "WindowsUpdate",
                Name = "Windows Update Cleanup",
                Description = "Old Windows update files and delivery optimization",
                DescriptionRu = "Очистка старых файлов обновлений Windows",
                IsSelectedByDefault = true,
                RequiresAdmin = true,
                RiskLevel = RiskLevel.Low,
                Paths = new() { @"C:\Windows\SoftwareDistribution\Download", @"C:\Windows\SoftwareDistribution\DeliveryOptimization" }
            },
            new CleanupCategory
            {
                Id = "Thumbnails",
                Name = "Thumbnail Cache",
                Description = "Image and video thumbnail cache files",
                DescriptionRu = "Кэш эскизов изображений и видео",
                IsSelectedByDefault = true,
                RequiresAdmin = false,
                RiskLevel = RiskLevel.Low,
                Paths = new() { Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"Microsoft\Windows\Explorer") }
            },
            new CleanupCategory
            {
                Id = "RecycleBin",
                Name = "Recycle Bin",
                Description = "Files in recycle bin for all users",
                DescriptionRu = "Корзина (файлы всех пользователей)",
                IsSelectedByDefault = false, // User should explicitly choose
                RequiresAdmin = false,
                RiskLevel = RiskLevel.Medium,
                Paths = new() { @"C:\$Recycle.Bin" }
            },
            new CleanupCategory
            {
                Id = "MemoryDumps",
                Name = "Memory Dump Files",
                Description = "System crash dump files",
                DescriptionRu = "Файлы дампов памяти при сбоях системы",
                IsSelectedByDefault = true,
                RequiresAdmin = true,
                RiskLevel = RiskLevel.Low,
                Paths = new() { @"C:\Windows\MEMORY.DMP", @"C:\Windows\Minidump" }
            },
            new CleanupCategory
            {
                Id = "DeliveryOptimization",
                Name = "Delivery Optimization Files",
                Description = "Files used for peer-to-peer Windows updates",
                DescriptionRu = "Файлы оптимизации доставки обновлений",
                IsSelectedByDefault = true,
                RequiresAdmin = true,
                RiskLevel = RiskLevel.Low,
                Paths = new() { @"C:\Windows\SoftwareDistribution\DeliveryOptimization" }
            },
            new CleanupCategory
            {
                Id = "DriverStore",
                Name = "Old Driver Packages",
                Description = "Old versions of driver packages (use with caution)",
                DescriptionRu = "Старые версии пакетов драйверов (с осторожностью)",
                IsSelectedByDefault = false,
                RequiresAdmin = true,
                RiskLevel = RiskLevel.High,
                Paths = new() { @"C:\Windows\System32\DriverStore\FileRepository" }
            },
            new CleanupCategory
            {
                Id = "BrowserCache",
                Name = "Browser Cache (Safe)",
                Description = "Browser cache files only - cookies, sessions, logins preserved",
                DescriptionRu = "Кэш браузеров (только кэш - куки, сессии, логины сохраняются)",
                IsSelectedByDefault = true,
                RequiresAdmin = false,
                RiskLevel = RiskLevel.Low,
                Paths = new() 
                { 
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"Google\Chrome\User Data\Default\Cache"),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"Microsoft\Edge\User Data\Default\Cache"),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"Mozilla\Firefox\Profiles")
                }
            },
            new CleanupCategory
            {
                Id = "AppCaches",
                Name = "Application Caches",
                Description = "Known safe application cache directories",
                DescriptionRu = "Кэши известных приложений",
                IsSelectedByDefault = true,
                RequiresAdmin = false,
                RiskLevel = RiskLevel.Low,
                Paths = new() 
                { 
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), @"Code\Cache"),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), @"discord\Cache"),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"Spotify\Storage"),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"Slack\Cache")
                }
            },
            new CleanupCategory
            {
                Id = "DefenderCache",
                Name = "Windows Defender Cache",
                Description = "Windows Defender scan cache and temporary files",
                DescriptionRu = "Кэш сканирований Windows Defender",
                IsSelectedByDefault = true,
                RequiresAdmin = true,
                RiskLevel = RiskLevel.Low,
                Paths = new() { @"C:\ProgramData\Microsoft\Windows Defender\Scans\History\CacheManager" }
            },
            new CleanupCategory
            {
                Id = "OldChkdsk",
                Name = "Old Chkdsk Files",
                Description = "Recovered file fragments from disk checks",
                DescriptionRu = "Файлы восстановленные chkdsk (FOUND.000 и т.д.)",
                IsSelectedByDefault = true,
                RequiresAdmin = true,
                RiskLevel = RiskLevel.Low,
                Paths = new() { @"C:\FOUND.000", @"C:\FOUND.001", @"C:\FOUND.002" }
            },
            new CleanupCategory
            {
                Id = "Logs",
                Name = "System Logs (Archived)",
                Description = "Archived Windows event logs and system logs",
                DescriptionRu = "Архивированные системные журналы Windows",
                IsSelectedByDefault = false,
                RequiresAdmin = true,
                RiskLevel = RiskLevel.Medium,
                Paths = new() { @"C:\Windows\Logs", @"C:\Windows\System32\winevt\Logs" }
            }
        });
    }

    public async Task<DiskCleanupScanResult> ScanAsync(string driveLetter, CleanupScanSettings settings, IProgress<CleanupScanProgress>? progress = null, CancellationToken cancellationToken = default)
    {
        var result = new DiskCleanupScanResult
        {
            DriveLetter = driveLetter,
            ScanTime = DateTime.Now
        };
        var stopwatch = System.Diagnostics.Stopwatch.StartNew();

        var categories = await GetCategoriesAsync();
        var allItems = new List<CleanupItem>();

        for (int i = 0; i < categories.Count; i++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            
            var category = categories[i];
            
            // Check if category is enabled in settings
            if (!IsCategoryEnabled(category.Id, settings)) continue;

            progress?.Report(new CleanupScanProgress
            {
                CurrentCategory = category.Name,
                ProgressPercent = (int)((double)i / categories.Count * 100),
                StatusMessage = $"Scanning {category.Name}..."
            });

            var items = await ScanCategoryAsync(driveLetter, category, settings, progress, cancellationToken);
            allItems.AddRange(items);
        }

        result.Items = allItems;
        result.TotalFiles = allItems.Count;
        result.TotalSize = allItems.Sum(i => i.Size);
        result.ScanDuration = stopwatch.Elapsed;

        // Build category summaries
        result.CategorySummaries = allItems
            .Where(i => i.CanDelete)
            .GroupBy(i => i.CategoryId)
            .Select(g => new CleanupCategorySummary
            {
                CategoryId = g.Key,
                CategoryName = categories.First(c => c.Id == g.Key).Name,
                TotalSize = g.Sum(i => i.Size),
                FileCount = g.Count(),
                SelectedSize = g.Where(i => i.IsSelected).Sum(i => i.Size),
                SelectedFiles = g.Count(i => i.IsSelected)
            })
            .ToList();

        stopwatch.Stop();
        _logger.Information("Disk cleanup scan completed: {Count} files, {Size} bytes", result.TotalFiles, result.TotalSize);

        return result;
    }

    private bool IsCategoryEnabled(string categoryId, CleanupScanSettings settings)
    {
        return categoryId switch
        {
            "SystemTemp" => settings.IncludeSystemTemp,
            "UserTemp" => settings.IncludeUserTemp,
            "WindowsUpdate" => settings.IncludeWindowsUpdate,
            "Thumbnails" => settings.IncludeThumbnails,
            "RecycleBin" => settings.IncludeRecycleBin,
            "MemoryDumps" => settings.IncludeMemoryDumps,
            "DeliveryOptimization" => settings.IncludeDeliveryOptimization,
            "DriverStore" => settings.IncludeDriverStore,
            "BrowserCache" => settings.IncludeBrowserCache,
            "AppCaches" => settings.IncludeAppCaches,
            "DefenderCache" => settings.IncludeDefenderCache,
            "OldChkdsk" => settings.IncludeOldChkdsk,
            "Logs" => settings.IncludeLogs,
            _ => true
        };
    }

    private async Task<List<CleanupItem>> ScanCategoryAsync(string driveLetter, CleanupCategory category, CleanupScanSettings settings, IProgress<CleanupScanProgress>? progress, CancellationToken cancellationToken)
    {
        var items = new List<CleanupItem>();
        var cutoffDate = DateTime.Now.AddDays(-settings.MinFileAgeDays);

        foreach (var path in category.Paths)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var fullPath = path;
            if (!Path.IsPathRooted(fullPath))
            {
                fullPath = Path.Combine(driveLetter, fullPath.TrimStart('\\'));
            }

            if (!Directory.Exists(fullPath))
            {
                // Try common variations
                var variations = GetPathVariations(fullPath, driveLetter);
                foreach (var variation in variations)
                {
                    if (Directory.Exists(variation))
                    {
                        fullPath = variation;
                        break;
                    }
                }
            }

            if (!Directory.Exists(fullPath)) continue;

            try
            {
                var files = await GetFilesAsync(fullPath, settings, cancellationToken);
                
                foreach (var file in files)
                {
                    cancellationToken.ThrowIfCancellationRequested();

                    var fileInfo = new FileInfo(file);
                    
                    // Check age
                    if (fileInfo.LastWriteTime > cutoffDate) continue;
                    
                    // Check size limit
                    if (settings.MaxFileSize > 0 && fileInfo.Length > settings.MaxFileSize) continue;

                    // Check exclusions
                    if (settings.ExcludedPaths.Any(e => file.StartsWith(e, StringComparison.OrdinalIgnoreCase))) continue;

                    // Check if in use
                    var isInUse = false;
                    if (settings.SkipFilesInUse)
                    {
                        isInUse = IsFileLocked(file);
                    }

                    // Check if system file
                    var isSystem = (fileInfo.Attributes & FileAttributes.System) != 0 ||
                                   (fileInfo.Attributes & FileAttributes.Hidden) != 0;

                    var item = new CleanupItem
                    {
                        CategoryId = category.Id,
                        CategoryName = category.Name,
                        FilePath = file,
                        FileName = fileInfo.Name,
                        Size = fileInfo.Length,
                        LastAccessTime = fileInfo.LastAccessTime,
                        LastWriteTime = fileInfo.LastWriteTime,
                        CreationTime = fileInfo.CreationTime,
                        Attributes = fileInfo.Attributes,
                        IsSelected = true,
                        CanDelete = !isInUse && !isSystem,
                        CannotDeleteReason = isInUse ? "File is in use" : (isSystem ? "System file" : ""),
                        IsInUse = isInUse,
                        IsSystemFile = isSystem,
                        DescriptionRu = GenerateDescriptionRu(category, fileInfo),
                        RiskLevel = category.RiskLevel
                    };

                    items.Add(item);
                }
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Error scanning category {Category} at {Path}", category.Id, fullPath);
            }
        }

        return items;
    }

    private List<string> GetPathVariations(string path, string driveLetter)
    {
        var variations = new List<string>();
        var fileName = Path.GetFileName(path);
        
        // Check all drive letters
        foreach (var drive in System.IO.DriveInfo.GetDrives().Where(d => d.IsReady))
        {
            variations.Add(Path.Combine(drive.Name, fileName));
            variations.Add(Path.Combine(drive.Name, path.TrimStart('\\')));
        }

        // Environment variable expansion
        variations.Add(Environment.ExpandEnvironmentVariables(path));
        
        return variations;
    }

    private async Task<List<string>> GetFilesAsync(string path, CleanupScanSettings settings, CancellationToken cancellationToken)
    {
        return await Task.Run(() =>
        {
            var files = new List<string>();
            try
            {
                var searchOption = settings.IncludeSubdirectories ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly;
                files.AddRange(Directory.GetFiles(path, "*", searchOption));
            }
            catch (UnauthorizedAccessException)
            {
                // Skip inaccessible directories
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Error getting files from {Path}", path);
            }
            return files;
        }, cancellationToken);
    }

    private bool IsFileLocked(string filePath)
    {
        try
        {
            using var stream = File.Open(filePath, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
            return false;
        }
        catch (IOException)
        {
            return true;
        }
        catch
        {
            return true; // Assume locked if we can't check
        }
    }

    private string GenerateDescriptionRu(CleanupCategory category, FileInfo fileInfo)
    {
        var ageDays = (DateTime.Now - fileInfo.LastWriteTime).TotalDays;
        return $"{category.DescriptionRu}: {fileInfo.Name} ({FormatSize(fileInfo.Length)}, {ageDays:F0} дней назад)";
    }

    private string FormatSize(long bytes)
    {
        string[] suffixes = { "Б", "КБ", "МБ", "ГБ", "ТБ" };
        int i = 0;
        double size = bytes;
        while (size >= 1024 && i < suffixes.Length - 1)
        {
            size /= 1024;
            i++;
        }
        return $"{size:F1} {suffixes[i]}";
    }

    public async Task<CleanupResult> CleanAsync(List<CleanupItem> itemsToClean, bool createRestorePoint, IProgress<CleanupProgress>? progress = null, CancellationToken cancellationToken = default)
    {
        var result = new CleanupResult();
        var stopwatch = System.Diagnostics.Stopwatch.StartNew();
        var items = itemsToClean.Where(i => i.IsSelected && i.CanDelete).ToList();
        var total = items.Count;
        var processed = 0;

        // Create restore point if requested
        if (createRestorePoint)
        {
            progress?.Report(new CleanupProgress
            {
                StatusMessage = "Creating restore point...",
                ProgressPercent = 0
            });

            var restorePointService = new RestorePointService(_logger);
            var rpCreated = await restorePointService.CreateRestorePointAsync($"ScanSysDefence Disk Cleanup - {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            result.RestorePointCreated = rpCreated;
        }

        foreach (var item in items)
        {
            cancellationToken.ThrowIfCancellationRequested();

            progress?.Report(new CleanupProgress
            {
                CurrentFileIndex = processed,
                TotalFiles = total,
                CurrentFile = item.FileName,
                BytesCleaned = result.BytesFreed,
                TotalBytesToClean = items.Sum(i => i.Size),
                ProgressPercent = total > 0 ? (int)((double)processed / total * 100) : 100,
                StatusMessage = $"Deleting {item.FileName}..."
            });

            try
            {
                var fileInfo = new FileInfo(item.FilePath);
                
                if (item.MoveToRecycleBin)
                {
                    // Use Shell API for Recycle Bin
                    MoveToRecycleBin(item.FilePath);
                }
                else
                {
                    fileInfo.Delete();
                }

                result.FilesDeleted++;
                result.BytesFreed += item.Size;
                result.DeletedFiles.Add(item.FilePath);
            }
            catch (Exception ex)
            {
                result.FilesFailed++;
                result.FailedFiles.Add(item.FilePath);
                result.Errors.Add(new CleanupError
                {
                    FilePath = item.FilePath,
                    Error = ex.Message,
                    Exception = ex
                });
                _logger.Error(ex, "Failed to delete {File}", item.FilePath);
            }

            processed++;
        }

        stopwatch.Stop();
        result.Duration = stopwatch.Elapsed;
        result.Success = result.FilesFailed == 0;

        _logger.Information("Cleanup completed: {Deleted} files, {Failed} failed, {Bytes} bytes freed", 
            result.FilesDeleted, result.FilesFailed, result.BytesFreed);

        return result;
    }

    private void MoveToRecycleBin(string filePath)
    {
        try
        {
            // Use Microsoft.VisualBasic.FileIO for Recycle Bin support
            Microsoft.VisualBasic.FileIO.FileSystem.DeleteFile(
                filePath, 
                Microsoft.VisualBasic.FileIO.UIOption.OnlyErrorDialogs,
                Microsoft.VisualBasic.FileIO.RecycleOption.SendToRecycleBin,
                Microsoft.VisualBasic.FileIO.UICancelOption.DoNothing);
        }
        catch
        {
            // Fallback to permanent delete
            File.Delete(filePath);
        }
    }
}
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using ScanSysDefence.Core.Models;

namespace ScanSysDefence.Core.Services;

/// <summary>
/// Проверка диска/папки на вирусы, шпионы, трояны и прочие вредоносные файлы
/// набором эвристик (без внешних антивирусных движков):
///  - сигнатура тестового вируса EICAR;
///  - двойные расширения (маскировка троянов под документы);
///  - исполняемый код (PE) под видом картинок/текста/архивов;
///  - опасные команды в скриптах (powershell -enc, certutil, vssadmin и т.п.);
///  - строки криптомайнеров;
///  - подозрительные autorun.inf;
///  - неподписанные программы во временных папках и «Загрузках».
/// </summary>
public class VirusScanService : IVirusScanService
{
    private readonly ILogger _logger;
    private readonly IDigitalSignatureService _signatureService;

    private const int MaxDirectories = 150_000;

    private static readonly HashSet<string> SkippedDirNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "System Volume Information", "$Recycle.Bin", "$RECYCLE.BIN", "WinSxS", "servicing",
        "node_modules", ".git", ".vs", "catroot2", "DriverStore", "Package Cache"
    };

    private static readonly HashSet<string> SkipExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".mp4", ".mkv", ".avi", ".mov", ".wmv", ".flv", ".mp3", ".wav", ".flac", ".ogg",
        ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".ico", ".webp",
        ".zip", ".7z", ".rar", ".cab", ".gz", ".iso", ".vhd", ".vhdx", ".msi"
    };

    private static readonly HashSet<string> ExecutableExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".scr", ".com", ".pif", ".cpl", ".dll"
    };

    private static readonly HashSet<string> ScriptExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".bat", ".cmd", ".hta"
    };

    private static readonly string[] DocumentInnerExtensions =
    {
        ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".rtf",
        ".jpg", ".jpeg", ".png", ".gif", ".zip", ".rar", ".7z", ".mp3", ".mp4", ".csv"
    };

    private static readonly HashSet<string> DangerousOuterExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".scr", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jse",
        ".wsf", ".hta", ".pif", ".cpl", ".msi", ".lnk", ".reg", ".jar"
    };

    private static readonly HashSet<string> SpoofableExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".jpg", ".jpeg", ".png", ".gif", ".txt", ".pdf", ".doc", ".docx", ".zip", ".csv", ".log", ".mp4"
    };

    private static readonly Regex SuspiciousNamePattern = new(
        @"(keylog|stealer|ransom|backdoor|trojan|rootkit|botnet)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex AutorunPattern = new(
        @"^\s*(open|shellexecute|icon)\s*=",
        RegexOptions.IgnoreCase | RegexOptions.Multiline | RegexOptions.Compiled);

    private static readonly (Regex Pattern, string Reason, int Score, string Id)[] ScriptPatterns =
    {
        (new Regex(@"powershell(\.exe)?[^\r\n]{0,80}-e(nc|ncodedcommand)", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            "PowerShell со скрытой base64-командой (частая тактика троянов)", 45, "AV_PS_ENC"),
        (new Regex(@"certutil[^\r\n]{0,80}(-urlcache|-decode)", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            "Загрузка/декодирование файлов через certutil (обход защит)", 40, "AV_CERTUTIL"),
        (new Regex(@"bitsadmin[^\r\n]{0,80}/transfer", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            "Скачивание файлов через BITS", 35, "AV_BITS"),
        (new Regex(@"vssadmin[^\r\n]{0,80}delete[^\r\n]{0,40}shadow", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            "Удаление теневых копий — поведение шифровальщика", 55, "AV_VSSADMIN"),
        (new Regex(@"wbadmin[^\r\n]{0,60}delete[^\r\n]{0,40}catalog", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            "Удаление резервных копий — поведение шифровальщика", 50, "AV_WBADMIN"),
        (new Regex(@"wscript\.shell", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            "Запуск внешних программ через WScript.Shell (типично для вирусов-скриптов)", 30, "AV_WSCRIPT"),
        (new Regex(@"(invoke-webrequest|downloadstring|downloadfile|start-bitstransfer)", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            "Скачивание кода из интернета", 35, "AV_DOWNLOAD"),
        (new Regex(@"\biex\s*\(|invoke-expression", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            "Выполнение кода из строки (Invoke-Expression)", 35, "AV_IEX"),
        (new Regex(@"stratum\+(tcp|ssl)", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            "Подключение к пулу криптомайнинга", 50, "AV_STRATUM"),
        (new Regex(@"\bxmrig\b", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            "Майнер XMRig", 60, "AV_XMRIG"),
        (new Regex(@"net\s+user[^\r\n]{0,60}/add", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            "Создание учётной записи через net user", 45, "AV_NETUSER"),
        (new Regex(@"net\s+localgroup[^\r\n]{0,40}administrators[^\r\n]{0,80}/add", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            "Добавление пользователя в администраторы", 50, "AV_ADMINADD"),
        (new Regex(@"netsh[^\r\n]{0,60}(firewall|advfirewall)[^\r\n]{0,60}(off|disable)", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            "Отключение брандмауэра Windows", 45, "AV_FIREWALL"),
        (new Regex(@"(sc|net)\s+stop[^\r\n]{0,40}(windefend|wscsvc|wuauserv|msmpeng)", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            "Попытка остановить защитные службы Windows", 50, "AV_STOPSVC"),
        (new Regex(@"schtasks[^\r\n]{0,80}/create[^\r\n]{0,120}/ru\s+system", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            "Создание задачи с правами SYSTEM (закрепление в системе)", 40, "AV_SCHTASKS"),
        (new Regex(@"reg\s+add[^\r\n]{0,120}\\run", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            "Добавление программы в автозапуск через реестр", 30, "AV_REG_RUN")
    };

    private static readonly string[] MinerStrings =
    {
        "xmrig", "stratum+tcp", "stratum+ssl", "cryptonight", "nicehash", "minerd"
    };

    public VirusScanService(ILogger logger, IDigitalSignatureService signatureService)
    {
        _logger = logger;
        _signatureService = signatureService;
    }

    public async Task<List<FileThreatInfo>> ScanAsync(
        string rootPath,
        VirusScanOptions options,
        IProgress<VirusScanProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        var threats = new List<FileThreatInfo>();

        if (string.IsNullOrWhiteSpace(rootPath) || !Directory.Exists(rootPath))
        {
            _logger.Warning("Virus scan path not found: {Path}", rootPath);
            return threats;
        }

        var dirs = CollectDirectories(rootPath, options, cancellationToken);
        var total = Math.Max(1, dirs.Count);
        _logger.Information("Virus scan started: {Path} ({Dirs} папок)", rootPath, dirs.Count);

        var throttle = Stopwatch.StartNew();

        return await Task.Run(async () =>
        {
            int filesScanned = 0;
            int dirIndex = 0;

            foreach (var dir in dirs)
            {
                cancellationToken.ThrowIfCancellationRequested();
                dirIndex++;

                try
                {
                    foreach (var file in Directory.EnumerateFiles(dir))
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        filesScanned++;

                        try
                        {
                            var threat = await AnalyzeFileAsync(file, options);
                            if (threat != null)
                            {
                                threats.Add(threat);
                                _logger.Information("Threat heuristics hit: {File} ({Threat})", file, threat.ThreatName);
                            }
                        }
                        catch (Exception ex)
                        {
                            _logger.Debug("File analysis skipped {File}: {Message}", file, ex.Message);
                        }

                        if (throttle.ElapsedMilliseconds >= 120)
                        {
                            throttle.Restart();
                            ReportProgress(progress, dir, filesScanned, threats.Count, dirIndex, total);
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.Debug("Directory skipped {Dir}: {Message}", dir, ex.Message);
                }

                ReportProgress(progress, dir, filesScanned, threats.Count, dirIndex, total);
            }

            _logger.Information("Virus scan completed: {Files} файлов, {Threats} подозрительных", filesScanned, threats.Count);
            progress?.Report(new VirusScanProgress
            {
                FilesScanned = filesScanned,
                ThreatsFound = threats.Count,
                ProgressPercent = 100,
                StatusMessage = $"Готово: проверено файлов {filesScanned}, найдено подозрительных {threats.Count}"
            });

            return threats;
        }, cancellationToken);
    }

    private static void ReportProgress(IProgress<VirusScanProgress>? progress, string dir, int files, int found, int index, int total)
    {
        progress?.Report(new VirusScanProgress
        {
            CurrentPath = dir,
            FilesScanned = files,
            ThreatsFound = found,
            ProgressPercent = Math.Min(99, (int)((double)index / total * 100)),
            StatusMessage = $"Папка: {dir} · проверено файлов: {files}, найдено подозрительных: {found}"
        });
    }

    private async Task<FileThreatInfo?> AnalyzeFileAsync(string filePath, VirusScanOptions options)
    {
        var name = Path.GetFileName(filePath);
        var ext = Path.GetExtension(filePath);
        var lowerName = name.ToLowerInvariant();

        long size = 0;
        try { size = new FileInfo(filePath).Length; } catch { }
        if (size <= 0) return null;

        var reasons = new List<string>();
        var factors = new List<RiskFactor>();
        string? threatName = null;

        void Add(string id, string reason, int score, RiskSeverity severity)
        {
            reasons.Add(reason);
            factors.Add(new RiskFactor
            {
                Id = id,
                Category = "Файл",
                Description = reason,
                Score = score,
                Severity = severity,
                Evidence = filePath,
                Recommendation = "Проверьте файл: поместите в карантин или удалите (кнопки внизу)."
            });
        }

        var deep = options.DeepContentCheck;

        // 1. Сигнатура EICAR (стандартный тест антивирусов)
        if (size <= 1_048_576)
        {
            var head = ReadTextHead(filePath, 8192);

            if (head != null && head.Contains("EICAR-STANDARD-ANTIVIRUS-TEST-FILE", StringComparison.OrdinalIgnoreCase))
            {
                threatName = "Тестовый вирус EICAR";
                Add("AV_EICAR", "Сигнатура EICAR — стандартный антивирусный тест (безвреден, применяется для проверки сканеров)", 80, RiskSeverity.Critical);
            }
            else if (deep && size <= 4_194_304 && head != null && ContainsMinerStrings(head))
            {
                threatName = "Криптомайнер";
                Add("AV_MINER", "Строки криптомайнера (xmrig / stratum / cryptonight)", 60, RiskSeverity.High);
            }
        }

        // 2. Двойное расширение (invoice.pdf.exe)
        if (HasDoubleDangerousExtension(lowerName, ext))
        {
            threatName ??= "Маскировка двойным расширением";
            Add("AV_DOUBLE_EXT", $"Двойное расширение: «{name}» — типичная маскировка трояна под документ", 55, RiskSeverity.High);
        }

        // 3. Исполняемый код (PE) под видом картинки/текста/архива
        if (deep && size <= 52_428_800 && SpoofableExtensions.Contains(ext) && IsPeFile(filePath))
        {
            threatName ??= "Исполняемый файл под видом документа";
            Add("AV_SPOOFED_PE", "Внутри файла исполняемый код (PE), хотя расширение — не программа", 65, RiskSeverity.Critical);
        }

        // 4. Опасные команды в скриптах
        if (deep && ScriptExtensions.Contains(ext) && size <= 2_097_152)
        {
            var text = ReadTextHead(filePath, 262_144);
            if (!string.IsNullOrEmpty(text))
            {
                foreach (var (pattern, reason, score, id) in ScriptPatterns)
                {
                    if (pattern.IsMatch(text))
                    {
                        threatName ??= "Скрипт с опасными командами";
                        Add(id, reason, score, RiskSeverity.High);
                        break;
                    }
                }

                if (ContainsMinerStrings(text))
                {
                    threatName ??= "Криптомайнер";
                    Add("AV_MINER", "Строки криптомайнера (xmrig / stratum / cryptonight)", 60, RiskSeverity.High);
                }
            }
        }

        // 5. Подозрительный autorun.inf
        if (deep && name.Equals("autorun.inf", StringComparison.OrdinalIgnoreCase) && size <= 262_144)
        {
            var text = ReadTextHead(filePath, 65536);
            if (!string.IsNullOrEmpty(text) && AutorunPattern.IsMatch(text))
            {
                threatName ??= "Подозрительный autorun.inf";
                Add("AV_AUTORUN", "autorun.inf автоматически запускает программы при открытии носителя", 40, RiskSeverity.Medium);
            }
        }

        // 6. Подозрительное имя файла
        if (SuspiciousNamePattern.IsMatch(lowerName))
        {
            threatName ??= "Подозрительное имя файла";
            Add("AV_NAME", "Имя файла характерно для вредоносных программ (keylog/stealer/ransom и т.п.)", 30, RiskSeverity.Medium);
        }

        // 7. Неподписанная программа во временной папке или «Загрузках»
        if (deep && ExecutableExtensions.Contains(ext) && IsHotPath(filePath))
        {
            try
            {
                var signature = await _signatureService.VerifySignatureAsync(filePath);
                if (!signature.IsValid)
                {
                    threatName ??= "Неподписанная программа в опасной папке";
                    Add("AV_UNSIGNED_HOTPATH",
                        $"Неподписанная программа во временной папке/«Загрузках» ({DescribeHotPath(filePath)})", 35, RiskSeverity.Medium);
                }
            }
            catch
            {
                // не смогли проверить подпись — пропускаем эту проверку
            }
        }

        if (factors.Count == 0) return null;

        var assessment = new RiskAssessment
        {
            Factors = factors,
            TotalScore = Math.Max(0, Math.Min(100, factors.Sum(f => f.Score)))
        };
        assessment.Level = CalculateLevel(assessment.TotalScore);

        return new FileThreatInfo
        {
            FileName = name,
            FilePath = filePath,
            SizeBytes = size,
            ThreatName = threatName ?? "Подозрительный файл",
            Reasons = reasons,
            RiskAssessment = assessment,
            CanDelete = true,
            CanStop = false,
            CanDisable = false
        };
    }

    private static RiskLevel CalculateLevel(int score) => score switch
    {
        >= 70 => RiskLevel.Critical,
        >= 50 => RiskLevel.High,
        >= 30 => RiskLevel.Medium,
        >= 10 => RiskLevel.Low,
        _ => RiskLevel.Informational
    };

    private static bool HasDoubleDangerousExtension(string lowerName, string ext)
    {
        if (!DangerousOuterExtensions.Contains(ext)) return false;

        var stem = lowerName.Substring(0, Math.Max(0, lowerName.Length - ext.Length));
        foreach (var inner in DocumentInnerExtensions)
        {
            if (stem.EndsWith(inner, StringComparison.OrdinalIgnoreCase)) return true;
        }

        return false;
    }

    private static bool ContainsMinerStrings(string text)
    {
        foreach (var marker in MinerStrings)
        {
            if (text.Contains(marker, StringComparison.OrdinalIgnoreCase)) return true;
        }
        return false;
    }

    private static bool IsPeFile(string filePath)
    {
        try
        {
            using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            return stream.ReadByte() == 'M' && stream.ReadByte() == 'Z';
        }
        catch
        {
            return false;
        }
    }

    private static string? ReadTextHead(string filePath, int maxBytes)
    {
        try
        {
            using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            var buffer = new byte[Math.Min(maxBytes, (int)Math.Min(stream.Length, int.MaxValue))];
            var read = stream.Read(buffer, 0, buffer.Length);
            return Encoding.Latin1.GetString(buffer, 0, read);
        }
        catch
        {
            return null;
        }
    }

    private static bool IsHotPath(string filePath)
    {
        var lower = filePath.ToLowerInvariant();
        return lower.Contains(@"\appdata\local\temp\") ||
               lower.Contains(@"\windows\temp\") ||
               lower.Contains(@"\downloads\") ||
               lower.Contains(@"\загрузки\") ||
               lower.Contains(@"\temp\");
    }

    private static string DescribeHotPath(string filePath)
    {
        var lower = filePath.ToLowerInvariant();
        if (lower.Contains(@"\downloads\") || lower.Contains(@"\загрузки\")) return "Загрузки";
        return "временная папка";
    }

    private static List<string> CollectDirectories(string root, VirusScanOptions options, CancellationToken ct)
    {
        var result = new List<string>();
        var stack = new Stack<string>();
        stack.Push(root);

        while (stack.Count > 0 && result.Count < MaxDirectories)
        {
            ct.ThrowIfCancellationRequested();
            var dir = stack.Pop();
            result.Add(dir);

            if (!options.IncludeSubdirectories) continue;

            try
            {
                foreach (var sub in Directory.EnumerateDirectories(dir))
                {
                    var name = Path.GetFileName(sub);
                    if (SkippedDirNames.Contains(name)) continue;
                    if (IsReparsePoint(sub)) continue;
                    if (options.SkipSystemFolders && IsSystemDirectory(sub)) continue;
                    stack.Push(sub);
                }
            }
            catch
            {
                // нет доступа к подпапкам — пропускаем
            }
        }

        return result;
    }

    private static bool IsReparsePoint(string dir)
    {
        try
        {
            return (File.GetAttributes(dir) & FileAttributes.ReparsePoint) != 0;
        }
        catch
        {
            return true;
        }
    }

    private static bool IsSystemDirectory(string path)
    {
        try
        {
            var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            if (string.IsNullOrEmpty(windows)) return false;
            if (!path.StartsWith(windows, StringComparison.OrdinalIgnoreCase)) return false;

            // Windows\Temp проверяем — там часто живут трояны; остальную папку Windows пропускаем
            var temp = Path.Combine(windows, "Temp");
            return !path.StartsWith(temp, StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }
}

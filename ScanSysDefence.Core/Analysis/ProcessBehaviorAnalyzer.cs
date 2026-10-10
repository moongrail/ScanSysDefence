using System.Diagnostics;
using System.Management;
using ScanSysDefence.Core.Models;
using ScanSysDefence.Core.Services;

namespace ScanSysDefence.Core.Analysis;

public class ProcessBehaviorAnalyzer : IProcessBehaviorAnalyzer
{
    private readonly ILogger _logger;

    public ProcessBehaviorAnalyzer(ILogger logger)
    {
        _logger = logger;
    }

    public async Task<ProcessBehaviorReport> AnalyzeAsync(ProcessInfo process, CancellationToken ct = default)
    {
        return await Task.Run(() =>
        {
            var report = new ProcessBehaviorReport
            {
                ProcessName = process.ProcessName,
                ProcessId = process.ProcessId
            };

            var behaviors = new List<BehaviorCategory>();

            behaviors.Add(AnalyzeProcessPurpose(process));
            behaviors.Add(AnalyzeNetworkBehavior(process));
            behaviors.Add(AnalyzeFileBehavior(process));
            behaviors.Add(AnalyzeCommandLineBehavior(process));
            behaviors.Add(AnalyzeParentChild(process));

            report.Categories = behaviors.Where(b => b != null).ToList();
            report.NetworkBehaviors = BuildNetworkBehaviors(process);
            report.FileBehaviors = BuildFileBehaviors(process);
            report.MITRETechniques = CollectMITRE(process);
            report.Indicators = CollectIndicators(process);
            report.OverallRisk = process.RiskAssessment.Level;

            report.Summary = GenerateSummary(process);
            report.DetailedDescription = GenerateDetailedDescription(process, report.Categories);

            return report;
        }, ct);
    }

    public async Task<ProcessBehaviorReport> AnalyzeFromSnapshotAsync(ProcessSnapshot snapshot, CancellationToken ct = default)
    {
        return await AnalyzeAsync(snapshot.Process, ct);
    }

    private BehaviorCategory AnalyzeProcessPurpose(ProcessInfo p)
    {
        var cat = new BehaviorCategory { Name = "Purpose", NameRu = "Назначение" };

        if (IsKnownSystemProcess(p.ProcessName))
        {
            cat.Description = $"System process: {GetSystemProcessDescription(p.ProcessName)}";
            cat.DescriptionRu = $"Системный процесс: {GetSystemProcessDescriptionRu(p.ProcessName)}";
            cat.Risk = RiskLevel.Informational;
            cat.Evidence.Add($"System path: {p.Path}");
        }
        else if (IsKnownApplication(p.ProcessName, p.CompanyName))
        {
            cat.Description = $"Application process: {p.FileDescription}";
            cat.DescriptionRu = $"Приложение: {p.FileDescription} от {p.CompanyName}";
            cat.Risk = RiskLevel.Low;
        }
        else
        {
            cat.Description = "Unknown process";
            cat.DescriptionRu = "Неизвестный процесс. Не удалось определить назначение по сигнатуре или имени.";
            cat.Risk = RiskLevel.Medium;
            cat.Evidence.Add($"Name: {p.ProcessName}");
            cat.Evidence.Add($"Publisher: {(string.IsNullOrEmpty(p.Publisher) ? "Нет" : p.Publisher)}");
        }

        return cat;
    }

    private BehaviorCategory AnalyzeNetworkBehavior(ProcessInfo p)
    {
        var cat = new BehaviorCategory { Name = "Network", NameRu = "Сетевая активность" };

        if (p.NetworkConnections.Count == 0)
        {
            cat.Description = "No active network connections";
            cat.DescriptionRu = "Активных сетевых соединений нет. Процесс не взаимодействует с сетью.";
            cat.Risk = RiskLevel.Informational;
            return cat;
        }

        var suspicious = p.NetworkConnections.Where(c => c.IsSuspicious).ToList();
        cat.Description = $"{p.NetworkConnections.Count} connection(s), {suspicious.Count} suspicious";
        cat.DescriptionRu = $"Обнаружено {p.NetworkConnections.Count} сетевых соединений, из них подозрительных: {suspicious.Count}.";

        foreach (var conn in p.NetworkConnections)
        {
            var desc = conn.RemoteAddress == "127.0.0.1" || conn.RemoteAddress == "::1"
                ? $"Локальное соединение {conn.RemoteAddress}:{conn.RemotePort} ({conn.Protocol})"
                : $"Внешнее соединение {conn.RemoteAddress}:{conn.RemotePort} ({conn.Protocol}, состояние: {conn.State})";

            if (conn.IsSuspicious)
                desc += " ⚠ ПОДОЗРИТЕЛЬНЫЙ ПОРТ";

            cat.Evidence.Add(desc);
        }

        if (suspicious.Count > 0)
        {
            cat.Risk = RiskLevel.High;
            cat.DescriptionRu += " Обнаружены подозрительные соединения на нетипичных портах. Это может указывать на коммуникацию с командным сервером (C2).";
        }
        else
        {
            cat.Risk = RiskLevel.Low;
            cat.DescriptionRu += " Все соединения на типичных портах. Сетевая активность выглядит нормальной.";
        }

        return cat;
    }

    private BehaviorCategory AnalyzeFileBehavior(ProcessInfo p)
    {
        var cat = new BehaviorCategory { Name = "File System", NameRu = "Файловая система" };

        var pathInfo = new List<string>();
        var risk = RiskLevel.Informational;

        if (p.IsRunningFromTemp)
        {
            pathInfo.Add("Процесс запущен из временной папки — это типичное поведение вредоносного ПО после загрузки.");
            risk = RiskLevel.Critical;
        }

        if (p.IsSuspiciousPath)
        {
            pathInfo.Add($"Подозрительное расположение файла: {p.Path}");
            if (risk < RiskLevel.High) risk = RiskLevel.High;
        }

        if (p.Modules.Count > 0)
        {
            var suspiciousModules = p.Modules.Where(m => m.IsSuspicious).ToList();
            if (suspiciousModules.Any())
            {
                pathInfo.Add($"Загружено {suspiciousModules.Count} подозрительных модулей:");
                foreach (var m in suspiciousModules)
                    pathInfo.Add($"  - {m.Name} ({m.Path})");
                if (risk < RiskLevel.High) risk = RiskLevel.High;
            }
            else
            {
                pathInfo.Add($"Загружено {p.Modules.Count} модулей, все с валидными подписями.");
            }
        }

        if (!p.IsPacked)
        {
            pathInfo.Add("Исполняемый файл не упакован/не обфусцирован.");
        }
        else
        {
            pathInfo.Add("⚠ Файл упакован или обфусцирован. Это может использоваться для скрытия вредоносного кода.");
            if (risk < RiskLevel.Medium) risk = RiskLevel.Medium;
        }

        if (p.IsDotNet)
        {
            pathInfo.Add("Процесс является .NET-сборкой. Может быть декомпилирован для анализа.");
        }

        if (pathInfo.Count == 0) pathInfo.Add("Файловая активность в норме. Путь и модули соответствуют системным стандартам.");

        cat.DescriptionRu = string.Join("\n", pathInfo);
        cat.Description = "File system behavior analyzed";
        cat.Risk = risk;
        cat.Evidence = pathInfo;
        return cat;
    }

    private BehaviorCategory AnalyzeCommandLineBehavior(ProcessInfo p)
    {
        var cat = new BehaviorCategory { Name = "Command Line", NameRu = "Аргументы командной строки" };
        var risk = RiskLevel.Informational;

        if (string.IsNullOrWhiteSpace(p.CommandLine))
        {
            cat.DescriptionRu = "Командная строка не содержит аргументов или недоступна.";
            cat.Risk = risk;
            return cat;
        }

        var analysis = new List<string> { $"Полная командная строка: {p.CommandLine}" };

        // PowerShell analysis
        if (ContainsIgnoreCase(p.CommandLine, "powershell") || ContainsIgnoreCase(p.CommandLine, "pwsh"))
        {
            analysis.Add("");
            analysis.Add("🔍 ОБНАРУЖЕН PowerShell:");
            if (ContainsIgnoreCase(p.CommandLine, "-enc") || ContainsIgnoreCase(p.CommandLine, "-encodedcommand"))
            {
                analysis.Add("  ⚠ Закодированная команда (-EncodedCommand). Маскировка команд для обхода аудита и мониторинга.");
                analysis.Add("  Используется малварями для скрытия действий от систем безопасности.");
                risk = RiskLevel.Critical;
            }
            if (ContainsIgnoreCase(p.CommandLine, "bypass"))
            {
                analysis.Add("  ⚠ Обход политик выполнения (ExecutionPolicy Bypass). Снимает ограничения PowerShell.");
                if (risk < RiskLevel.High) risk = RiskLevel.High;
            }
            if (ContainsIgnoreCase(p.CommandLine, "downloadstring") || ContainsIgnoreCase(p.CommandLine, "invoke-webrequest") || ContainsIgnoreCase(p.CommandLine, "webclient"))
            {
                analysis.Add("  ⚠ Загрузка данных из интернета. Процесс скачивает внешний контент.");
                risk = RiskLevel.Critical;
            }
            if (ContainsIgnoreCase(p.CommandLine, "iex") || ContainsIgnoreCase(p.CommandLine, "invoke-expression"))
            {
                analysis.Add("  ⚠ Динамическое выполнение кода (Invoke-Expression). Загруженный код выполняется в памяти.");
                risk = RiskLevel.Critical;
            }
            if (ContainsIgnoreCase(p.CommandLine, "hidden") || ContainsIgnoreCase(p.CommandLine, "-w hidden"))
            {
                analysis.Add("  ⚠ Скрытый режим выполнения. Окно PowerShell не отображается пользователю.");
                if (risk < RiskLevel.High) risk = RiskLevel.High;
            }
            if (ContainsIgnoreCase(p.CommandLine, "frombase64string"))
            {
                analysis.Add("  ⚠ Декодирование Base64. Код может быть замаскирован в base64.");
                risk = RiskLevel.Critical;
            }
        }

        // CMD analysis
        if (ContainsIgnoreCase(p.CommandLine, "cmd /c") || ContainsIgnoreCase(p.CommandLine, "cmd.exe /c"))
        {
            analysis.Add("");
            analysis.Add("🔍 ОБНАРУЖЕН CMD с флагом /c:");
            analysis.Add("  Выполнение одной команды и завершение. Используется для запуска вредоносных скриптов.");
            if (risk < RiskLevel.Medium) risk = RiskLevel.Medium;
        }

        // LOLBins analysis
        var lolbins = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["rundll32"] = "Загрузка DLL-код. Может использоваться для выполнения вредоносных библиотек.",
            ["regsvr32"] = "Регистрация COM-объектов. Может использоваться для скрытого выполнения кода.",
            ["certutil"] = "Сертификаты. Может использоваться для загрузки файлов из интернета.",
            ["mshta"] = "HTML-приложения. Выполняет HTML/JS код, может загружать удалённые скрипты.",
            ["bitsadmin"] = "Менеджер фоновой передачи. Загрузка файлов через службу Windows.",
            ["wscript"] = "Windows Script Host. Выполнение VBScript/JavaScript.",
            ["cscript"] = "Windows Script Host (консоль). Выполнение VBScript/JavaScript.",
            ["msbuild"] = "Компиляция C# кода. Может выполнять произвольный код без установки .NET.",
            ["installutil"] = "Утилита установки .NET. Может выполнять вредоносные сборки.",
            ["regasm"] = "Регистрация .NET-сборок. Может загружать вредоносный код.",
            ["wmic"] = "WMI утилита. Управление системой, удалённое выполнение команд.",
            ["schtasks"] = "Планировщик задач. Создание заданий для автоматического запуска.",
            ["net"] = "Управление сетью. Создание пользователей, управление правами.",
            ["sc"] = "Управление службами. Создание/запуск/изменение служб Windows.",
            ["attrib"] = "Изменение атрибутов файлов. Скрытие файлов.",
            ["vssadmin"] = "Теневые копии. Удаление точек восстановления."
        };

        foreach (var (bin, desc) in lolbins)
        {
            if (ContainsIgnoreCase(p.CommandLine, bin))
            {
                analysis.Add("");
                analysis.Add($"🔍 ОБНАРУЖЕН LOLBin: {bin}");
                analysis.Add($"  {desc}");
                if (risk < RiskLevel.High) risk = RiskLevel.High;
            }
        }

        // Base64 detection
        if (System.Text.RegularExpressions.Regex.IsMatch(p.CommandLine, @"[A-Za-z0-9+/]{40,}={0,2}"))
        {
            analysis.Add("");
            analysis.Add("⚠ Обнаружена base64-строка в аргументах. Код может быть замаскирован.");
            if (risk < RiskLevel.High) risk = RiskLevel.High;
        }

        cat.DescriptionRu = string.Join("\n", analysis);
        cat.Description = "Command line analyzed";
        cat.Risk = risk;
        cat.Evidence = analysis;
        return cat;
    }

    private BehaviorCategory AnalyzeParentChild(ProcessInfo p)
    {
        var cat = new BehaviorCategory { Name = "Process Tree", NameRu = "Дерево процессов" };
        var risk = RiskLevel.Informational;
        var info = new List<string>();

        info.Add($"PID: {p.ProcessId}, Родительский PID: {p.ParentProcessId}");

        try
        {
            var parent = Process.GetProcessById(p.ParentProcessId);
            var parentPath = "";
            try { parentPath = parent.MainModule?.FileName ?? ""; } catch { }
            
            info.Add($"Родительский процесс: {parent.ProcessName} (PID: {parent.Id})");
            if (!string.IsNullOrEmpty(parentPath))
                info.Add($"Путь родителя: {parentPath}");

            // Suspicious parent-child relationships
            var suspicious = DetectSuspiciousParentChild(parent.ProcessName, p.ProcessName);
            if (suspicious != null)
            {
                info.Add($"⚠ {suspicious}");
                risk = RiskLevel.High;
            }
        }
        catch
        {
            info.Add("Родительский процесс завершён (PID: " + p.ParentProcessId + ")");
            info.Add("Процесс мог быть запущен другим процессом, который уже завершён.");
            risk = RiskLevel.Medium;
        }

        cat.DescriptionRu = string.Join("\n", info);
        cat.Description = "Process tree analyzed";
        cat.Risk = risk;
        cat.Evidence = info;
        return cat;
    }

    private string? DetectSuspiciousParentChild(string parentName, string childName)
    {
        var pairs = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["excel.exe"] = "cmd.exe, powershell.exe, wscript.exe, cscript.exe, mshta.exe",
            ["winword.exe"] = "cmd.exe, powershell.exe, wscript.exe, cscript.exe, mshta.exe",
            ["powerpnt.exe"] = "cmd.exe, powershell.exe, wscript.exe, cscript.exe, mshta.exe",
            ["outlook.exe"] = "cmd.exe, powershell.exe, wscript.exe, cscript.exe, mshta.exe",
            ["explorer.exe"] = "cmd.exe, powershell.exe",
            ["svchost.exe"] = "cmd.exe, powershell.exe",
        };

        foreach (var (parent, suspiciousChildren) in pairs)
        {
            if (parentName.Equals(parent, StringComparison.OrdinalIgnoreCase))
            {
                var children = suspiciousChildren.Split(", ");
                if (children.Any(c => childName.Equals(c, StringComparison.OrdinalIgnoreCase)))
                {
                    return $"{parentName} породил {childName}. Это нетипичная связь — может указывать на макрос-вредонос или эксплуатацию уязвимости.";
                }
            }
        }

        return null;
    }

    private List<NetworkBehavior> BuildNetworkBehaviors(ProcessInfo p)
    {
        return p.NetworkConnections.Select(c => new NetworkBehavior
        {
            RemoteAddress = c.RemoteAddress,
            RemotePort = c.RemotePort,
            Protocol = c.Protocol,
            State = c.State,
            ProcessName = p.ProcessName,
            DescriptionRu = c.IsSuspicious
                ? $"Подозрительное соединение с {c.RemoteAddress}:{c.RemotePort} на нестандартном порту."
                : $"Нормальное соединение с {c.RemoteAddress}:{c.RemotePort} ({c.Protocol}).",
            Risk = c.IsSuspicious ? RiskLevel.High : RiskLevel.Informational,
            IsSuspicious = c.IsSuspicious
        }).ToList();
    }

    private List<FileBehavior> BuildFileBehaviors(ProcessInfo p)
    {
        var behaviors = new List<FileBehavior>
        {
            new()
            {
                Path = p.Path,
                Operation = FileOperation.Execute,
                DescriptionRu = $"Исполняемый файл запущен из: {p.Path}",
                Risk = p.IsRunningFromTemp ? RiskLevel.Critical : RiskLevel.Informational,
                IsSystemPath = !p.IsSuspiciousPath,
                IsSensitivePath = p.IsRunningFromTemp
            }
        };

        foreach (var mod in p.Modules.Where(m => m.IsSuspicious))
        {
            behaviors.Add(new FileBehavior
            {
                Path = mod.Path,
                Operation = FileOperation.MemoryMap,
                DescriptionRu = $"Подозрительная DLL загружена в память: {mod.Name}",
                Risk = RiskLevel.High,
                IsSystemPath = false,
                IsSensitivePath = true
            });
        }

        return behaviors;
    }

    private List<string> CollectMITRE(ProcessInfo p)
    {
        var techniques = new List<string>();

        if (p.IsRunningFromTemp) techniques.Add("T1059 - Command and Scripting Interpreter");
        if (ContainsIgnoreCase(p.CommandLine, "powershell")) techniques.Add("T1059.001 - PowerShell");
        if (ContainsIgnoreCase(p.CommandLine, "encodedcommand")) techniques.Add("T1027 - Obfuscated Files or Information");
        if (p.IsElevated) techniques.Add("T1548 - Abuse Elevation Control Mechanism");
        if (p.NetworkConnections.Any(c => c.IsSuspicious)) techniques.Add("T1071 - Application Layer Protocol");
        if (p.IsPacked) techniques.Add("T1027.002 - Software Packing");
        if (p.IsMasquerading) techniques.Add("T1036 - Masquerading");
        if (ContainsIgnoreCase(p.CommandLine, "hidden")) techniques.Add("T1564 - Hide Artifacts");
        if (ContainsIgnoreCase(p.CommandLine, "downloadstring") || ContainsIgnoreCase(p.CommandLine, "webclient"))
            techniques.Add("T1105 - Ingress Tool Transfer");
        if (ContainsIgnoreCase(p.CommandLine, "certutil")) techniques.Add("T1105 - Ingress Tool Transfer (Certutil)");
        if (ContainsIgnoreCase(p.CommandLine, "rundll32")) techniques.Add("T1218.011 - Rundll32");

        return techniques.Distinct().ToList();
    }

    private List<string> CollectIndicators(ProcessInfo p)
    {
        var indicators = new List<string>();

        if (p.IsUnsigned) indicators.Add($"Подпись отсутствует: {p.Path}");
        if (!p.SignatureValid && p.IsSigned) indicators.Add($"Подпись невалидна: {p.Path}");
        if (p.IsRunningFromTemp) indicators.Add($"Запуск из Temp: {p.Path}");
        if (p.IsMasquerading) indicators.Add($"Мимикрия под системный процесс: {p.ProcessName}");
        if (p.IsPacked) indicators.Add($"Упакованный файл: {p.Path}");
        if (p.NetworkConnections.Any(c => c.IsSuspicious))
            indicators.Add($"Подозрительные соединения: {string.Join(", ", p.NetworkConnections.Where(c => c.IsSuspicious).Select(c => $"{c.RemoteAddress}:{c.RemotePort}"))}");

        return indicators;
    }

    private string GenerateSummary(ProcessInfo p)
    {
        var risk = p.RiskAssessment.Level;
        var score = p.RiskAssessment.TotalScore;

        var summary = $"Процесс «{p.ProcessName}» (PID: {p.ProcessId})";

        if (!string.IsNullOrEmpty(p.CompanyName))
            summary += $" от {p.CompanyName}";

        summary += $"\nУровень риска: {risk.GetDisplayName()} ({score}/100)";

        if (p.NetworkConnections.Any())
            summary += $"\nСетевая активность: {p.NetworkConnections.Count} соединений";

        if (p.Modules.Any(m => m.IsSuspicious))
            summary += $"\nПодозрительных модулей: {p.Modules.Count(m => m.IsSuspicious)}";

        return summary;
    }

    private string GenerateDetailedDescription(ProcessInfo p, List<BehaviorCategory> categories)
    {
        var sb = new System.Text.StringBuilder();
        sb.AppendLine($"=== АНАЛИЗ ПРОЦЕССА: {p.ProcessName} (PID: {p.ProcessId}) ===");
        sb.AppendLine();

        foreach (var cat in categories)
        {
            sb.AppendLine($"▶ {cat.NameRu}:");
            sb.AppendLine(cat.DescriptionRu);
            sb.AppendLine();
        }

        if (p.RiskAssessment.Factors.Any())
        {
            sb.AppendLine("=== ФАКТОРЫ РИСКА ===");
            foreach (var factor in p.RiskAssessment.Factors)
            {
                sb.AppendLine($"  [{factor.Severity}] {factor.Description}");
                sb.AppendLine($"    Рекомендация: {factor.Recommendation}");
            }
        }

        return sb.ToString();
    }

    private bool IsKnownSystemProcess(string name)
    {
        var systemProcesses = new[]
        {
            "system", "registry", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
            "services.exe", "lsass.exe", "svchost.exe", "dwm.exe", "explorer.exe",
            "taskhostw.exe", "sihost.exe", "conhost.exe", "fontdrvhost.exe"
        };
        return systemProcesses.Contains(name.ToLowerInvariant() + (name.EndsWith(".exe") ? "" : ".exe"), StringComparer.OrdinalIgnoreCase)
            || systemProcesses.Contains(name.ToLowerInvariant(), StringComparer.OrdinalIgnoreCase);
    }

    private string GetSystemProcessDescription(string name)
    {
        return name.ToLowerInvariant() switch
        {
            "csrss" or "csrss.exe" => "Client/Server Runtime Subsystem — подсистема клиент-серверных вызовов Windows",
            "lsass" or "lsass.exe" => "Local Security Authority — управление аутентификацией и политиками безопасности",
            "svchost" or "svchost.exe" => "Service Host — хост системных служб Windows",
            "dwm" or "dwm.exe" => "Desktop Window Manager — менеджер окон рабочего стола",
            "explorer" or "explorer.exe" => "Проводник Windows — файловый менеджер и оболочка рабочего стола",
            "winlogon" or "winlogon.exe" => "Windows Logon — управление входом в систему",
            "services" or "services.exe" => "Service Control Manager — диспетчер служб Windows",
            _ => "Системный процесс Windows"
        };
    }

    private string GetSystemProcessDescriptionRu(string name)
    {
        return name.ToLowerInvariant() switch
        {
            "csrss" or "csrss.exe" => "Подсистема клиент-серверных вызовов Windows. Управляет созданием/удалением потоков и консольными окнами.",
            "lsass" or "lsass.exe" => "Локальный орган безопасности. Аутентификация пользователей, проверка паролей, создание токенов.",
            "svchost" or "svchost.exe" => "Хост системных служб. Запускает службы Windows в виде DLL внутри одного процесса.",
            "dwm" or "dwm.exe" => "Менеджер окон рабочего стола. Отвечает за прозрачность, анимации и рендеринг окон.",
            "explorer" or "explorer.exe" => "Проводник Windows. Файловый менеджер, рабочий стол, панель задач.",
            "winlogon" or "winlogon.exe" => "Процесс входа в Windows. Управляет экраном приветствия, блокировкой, Ctrl+Alt+Del.",
            "services" or "services.exe" => "Диспетчер служб. Управляет запуском, остановкой и работой системных служб.",
            "taskhostw" or "taskhostw.exe" => "Хост задач. Запускает задачи планировщика в изолированном процессе.",
            "sihost" or "sihost.exe" => "Shell Infrastructure Host. Подсистема оболочки для уведомлений и панелей.",
            "conhost" or "conhost.exe" => "Console Window Host. Отвечает за отображение консольных окон.",
            "fontdrvhost" or "fontdrvhost.exe" => "Драйвер шрифтов пользовательского режима. Управляет отрисовкой шрифтов.",
            _ => "Системный процесс Windows"
        };
    }

    private bool IsKnownApplication(string name, string company)
    {
        var known = new[] { "google", "microsoft", "mozilla", "adobe", "slack", "discord", "spotify", "steam", "visual studio", "code" };
        return known.Any(k => (company ?? "").Contains(k, StringComparison.OrdinalIgnoreCase));
    }

    private bool ContainsIgnoreCase(string source, string value)
    {
        return source?.Contains(value, StringComparison.OrdinalIgnoreCase) ?? false;
    }
}
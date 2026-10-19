using ScanSysDefence.Core.Models;

namespace ScanSysDefence.Core.Services;

public class VirusScanOptions
{
    /// <summary>Проходить по вложенным папкам.</summary>
    public bool IncludeSubdirectories { get; set; } = true;

    /// <summary>Пропускать папку Windows (WinSxS и т.п.) — ускоряет полную проверку диска.</summary>
    public bool SkipSystemFolders { get; set; } = true;

    /// <summary>Проверять содержимое файлов (строки, сигнатуры), а не только имена.</summary>
    public bool DeepContentCheck { get; set; } = true;
}

public class VirusScanProgress
{
    public string CurrentPath { get; set; } = string.Empty;
    public int FilesScanned { get; set; }
    public int ThreatsFound { get; set; }
    public int ProgressPercent { get; set; }
    public string StatusMessage { get; set; } = string.Empty;
}

/// <summary>
/// Проверка файлов на вирусы/шпионы/трояны без внешних антивирусов:
/// эвристики (двойные расширения, маскировка PE, опасные команды в скриптах,
/// майнеры, сигнатура EICAR и т.д.).
/// </summary>
public interface IVirusScanService
{
    Task<List<FileThreatInfo>> ScanAsync(
        string rootPath,
        VirusScanOptions options,
        IProgress<VirusScanProgress>? progress = null,
        CancellationToken cancellationToken = default);
}

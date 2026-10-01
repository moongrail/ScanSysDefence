using System.IO;

namespace ScanSysDefence.Core.Models;

/// <summary>Запись в карантине: позволяет увидеть, что случилось с файлом, и восстановить его.</summary>
public class QuarantineEntry
{
    /// <summary>Полный путь к файлу внутри папки карантина.</summary>
    public string QuarantinePath { get; set; } = string.Empty;

    /// <summary>Имя файла в карантине.</summary>
    public string FileName { get; set; } = string.Empty;

    /// <summary>Исходный путь файла до помещения в карантин (пусто, если неизвестен).</summary>
    public string OriginalPath { get; set; } = string.Empty;

    /// <summary>Причина/источник помещения в карантин.</summary>
    public string Reason { get; set; } = string.Empty;

    public long SizeBytes { get; set; }
    public DateTime QuarantinedAt { get; set; }
    public bool IsBackup { get; set; }

    public bool CanRestore => File.Exists(QuarantinePath) && !IsBackup && !string.IsNullOrWhiteSpace(OriginalPath);

    public string DisplayName =>
        !string.IsNullOrWhiteSpace(OriginalPath) ? Path.GetFileName(OriginalPath) : FileName;

    public string SizeText
    {
        get
        {
            string[] suffixes = { "Б", "КБ", "МБ", "ГБ", "ТБ" };
            int i = 0;
            double size = SizeBytes;
            while (size >= 1024 && i < suffixes.Length - 1)
            {
                size /= 1024;
                i++;
            }
            return $"{size:F1} {suffixes[i]}";
        }
    }

    public string StatusText => CanRestore
        ? "В карантине (можно восстановить)"
        : IsBackup
            ? "Резервная копия удалённого файла"
            : "В карантине (исходный путь неизвестен)";
}

/// <summary>Метаданные, сохраняемые рядом с файлом карантина (JSON).</summary>
public class QuarantineMeta
{
    public string OriginalPath { get; set; } = string.Empty;
    public string Reason { get; set; } = string.Empty;
    public DateTime QuarantinedAt { get; set; } = DateTime.Now;
    public long SizeBytes { get; set; }
}

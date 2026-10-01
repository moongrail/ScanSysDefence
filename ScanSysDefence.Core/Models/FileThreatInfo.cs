namespace ScanSysDefence.Core.Models;

/// <summary>
/// Подозрительный файл, найденный при проверке диска на вирусы/шпионы/трояны.
/// </summary>
public class FileThreatInfo : ScanItemBase, System.ComponentModel.INotifyPropertyChanged
{
    private string _stateText = "Обнаружен";

    /// <summary>Уведомление об изменении свойств (нужно для обновления ячеек в таблице UI).</summary>
    public event System.ComponentModel.PropertyChangedEventHandler? PropertyChanged;

    public string FileName { get; set; } = string.Empty;
    public string FilePath { get; set; } = string.Empty;
    public long SizeBytes { get; set; }

    /// <summary>Краткое название угрозы, например «Двойное расширение».</summary>
    public string ThreatName { get; set; } = string.Empty;

    /// <summary>Причины, по которым файл признан подозрительным.</summary>
    public List<string> Reasons { get; set; } = new();

    /// <summary>Состояние после действий пользователя (обнаружен / в карантине / удалён).</summary>
    public string StateText
    {
        get => _stateText;
        set
        {
            if (_stateText == value) return;
            _stateText = value;
            PropertyChanged?.Invoke(this, new System.ComponentModel.PropertyChangedEventArgs(nameof(StateText)));
        }
    }

    public override string Name => FileName;
    public override string Path => FilePath;

    public string ReasonsText => string.Join("; ", Reasons);

    public string SizeText
    {
        get
        {
            string[] suffixes = { "Б", "КБ", "МБ", "ГБ" };
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
}

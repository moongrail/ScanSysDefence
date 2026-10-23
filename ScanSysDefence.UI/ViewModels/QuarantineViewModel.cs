using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows.Input;
using ScanSysDefence.Core.Models;
using ScanSysDefence.Core.Remediation;

namespace ScanSysDefence.UI.ViewModels;

/// <summary>Управление карантином: просмотр, восстановление и окончательное удаление файлов.</summary>
public class QuarantineViewModel : INotifyPropertyChanged
{
    private readonly IRemediationService _remediation;

    private QuarantineEntry? _selectedEntry;
    private bool _isBusy;
    private string _statusMessage = "Нажмите «Обновить список», чтобы увидеть файлы в карантине";

    public event PropertyChangedEventHandler? PropertyChanged;

    public ICommand RefreshCommand { get; }
    public ICommand RestoreCommand { get; }
    public ICommand DeleteCommand { get; }

    public ObservableCollection<QuarantineEntry> Entries { get; } = new();

    public QuarantineViewModel(IRemediationService remediation)
    {
        _remediation = remediation;

        RefreshCommand = new RelayCommand(async () => await RefreshAsync(), () => !IsBusy);
        RestoreCommand = new RelayCommand(async () => await RestoreAsync(), () => CanRestore);
        DeleteCommand = new RelayCommand(async () => await DeleteAsync(), () => SelectedEntry != null && !IsBusy);
    }

    public async Task InitializeAsync()
    {
        await RefreshAsync();
    }

    public string FolderPath => _remediation.QuarantineFolderPath;

    public QuarantineEntry? SelectedEntry
    {
        get => _selectedEntry;
        set
        {
            _selectedEntry = value;
            OnPropertyChanged();
            OnPropertyChanged(nameof(CanRestore));
            OnPropertyChanged(nameof(RestoreDisabledReason));
            RaiseCommands();
        }
    }

    public bool CanRestore => SelectedEntry?.CanRestore == true;

    public string RestoreDisabledReason
    {
        get
        {
            if (SelectedEntry == null) return "Сначала выберите файл в списке";
            if (SelectedEntry.IsBackup) return "Это резервная копия удалённого файла — восстановление невозможно, можно только удалить";
            if (string.IsNullOrWhiteSpace(SelectedEntry.OriginalPath)) return "Исходный путь неизвестен — восстановление невозможно";
            return $"Восстановить файл: {SelectedEntry.OriginalPath}";
        }
    }

    public bool IsBusy
    {
        get => _isBusy;
        set
        {
            _isBusy = value;
            OnPropertyChanged();
            RaiseCommands();
        }
    }

    public string StatusMessage
    {
        get => _statusMessage;
        set { _statusMessage = value; OnPropertyChanged(); }
    }

    public async Task RefreshAsync()
    {
        if (IsBusy) return;

        IsBusy = true;
        try
        {
            var entries = await _remediation.GetQuarantineEntriesAsync();
            Entries.Clear();
            foreach (var entry in entries) Entries.Add(entry);

            StatusMessage = Entries.Count == 0
                ? "Карантин пуст"
                : $"Файлов в карантине: {Entries.Count}. Папка: {FolderPath}";
        }
        catch (Exception ex)
        {
            StatusMessage = "Ошибка чтения карантина: " + ex.Message;
        }
        finally
        {
            IsBusy = false;
        }
    }

    private async Task RestoreAsync()
    {
        var entry = SelectedEntry;
        if (entry == null || !entry.CanRestore) return;

        IsBusy = true;
        try
        {
            var result = await _remediation.RestoreFromQuarantineAsync(entry.QuarantinePath);
            StatusMessage = result.Success ? "✔ " + result.Message : "✖ " + result.Error;
        }
        finally
        {
            IsBusy = false;
            await RefreshAsync();
        }
    }

    private async Task DeleteAsync()
    {
        var entry = SelectedEntry;
        if (entry == null) return;

        IsBusy = true;
        try
        {
            var result = await _remediation.DeleteFromQuarantineAsync(entry.QuarantinePath);
            StatusMessage = result.Success ? "✔ " + result.Message : "✖ " + result.Error;
        }
        finally
        {
            IsBusy = false;
            await RefreshAsync();
        }
    }

    private void RaiseCommands()
    {
        (RefreshCommand as RelayCommand)?.RaiseCanExecuteChanged();
        (RestoreCommand as RelayCommand)?.RaiseCanExecuteChanged();
        (DeleteCommand as RelayCommand)?.RaiseCanExecuteChanged();
    }

    protected void OnPropertyChanged([CallerMemberName] string? propertyName = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}

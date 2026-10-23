using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows.Input;
using ScanSysDefence.Core.Services;

namespace ScanSysDefence.UI.ViewModels;

public class RegistryRepairViewModel : INotifyPropertyChanged
{
    private readonly IRegistryRepairService _service;
    private bool _isScanning;
    private bool _isRepairing;
    private string _statusMessage = "Нажмите «Сканировать» для проверки реестра";
    private double _progressPercent;
    private bool _createBackup = true;
    private RegistryBackup? _selectedBackup;
    private int _selectedCount;

    public event PropertyChangedEventHandler? PropertyChanged;

    public ICommand ScanCommand { get; }
    public ICommand RepairCommand { get; }
    public ICommand RestoreCommand { get; }
    public ICommand RefreshBackupsCommand { get; }
    public ICommand SelectAllCommand { get; }
    public ICommand SelectNoneCommand { get; }

    public ObservableCollection<RegistryIssue> Issues { get; } = new();
    public ObservableCollection<RegistryBackup> Backups { get; } = new();

    public bool IsScanning
    {
        get => _isScanning;
        set { _isScanning = value; OnPropertyChanged(); UpdateStates(); }
    }

    public bool IsRepairing
    {
        get => _isRepairing;
        set { _isRepairing = value; OnPropertyChanged(); UpdateStates(); }
    }

    public string StatusMessage
    {
        get => _statusMessage;
        set { _statusMessage = value; OnPropertyChanged(); }
    }

    public double ProgressPercent
    {
        get => _progressPercent;
        set { _progressPercent = value; OnPropertyChanged(); }
    }

    public bool CreateBackup
    {
        get => _createBackup;
        set { _createBackup = value; OnPropertyChanged(); }
    }

    public RegistryBackup? SelectedBackup
    {
        get => _selectedBackup;
        set { _selectedBackup = value; OnPropertyChanged(); UpdateStates(); }
    }

    public int SelectedCount
    {
        get => _selectedCount;
        set { _selectedCount = value; OnPropertyChanged(); }
    }

    public bool HasResults => Issues.Count > 0;
    public bool IsIdle => !IsScanning && !IsRepairing;

    public RegistryRepairViewModel(IRegistryRepairService service)
    {
        _service = service;
        ScanCommand = new RelayCommand(async () => await ScanAsync(), () => IsIdle);
        RepairCommand = new RelayCommand(async () => await RepairAsync(), () => IsIdle && SelectedCount > 0);
        RestoreCommand = new RelayCommand(async () => await RestoreAsync(), () => IsIdle && SelectedBackup != null);
        RefreshBackupsCommand = new RelayCommand(async () => await LoadBackupsAsync(), () => IsIdle);
        SelectAllCommand = new RelayCommand(() => SetSelection(true));
        SelectNoneCommand = new RelayCommand(() => SetSelection(false));
        _ = LoadBackupsAsync();
    }

    private async Task ScanAsync()
    {
        IsScanning = true;
        ProgressPercent = 0;
        StatusMessage = "Сканирование реестра...";

        try
        {
            var progress = new Progress<RegistryScanProgress>(p =>
            {
                ProgressPercent = p.ProgressPercent;
                StatusMessage = p.StatusMessage;
            });

            var result = await _service.ScanAsync(progress);

            Issues.Clear();
            foreach (var issue in result.Issues)
            {
                issue.PropertyChanged += (_, e) =>
                {
                    if (e.PropertyName == nameof(RegistryIssue.IsSelected)) UpdateSelectedCount();
                };
                Issues.Add(issue);
            }

            UpdateSelectedCount();
            OnPropertyChanged(nameof(HasResults));
            var repairable = result.Issues.Count(i => i.CanRepair);
            StatusMessage = $"Сканирование завершено за {result.Duration.TotalSeconds:F1} с: найдено проблем {result.Issues.Count} " +
                            $"(исправимо автоматически: {repairable}, просмотрено ключей: {result.TotalKeysScanned}). " +
                            "Нажмите «Выбрать всё», затем «Исправить».";
        }
        catch (OperationCanceledException)
        {
            StatusMessage = "Сканирование отменено";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Ошибка сканирования: {ex.Message}";
        }
        finally
        {
            IsScanning = false;
        }
    }

    private async Task RepairAsync()
    {
        var selected = Issues.Where(i => i.IsSelected && i.CanRepair).ToList();
        if (selected.Count == 0)
        {
            StatusMessage = "Нет выбранных проблем для исправления";
            return;
        }

        IsRepairing = true;
        ProgressPercent = 0;
        StatusMessage = CreateBackup ? "Создание резервной копии реестра..." : "Исправление...";

        try
        {
            var progress = new Progress<RegistryRepairProgress>(p =>
            {
                ProgressPercent = p.ProgressPercent;
                StatusMessage = p.StatusMessage;
            });

            var result = await _service.RepairAsync(selected, CreateBackup, progress);
            var repairMessage = result.Message;

            await LoadBackupsAsync();
            await ScanAsync();
            StatusMessage = repairMessage + $" Осталось проблем: {Issues.Count}.";
        }
        catch (OperationCanceledException)
        {
            StatusMessage = "Исправление отменено";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Ошибка исправления: {ex.Message}";
        }
        finally
        {
            IsRepairing = false;
        }
    }

    private async Task RestoreAsync()
    {
        if (SelectedBackup == null) return;

        IsRepairing = true;
        StatusMessage = $"Восстановление из {SelectedBackup.Description}...";

        try
        {
            var result = await _service.RestoreBackupAsync(SelectedBackup.FilePath);
            StatusMessage = result.Message;
        }
        catch (Exception ex)
        {
            StatusMessage = $"Ошибка восстановления: {ex.Message}";
        }
        finally
        {
            IsRepairing = false;
        }
    }

    private async Task LoadBackupsAsync()
    {
        try
        {
            var backups = await _service.GetBackupsAsync();
            Backups.Clear();
            foreach (var backup in backups) Backups.Add(backup);
        }
        catch
        {
            // ignore backup listing errors
        }
    }

    private void SetSelection(bool isSelected)
    {
        foreach (var issue in Issues.Where(i => i.CanRepair))
        {
            issue.IsSelected = isSelected;
        }
        UpdateSelectedCount();
    }

    public void ToggleType(RegistryIssueType type, bool isSelected)
    {
        foreach (var issue in Issues.Where(i => i.Type == type && i.CanRepair))
        {
            issue.IsSelected = isSelected;
        }
        UpdateSelectedCount();
    }

    public void UpdateSelectedCount()
    {
        SelectedCount = Issues.Count(i => i.IsSelected && i.CanRepair);
        (RepairCommand as RelayCommand)?.RaiseCanExecuteChanged();
    }

    private void UpdateStates()
    {
        OnPropertyChanged(nameof(IsIdle));
        (ScanCommand as RelayCommand)?.RaiseCanExecuteChanged();
        (RepairCommand as RelayCommand)?.RaiseCanExecuteChanged();
        (RestoreCommand as RelayCommand)?.RaiseCanExecuteChanged();
        (RefreshBackupsCommand as RelayCommand)?.RaiseCanExecuteChanged();
    }

    protected void OnPropertyChanged([CallerMemberName] string? propertyName = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}

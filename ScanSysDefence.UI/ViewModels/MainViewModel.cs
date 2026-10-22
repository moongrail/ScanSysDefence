using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Runtime.CompilerServices;
using System.Text;
using System.Windows.Input;
using ScanSysDefence.Core.Models;
using ScanSysDefence.Core.Scanners;
using ScanSysDefence.Core.Services;

namespace ScanSysDefence.UI.ViewModels;

public class MainViewModel : INotifyPropertyChanged
{
    private readonly ScanCoordinator _scanCoordinator;
    private readonly ILogger _logger;

    private bool _isScanning;
    private ScanProgress? _currentProgress;
    private ScanResult? _lastScanResult;
    private string _statusMessage = "Готов к сканированию";
    private int _selectedTabIndex;
    private bool _isCategoryScanning;

    public event PropertyChangedEventHandler? PropertyChanged;

    public ICommand ScanCommand { get; }
    public ICommand CancelScanCommand { get; }
    public ICommand ExportResultsCommand { get; }
    public ICommand ScanCategoryCommand { get; }

    public DashboardViewModel Dashboard { get; }
    public ResultsViewModel Results { get; }
    public DiskCleanupViewModel DiskCleanup { get; }
    public RegistryRepairViewModel RegistryRepair { get; }
    public MalwareViewModel Malware { get; }
    public VirusScanViewModel VirusScan { get; }
    public QuarantineViewModel Quarantine { get; }
    public SettingsViewModel Settings { get; }

    public bool IsScanning
    {
        get => _isScanning;
        set { _isScanning = value; OnPropertyChanged(); OnPropertyChanged(nameof(IsIdle)); RaiseCommandStates(); }
    }

    public bool IsIdle => !IsScanning;

    public bool IsCategoryScanning
    {
        get => _isCategoryScanning;
        set { _isCategoryScanning = value; OnPropertyChanged(); RaiseCommandStates(); }
    }

    public ScanProgress? CurrentProgress
    {
        get => _currentProgress;
        set { _currentProgress = value; OnPropertyChanged(); }
    }

    public ScanResult? LastScanResult
    {
        get => _lastScanResult;
        set { _lastScanResult = value; OnPropertyChanged(); RaiseCommandStates(); }
    }

    public string StatusMessage
    {
        get => _statusMessage;
        set { _statusMessage = value; OnPropertyChanged(); }
    }

    public int SelectedTabIndex
    {
        get => _selectedTabIndex;
        set
        {
            if (_selectedTabIndex == value) return;
            _selectedTabIndex = value;
            OnPropertyChanged();

            // При входе на вкладку «Карантин» (индекс 6) обновляем список: файлы могли быть
            // помещены в карантин с вкладки «Проверка диска» уже после последнего обновления.
            if (value == 6 && Quarantine.RefreshCommand.CanExecute(null))
            {
                Quarantine.RefreshCommand.Execute(null);
            }
        }
    }

    private static readonly ScanPhase[] ScanPhases =
    {
        ScanPhase.ScanningServices,
        ScanPhase.ScanningStartup,
        ScanPhase.ScanningProcesses,
        ScanPhase.ScanningDrivers,
        ScanPhase.ScanningTasks,
        ScanPhase.ScanningWmi,
        ScanPhase.ScanningBrowsers
    };

    public double ScanProgressPercent
    {
        get
        {
            if (CurrentProgress == null) return 0;

            if (CurrentProgress.CurrentPhase == ScanPhase.Finalizing) return 100;
            if (CurrentProgress.CurrentPhase == ScanPhase.Analyzing) return 97;

            var index = Array.IndexOf(ScanPhases, CurrentProgress.CurrentPhase);
            if (index < 0) return 0;

            var phaseFraction = Math.Clamp(CurrentProgress.CurrentPhaseProgress / 100.0, 0, 1);
            return Math.Min(96, (index + phaseFraction) / ScanPhases.Length * 96);
        }
    }

    private void RaiseCommandStates()
    {
        (ScanCommand as RelayCommand)?.RaiseCanExecuteChanged();
        (CancelScanCommand as RelayCommand)?.RaiseCanExecuteChanged();
        (ExportResultsCommand as RelayCommand)?.RaiseCanExecuteChanged();
        (ScanCategoryCommand as ParameterizedRelayCommand<string>)?.RaiseCanExecuteChanged();
    }

    public MainViewModel(
        ScanCoordinator scanCoordinator,
        DashboardViewModel dashboard,
        ResultsViewModel results,
        DiskCleanupViewModel diskCleanup,
        RegistryRepairViewModel registryRepair,
        MalwareViewModel malware,
        VirusScanViewModel virusScan,
        QuarantineViewModel quarantine,
        SettingsViewModel settings,
        ILogger logger)
    {
        _scanCoordinator = scanCoordinator;
        _logger = logger;
        Dashboard = dashboard;
        Results = results;
        DiskCleanup = diskCleanup;
        RegistryRepair = registryRepair;
        Malware = malware;
        VirusScan = virusScan;
        Quarantine = quarantine;
        Settings = settings;

        ScanCommand = new RelayCommand(async () => await StartScanAsync(), () => IsIdle && !IsCategoryScanning);
        ScanCategoryCommand = new ParameterizedRelayCommand<string>(
            async phase => await ScanCategoryAsync(phase),
            _ => IsIdle && !IsCategoryScanning);
        CancelScanCommand = new RelayCommand(() => _scanCoordinator.CancelScan(), () => IsScanning);
        ExportResultsCommand = new RelayCommand(() => ExportResults(), () => LastScanResult != null && !IsScanning);

        _scanCoordinator.ProgressUpdated += OnProgressUpdated;
        _scanCoordinator.ScanCompleted += OnScanCompleted;
        _scanCoordinator.ErrorOccurred += OnError;
    }

    private async Task StartScanAsync()
    {
        IsScanning = true;
        StatusMessage = "Сканирование запущено...";

        try
        {
            var result = await _scanCoordinator.StartScanAsync(Settings.ToScanSettings());
            LastScanResult = result;
            Results.LoadResults(result);
            Dashboard.UpdateFromScan(result);
            Malware.LoadFromScan(result);
            StatusMessage = $"Сканирование завершено: {result.TotalItems} элементов, {result.SuspiciousCount} подозрительных";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Ошибка: {ex.Message}";
            _logger.Error(ex, "Scan failed in MainViewModel");
        }
        finally
        {
            IsScanning = false;
        }
    }

    private async Task ScanCategoryAsync(string? phaseName)
    {
        if (string.IsNullOrWhiteSpace(phaseName)) return;
        if (!Enum.TryParse<ScanPhase>(phaseName, out var phase)) return;
        if (IsScanning || IsCategoryScanning) return;

        IsCategoryScanning = true;
        StatusMessage = $"Сканирование: {PhaseDisplayName(phase)}...";

        try
        {
            var progress = new Progress<ScanProgress>(OnProgressUpdated);
            var items = await _scanCoordinator.ScanPhaseAsync(phase, Settings.ToScanSettings(), progress);
            var list = items.ToList();

            UpdateResultCategory(phase, list);

            if (LastScanResult != null)
            {
                Results.LoadResults(LastScanResult);
                Dashboard.UpdateFromScan(LastScanResult);
                Malware.LoadFromScan(LastScanResult);
            }

            StatusMessage = $"{PhaseDisplayName(phase)}: просканировано элементов — {list.Count}";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Ошибка сканирования «{PhaseDisplayName(phase)}»: {ex.Message}";
            _logger.Error(ex, "Category scan failed");
        }
        finally
        {
            IsCategoryScanning = false;
        }
    }

    private void UpdateResultCategory(ScanPhase phase, List<ScanItemBase> items)
    {
        LastScanResult ??= new ScanResult();

        switch (phase)
        {
            case ScanPhase.ScanningServices:
                LastScanResult.Services = items.Cast<ServiceInfo>().ToList();
                break;
            case ScanPhase.ScanningStartup:
                LastScanResult.StartupItems = items.Cast<StartupItem>().ToList();
                break;
            case ScanPhase.ScanningProcesses:
                LastScanResult.Processes = items.Cast<ProcessInfo>().ToList();
                break;
            case ScanPhase.ScanningDrivers:
                LastScanResult.Drivers = items.Cast<DriverInfo>().ToList();
                break;
            case ScanPhase.ScanningTasks:
                LastScanResult.ScheduledTasks = items.Cast<ScheduledTaskInfo>().ToList();
                break;
            case ScanPhase.ScanningWmi:
                LastScanResult.WmiSubscriptions = items.Cast<WmiSubscriptionInfo>().ToList();
                break;
            case ScanPhase.ScanningBrowsers:
                LastScanResult.BrowserExtensions = items.Cast<BrowserExtensionInfo>().ToList();
                break;
        }
    }

    private static string PhaseDisplayName(ScanPhase phase) => phase switch
    {
        ScanPhase.ScanningServices => "Службы",
        ScanPhase.ScanningStartup => "Автозапуск",
        ScanPhase.ScanningProcesses => "Процессы",
        ScanPhase.ScanningDrivers => "Драйверы",
        ScanPhase.ScanningTasks => "Задачи планировщика",
        ScanPhase.ScanningWmi => "WMI-подписки",
        ScanPhase.ScanningBrowsers => "Расширения браузеров",
        _ => phase.ToString()
    };

    private void OnProgressUpdated(ScanProgress progress)
    {
        CurrentProgress = progress;
        StatusMessage = progress.StatusMessage;
        OnPropertyChanged(nameof(ScanProgressPercent));
    }

    private void OnScanCompleted(ScanResult result)
    {
        IsScanning = false;
    }

    private void OnError(string error)
    {
        StatusMessage = $"Ошибка: {error}";
        IsScanning = false;
    }

    private void ExportResults()
    {
        if (LastScanResult == null) return;

        var dialog = new Microsoft.Win32.SaveFileDialog
        {
            Title = "Экспорт результатов сканирования",
            Filter = "JSON (*.json)|*.json|CSV (*.csv)|*.csv",
            FileName = $"ScanSysDefence_{LastScanResult.ScanId[..8]}_{DateTime.Now:yyyyMMdd_HHmmss}"
        };
        if (dialog.ShowDialog() != true) return;

        StatusMessage = "Экспорт результатов...";
        try
        {
            if (dialog.FilterIndex == 2)
            {
                File.WriteAllText(dialog.FileName, ExportToCsv(LastScanResult), Encoding.UTF8);
            }
            else
            {
                var options = new System.Text.Json.JsonSerializerOptions
                {
                    WriteIndented = true,
                    Converters = { new System.Text.Json.Serialization.JsonStringEnumConverter() }
                };
                File.WriteAllText(dialog.FileName, System.Text.Json.JsonSerializer.Serialize(LastScanResult, options), Encoding.UTF8);
            }
            StatusMessage = $"Результаты экспортированы: {dialog.FileName}";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Ошибка экспорта: {ex.Message}";
            _logger.Error(ex, "Export failed");
        }
    }

    private static string ExportToCsv(ScanResult result)
    {
        static string Csv(string value)
        {
            value ??= string.Empty;
            if (value.Contains('"') || value.Contains(',') || value.Contains('\n') || value.Contains('\r'))
            {
                return '"' + value.Replace("\"", "\"\"") + '"';
            }
            return value;
        }

        var sb = new StringBuilder();
        sb.AppendLine("Тип;Имя;Путь;Издатель;Уровень риска;Счёт;Описание");
        foreach (var item in result.AllItems)
        {
            sb.Append(Csv(item.GetType().Name)).Append(';')
              .Append(Csv(item.Name)).Append(';')
              .Append(Csv(item.Path)).Append(';')
              .Append(Csv(item.Publisher)).Append(';')
              .Append(Csv(item.RiskAssessment.Level.ToString())).Append(';')
              .Append(item.RiskAssessment.TotalScore).Append(';')
              .Append(Csv(item.Description))
              .AppendLine();
        }
        return sb.ToString();
    }

    protected void OnPropertyChanged([CallerMemberName] string? propertyName = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}

public class RelayCommand : ICommand
{
    private readonly Func<Task>? _asyncExecute;
    private readonly Action? _execute;
    private readonly Func<bool>? _canExecute;

    public event EventHandler? CanExecuteChanged;

    public RelayCommand(Action execute, Func<bool>? canExecute = null)
    {
        _execute = execute;
        _canExecute = canExecute;
    }

    public RelayCommand(Func<Task> asyncExecute, Func<bool>? canExecute = null)
    {
        _asyncExecute = asyncExecute;
        _canExecute = canExecute;
    }

    public bool CanExecute(object? parameter)
    {
        return _canExecute?.Invoke() ?? true;
    }

    public async void Execute(object? parameter)
    {
        if (_asyncExecute != null)
            await _asyncExecute();
        else
            _execute?.Invoke();
    }

    public void RaiseCanExecuteChanged()
    {
        CanExecuteChanged?.Invoke(this, EventArgs.Empty);
    }
}
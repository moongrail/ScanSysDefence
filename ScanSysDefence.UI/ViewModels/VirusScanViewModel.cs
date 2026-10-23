using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.CompilerServices;
using System.Windows.Input;
using ScanSysDefence.Core.Models;
using ScanSysDefence.Core.Remediation;
using ScanSysDefence.Core.Services;
using DriveInfo = ScanSysDefence.Core.Services.DriveInfo;

namespace ScanSysDefence.UI.ViewModels;

/// <summary>Проверка отдельных дисков на вирусы, шпионы, трояны и вредоносные файлы.</summary>
public class VirusScanViewModel : INotifyPropertyChanged
{
    private readonly IVirusScanService _virusScanService;
    private readonly IDiskCleanupService _cleanupService;
    private readonly IRemediationService _remediation;
    private readonly ILogger _logger;

    private DriveInfo? _selectedDrive;
    private string _customPath = string.Empty;
    private bool _useCustomPath;
    private bool _skipSystemFolders = true;
    private bool _deepContentCheck = true;
    private bool _isScanning;
    private int _progressPercent;
    private string _statusMessage = "Выберите диск и нажмите «Начать проверку»";
    private FileThreatInfo? _selectedThreat;
    private string _actionStatus = string.Empty;
    private CancellationTokenSource? _cts;

    public event PropertyChangedEventHandler? PropertyChanged;

    public ICommand ScanCommand { get; }
    public ICommand CancelCommand { get; }
    public ICommand QuarantineCommand { get; }
    public ICommand DeleteCommand { get; }
    public ICommand OpenFolderCommand { get; }
    public ICommand RefreshDrivesCommand { get; }

    public ObservableCollection<DriveInfo> Drives { get; } = new();
    public ObservableCollection<FileThreatInfo> Threats { get; } = new();
    public ObservableCollection<ActionLogEntry> ActionLog { get; } = new();

    public VirusScanViewModel(
        IVirusScanService virusScanService,
        IDiskCleanupService cleanupService,
        IRemediationService remediation,
        ILogger logger)
    {
        _virusScanService = virusScanService;
        _cleanupService = cleanupService;
        _remediation = remediation;
        _logger = logger;

        ScanCommand = new RelayCommand(async () => await ScanAsync(), () => !IsScanning);
        CancelCommand = new RelayCommand(() => _cts?.Cancel(), () => IsScanning);
        QuarantineCommand = new RelayCommand(async () => await QuarantineAsync(), CanActOnThreat);
        DeleteCommand = new RelayCommand(async () => await DeleteAsync(), CanActOnThreat);
        OpenFolderCommand = new RelayCommand(OpenFolder, () => SelectedThreat != null);
        RefreshDrivesCommand = new RelayCommand(async () => await LoadDrivesAsync(), () => !IsScanning);
    }

    public async Task InitializeAsync()
    {
        await LoadDrivesAsync();
    }

    public DriveInfo? SelectedDrive
    {
        get => _selectedDrive;
        set { _selectedDrive = value; OnPropertyChanged(); }
    }

    public string CustomPath
    {
        get => _customPath;
        set { _customPath = value; OnPropertyChanged(); }
    }

    public bool UseCustomPath
    {
        get => _useCustomPath;
        set { _useCustomPath = value; OnPropertyChanged(); }
    }

    public bool SkipSystemFolders
    {
        get => _skipSystemFolders;
        set { _skipSystemFolders = value; OnPropertyChanged(); }
    }

    public bool DeepContentCheck
    {
        get => _deepContentCheck;
        set { _deepContentCheck = value; OnPropertyChanged(); }
    }

    public bool IsScanning
    {
        get => _isScanning;
        set
        {
            _isScanning = value;
            OnPropertyChanged();
            RaiseCommands();
        }
    }

    public int ProgressPercent
    {
        get => _progressPercent;
        set { _progressPercent = value; OnPropertyChanged(); }
    }

    public string StatusMessage
    {
        get => _statusMessage;
        set { _statusMessage = value; OnPropertyChanged(); }
    }

    public string ActionStatus
    {
        get => _actionStatus;
        set { _actionStatus = value; OnPropertyChanged(); }
    }

    public FileThreatInfo? SelectedThreat
    {
        get => _selectedThreat;
        set
        {
            _selectedThreat = value;
            OnPropertyChanged();
            RaiseCommands();
        }
    }

    public int ThreatsCount => Threats.Count;

    private async Task LoadDrivesAsync()
    {
        try
        {
            var drives = await _cleanupService.GetDrivesAsync();
            var previous = SelectedDrive?.Letter;
            Drives.Clear();
            foreach (var drive in drives) Drives.Add(drive);

            SelectedDrive = Drives.FirstOrDefault(d => d.Letter == previous) ?? Drives.FirstOrDefault();
        }
        catch (Exception ex)
        {
            StatusMessage = "Не удалось получить список дисков: " + ex.Message;
        }
    }

    private async Task ScanAsync()
    {
        if (IsScanning) return;

        string root;
        if (UseCustomPath)
        {
            root = CustomPath?.Trim() ?? string.Empty;
            if (!Directory.Exists(root))
            {
                StatusMessage = "Папка не найдена: " + root;
                return;
            }
        }
        else
        {
            root = SelectedDrive?.Letter ?? string.Empty;
            if (string.IsNullOrWhiteSpace(root))
            {
                StatusMessage = "Выберите диск из списка";
                return;
            }
            if (!root.EndsWith('\\')) root += "\\";
        }

        _cts = new CancellationTokenSource();
        IsScanning = true;
        ProgressPercent = 0;
        Threats.Clear();
        OnPropertyChanged(nameof(ThreatsCount));
        ActionStatus = string.Empty;
        StatusMessage = $"Проверка {root}...";

        try
        {
            var progress = new Progress<VirusScanProgress>(p =>
            {
                ProgressPercent = p.ProgressPercent;
                StatusMessage = p.StatusMessage;
            });

            var options = new VirusScanOptions
            {
                SkipSystemFolders = SkipSystemFolders,
                DeepContentCheck = DeepContentCheck
            };

            var found = await _virusScanService.ScanAsync(root, options, progress, _cts.Token);

            foreach (var threat in found.OrderByDescending(t => t.RiskAssessment.TotalScore))
            {
                Threats.Add(threat);
            }

            OnPropertyChanged(nameof(ThreatsCount));
            StatusMessage = Threats.Count == 0
                ? $"Проверка {root} завершена: подозрительных файлов не найдено"
                : $"Проверка {root} завершена: найдено подозрительных файлов — {Threats.Count}. " +
                  "Выберите файл в списке и нажмите «В карантин» или «Удалить».";
        }
        catch (OperationCanceledException)
        {
            StatusMessage = "Проверка отменена пользователем";
        }
        catch (Exception ex)
        {
            StatusMessage = "Ошибка проверки: " + ex.Message;
            _logger.Error(ex, "Virus scan failed");
        }
        finally
        {
            IsScanning = false;
            _cts?.Dispose();
            _cts = null;
            ProgressPercent = 100;
        }
    }

    private bool CanActOnThreat()
    {
        if (SelectedThreat == null) return false;
        if (!File.Exists(SelectedThreat.FilePath)) return false;
        return SelectedThreat.StateText == "Обнаружен";
    }

    private async Task QuarantineAsync()
    {
        var threat = SelectedThreat;
        if (threat == null) return;

        ActionStatus = "Помещение в карантин...";
        var result = await _remediation.QuarantineFileAsync(threat.FilePath);
        if (result.Success)
        {
            threat.StateText = "В карантине (можно восстановить во вкладке «Карантин»)";
            ActionStatus = $"✔ {result.Message}";
        }
        else
        {
            ActionStatus = $"✖ Не удалось поместить в карантин: {result.Error}";
        }

        ActionLog.Insert(0, new ActionLogEntry { Action = $"Карантин: {threat.FileName}", Result = ActionStatus, Success = result.Success });
        while (ActionLog.Count > 30) ActionLog.RemoveAt(ActionLog.Count - 1);
        RaiseCommands();
    }

    private async Task DeleteAsync()
    {
        var threat = SelectedThreat;
        if (threat == null) return;

        ActionStatus = "Удаление файла...";
        var result = await _remediation.DeleteFileAsync(threat.FilePath, createBackup: true);
        if (result.Success)
        {
            threat.StateText = "Удалён (резервная копия в карантине)";
            ActionStatus = $"✔ {result.Message}";
        }
        else
        {
            ActionStatus = $"✖ Не удалось удалить: {result.Error}";
        }

        ActionLog.Insert(0, new ActionLogEntry { Action = $"Удаление: {threat.FileName}", Result = ActionStatus, Success = result.Success });
        while (ActionLog.Count > 30) ActionLog.RemoveAt(ActionLog.Count - 1);
        RaiseCommands();
    }

    private void OpenFolder()
    {
        var threat = SelectedThreat;
        if (threat == null) return;

        try
        {
            Process.Start(new ProcessStartInfo("explorer.exe", $"/select,\"{threat.FilePath}\"") { UseShellExecute = true });
        }
        catch (Exception ex)
        {
            ActionStatus = "Не удалось открыть папку: " + ex.Message;
        }
    }

    private void RaiseCommands()
    {
        (ScanCommand as RelayCommand)?.RaiseCanExecuteChanged();
        (CancelCommand as RelayCommand)?.RaiseCanExecuteChanged();
        (QuarantineCommand as RelayCommand)?.RaiseCanExecuteChanged();
        (DeleteCommand as RelayCommand)?.RaiseCanExecuteChanged();
        (OpenFolderCommand as RelayCommand)?.RaiseCanExecuteChanged();
        (RefreshDrivesCommand as RelayCommand)?.RaiseCanExecuteChanged();
    }

    protected void OnPropertyChanged([CallerMemberName] string? propertyName = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}

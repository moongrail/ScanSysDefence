using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.CompilerServices;
using System.ServiceProcess;
using System.Windows.Input;
using ScanSysDefence.Core.Models;
using ScanSysDefence.Core.Remediation;

namespace ScanSysDefence.UI.ViewModels;

public class ResultsViewModel : INotifyPropertyChanged
{
    private readonly IRemediationService _remediation;

    private ScanItemBase? _selectedItem;
    private string _filterText = string.Empty;
    private RiskLevel _minRiskFilter = RiskLevel.Informational;
    private string _actionStatus = string.Empty;

    private readonly List<ServiceInfo> _allServices = new();
    private readonly List<StartupItem> _allStartupItems = new();
    private readonly List<ProcessInfo> _allProcesses = new();
    private readonly List<DriverInfo> _allDrivers = new();
    private readonly List<ScheduledTaskInfo> _allScheduledTasks = new();
    private readonly List<WmiSubscriptionInfo> _allWmiSubscriptions = new();
    private readonly List<BrowserExtensionInfo> _allBrowserExtensions = new();

    /// <summary>Ручные пометки состояния после действий (карантин, удаление файла и т.п.).</summary>
    private readonly Dictionary<object, string> _stateOverrides = new(ReferenceEqualityComparer.Instance);

    public event PropertyChangedEventHandler? PropertyChanged;

    public ICommand StopCommand { get; }
    public ICommand ForceKillCommand { get; }
    public ICommand DisableCommand { get; }
    public ICommand QuarantineCommand { get; }
    public ICommand DeleteFileCommand { get; }
    public ICommand DeleteCommand { get; }
    public ICommand RefreshStateCommand { get; }

    public ObservableCollection<ServiceInfo> Services { get; } = new();
    public ObservableCollection<StartupItem> StartupItems { get; } = new();
    public ObservableCollection<ProcessInfo> Processes { get; } = new();
    public ObservableCollection<DriverInfo> Drivers { get; } = new();
    public ObservableCollection<ScheduledTaskInfo> ScheduledTasks { get; } = new();
    public ObservableCollection<WmiSubscriptionInfo> WmiSubscriptions { get; } = new();
    public ObservableCollection<BrowserExtensionInfo> BrowserExtensions { get; } = new();

    /// <summary>Журнал действий: показывает, что именно случилось с выбранным элементом.</summary>
    public ObservableCollection<ActionLogEntry> ActionLog { get; } = new();

    public ResultsViewModel(IRemediationService remediation)
    {
        _remediation = remediation;

        StopCommand = new RelayCommand(async () => await StopAsync(), () => CanStop(out _));
        ForceKillCommand = new RelayCommand(async () => await ForceKillAsync(), () => SelectedItem is ProcessInfo);
        DisableCommand = new RelayCommand(async () => await DisableAsync(), () => CanDisable(out _));
        QuarantineCommand = new RelayCommand(async () => await QuarantineAsync(), () => CanQuarantine(out _));
        DeleteFileCommand = new RelayCommand(async () => await DeleteFileAsync(), () => CanDeleteFile(out _));
        DeleteCommand = new RelayCommand(async () => await DeleteAsync(),
            () => SelectedItem is ScheduledTaskInfo or WmiSubscriptionInfo or StartupItem or DriverInfo);
        RefreshStateCommand = new RelayCommand(() => RefreshSelectedState(), () => SelectedItem != null);
    }

    public ScanItemBase? SelectedItem
    {
        get => _selectedItem;
        set
        {
            _selectedItem = value;
            OnPropertyChanged();
            OnPropertyChanged(nameof(HasSelection));
            RefreshSelectedState();
            RaiseCommandStates();
        }
    }

    public bool HasSelection => _selectedItem != null;

    /// <summary>Текущее состояние выбранного элемента (проверяется «вживую»).</summary>
    public string CurrentStateText => _selectedItem == null
        ? "Выберите элемент, чтобы увидеть его состояние"
        : ComputeCurrentState(_selectedItem);

    public string FilterText
    {
        get => _filterText;
        set { _filterText = value; OnPropertyChanged(); ApplyFilters(); }
    }

    public RiskLevel MinRiskFilter
    {
        get => _minRiskFilter;
        set { _minRiskFilter = value; OnPropertyChanged(); ApplyFilters(); }
    }

    public string ActionStatus
    {
        get => _actionStatus;
        set { _actionStatus = value; OnPropertyChanged(); }
    }

    public bool HasActionLog => ActionLog.Count > 0;

    // Причины недоступности кнопок (для всплывающих подсказок)
    public string StopDisabledReason { get; private set; } = string.Empty;
    public string ForceKillDisabledReason { get; private set; } = string.Empty;
    public string DisableDisabledReason { get; private set; } = string.Empty;
    public string QuarantineDisabledReason { get; private set; } = string.Empty;
    public string DeleteFileDisabledReason { get; private set; } = string.Empty;
    public string DeleteDisabledReason { get; private set; } = string.Empty;

    private bool CanStop(out string reason)
    {
        if (SelectedItem == null) { reason = "Сначала выберите элемент в списке"; return false; }
        if (SelectedItem is ProcessInfo p)
        {
            reason = $"Остановить процесс «{p.ProcessName}» (PID {p.ProcessId})";
            return true;
        }
        if (SelectedItem is ServiceInfo s)
        {
            if (!s.CanStop) { reason = "Служба уже остановлена"; return false; }
            reason = $"Остановить службу «{s.DisplayName}»";
            return true;
        }
        reason = "Действие доступно только для процессов и служб";
        return false;
    }

    private bool CanDisable(out string reason)
    {
        if (SelectedItem is ServiceInfo s)
        {
            if (!s.CanDisable) { reason = "Служба уже отключена (Start=4)"; return false; }
            reason = $"Отключить службу «{s.DisplayName}» (запретить автозапуск)";
            return true;
        }
        if (SelectedItem is ScheduledTaskInfo t)
        {
            if (!t.Enabled) { reason = "Задача уже отключена"; return false; }
            reason = $"Отключить задачу «{t.TaskName}»";
            return true;
        }
        reason = "Действие доступно только для служб и задач планировщика";
        return false;
    }

    private bool CanQuarantine(out string reason)
    {
        if (SelectedItem == null) { reason = "Сначала выберите элемент в списке"; return false; }
        if (_stateOverrides.TryGetValue(SelectedItem, out var ov) && ov.Contains("карантин"))
        {
            reason = "Файл уже помещён в карантин";
            return false;
        }
        if (string.IsNullOrWhiteSpace(SelectedItem.Path))
        {
            reason = "У элемента нет пути к файлу — поместить в карантин нельзя";
            return false;
        }
        if (!File.Exists(SelectedItem.Path))
        {
            reason = "Файл не найден по указанному пути";
            return false;
        }
        reason = $"Поместить файл в карантин: {SelectedItem.Path}";
        return true;
    }

    private bool CanDeleteFile(out string reason)
    {
        if (SelectedItem == null) { reason = "Сначала выберите элемент в списке"; return false; }
        if (string.IsNullOrWhiteSpace(SelectedItem.Path))
        {
            reason = "У элемента нет пути к файлу — удалить нельзя";
            return false;
        }
        if (!File.Exists(SelectedItem.Path))
        {
            reason = "Файл не найден по указанному пути";
            return false;
        }
        reason = $"Удалить файл с резервной копией в карантине: {SelectedItem.Path}";
        return true;
    }

    public void LoadResults(ScanResult result)
    {
        _allServices.Clear();
        _allStartupItems.Clear();
        _allProcesses.Clear();
        _allDrivers.Clear();
        _allScheduledTasks.Clear();
        _allWmiSubscriptions.Clear();
        _allBrowserExtensions.Clear();

        _allServices.AddRange(result.Services);
        _allStartupItems.AddRange(result.StartupItems);
        _allProcesses.AddRange(result.Processes);
        _allDrivers.AddRange(result.Drivers);
        _allScheduledTasks.AddRange(result.ScheduledTasks);
        _allWmiSubscriptions.AddRange(result.WmiSubscriptions);
        _allBrowserExtensions.AddRange(result.BrowserExtensions);

        SelectedItem = null;
        ApplyFilters();
    }

    private bool Matches(ScanItemBase item)
    {
        if (item.RiskAssessment.Level < _minRiskFilter) return false;

        if (string.IsNullOrWhiteSpace(_filterText)) return true;

        return item.Name.Contains(_filterText, StringComparison.OrdinalIgnoreCase) ||
               (item.Path?.Contains(_filterText, StringComparison.OrdinalIgnoreCase) ?? false);
    }

    private void Fill<T>(ObservableCollection<T> target, List<T> source) where T : ScanItemBase
    {
        target.Clear();
        foreach (var item in source.Where(Matches))
        {
            target.Add(item);
        }
    }

    private void ApplyFilters()
    {
        Fill(Services, _allServices);
        Fill(StartupItems, _allStartupItems);
        Fill(Processes, _allProcesses);
        Fill(Drivers, _allDrivers);
        Fill(ScheduledTasks, _allScheduledTasks);
        Fill(WmiSubscriptions, _allWmiSubscriptions);
        Fill(BrowserExtensions, _allBrowserExtensions);
    }

    private void RaiseCommandStates()
    {
        StopDisabledReason = BuildReason(CanStop, "Остановить");
        ForceKillDisabledReason = BuildReason(CanForceKill, "Убить процесс");
        DisableDisabledReason = BuildReason(CanDisable, "Отключить");
        QuarantineDisabledReason = BuildReason(CanQuarantine, "Карантин");
        DeleteFileDisabledReason = BuildReason(CanDeleteFile, "Удалить файл");
        DeleteDisabledReason = SelectedItem == null
            ? "Почему нельзя: сначала выберите элемент в списке"
            : SelectedItem is ScheduledTaskInfo or WmiSubscriptionInfo or StartupItem or DriverInfo
                ? "Удалить элемент (задача/WMI-подписка/автозапуск/выгрузка драйвера)"
                : "Почему нельзя: доступно для задач, WMI-подписок, записей автозапуска и драйверов";

        OnPropertyChanged(nameof(StopDisabledReason));
        OnPropertyChanged(nameof(ForceKillDisabledReason));
        OnPropertyChanged(nameof(DisableDisabledReason));
        OnPropertyChanged(nameof(QuarantineDisabledReason));
        OnPropertyChanged(nameof(DeleteFileDisabledReason));
        OnPropertyChanged(nameof(DeleteDisabledReason));

        (StopCommand as RelayCommand)?.RaiseCanExecuteChanged();
        (ForceKillCommand as RelayCommand)?.RaiseCanExecuteChanged();
        (DisableCommand as RelayCommand)?.RaiseCanExecuteChanged();
        (QuarantineCommand as RelayCommand)?.RaiseCanExecuteChanged();
        (DeleteFileCommand as RelayCommand)?.RaiseCanExecuteChanged();
        (DeleteCommand as RelayCommand)?.RaiseCanExecuteChanged();
        (RefreshStateCommand as RelayCommand)?.RaiseCanExecuteChanged();
    }

    private bool CanForceKill(out string reason)
    {
        if (SelectedItem is ProcessInfo p)
        {
            reason = $"Принудительно убить процесс «{p.ProcessName}» (PID {p.ProcessId}) — без диалогов";
            return true;
        }
        reason = "Действие доступно только для процессов";
        return false;
    }

    private delegate bool ReasonCheck(out string reason);

    private static string BuildReason(ReasonCheck check, string actionName)
    {
        try
        {
            return check(out var reason) ? reason : "Почему нельзя: " + reason;
        }
        catch
        {
            return actionName;
        }
    }

    private void RefreshSelectedState()
    {
        OnPropertyChanged(nameof(CurrentStateText));
    }

    private string ComputeCurrentState(ScanItemBase item)
    {
        if (_stateOverrides.TryGetValue(item, out var overridden))
        {
            return overridden;
        }

        try
        {
            switch (item)
            {
                case ProcessInfo p:
                    try
                    {
                        using var proc = Process.GetProcessById(p.ProcessId);
                        if (proc.HasExited) return "Остановлен";
                        return $"Работает (PID {p.ProcessId}, память {p.WorkingSet64 / 1024 / 1024} МБ)";
                    }
                    catch (ArgumentException)
                    {
                        return "Остановлен (процесс не найден)";
                    }
                    catch
                    {
                        return "Работает (состояние не удалось проверить — нет доступа)";
                    }

                case ServiceInfo s:
                    if (OperatingSystem.IsWindows())
                    {
                        try
                        {
                            using var sc = new ServiceController(s.ServiceName);
                            sc.Refresh();
                            var statusText = TranslateServiceStatus(sc.Status);
                            var startText = sc.StartType switch
                            {
                                ServiceStartMode.Disabled => "запуск отключён",
                                ServiceStartMode.Automatic => "автозапуск",
                                ServiceStartMode.Manual => "ручной запуск",
                                ServiceStartMode.Boot => "загрузочный запуск",
                                ServiceStartMode.System => "системный запуск",
                                _ => string.Empty
                            };
                            return string.IsNullOrEmpty(startText) ? statusText : $"{statusText} ({startText})";
                        }
                        catch
                        {
                            // Служба не найдена/недоступна — показываем данные последнего скана
                        }
                    }
                    return s.IsRunning ? "Работает" : "Остановлена";

                case ScheduledTaskInfo t:
                    return t.Enabled ? "Включена (по данным последнего скана)" : "Отключена";

                case DriverInfo d:
                    if (d.StartType.Equals("Disabled", StringComparison.OrdinalIgnoreCase)) return "Отключён (запуск запрещён)";
                    return string.IsNullOrWhiteSpace(d.State) ? "Состояние неизвестно" : d.State;

                case StartupItem:
                    return "Запись автозапуска присутствует";

                case WmiSubscriptionInfo:
                    return "WMI-подписка активна";

                case BrowserExtensionInfo b:
                    return b.IsEnabled ? "Расширение включено" : "Расширение отключено";
            }
        }
        catch
        {
            // Ничего не поделать — показываем заглушку
        }

        return "Состояние неизвестно";
    }

    private static string TranslateServiceStatus(ServiceControllerStatus status) => status switch
    {
        ServiceControllerStatus.Running => "Работает",
        ServiceControllerStatus.Stopped => "Остановлена",
        ServiceControllerStatus.StartPending => "Запускается",
        ServiceControllerStatus.StopPending => "Останавливается",
        ServiceControllerStatus.Paused => "Приостановлена",
        ServiceControllerStatus.PausePending => "Приостанавливается",
        ServiceControllerStatus.ContinuePending => "Возобновляется",
        _ => status.ToString()
    };

    private async Task StopAsync()
    {
        if (SelectedItem == null) return;

        if (SelectedItem is ProcessInfo p)
        {
            await RunActionAsync("Остановить процесс", () => _remediation.StopProcessAsync(p.ProcessId, p.ProcessName));
        }
        else if (SelectedItem is ServiceInfo s)
        {
            await RunActionAsync("Остановить службу", async () =>
            {
                var result = await _remediation.StopServiceAsync(s.ServiceName);
                if (result.Success) s.CurrentState = ServiceState.Stopped;
                return result;
            });
        }
    }

    private async Task ForceKillAsync()
    {
        if (SelectedItem is not ProcessInfo p) return;

        await RunActionAsync("Убить процесс (принудительно)", () => _remediation.ForceKillProcessAsync(p.ProcessId, p.ProcessName));
    }

    private async Task DisableAsync()
    {
        if (SelectedItem == null) return;

        if (SelectedItem is ServiceInfo s)
        {
            await RunActionAsync("Отключить службу", async () =>
            {
                var result = await _remediation.DisableServiceAsync(s.ServiceName);
                if (result.Success)
                {
                    s.StartType = ServiceStartType.Disabled;
                    if (s.CurrentState == ServiceState.Running) s.CurrentState = ServiceState.Stopped;
                }
                return result;
            });
        }
        else if (SelectedItem is ScheduledTaskInfo t)
        {
            await RunActionAsync("Отключить задачу", async () =>
            {
                var result = await _remediation.DisableScheduledTaskAsync(t.TaskName, t.TaskPath);
                if (result.Success) t.Enabled = false;
                return result;
            });
        }
    }

    private async Task QuarantineAsync()
    {
        if (SelectedItem == null || string.IsNullOrWhiteSpace(SelectedItem.Path)) return;
        var item = SelectedItem;
        var path = item.Path;

        await RunActionAsync("Карантин", async () =>
        {
            var result = await _remediation.QuarantineFileAsync(path);
            if (result.Success)
            {
                _stateOverrides[item] = $"Файл помещён в карантин (можно восстановить во вкладке «Карантин»): {path}";
            }
            return result;
        });
    }

    private async Task DeleteFileAsync()
    {
        if (SelectedItem == null || string.IsNullOrWhiteSpace(SelectedItem.Path)) return;
        var item = SelectedItem;
        var path = item.Path;

        await RunActionAsync("Удалить файл", async () =>
        {
            var result = await _remediation.DeleteFileAsync(path, createBackup: true);
            if (result.Success)
            {
                _stateOverrides[item] = $"Файл удалён (резервная копия сохранена в карантине): {path}";
            }
            return result;
        });
    }

    private async Task DeleteAsync()
    {
        if (SelectedItem == null) return;

        switch (SelectedItem)
        {
            case ScheduledTaskInfo t:
                await RunActionAsync("Удалить задачу", async () =>
                {
                    var result = await _remediation.DeleteScheduledTaskAsync(t.TaskName, t.TaskPath);
                    if (result.Success) RemoveFromResults(t);
                    return result;
                });
                break;
            case WmiSubscriptionInfo w:
                await RunActionAsync("Удалить WMI-подписку", async () =>
                {
                    var result = await _remediation.RemoveWmiSubscriptionAsync(w.SubscriptionName);
                    if (result.Success) RemoveFromResults(w);
                    return result;
                });
                break;
            case StartupItem su:
                await RunActionAsync("Удалить запись автозапуска", async () =>
                {
                    var result = await _remediation.RemoveStartupEntryAsync(su);
                    if (result.Success) RemoveFromResults(su);
                    return result;
                });
                break;
            case DriverInfo d:
                await RunActionAsync("Выгрузить драйвер", async () =>
                {
                    var result = await _remediation.UnloadDriverAsync(d.DriverName);
                    if (result.Success) d.State = "Stopped";
                    return result;
                });
                break;
        }
    }

    private async Task RunActionAsync(string actionName, Func<Task<RemediationResult>> actionAsync)
    {
        ActionStatus = $"{actionName}: выполняется...";
        try
        {
            var result = await actionAsync();
            var text = result.Success
                ? (string.IsNullOrWhiteSpace(result.Message) ? "Готово" : result.Message)
                : (string.IsNullOrWhiteSpace(result.Error) ? "Неизвестная ошибка" : result.Error);

            ActionStatus = result.Success ? $"✔ {actionName}: {text}" : $"✖ {actionName}: {text}";
            ActionLog.Insert(0, new ActionLogEntry
            {
                Action = actionName,
                Result = text,
                Success = result.Success
            });
            while (ActionLog.Count > 30) ActionLog.RemoveAt(ActionLog.Count - 1);
            OnPropertyChanged(nameof(HasActionLog));
        }
        catch (Exception ex)
        {
            ActionStatus = $"✖ {actionName}: {ex.Message}";
            ActionLog.Insert(0, new ActionLogEntry { Action = actionName, Result = ex.Message, Success = false });
            OnPropertyChanged(nameof(HasActionLog));
        }
        finally
        {
            RefreshSelectedState();
            RaiseCommandStates();
        }
    }

    private void RemoveFromResults(ScanItemBase item)
    {
        switch (item)
        {
            case ScheduledTaskInfo t: _allScheduledTasks.Remove(t); break;
            case WmiSubscriptionInfo w: _allWmiSubscriptions.Remove(w); break;
            case StartupItem su: _allStartupItems.Remove(su); break;
        }

        SelectedItem = null;
        ApplyFilters();
    }

    protected void OnPropertyChanged([CallerMemberName] string? propertyName = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}

public class ActionLogEntry
{
    public DateTime Time { get; set; } = DateTime.Now;
    public string Action { get; set; } = string.Empty;
    public string Result { get; set; } = string.Empty;
    public bool Success { get; set; }
    public string TimeText => Time.ToString("HH:mm:ss");
    public string StatusIcon => Success ? "✔" : "✖";
}

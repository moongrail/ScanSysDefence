using System.Diagnostics;
using ScanSysDefence.Core.Models;
using ScanSysDefence.Core.Scanners;
using ScanSysDefence.Core.Services;

namespace ScanSysDefence.UI.ViewModels;

public class ScanCoordinator
{
    private readonly IEnumerable<IScanner> _scanners;
    private readonly ILogger _logger;
    private CancellationTokenSource? _cts;

    public event Action<ScanProgress>? ProgressUpdated;
    public event Action<ScanResult>? ScanCompleted;
    public event Action<string>? ErrorOccurred;

    public bool IsScanning { get; private set; }

    public ScanCoordinator(IEnumerable<IScanner> scanners, ILogger logger)
    {
        _scanners = scanners;
        _logger = logger;
    }

    public async Task<ScanResult> StartScanAsync(ScanSettings? settings = null)
    {
        if (IsScanning)
        {
            throw new InvalidOperationException("Scan already in progress");
        }

        _cts = new CancellationTokenSource();
        var settingsObj = settings ?? new ScanSettings();
        var progress = new Progress<ScanProgress>(p => ProgressUpdated?.Invoke(p));
        var context = new ScanContext
        {
            Settings = settingsObj,
            Progress = progress,
            Logger = _logger
        };

        var result = new ScanResult
        {
            StartedAt = DateTime.Now,
            Status = ScanStatus.Running
        };

        IsScanning = true;
        var stopwatch = Stopwatch.StartNew();

        try
        {
            foreach (var scanner in _scanners)
            {
                _cts.Token.ThrowIfCancellationRequested();

                var items = await Task.Run(() => scanner.ScanAsync(context, _cts.Token), _cts.Token);

                switch (scanner.Phase)
                {
                    case ScanPhase.ScanningServices:
                        result.Services.AddRange(items.Cast<ServiceInfo>());
                        break;
                    case ScanPhase.ScanningStartup:
                        result.StartupItems.AddRange(items.Cast<StartupItem>());
                        break;
                    case ScanPhase.ScanningProcesses:
                        result.Processes.AddRange(items.Cast<ProcessInfo>());
                        break;
                    case ScanPhase.ScanningDrivers:
                        result.Drivers.AddRange(items.Cast<DriverInfo>());
                        break;
                    case ScanPhase.ScanningTasks:
                        result.ScheduledTasks.AddRange(items.Cast<ScheduledTaskInfo>());
                        break;
                    case ScanPhase.ScanningWmi:
                        result.WmiSubscriptions.AddRange(items.Cast<WmiSubscriptionInfo>());
                        break;
                    case ScanPhase.ScanningBrowsers:
                        result.BrowserExtensions.AddRange(items.Cast<BrowserExtensionInfo>());
                        break;
                }
            }

            result.Status = ScanStatus.Completed;
        }
        catch (OperationCanceledException)
        {
            result.Status = ScanStatus.Cancelled;
            _logger.Warning("Scan was cancelled by user");
        }
        catch (Exception ex)
        {
            result.Status = ScanStatus.Failed;
            _logger.Error(ex, "Scan failed");
            ErrorOccurred?.Invoke(ex.Message);
        }

        stopwatch.Stop();
        result.CompletedAt = DateTime.Now;
        IsScanning = false;

        ScanCompleted?.Invoke(result);
        return result;
    }

    /// <summary>Сканирование одной категории (вкладки) без полного прогона всех сканеров.</summary>
    public async Task<IEnumerable<ScanItemBase>> ScanPhaseAsync(
        ScanPhase phase,
        ScanSettings settings,
        IProgress<ScanProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        var scanner = _scanners.FirstOrDefault(s => s.Phase == phase)
            ?? throw new InvalidOperationException($"Сканер для фазы {phase} не найден");

        var context = new ScanContext
        {
            Settings = settings,
            Progress = progress,
            Logger = _logger
        };

        _logger.Information("Category scan started: {Phase}", phase);
        var items = await Task.Run(async () => await scanner.ScanAsync(context, cancellationToken), cancellationToken);
        var list = items.ToList();
        _logger.Information("Category scan completed: {Phase} ({Count} items)", phase, list.Count);
        return list;
    }

    public void CancelScan()
    {
        _cts?.Cancel();
    }
}
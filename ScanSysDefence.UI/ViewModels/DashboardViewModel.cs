using System.ComponentModel;
using System.Runtime.CompilerServices;
using ScanSysDefence.Core.Models;

namespace ScanSysDefence.UI.ViewModels;

public class DashboardViewModel : INotifyPropertyChanged
{
    private int _totalServices;
    private int _totalStartupItems;
    private int _totalProcesses;
    private int _totalDrivers;
    private int _totalTasks;
    private int _totalWmiSubscriptions;
    private int _criticalCount;
    private int _highCount;
    private int _mediumCount;
    private int _lowCount;
    private string _lastScanTime = "Никогда";
    private string _scanDuration = "-";
    private string _overallStatus = "Не сканировано";

    public event PropertyChangedEventHandler? PropertyChanged;

    public int TotalServices { get => _totalServices; set { _totalServices = value; OnPropertyChanged(); } }
    public int TotalStartupItems { get => _totalStartupItems; set { _totalStartupItems = value; OnPropertyChanged(); } }
    public int TotalProcesses { get => _totalProcesses; set { _totalProcesses = value; OnPropertyChanged(); } }
    public int TotalDrivers { get => _totalDrivers; set { _totalDrivers = value; OnPropertyChanged(); } }
    public int TotalTasks { get => _totalTasks; set { _totalTasks = value; OnPropertyChanged(); } }
    public int TotalWmiSubscriptions { get => _totalWmiSubscriptions; set { _totalWmiSubscriptions = value; OnPropertyChanged(); } }
    public int CriticalCount { get => _criticalCount; set { _criticalCount = value; OnPropertyChanged(); } }
    public int HighCount { get => _highCount; set { _highCount = value; OnPropertyChanged(); } }
    public int MediumCount { get => _mediumCount; set { _mediumCount = value; OnPropertyChanged(); } }
    public int LowCount { get => _lowCount; set { _lowCount = value; OnPropertyChanged(); } }
    public string LastScanTime { get => _lastScanTime; set { _lastScanTime = value; OnPropertyChanged(); } }
    public string ScanDuration { get => _scanDuration; set { _scanDuration = value; OnPropertyChanged(); } }
    public string OverallStatus { get => _overallStatus; set { _overallStatus = value; OnPropertyChanged(); } }

    public int TotalScanned => TotalServices + TotalStartupItems + TotalProcesses + TotalDrivers + TotalTasks + TotalWmiSubscriptions;

    public void UpdateFromScan(ScanResult result)
    {
        TotalServices = result.Services.Count;
        TotalStartupItems = result.StartupItems.Count;
        TotalProcesses = result.Processes.Count;
        TotalDrivers = result.Drivers.Count;
        TotalTasks = result.ScheduledTasks.Count;
        TotalWmiSubscriptions = result.WmiSubscriptions.Count;
        CriticalCount = result.CriticalCount;
        HighCount = result.HighCount;
        MediumCount = result.AllItems.Count(i => i.RiskAssessment.Level == RiskLevel.Medium);
        LowCount = result.AllItems.Count(i => i.RiskAssessment.Level == RiskLevel.Low);
        LastScanTime = result.CompletedAt?.ToString("dd.MM.yyyy HH:mm:ss") ?? DateTime.Now.ToString("dd.MM.yyyy HH:mm:ss");
        ScanDuration = result.Duration.ToString(@"mm\:ss");
        OverallStatus = result.CriticalCount > 0 ? "⚠ Обнаружены критические угрозы"
            : result.HighCount > 0 ? "Обнаружены подозрительные элементы"
            : "Система выглядит чистой";
        OnPropertyChanged(nameof(TotalScanned));
    }

    protected void OnPropertyChanged([CallerMemberName] string? propertyName = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}
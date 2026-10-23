using System.ComponentModel;
using System.Runtime.CompilerServices;
using ScanSysDefence.Core.Scanners;

namespace ScanSysDefence.UI.ViewModels;

public class SettingsViewModel : INotifyPropertyChanged
{
    private bool _includeSystemServices = true;
    private bool _includeMicrosoftSigned = true;
    private bool _deepProcessAnalysis = true;
    private bool _checkNetworkConnections = true;
    private bool _scanDrivers = true;
    private bool _scanScheduledTasks = true;
    private bool _scanWmiSubscriptions = true;
    private bool _scanBrowserExtensions = true;
    private int _timeoutSeconds = 300;
    private int _minFileAgeDays = 7;

    public event PropertyChangedEventHandler? PropertyChanged;

    public bool IncludeSystemServices { get => _includeSystemServices; set { _includeSystemServices = value; OnPropertyChanged(); } }
    public bool IncludeMicrosoftSigned { get => _includeMicrosoftSigned; set { _includeMicrosoftSigned = value; OnPropertyChanged(); } }
    public bool DeepProcessAnalysis { get => _deepProcessAnalysis; set { _deepProcessAnalysis = value; OnPropertyChanged(); } }
    public bool CheckNetworkConnections { get => _checkNetworkConnections; set { _checkNetworkConnections = value; OnPropertyChanged(); } }
    public bool ScanDrivers { get => _scanDrivers; set { _scanDrivers = value; OnPropertyChanged(); } }
    public bool ScanScheduledTasks { get => _scanScheduledTasks; set { _scanScheduledTasks = value; OnPropertyChanged(); } }
    public bool ScanWmiSubscriptions { get => _scanWmiSubscriptions; set { _scanWmiSubscriptions = value; OnPropertyChanged(); } }
    public bool ScanBrowserExtensions { get => _scanBrowserExtensions; set { _scanBrowserExtensions = value; OnPropertyChanged(); } }
    public int TimeoutSeconds { get => _timeoutSeconds; set { _timeoutSeconds = value; OnPropertyChanged(); } }
    public int MinFileAgeDays { get => _minFileAgeDays; set { _minFileAgeDays = value; OnPropertyChanged(); } }

    public ScanSettings ToScanSettings()
    {
        return new ScanSettings
        {
            IncludeSystemServices = IncludeSystemServices,
            IncludeMicrosoftSigned = IncludeMicrosoftSigned,
            DeepProcessAnalysis = DeepProcessAnalysis,
            CheckNetworkConnections = CheckNetworkConnections,
            ScanDrivers = ScanDrivers,
            ScanScheduledTasks = ScanScheduledTasks,
            ScanWmiSubscriptions = ScanWmiSubscriptions,
            ScanBrowserExtensions = ScanBrowserExtensions,
            TimeoutSeconds = TimeoutSeconds
        };
    }

    protected void OnPropertyChanged([CallerMemberName] string? propertyName = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}
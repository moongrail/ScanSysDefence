using System.IO;
using System.Windows;
using Microsoft.Extensions.DependencyInjection;
using Serilog;
using ScanSysDefence.Core.Analysis;
using ScanSysDefence.Core.Remediation;
using ScanSysDefence.Core.Scanners;
using ScanSysDefence.Core.Services;
using ScanSysDefence.UI.ViewModels;

namespace ScanSysDefence.UI;

public partial class App : Application
{
    private readonly ServiceProvider _serviceProvider;

    public App()
    {
        Log.Logger = new LoggerConfiguration()
            .MinimumLevel.Information()
            .WriteTo.File(
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "ScanSysDefence", "Logs", "scan-.log"),
                rollingInterval: RollingInterval.Day,
                retainedFileCountLimit: 7)
            .CreateLogger();

        var services = new ServiceCollection();
        ConfigureServices(services);
        _serviceProvider = services.BuildServiceProvider();
    }

    private void ConfigureServices(IServiceCollection services)
    {
        services.AddSingleton<Core.Services.ILogger>(new SerilogLogger(Log.Logger));

        services.AddSingleton<IDigitalSignatureService, DigitalSignatureService>();
        services.AddSingleton<IRestorePointService, RestorePointService>();
        services.AddSingleton<IRestorePointPromptService, RestorePointPromptService>();
        services.AddSingleton<ISafetyService, SafetyService>();
        services.AddSingleton<IDiskCleanupService, DiskCleanupService>();
        services.AddSingleton<IRegistryRepairService, RegistryRepairService>();
        services.AddSingleton<IProcessBehaviorAnalyzer, ProcessBehaviorAnalyzer>();
        services.AddSingleton<IRemediationService, RemediationService>();
        services.AddSingleton<IVirusScanService, VirusScanService>();

        services.AddSingleton<IScanner, ServiceScanner>();
        services.AddSingleton<IScanner, StartupScanner>();
        services.AddSingleton<IScanner, ProcessScanner>();
        services.AddSingleton<IScanner, DriverScanner>();
        services.AddSingleton<IScanner, ScheduledTaskScanner>();
        services.AddSingleton<IScanner, WmiSubscriptionScanner>();
        services.AddSingleton<IScanner, BrowserExtensionScanner>();

        services.AddSingleton<ScanCoordinator>();
        services.AddSingleton<MainViewModel>();
        services.AddSingleton<DashboardViewModel>();
        services.AddSingleton<ResultsViewModel>();
        services.AddSingleton<DiskCleanupViewModel>();
        services.AddSingleton<RegistryRepairViewModel>();
        services.AddSingleton<MalwareViewModel>();
        services.AddSingleton<VirusScanViewModel>();
        services.AddSingleton<QuarantineViewModel>();
        services.AddSingleton<SettingsViewModel>();

        services.AddTransient<MainWindow>();
    }

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        var mainWindow = _serviceProvider.GetRequiredService<MainWindow>();
        mainWindow.DataContext = _serviceProvider.GetRequiredService<MainViewModel>();
        mainWindow.Show();
    }

    protected override void OnExit(ExitEventArgs e)
    {
        _serviceProvider.Dispose();
        Log.CloseAndFlush();
        base.OnExit(e);
    }
}
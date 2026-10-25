using ScanSysDefence.Core.Models;
using ScanSysDefence.Core.Scanners;
using ScanSysDefence.Core.Services;
using ScanSysDefence.Native.Win32;

namespace ScanSysDefence.Tests;

/// <summary>
/// Тесты, требующие Windows: в Linux-контейнере показываются как Skipped,
/// на Windows-хосте и в Windows-контейнере выполняются полностью.
/// </summary>
public class WindowsIntegrationTests
{
    private static void RequireWindows() =>
        Skip.If(!OperatingSystem.IsWindows(), "Тест требует Windows");

    [SkippableFact]
    public async Task DigitalSignatureService_Notepad_IsSignedByMicrosoft()
    {
        RequireWindows();

        var service = new DigitalSignatureService(new FakeLogger());
        var info = await service.VerifySignatureAsync(@"C:\Windows\System32\notepad.exe");

        Assert.True(info.IsSigned, "notepad.exe должен быть подписан (каталожная подпись)");
        Assert.False(string.IsNullOrWhiteSpace(info.Publisher));
    }

    [SkippableFact]
    public async Task DigitalSignatureService_MissingFile_ResultIsCached()
    {
        RequireWindows();

        var service = new DigitalSignatureService(new FakeLogger());
        const string missing = @"C:\definitely-missing-file-12345.exe";

        var first = await service.VerifySignatureAsync(missing);
        var second = await service.VerifySignatureAsync(missing);

        Assert.NotEmpty(first.Errors);
        Assert.Same(first, second); // повторный вызов вернул закэшированный результат
    }

    [SkippableFact]
    public void NetworkTable_GetTcpAndUdpEndpoints_DoNotThrow()
    {
        RequireWindows();

        var tcp = NetworkTable.GetTcpEndpoints();
        var udp = NetworkTable.GetUdpEndpoints();

        Assert.NotNull(tcp);
        Assert.NotNull(udp);
        Assert.All(tcp, e => Assert.True(e.ProcessId >= 0));
    }

    [SkippableFact]
    public async Task RegistryRepairService_GetBackups_ReturnsList()
    {
        RequireWindows();

        var service = new RegistryRepairService(new FakeLogger());
        var backups = await service.GetBackupsAsync();

        Assert.NotNull(backups);
    }

    [Fact]
    public async Task DiskCleanupService_GetCategories_ReturnsCategories()
    {
        var service = new DiskCleanupService(new FakeLogger(), new SafetyServiceStub());
        var categories = await service.GetCategoriesAsync();

        Assert.NotNull(categories);
        Assert.NotEmpty(categories);
    }

    [SkippableFact]
    public async Task BrowserExtensionScanner_RunsWithoutExceptions()
    {
        RequireWindows();

        var scanner = new ScanSysDefence.Core.Scanners.BrowserExtensionScanner(new FakeLogger());
        var items = await scanner.ScanAsync(new ScanSysDefence.Core.Scanners.ScanContext
        {
            Settings = new ScanSettings { ScanBrowserExtensions = true }
        });

        Assert.NotNull(items);
    }

    [SkippableFact]
    public async Task ProcessScanner_ScanCompletesWithinTimeout()
    {
        RequireWindows();

        var logger = new FakeLogger();
        var scanner = new ScanSysDefence.Core.Scanners.ProcessScanner(logger, new DigitalSignatureService(logger));

        using var cts = new CancellationTokenSource(TimeSpan.FromMinutes(5));
        var task = scanner.ScanAsync(new ScanSysDefence.Core.Scanners.ScanContext
        {
            Settings = new ScanSettings
            {
                DeepProcessAnalysis = true,
                CheckNetworkConnections = true,
                IncludeMicrosoftSigned = false
            }
        }, cts.Token);

        var completed = await Task.WhenAny(task, Task.Delay(TimeSpan.FromMinutes(5)));
        Assert.Same(task, completed); // сканирование не должно зависать

        var items = await task;
        Assert.NotNull(items);
    }

    // ---------- Регрессионные тесты сканеров (вкладки «Результаты») ----------

    [SkippableFact]
    public async Task ServiceScanner_ScanFindsServices()
    {
        RequireWindows();

        var scanner = new ServiceScanner(new FakeLogger(), new DigitalSignatureService(new FakeLogger()));
        var items = (await scanner.ScanAsync(new ScanContext { Settings = new ScanSettings() })).ToList();

        Assert.NotEmpty(items); // раньше падало из-за ValueMap «Share Process»
    }

    [SkippableFact]
    public async Task DriverScanner_ScanFindsDrivers()
    {
        RequireWindows();

        var scanner = new DriverScanner(new FakeLogger(), new DigitalSignatureService(new FakeLogger()));
        var items = (await scanner.ScanAsync(new ScanContext
        {
            Settings = new ScanSettings { ScanDrivers = true }
        })).ToList();

        Assert.NotEmpty(items);
    }

    [SkippableFact]
    public async Task ScheduledTaskScanner_ScanFindsTasks()
    {
        RequireWindows();

        var logger = new FakeLogger();
        var scanner = new ScheduledTaskScanner(logger, new DigitalSignatureService(new FakeLogger()));
        var items = (await scanner.ScanAsync(new ScanContext
        {
            Settings = new ScanSettings { ScanScheduledTasks = true }
        })).ToList();

        Assert.True(items.Count > 0,
            $"Задач найдено: {items.Count}. Лог сканера: {string.Join(" | ", logger.Messages)}");
    }

    [SkippableFact]
    public async Task WmiSubscriptionScanner_RunsWithoutExceptions()
    {
        RequireWindows();

        var scanner = new WmiSubscriptionScanner(new FakeLogger(), new DigitalSignatureService(new FakeLogger()));
        var items = (await scanner.ScanAsync(new ScanContext
        {
            Settings = new ScanSettings { ScanWmiSubscriptions = true }
        })).ToList();

        Assert.NotNull(items);
    }
}

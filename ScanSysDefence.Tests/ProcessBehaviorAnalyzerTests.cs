using ScanSysDefence.Core.Analysis;
using ScanSysDefence.Core.Models;

namespace ScanSysDefence.Tests;

public class ProcessBehaviorAnalyzerTests
{
    [Fact]
    public async Task AnalyzeAsync_ReturnsFiveCategoriesWithRussianNames()
    {
        var analyzer = new ProcessBehaviorAnalyzer(new FakeLogger());
        var process = new ProcessInfo
        {
            ProcessId = 1234,
            ProcessName = "powershell.exe",
            Path = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            CommandLine = "powershell.exe -enc SQBFAFgA"
        };

        var report = await analyzer.AnalyzeAsync(process);

        Assert.Equal("powershell.exe", report.ProcessName);
        Assert.Equal(1234, report.ProcessId);
        Assert.Equal(5, report.Categories.Count);
        Assert.All(report.Categories, c => Assert.False(string.IsNullOrWhiteSpace(c.NameRu)));
        Assert.False(string.IsNullOrWhiteSpace(report.Summary));
        Assert.False(string.IsNullOrWhiteSpace(report.DetailedDescription));
        Assert.NotNull(report.MITRETechniques);
        Assert.NotNull(report.Indicators);
    }

    [Fact]
    public async Task AnalyzeAsync_SuspiciousCommandLine_ProducesHighRiskCategory()
    {
        var analyzer = new ProcessBehaviorAnalyzer(new FakeLogger());
        var process = new ProcessInfo
        {
            ProcessName = "powershell.exe",
            CommandLine = "powershell -nop -w hidden -enc SQBFAFgA",
            Path = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
        };

        var report = await analyzer.AnalyzeAsync(process);

        var cmdCategory = report.Categories.FirstOrDefault(c => c.Name == "Command Line");
        Assert.NotNull(cmdCategory);
        Assert.True(cmdCategory!.Risk >= RiskLevel.Medium,
            $"Ожидался риск Medium+ для скрытой команды, получен {cmdCategory.Risk}");
    }

    [Fact]
    public async Task AnalyzeFromSnapshotAsync_UsesSnapshotProcess()
    {
        var analyzer = new ProcessBehaviorAnalyzer(new FakeLogger());
        var snapshot = new ProcessSnapshot
        {
            Source = "test",
            Process = new ProcessInfo
            {
                ProcessName = "explorer.exe",
                Path = @"C:\Windows\explorer.exe",
                IsSigned = true,
                SignatureValid = true,
                Publisher = "Microsoft Corporation"
            }
        };

        var report = await analyzer.AnalyzeFromSnapshotAsync(snapshot);

        Assert.Equal("explorer.exe", report.ProcessName);
        Assert.NotEmpty(report.Categories);
    }
}

using ScanSysDefence.Core.Analysis;
using ScanSysDefence.Core.Models;

namespace ScanSysDefence.Tests;

public class RiskAnalyzerTests
{
    [Fact]
    public async Task AnalyzeProcessAsync_MasqueradingSvchostFromTemp_FlagsCriticalFactors()
    {
        var process = new ProcessInfo
        {
            ProcessName = "svchost.exe",
            Path = @"C:\Users\user\AppData\Local\Temp\svchost.exe",
            IsSigned = false,
            SignatureValid = false
        };

        var assessment = await RiskAnalyzer.AnalyzeProcessAsync(process, new FakeSignatureService());

        Assert.Contains(assessment.Factors, f => f.Id == "PROC_MASQUERADING");
        Assert.Contains(assessment.Factors, f => f.Id == "PROC_FROM_TEMP");
        Assert.True(assessment.TotalScore >= 80, $"Ожидался высокий счёт, получено {assessment.TotalScore}");
        Assert.Equal(RiskLevel.Critical, assessment.Level);
    }

    [Fact]
    public async Task AnalyzeProcessAsync_TrustedSignedProcess_LowRisk()
    {
        var process = new ProcessInfo
        {
            ProcessName = "notepad.exe",
            Path = @"C:\Windows\System32\notepad.exe",
            IsSigned = true,
            SignatureValid = true,
            Publisher = "CN=Microsoft Windows, O=Microsoft Corporation",
            IsSystemItem = true
        };

        var assessment = await RiskAnalyzer.AnalyzeProcessAsync(process, new FakeSignatureService());

        Assert.Contains(assessment.Factors, f => f.Id == "PROC_TRUSTED_SIGNED");
        Assert.DoesNotContain(assessment.Factors, f => f.Id == "PROC_UNSIGNED");
        Assert.True(assessment.TotalScore <= 20, $"Ожидался низкий счёт, получено {assessment.TotalScore}");
    }

    [Fact]
    public async Task AnalyzeProcessAsync_EncodedPowerShellCommand_FlagsCommandLine()
    {
        var process = new ProcessInfo
        {
            ProcessName = "powershell.exe",
            Path = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            CommandLine = "powershell.exe -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACkA",
            IsSigned = true,
            SignatureValid = true,
            Publisher = "Microsoft Corporation"
        };

        var assessment = await RiskAnalyzer.AnalyzeProcessAsync(process, new FakeSignatureService());

        Assert.Contains(assessment.Factors, f => f.Id == "PROC_SUSPICIOUS_CMDLINE");
    }

    [Fact]
    public async Task AnalyzeScheduledTaskAsync_HiddenTask_ContainsHiddenFactor()
    {
        var task = new ScheduledTaskInfo
        {
            Name = "Updater",
            Hidden = true,
            Author = "Unknown"
        };

        var assessment = await RiskAnalyzer.AnalyzeScheduledTaskAsync(task, new FakeSignatureService());

        Assert.Contains(assessment.Factors, f => f.Id == "TASK_HIDDEN");
        Assert.True(assessment.TotalScore >= 25);
    }

    [Fact]
    public async Task AnalyzeServiceAsync_UnsignedService_FlagsSignature()
    {
        var service = new ServiceInfo
        {
            ServiceName = "EvilService",
            DisplayName = "Evil Service",
            BinaryPath = @"C:\Users\Public\evil.exe",
            IsSigned = false,
            SignatureValid = false
        };

        var assessment = await RiskAnalyzer.AnalyzeServiceAsync(service, new FakeSignatureService());

        Assert.Contains(assessment.Factors, f => f.Id == "SVC_UNSIGNED");
        Assert.True(assessment.TotalScore >= 30);
    }
}

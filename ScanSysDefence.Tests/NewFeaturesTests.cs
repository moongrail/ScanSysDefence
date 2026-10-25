using ScanSysDefence.Core.Remediation;
using ScanSysDefence.Core.Services;
using ScanSysDefence.Core.Utils;

namespace ScanSysDefence.Tests;

/// <summary>Безопасное чтение WMI-значений, включая строки из ValueMap («Share Process»).</summary>
public class WmiSafeTests
{
    [Theory]
    [InlineData("Share Process", 32u)]
    [InlineData("Own Process", 16u)]
    [InlineData("Kernel Driver", 1u)]
    [InlineData("File System Driver", 2u)]
    [InlineData("Adapter", 4u)]
    [InlineData("Interactive Process", 256u)]
    public void ParseUInt32_ValueMapStrings_AreMapped(string value, uint expected)
    {
        Assert.Equal(expected, WmiSafe.ParseUInt32(value));
    }

    [Fact]
    public void ParseUInt32_Numbers_Work()
    {
        Assert.Equal(42u, WmiSafe.ParseUInt32("42"));
        Assert.Equal(5u, WmiSafe.ParseUInt32(5));
        Assert.Equal(7u, WmiSafe.ParseUInt32((byte)7));
        Assert.Equal(9u, WmiSafe.ParseUInt32((ushort)9));
    }

    [Fact]
    public void ParseUInt32_InvalidOrNull_ReturnsNull()
    {
        Assert.Null(WmiSafe.ParseUInt32("мусор"));
        Assert.Null(WmiSafe.ParseUInt32(null));
        Assert.Null(WmiSafe.ParseUInt32(DBNull.Value));
        Assert.Null(WmiSafe.ParseUInt32(-1));
    }

    [Fact]
    public void ParseInt32_Works()
    {
        Assert.Equal(123, WmiSafe.ParseInt32("123"));
        Assert.Equal(-5, WmiSafe.ParseInt32(-5));
        Assert.Equal(77, WmiSafe.ParseInt32(77));
        Assert.Null(WmiSafe.ParseInt32("abc"));
        Assert.Null(WmiSafe.ParseInt32(null));
    }

    [Fact]
    public void ParseBool_Works()
    {
        Assert.True(WmiSafe.ParseBool("true"));
        Assert.True(WmiSafe.ParseBool(1));
        Assert.False(WmiSafe.ParseBool(0));
        Assert.False(WmiSafe.ParseBool("false"));
        Assert.Null(WmiSafe.ParseBool("не bool"));
        Assert.Null(WmiSafe.ParseBool(null));
    }

    [Fact]
    public void ParseString_Works()
    {
        Assert.Equal("hello", WmiSafe.ParseString("hello"));
        Assert.Null(WmiSafe.ParseString(null));
        Assert.Null(WmiSafe.ParseString(DBNull.Value));
        Assert.Equal("5", WmiSafe.ParseString(5));
    }
}

/// <summary>Эвристики антивирусной проверки файлов (без внешних движков).</summary>
public class VirusScanServiceTests : IDisposable
{
    private readonly string _root;

    public VirusScanServiceTests()
    {
        _root = Path.Combine(Path.GetTempPath(), "wss_virustest_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_root);
    }

    public void Dispose()
    {
        try { Directory.Delete(_root, true); } catch { /* ignore */ }
    }

    private static VirusScanService CreateService() => new(new FakeLogger(), new FakeSignatureService());

    private static VirusScanOptions Options() => new()
    {
        SkipSystemFolders = false,
        DeepContentCheck = true
    };

    [Fact]
    public async Task Scan_DetectsEicarTestFile()
    {
        var path = Path.Combine(_root, "eicar.com");
        await File.WriteAllTextAsync(path, @"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*");

        var threats = await CreateService().ScanAsync(_root, Options());

        var threat = Assert.Single(threats);
        Assert.Contains(threat.Reasons, r => r.Contains("EICAR", StringComparison.OrdinalIgnoreCase));
        Assert.True(threat.RiskAssessment.TotalScore >= 60);
    }

    [Fact]
    public async Task Scan_DetectsDoubleExtension()
    {
        await File.WriteAllTextAsync(Path.Combine(_root, "invoice.pdf.exe"), "fake content");

        var threats = await CreateService().ScanAsync(_root, Options());

        Assert.Contains(threats, t => t.Reasons.Any(r => r.Contains("Двойное расширение")));
    }

    [Fact]
    public async Task Scan_DetectsDangerousScript()
    {
        await File.WriteAllTextAsync(Path.Combine(_root, "run.ps1"), "powershell -enc SQBFAFgA");

        var threats = await CreateService().ScanAsync(_root, Options());

        Assert.Contains(threats, t => t.Reasons.Any(r => r.Contains("base64")));
    }

    [Fact]
    public async Task Scan_DetectsMinerStrings()
    {
        await File.WriteAllTextAsync(Path.Combine(_root, "miner.bat"), "start xmrig.exe --url stratum+tcp://pool:3333");

        var threats = await CreateService().ScanAsync(_root, Options());

        Assert.Contains(threats, t => t.Reasons.Any(r => r.Contains("майнер", StringComparison.OrdinalIgnoreCase)));
    }

    [Fact]
    public async Task Scan_CleanTextFile_FindsNothing()
    {
        await File.WriteAllTextAsync(Path.Combine(_root, "notes.txt"), "обычный текст без команд, просто заметки");

        var threats = await CreateService().ScanAsync(_root, Options());

        Assert.Empty(threats);
    }

    [Fact]
    public async Task Scan_MissingFolder_ReturnsEmpty()
    {
        var threats = await CreateService().ScanAsync(Path.Combine(_root, "no-such-dir"), Options());
        Assert.Empty(threats);
    }
}

/// <summary>Карантин: файл можно восстановить на прежнее место и удалить навсегда.</summary>
public class QuarantineRoundtripTests
{
    [Fact]
    public async Task Quarantine_Restore_And_DeleteForever_Work()
    {
        var remediation = new RemediationService(
            new FakeLogger(),
            new RestorePointServiceStub(),
            new RestorePointPromptServiceStub(),
            new SafetyServiceStub());

        var file = Path.Combine(Path.GetTempPath(), $"wss_quarantine_{Guid.NewGuid():N}.txt");
        const string content = "MALWARE-CONTENT-12345";
        await File.WriteAllTextAsync(file, content);

        // 1. Помещаем в карантин
        var quarantineResult = await remediation.QuarantineFileAsync(file);
        Assert.True(quarantineResult.Success, quarantineResult.Error);
        Assert.False(File.Exists(file), "после помещения в карантин файла на прежнем месте быть не должно");

        // 2. Видим запись в списке карантина, с исходным путём
        var entries = await remediation.GetQuarantineEntriesAsync();
        var entry = Assert.Single(entries, e =>
            e.OriginalPath.Equals(file, StringComparison.OrdinalIgnoreCase));
        Assert.True(entry.CanRestore, "запись должна позволять восстановление");

        // 3. Восстанавливаем — файл возвращается на прежнее место с тем же содержимым
        var restoreResult = await remediation.RestoreFromQuarantineAsync(entry.QuarantinePath);
        Assert.True(restoreResult.Success, restoreResult.Error);
        Assert.True(File.Exists(file), "файл должен вернуться на исходное место");
        Assert.Equal(content, await File.ReadAllTextAsync(file));

        // 4. Снова в карантин и удаляем навсегда
        var quarantineAgain = await remediation.QuarantineFileAsync(file);
        Assert.True(quarantineAgain.Success, quarantineAgain.Error);

        var deleteResult = await remediation.DeleteFromQuarantineAsync(quarantineAgain.BackupPath);
        Assert.True(deleteResult.Success, deleteResult.Error);
        Assert.False(File.Exists(quarantineAgain.BackupPath), "файл должен быть удалён из карантина");

        try { if (File.Exists(file)) File.Delete(file); } catch { /* ignore */ }
    }
}

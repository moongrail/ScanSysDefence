using System.Text;
using ScanSysDefence.Core.Scanners;
using ScanSysDefence.Core.Models;
using ScanSysDefence.Core.Services;
using Xunit;

namespace ScanSysDefence.Tests;

/// <summary>
/// Диагностический тест для VM: подробно пишет результаты проверок в C:\wss\diag-out.txt.
/// Запускается вместе с остальными; файл читается после прогона.
/// </summary>
public class DiagTests
{
    [Fact]
    public async Task Diag_WriteResults()
    {
        var sb = new List<string>();
        sb.Add("=== DIAG START " + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + " ===");

        // --- 1) EICAR: примитив чтения + сканер ---
        try
        {
            var dir = Path.Combine(Path.GetTempPath(), "wss_diag_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dir);
            var file = Path.Combine(dir, "eicar.com");
            await File.WriteAllTextAsync(file, "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*");

            var bytes = await File.ReadAllBytesAsync(file);
            var latin1 = Encoding.Latin1.GetString(bytes);
            sb.Add($"EICAR file bytes={bytes.Length}; latin1 contains marker={latin1.Contains("EICAR-STANDARD-ANTIVIRUS-TEST-FILE", StringComparison.OrdinalIgnoreCase)}");

            var logger = new FakeLogger();
            var svc = new VirusScanService(logger, new FakeSignatureService());
            var threats = await svc.ScanAsync(dir, new VirusScanOptions { SkipSystemFolders = false, DeepContentCheck = true });
            sb.Add($"VirusScanService threats={threats.Count}");
            foreach (var t in threats)
            {
                sb.Add("  THREAT: " + t.ThreatName + " (score=" + t.RiskAssessment.TotalScore + ")");
                foreach (var r in t.Reasons) sb.Add("    reason: " + r);
            }
            sb.Add("VirusScanService log: " + string.Join(" | ", logger.Messages));
            try { Directory.Delete(dir, true); } catch { }
        }
        catch (Exception ex)
        {
            sb.Add("EICAR diag EXCEPTION: " + ex);
        }

        // --- 2) Задачи планировщика: COM count/Item + сканер ---
        try
        {
            var schedulerType = Type.GetTypeFromProgID("Schedule.Service");
            dynamic scheduler = Activator.CreateInstance(schedulerType!)!;
            scheduler.Connect();
            object rootFolder = scheduler.GetFolder("\\");
            var all = new List<object>();
            CollectTasks(rootFolder, all);
            sb.Add($"COM count/Item walk: {all.Count} tasks");
            var shown = 0;
            foreach (var t in all)
            {
                dynamic td = t;
                sb.Add("  task: " + (string)td.Path);
                if (++shown >= 5) break;
            }

            var logger = new FakeLogger();
            var scanner = new ScheduledTaskScanner(logger, new DigitalSignatureService(new FakeLogger()));
            var items = (await scanner.ScanAsync(new ScanContext
            {
                Settings = new ScanSettings { ScanScheduledTasks = true }
            })).ToList();
            sb.Add($"ScheduledTaskScanner items={items.Count}");
            sb.Add("scanner log: " + string.Join(" | ", logger.Messages));
        }
        catch (Exception ex)
        {
            sb.Add("Tasks diag EXCEPTION: " + ex);
        }

        sb.Add("=== DIAG END ===");
        // Запись только в средах, где каталог C:\wss существует (тестовая VM);
        // на обычной машине диагностика ничего не пишет и ни на что не влияет.
        if (Directory.Exists(@"C:\wss"))
        {
            await File.WriteAllLinesAsync(@"C:\wss\diag-out.txt", sb, Encoding.UTF8);
        }
        Assert.True(true);
    }

    private static void CollectTasks(object folderObj, List<object> sink)
    {
        dynamic folder = folderObj;
        dynamic tasks = folder.GetTasks(1);
        int count = (int)tasks.Count;
        for (var i = 1; i <= count; i++) sink.Add((object)tasks.Item(i));

        dynamic subFolders = folder.GetFolders(0);
        int folderCount = (int)subFolders.Count;
        for (var i = 1; i <= folderCount; i++) CollectTasks((object)subFolders.Item(i), sink);
    }
}

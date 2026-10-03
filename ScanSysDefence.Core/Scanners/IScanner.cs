using ScanSysDefence.Core.Models;
using ScanSysDefence.Core.Services;

namespace ScanSysDefence.Core.Scanners;

public interface IScanner
{
    string Name { get; }
    ScanPhase Phase { get; }
    Task<IEnumerable<ScanItemBase>> ScanAsync(ScanContext context, CancellationToken cancellationToken = default);
}

public class ScanContext
{
    public ScanSettings Settings { get; set; } = new();
    public IProgress<ScanProgress>? Progress { get; set; }
    public ILogger? Logger { get; set; }
}

public class ScanSettings
{
    public bool IncludeSystemServices { get; set; } = true;
    public bool IncludeMicrosoftSigned { get; set; } = true;
    public bool DeepProcessAnalysis { get; set; } = true;
    public bool CheckNetworkConnections { get; set; } = true;
    public bool ScanDrivers { get; set; } = true;
    public bool ScanScheduledTasks { get; set; } = true;
    public bool ScanWmiSubscriptions { get; set; } = true;
    public bool ScanBrowserExtensions { get; set; } = true;
    public int TimeoutSeconds { get; set; } = 300;
    public List<string> ExcludedPaths { get; set; } = new();
    public List<string> ExcludedPublishers { get; set; } = new() { "Microsoft Corporation", "Windows", "Microsoft Windows" };
    public List<string> ExcludedProcessNames { get; set; } = new();
}
using ScanSysDefence.Core.Models;

namespace ScanSysDefence.Core.Analysis;

public interface IProcessBehaviorAnalyzer
{
    Task<ProcessBehaviorReport> AnalyzeAsync(ProcessInfo process, CancellationToken ct = default);
    Task<ProcessBehaviorReport> AnalyzeFromSnapshotAsync(ProcessSnapshot snapshot, CancellationToken ct = default);
}

public class ProcessSnapshot
{
    public ProcessInfo Process { get; set; } = new();
    public DateTime CapturedAt { get; set; } = DateTime.Now;
    public string Source { get; set; } = string.Empty;
}

public class ProcessBehaviorReport
{
    public string ProcessName { get; set; } = string.Empty;
    public int ProcessId { get; set; }
    public List<BehaviorCategory> Categories { get; set; } = new();
    public List<NetworkBehavior> NetworkBehaviors { get; set; } = new();
    public List<FileBehavior> FileBehaviors { get; set; } = new();
    public List<string> MITRETechniques { get; set; } = new();
    public List<string> Indicators { get; set; } = new();
    public RiskLevel OverallRisk { get; set; }
    public string Summary { get; set; } = string.Empty;
    public string DetailedDescription { get; set; } = string.Empty;
}

public class BehaviorCategory
{
    public string Name { get; set; } = string.Empty;
    public string NameRu { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string DescriptionRu { get; set; } = string.Empty;
    public RiskLevel Risk { get; set; }
    public List<string> Evidence { get; set; } = new();
}

public class NetworkBehavior
{
    public string RemoteAddress { get; set; } = string.Empty;
    public int RemotePort { get; set; }
    public string Protocol { get; set; } = string.Empty;
    public string State { get; set; } = string.Empty;
    public string ProcessName { get; set; } = string.Empty;
    public string DescriptionRu { get; set; } = string.Empty;
    public RiskLevel Risk { get; set; }
    public bool IsSuspicious { get; set; }
}

public enum FileOperation
{
    Execute,
    Read,
    Write,
    Create,
    Delete,
    MemoryMap
}

public class FileBehavior
{
    public string Path { get; set; } = string.Empty;
    public FileOperation Operation { get; set; }
    public string DescriptionRu { get; set; } = string.Empty;
    public RiskLevel Risk { get; set; }
    public bool IsSystemPath { get; set; }
    public bool IsSensitivePath { get; set; }
}

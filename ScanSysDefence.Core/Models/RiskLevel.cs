namespace ScanSysDefence.Core.Models;

public enum RiskLevel
{
    Informational = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4
}

public enum RiskSeverity
{
    None = 0,
    Informational = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4
}

public static class RiskLevelExtensions
{
    public static string GetDisplayName(this RiskLevel level) => level switch
    {
        RiskLevel.Critical => "Критический",
        RiskLevel.High => "Высокий",
        RiskLevel.Medium => "Средний",
        RiskLevel.Low => "Низкий",
        RiskLevel.Informational => "Информационный",
        _ => level.ToString()
    };

    public static string GetColor(this RiskLevel level) => level switch
    {
        RiskLevel.Critical => "#F14C4C",
        RiskLevel.High => "#E86C00",
        RiskLevel.Medium => "#FFB900",
        RiskLevel.Low => "#107C10",
        RiskLevel.Informational => "#0078D4",
        _ => "#666666"
    };

    public static int GetScoreThreshold(this RiskLevel level) => level switch
    {
        RiskLevel.Critical => 80,
        RiskLevel.High => 60,
        RiskLevel.Medium => 40,
        RiskLevel.Low => 20,
        RiskLevel.Informational => 0,
        _ => 0
    };
}
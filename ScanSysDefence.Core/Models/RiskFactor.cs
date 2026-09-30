namespace ScanSysDefence.Core.Models;

public class RiskFactor
{
    public string Id { get; set; } = string.Empty;
    public string Category { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public int Score { get; set; }
    public RiskSeverity Severity { get; set; }
    public string Evidence { get; set; } = string.Empty;
    public string Recommendation { get; set; } = string.Empty;
    public DateTime DetectedAt { get; set; } = DateTime.Now;
}

public class RiskAssessment
{
    public int TotalScore { get; set; }
    public RiskLevel Level { get; set; }
    public List<RiskFactor> Factors { get; set; } = new();
    public DateTime AssessedAt { get; set; } = DateTime.Now;
    public string Summary => GenerateSummary();

    private string GenerateSummary()
    {
        if (Factors.Count == 0) return "Рисков не обнаружено";
        var critical = Factors.Count(f => f.Severity == RiskSeverity.Critical);
        var high = Factors.Count(f => f.Severity == RiskSeverity.High);
        var medium = Factors.Count(f => f.Severity == RiskSeverity.Medium);
        var low = Factors.Count(f => f.Severity == RiskSeverity.Low);
        
        var parts = new List<string>();
        if (critical > 0) parts.Add($"{critical} крит.");
        if (high > 0) parts.Add($"{high} высоко");
        if (medium > 0) parts.Add($"{medium} средне");
        if (low > 0) parts.Add($"{low} низко");
        
        return $"Оценка: {TotalScore}/100 ({Level.GetDisplayName()}) — {string.Join(", ", parts)}";
    }
}
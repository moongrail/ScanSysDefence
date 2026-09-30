namespace ScanSysDefence.Core.Models;

public abstract class ScanItemBase
{
    public string Id { get; set; } = Guid.NewGuid().ToString();
    public virtual string Name { get; set; } = string.Empty;
    public virtual string Description { get; set; } = string.Empty;
    public virtual string Path { get; set; } = string.Empty;
    public string Publisher { get; set; } = string.Empty;
    public virtual string Version { get; set; } = string.Empty;
    public bool IsSigned { get; set; }
    public bool SignatureValid { get; set; }
    public string SignatureDetails { get; set; } = string.Empty;
    public RiskAssessment RiskAssessment { get; set; } = new();
    public DateTime ScannedAt { get; set; } = DateTime.Now;
    public Dictionary<string, object> Metadata { get; set; } = new();
    public bool IsSelected { get; set; }
    public bool IsSystemItem { get; set; }
    public bool CanStop { get; set; }
    public bool CanDisable { get; set; }
    public bool CanDelete { get; set; }
}

public class DigitalSignatureInfo
{
    public bool IsSigned { get; set; }
    public bool IsValid { get; set; }
    public string Publisher { get; set; } = string.Empty;
    public string Issuer { get; set; } = string.Empty;
    public DateTime ValidFrom { get; set; }
    public DateTime ValidTo { get; set; }
    public string Thumbprint { get; set; } = string.Empty;
    public string Subject { get; set; } = string.Empty;
    public List<string> Errors { get; set; } = new();
    public string RawDetails { get; set; } = string.Empty;
}
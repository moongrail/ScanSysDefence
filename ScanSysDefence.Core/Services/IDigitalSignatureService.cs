using ScanSysDefence.Core.Models;

namespace ScanSysDefence.Core.Services;

public interface IDigitalSignatureService
{
    Task<DigitalSignatureInfo> VerifySignatureAsync(string filePath);
    Task<DigitalSignatureInfo> VerifySignatureAsync(string filePath, CancellationToken cancellationToken);
}
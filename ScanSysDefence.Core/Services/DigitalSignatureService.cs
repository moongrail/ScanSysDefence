using System.Collections.Concurrent;
using ScanSysDefence.Core.Models;
using ScanSysDefence.Native.Win32;

namespace ScanSysDefence.Core.Services;

public class DigitalSignatureService : IDigitalSignatureService
{
    private readonly ILogger _logger;

    /// <summary>
    /// Кэш результатов проверки по пути файла: один и тот же файл (ntdll.dll и т.п.)
    /// проверяется один раз за время работы приложения.
    /// </summary>
    private readonly ConcurrentDictionary<string, DigitalSignatureInfo> _cache = new(StringComparer.OrdinalIgnoreCase);

    public DigitalSignatureService(ILogger logger)
    {
        _logger = logger;
    }

    public async Task<DigitalSignatureInfo> VerifySignatureAsync(string filePath)
    {
        return await VerifySignatureAsync(filePath, CancellationToken.None);
    }

    public async Task<DigitalSignatureInfo> VerifySignatureAsync(string filePath, CancellationToken cancellationToken)
    {
        if (!string.IsNullOrWhiteSpace(filePath) && _cache.TryGetValue(filePath, out var cached))
        {
            return cached;
        }

        var result = await Task.Run(() => VerifySignatureCore(filePath), cancellationToken);

        if (!string.IsNullOrWhiteSpace(filePath))
        {
            _cache[filePath] = result;
        }

        return result;
    }

    private DigitalSignatureInfo VerifySignatureCore(string filePath)
    {
        var result = new DigitalSignatureInfo();

        if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
        {
            result.Errors.Add("File not found or path is empty");
            return result;
        }

        try
        {
            // Полная проверка Authenticode: встроенная подпись + каталоги
            // (большинство системных файлов Windows подписано через каталоги).
            var auth = AuthenticodeVerifier.VerifyFile(filePath);

            result.IsSigned = auth.IsSigned;
            result.IsValid = auth.IsValid;
            result.Publisher = auth.Publisher;
            result.Issuer = auth.Issuer;
            result.Thumbprint = auth.Thumbprint;
            result.ValidFrom = auth.ValidFrom ?? DateTime.MinValue;
            result.ValidTo = auth.ValidTo ?? DateTime.MinValue;

            if (!auth.IsSigned)
            {
                result.Errors.Add("No signature found");
            }
            else if (!auth.IsValid)
            {
                result.Errors.Add(auth.ResultMessage);
            }

            var kind = !auth.IsSigned ? "None" : auth.IsCatalogSigned ? "Catalog" : "Embedded";
            var validRange = auth.ValidFrom.HasValue && auth.ValidTo.HasValue
                ? $"\nValid: {auth.ValidFrom:g} - {auth.ValidTo:g}"
                : string.Empty;
            result.RawDetails =
                $"Signature: {kind}\n" +
                $"Subject: {auth.Publisher}\n" +
                $"Issuer: {auth.Issuer}" +
                validRange + "\n" +
                $"Thumbprint: {auth.Thumbprint}\n" +
                $"Trust: {auth.ResultMessage}";
        }
        catch (Exception ex)
        {
            result.Errors.Add($"Verification error: {ex.Message}");
            _logger.Error(ex, "Signature verification failed for {Path}", filePath);
        }

        return result;
    }
}

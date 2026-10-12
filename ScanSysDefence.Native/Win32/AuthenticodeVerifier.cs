using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace ScanSysDefence.Native.Win32;

/// <summary>
/// Результат проверки Authenticode-подписи файла
/// (встроенная подпись или подпись через каталог, как sigcheck).
/// </summary>
public sealed class AuthenticodeVerificationResult
{
    public bool IsSigned { get; set; }
    public bool IsValid { get; set; }
    public bool IsCatalogSigned { get; set; }
    public string Publisher { get; set; } = string.Empty;
    public string Issuer { get; set; } = string.Empty;
    public string Thumbprint { get; set; } = string.Empty;
    public DateTime? ValidFrom { get; set; }
    public DateTime? ValidTo { get; set; }
    public int ResultCode { get; set; }
    public string ResultMessage { get; set; } = string.Empty;
}

/// <summary>
/// Проверка Authenticode через WinVerifyTrust:
/// 1) встроенная подпись (WTD_CHOICE_FILE);
/// 2) каталожная подпись (CryptCATAdmin* + WTD_CHOICE_CATALOG) —
///    так подписано большинство системных файлов Windows.
/// </summary>
public static class AuthenticodeVerifier
{
    private static readonly Guid GenericVerifyV2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    private const uint WTD_UI_NONE = 2;
    private const uint WTD_REVOKE_NONE = 0;
    private const uint WTD_CHOICE_FILE = 1;
    private const uint WTD_CHOICE_CATALOG = 2;
    private const uint WTD_STATEACTION_VERIFY = 1;
    private const uint WTD_STATEACTION_CLOSE = 2;
    private const uint WTD_REVOCATION_CHECK_NONE = 0x00000010;
    private const uint WTD_CACHE_ONLY_URL_RETRIEVAL = 0x00001000;

    private const int TRUST_E_NOSIGNATURE = unchecked((int)0x800B0100);
    private const int TRUST_E_SUBJECT_FORM_UNKNOWN = unchecked((int)0x800B0003);
    private const int TRUST_E_PROVIDER_UNKNOWN = unchecked((int)0x800B0001);

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_FILE_INFO
    {
        public uint cbStruct;
        public IntPtr pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_CATALOG_INFO
    {
        public uint cbStruct;
        public uint dwCatalogVersion;
        public IntPtr pcwszCatalogFilePath;
        public IntPtr pcwszMemberTag;
        public IntPtr pcwszMemberFilePath;
        public IntPtr hMemberFile;
        public IntPtr pbCalculatedFileHash;
        public uint cbCalculatedFileHash;
        public IntPtr pcCatalogContext;
        public IntPtr hCatAdmin;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_DATA
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pFile; // WINTRUST_FILE_INFO* или WINTRUST_CATALOG_INFO*
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct CATALOG_INFO
    {
        public uint cbStruct;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string wszCatalogFile;
    }

    [DllImport("wintrust.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    private static extern int WinVerifyTrust(IntPtr hwnd, [MarshalAs(UnmanagedType.LPStruct)] Guid pgActionID, ref WINTRUST_DATA pWVTData);

    [DllImport("wintrust.dll", ExactSpelling = true)]
    private static extern IntPtr WTHelperProvDataFromStateData(IntPtr hStateData);

    [DllImport("wintrust.dll", ExactSpelling = true)]
    private static extern IntPtr WTHelperGetProvSignerFromChain(IntPtr pProvData, uint idxSigner, bool fCounterSigner, uint idxCounterSigner);

    [DllImport("wintrust.dll", ExactSpelling = true)]
    private static extern IntPtr WTHelperGetProvCertFromChain(IntPtr pSgnr, uint idxCert);

    [DllImport("wintrust.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    private static extern bool CryptCATAdminAcquireContext2(out IntPtr phCatAdmin, IntPtr pgSubsystem,
        string pwszHashAlgorithm, IntPtr pStrongHashPolicy, uint dwFlags);

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
    private static extern bool CryptCATAdminCalcHashFromFileHandle2(IntPtr hCatAdmin, IntPtr hFile,
        ref int pcbHash, byte[]? pbHash, uint dwFlags);

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
    private static extern IntPtr CryptCATAdminEnumCatalogFromHash(IntPtr hCatAdmin, byte[] pbHash, int cbHash,
        uint dwFlags, ref IntPtr phPrevCatInfo);

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
    private static extern bool CryptCATCatalogInfoFromContext(IntPtr hCatInfo, ref CATALOG_INFO psCatInfo, uint dwFlags);

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
    private static extern bool CryptCATAdminReleaseCatalogContext(IntPtr hCatAdmin, IntPtr hCatInfo, uint dwFlags);

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
    private static extern bool CryptCATAdminReleaseContext(IntPtr hCatAdmin, uint dwFlags);

    /// <summary>Проверяет подпись файла. Никогда не бросает исключений.</summary>
    public static AuthenticodeVerificationResult VerifyFile(string filePath)
    {
        var result = new AuthenticodeVerificationResult();

        if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
        {
            result.ResultMessage = "Файл не найден";
            return result;
        }

        try
        {
            var (rc, cert) = VerifyEmbedded(filePath);

            if (rc == 0)
            {
                result.IsSigned = true;
                result.IsValid = true;
                result.ResultMessage = "Подпись действительна (встроенная)";
                FillFromCert(result, cert);
                return result;
            }

            if (rc != TRUST_E_NOSIGNATURE && rc != TRUST_E_SUBJECT_FORM_UNKNOWN && rc != TRUST_E_PROVIDER_UNKNOWN)
            {
                // Встроенная подпись есть, но цепочка не строится/файл изменён
                result.IsSigned = true;
                result.IsValid = false;
                result.ResultCode = rc;
                result.ResultMessage = DescribeError(rc);
                FillFromCert(result, cert);
                return result;
            }

            // Встроенной подписи нет — пробуем каталоги (так подписана большая часть системных файлов)
            var (catRc, catCert, catalogFound) = VerifyCatalog(filePath);

            if (!catalogFound)
            {
                result.IsSigned = false;
                result.ResultCode = rc;
                result.ResultMessage = "Подпись не найдена";
                return result;
            }

            result.IsSigned = true;
            result.IsCatalogSigned = true;
            result.IsValid = catRc == 0;
            result.ResultCode = catRc;
            result.ResultMessage = catRc == 0 ? "Подпись действительна (каталог)" : DescribeError(catRc);
            FillFromCert(result, catCert);
            return result;
        }
        catch (Exception ex)
        {
            result.ResultMessage = $"Ошибка проверки подписи: {ex.Message}";
            return result;
        }
    }

    private static (int rc, X509Certificate2? cert) VerifyEmbedded(string path)
    {
        var pathPtr = IntPtr.Zero;
        var fileInfoPtr = IntPtr.Zero;
        try
        {
            pathPtr = Marshal.StringToHGlobalUni(path);
            fileInfoPtr = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_FILE_INFO>());

            var fileInfo = new WINTRUST_FILE_INFO
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(),
                pcwszFilePath = pathPtr
            };
            Marshal.StructureToPtr(fileInfo, fileInfoPtr, false);

            var rc = VerifyWithData(WTD_CHOICE_FILE, fileInfoPtr, WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL, out var cert);

            // При ошибках цепочки (например, промежуточный CA не в кэше) пробуем без cache-only
            if (rc != 0 && rc != TRUST_E_NOSIGNATURE && rc != TRUST_E_SUBJECT_FORM_UNKNOWN && rc != TRUST_E_PROVIDER_UNKNOWN)
            {
                var rc2 = VerifyWithData(WTD_CHOICE_FILE, fileInfoPtr, WTD_REVOCATION_CHECK_NONE, out var cert2);
                if (rc2 == 0) return (0, cert2);
                return (rc2, cert2 ?? cert);
            }

            return (rc, cert);
        }
        finally
        {
            if (fileInfoPtr != IntPtr.Zero) Marshal.FreeHGlobal(fileInfoPtr);
            if (pathPtr != IntPtr.Zero) Marshal.FreeHGlobal(pathPtr);
        }
    }

    private static (int rc, X509Certificate2? cert, bool catalogFound) VerifyCatalog(string path)
    {
        foreach (var algorithm in new[] { "SHA256", "SHA1" })
        {
            if (!CryptCATAdminAcquireContext2(out var hCatAdmin, IntPtr.Zero, algorithm, IntPtr.Zero, 0) ||
                hCatAdmin == IntPtr.Zero)
            {
                continue;
            }

            try
            {
                var attempt = TryVerifyCatalogWithAlgorithm(hCatAdmin, path);
                if (attempt.catalogFound || attempt.rc == 0)
                {
                    return attempt;
                }
            }
            finally
            {
                CryptCATAdminReleaseContext(hCatAdmin, 0);
            }
        }

        return (TRUST_E_NOSIGNATURE, null, false);
    }

    private static (int rc, X509Certificate2? cert, bool catalogFound) TryVerifyCatalogWithAlgorithm(IntPtr hCatAdmin, string path)
    {
        using var fileHandle = File.OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        var hFile = fileHandle.DangerousGetHandle();

        var cbHash = 0;
        if (!CryptCATAdminCalcHashFromFileHandle2(hCatAdmin, hFile, ref cbHash, null, 0) || cbHash <= 0)
        {
            return (TRUST_E_NOSIGNATURE, null, false);
        }

        var hash = new byte[cbHash];
        if (!CryptCATAdminCalcHashFromFileHandle2(hCatAdmin, hFile, ref cbHash, hash, 0))
        {
            return (TRUST_E_NOSIGNATURE, null, false);
        }

        var hashTag = Convert.ToHexString(hash);
        var catalogFound = false;
        var lastRc = TRUST_E_NOSIGNATURE;
        X509Certificate2? lastCert = null;
        var prevCatInfo = IntPtr.Zero;

        while (true)
        {
            var hCatInfo = CryptCATAdminEnumCatalogFromHash(hCatAdmin, hash, cbHash, 0, ref prevCatInfo);
            if (hCatInfo == IntPtr.Zero) break;

            catalogFound = true;
            try
            {
                var catInfo = new CATALOG_INFO { cbStruct = (uint)Marshal.SizeOf<CATALOG_INFO>() };
                if (!CryptCATCatalogInfoFromContext(hCatInfo, ref catInfo, 0))
                {
                    continue;
                }

                var rc = VerifyCatalogMember(hCatAdmin, hCatInfo, catInfo.wszCatalogFile, hashTag, path, hFile, out var cert);
                if (rc == 0)
                {
                    return (0, cert, true);
                }

                // Запоминаем последнюю ошибку; продолжаем перебор остальных каталогов
                lastRc = rc;
                lastCert = cert;
            }
            finally
            {
                CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
            }
        }

        if (catalogFound)
        {
            return (lastRc, lastCert, true);
        }

        return (TRUST_E_NOSIGNATURE, null, false);
    }

    private static int VerifyCatalogMember(IntPtr hCatAdmin, IntPtr hCatInfo, string catalogFile, string memberTag,
        string filePath, IntPtr hFile, out X509Certificate2? cert)
    {
        cert = null;

        var catalogPtr = IntPtr.Zero;
        var tagPtr = IntPtr.Zero;
        var filePathPtr = IntPtr.Zero;
        var catalogInfoPtr = IntPtr.Zero;
        try
        {
            catalogPtr = Marshal.StringToHGlobalUni(catalogFile);
            tagPtr = Marshal.StringToHGlobalUni(memberTag);
            filePathPtr = Marshal.StringToHGlobalUni(filePath);

            var catalogInfo = new WINTRUST_CATALOG_INFO
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_CATALOG_INFO>(),
                pcwszCatalogFilePath = catalogPtr,
                pcwszMemberTag = tagPtr,
                pcwszMemberFilePath = filePathPtr,
                hMemberFile = hFile,
                hCatAdmin = hCatAdmin
            };

            catalogInfoPtr = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_CATALOG_INFO>());
            Marshal.StructureToPtr(catalogInfo, catalogInfoPtr, false);

            return VerifyWithData(WTD_CHOICE_CATALOG, catalogInfoPtr, WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL, out cert);
        }
        finally
        {
            if (catalogInfoPtr != IntPtr.Zero) Marshal.FreeHGlobal(catalogInfoPtr);
            if (filePathPtr != IntPtr.Zero) Marshal.FreeHGlobal(filePathPtr);
            if (tagPtr != IntPtr.Zero) Marshal.FreeHGlobal(tagPtr);
            if (catalogPtr != IntPtr.Zero) Marshal.FreeHGlobal(catalogPtr);
        }
    }

    private static int VerifyWithData(uint unionChoice, IntPtr infoPtr, uint provFlags, out X509Certificate2? cert)
    {
        cert = null;

        var data = new WINTRUST_DATA
        {
            cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
            dwUIChoice = WTD_UI_NONE,
            fdwRevocationChecks = WTD_REVOKE_NONE,
            dwUnionChoice = unionChoice,
            pFile = infoPtr,
            dwStateAction = WTD_STATEACTION_VERIFY,
            dwProvFlags = provFlags
        };

        var rc = WinVerifyTrust(IntPtr.Zero, GenericVerifyV2, ref data);

        if (data.hWVTStateData != IntPtr.Zero)
        {
            try { cert = ExtractSignerCert(data.hWVTStateData); }
            catch { /* сертификат недоступен — не критично */ }

            data.dwStateAction = WTD_STATEACTION_CLOSE;
            WinVerifyTrust(IntPtr.Zero, GenericVerifyV2, ref data);
        }

        return rc;
    }

    private static X509Certificate2? ExtractSignerCert(IntPtr hStateData)
    {
        var provData = WTHelperProvDataFromStateData(hStateData);
        if (provData == IntPtr.Zero) return null;

        var signer = WTHelperGetProvSignerFromChain(provData, 0, false, 0);
        if (signer == IntPtr.Zero) return null;

        var provCert = WTHelperGetProvCertFromChain(signer, 0);
        if (provCert == IntPtr.Zero) return null;

        // CRYPT_PROVIDER_CERT { DWORD cbStruct; PCCERT_CONTEXT pCert; ... }
        var certContext = Marshal.ReadIntPtr(provCert, IntPtr.Size == 8 ? 8 : 4);
        if (certContext == IntPtr.Zero) return null;

        // CERT_CONTEXT { DWORD dwCertEncodingType; BYTE* pbCertEncoded; DWORD cbCertEncoded; ... }
        var pbCert = Marshal.ReadIntPtr(certContext, IntPtr.Size == 8 ? 8 : 4);
        var cbCert = Marshal.ReadInt32(certContext, IntPtr.Size == 8 ? 16 : 8);
        if (pbCert == IntPtr.Zero || cbCert <= 0) return null;

        var bytes = new byte[cbCert];
        Marshal.Copy(pbCert, bytes, 0, cbCert);
        return new X509Certificate2(bytes);
    }

    private static void FillFromCert(AuthenticodeVerificationResult result, X509Certificate2? cert)
    {
        if (cert == null) return;

        result.Publisher = cert.Subject;
        result.Issuer = cert.Issuer;
        result.Thumbprint = cert.Thumbprint;
        result.ValidFrom = cert.NotBefore;
        result.ValidTo = cert.NotAfter;
    }

    private static string DescribeError(int code) => code switch
    {
        0 => "OK",
        unchecked((int)0x800B0100) => "Подпись не найдена (TRUST_E_NOSIGNATURE)",
        unchecked((int)0x800B0101) => "Сертификат истёк (CERT_E_EXPIRED)",
        unchecked((int)0x800B0109) => "Корневой сертификат не является доверенным (CERT_E_UNTRUSTEDROOT)",
        unchecked((int)0x800B010C) => "Сертификат отозван (CERT_E_REVOKED)",
        unchecked((int)0x800B0110) => "Сертификат не подходит для этой цели (CERT_E_WRONG_USAGE)",
        unchecked((int)0x800B0111) => "Подпись явно не доверенная (TRUST_E_EXPLICIT_DISTRUST)",
        unchecked((int)0x80096010) => "Хэш файла не совпадает с подписью (файл изменён, TRUST_E_BAD_DIGEST)",
        unchecked((int)0x80092003) => "Ошибка чтения файла (CRYPT_E_FILE_ERROR)",
        unchecked((int)0x800B0001) => "Неизвестный поставщик проверки (TRUST_E_PROVIDER_UNKNOWN)",
        unchecked((int)0x800B0003) => "Неизвестный формат субъекта (TRUST_E_SUBJECT_FORM_UNKNOWN)",
        _ => $"Ошибка проверки подписи (0x{code:X8})"
    };
}

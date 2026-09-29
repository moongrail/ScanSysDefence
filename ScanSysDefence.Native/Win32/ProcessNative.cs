using System;
using System.Runtime.InteropServices;
using System.Text;

namespace ScanSysDefence.Native.Win32;

/// <summary>
/// Нативные запросы информации о процессе через access token
/// (владелец, повышение прав, уровень целостности).
/// </summary>
public static class ProcessNative
{
    private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
    private const uint TOKEN_QUERY = 0x0008;
    private const int TokenUser = 1;
    private const int TokenElevation = 20;
    private const int TokenIntegrityLevel = 25;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, bool inheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetTokenInformation(IntPtr token, int infoClass, IntPtr buffer, int bufferLength, out int returnLength);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool LookupAccountSid(string? systemName, IntPtr sid, StringBuilder name, ref int nameLength,
        StringBuilder domain, ref int domainLength, out int sidType);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern IntPtr GetSidSubAuthority(IntPtr sid, uint subAuthorityIndex);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern IntPtr GetSidSubAuthorityCount(IntPtr sidLength);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern int GetLengthSid(IntPtr sid);

    public static string TryGetProcessUser(int processId)
    {
        var token = IntPtr.Zero;
        var process = IntPtr.Zero;
        try
        {
            process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, processId);
            if (process == IntPtr.Zero) return string.Empty;
            if (!OpenProcessToken(process, TOKEN_QUERY, out token)) return string.Empty;

            var sid = GetTokenSid(token, TokenUser);
            if (sid == IntPtr.Zero) return string.Empty;

            try
            {
                int nameLen = 256, domainLen = 256;
                var name = new StringBuilder(nameLen);
                var domain = new StringBuilder(domainLen);
                if (!LookupAccountSid(null, sid, name, ref nameLen, domain, ref domainLen, out _)) return string.Empty;
                return string.IsNullOrEmpty(domain.ToString()) ? name.ToString() : $"{domain}\\{name}";
            }
            finally
            {
                Marshal.FreeHGlobal(sid);
            }
        }
        catch
        {
            return string.Empty;
        }
        finally
        {
            if (token != IntPtr.Zero) CloseHandle(token);
            if (process != IntPtr.Zero) CloseHandle(process);
        }
    }

    public static bool IsProcessElevated(int processId)
    {
        var token = IntPtr.Zero;
        var process = IntPtr.Zero;
        var buffer = IntPtr.Zero;
        try
        {
            process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, processId);
            if (process == IntPtr.Zero) return false;
            if (!OpenProcessToken(process, TOKEN_QUERY, out token)) return false;

            buffer = Marshal.AllocHGlobal(sizeof(int));
            if (!GetTokenInformation(token, TokenElevation, buffer, sizeof(int), out _)) return false;
            return Marshal.ReadInt32(buffer) != 0;
        }
        catch
        {
            return false;
        }
        finally
        {
            if (buffer != IntPtr.Zero) Marshal.FreeHGlobal(buffer);
            if (token != IntPtr.Zero) CloseHandle(token);
            if (process != IntPtr.Zero) CloseHandle(process);
        }
    }

    public static string TryGetIntegrityLevel(int processId)
    {
        var token = IntPtr.Zero;
        var process = IntPtr.Zero;
        var buffer = IntPtr.Zero;
        try
        {
            process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, processId);
            if (process == IntPtr.Zero) return string.Empty;
            if (!OpenProcessToken(process, TOKEN_QUERY, out token)) return string.Empty;

            GetTokenInformation(token, TokenIntegrityLevel, IntPtr.Zero, 0, out var needed);
            if (needed <= 0) return string.Empty;

            buffer = Marshal.AllocHGlobal(needed);
            if (!GetTokenInformation(token, TokenIntegrityLevel, buffer, needed, out _)) return string.Empty;

            // TOKEN_MANDATORY_LABEL { SID_AND_ATTRIBUTES Label }
            var labelSid = Marshal.ReadIntPtr(buffer);
            if (labelSid == IntPtr.Zero) return string.Empty;

            var countPtr = GetSidSubAuthorityCount(labelSid);
            if (countPtr == IntPtr.Zero) return string.Empty;
            var subAuthorityCount = Marshal.ReadByte(countPtr);
            if (subAuthorityCount == 0) return string.Empty;

            var ridPtr = GetSidSubAuthority(labelSid, (uint)(subAuthorityCount - 1));
            if (ridPtr == IntPtr.Zero) return string.Empty;
            var rid = (uint)Marshal.ReadInt32(ridPtr);

            return RidToIntegrityName(rid);
        }
        catch
        {
            return string.Empty;
        }
        finally
        {
            if (buffer != IntPtr.Zero) Marshal.FreeHGlobal(buffer);
            if (token != IntPtr.Zero) CloseHandle(token);
            if (process != IntPtr.Zero) CloseHandle(process);
        }
    }

    private static IntPtr GetTokenSid(IntPtr token, int infoClass)
    {
        if (!GetTokenInformation(token, infoClass, IntPtr.Zero, 0, out var needed) || needed <= 0) return IntPtr.Zero;

        var buffer = Marshal.AllocHGlobal(needed);
        try
        {
            if (!GetTokenInformation(token, infoClass, buffer, needed, out _)) return IntPtr.Zero;

            // TOKEN_USER { SID_AND_ATTRIBUTES User { IntPtr Sid; uint Attributes } }
            var sid = Marshal.ReadIntPtr(buffer);
            if (sid == IntPtr.Zero) return IntPtr.Zero;

            // Скопировать SID, чтобы можно было освободить исходный буфер
            var sidLength = GetLengthSid(sid);
            if (sidLength <= 0) return IntPtr.Zero;

            var copy = Marshal.AllocHGlobal(sidLength);
            for (var i = 0; i < sidLength; i++)
            {
                Marshal.WriteByte(copy, i, Marshal.ReadByte(sid, i));
            }
            return copy;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static string RidToIntegrityName(uint rid) => rid switch
    {
        >= 0x5000 => "Protected",
        >= 0x4000 => "System",
        >= 0x3000 => "High",
        >= 0x2000 => "Medium",
        >= 0x1000 => "Low",
        _ => "Untrusted"
    };
}

using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace ScanSysDefence.Native.Win32;

/// <summary>
/// Смена владельца защищённых ключей реестра (аналог «Владелец → Администраторы» в regedit).
/// Нужна для удаления «осиротевших» COM-классов, владельцем которых является TrustedInstaller:
/// обычный администратор не может ни записать, ни удалить такие ключи.
/// </summary>
public static class RegistryNative
{
    private const int SeRegistryKey = 4;

    private const uint OwnerSecurityInformation = 0x00000001;
    private const uint DaclSecurityInformation = 0x00000004;

    private const int AclRevision = 2;
    private const uint KeyAllAccess = 0xF003F;

    private const uint TokenAdjustPrivileges = 0x0020;
    private const uint TokenQuery = 0x0008;
    private const uint SePrivilegeEnabled = 0x00000002;
    private const int ErrorNotAllAssigned = 1300;

    [StructLayout(LayoutKind.Sequential)]
    private struct Luid
    {
        public uint LowPart;
        public int HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LuidAndAttributes
    {
        public Luid Luid;
        public uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TokenPrivileges
    {
        public uint PrivilegeCount;
        public LuidAndAttributes Privilege;
    }

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr processHandle, uint desiredAccess, out IntPtr tokenHandle);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool LookupPrivilegeValue(string? systemName, string name, out Luid luid);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool AdjustTokenPrivileges(
        IntPtr tokenHandle,
        bool disableAllPrivileges,
        ref TokenPrivileges newState,
        uint bufferLength,
        IntPtr previousState,
        IntPtr returnLength);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool InitializeAcl(IntPtr pAcl, int nAclLength, int dwAclRevision);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool AddAccessAllowedAce(IntPtr pAcl, int dwAceRevision, uint accessMask, IntPtr pSid);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern uint SetNamedSecurityInfo(
        string pObjectName,
        int objectType,
        uint securityInfo,
        IntPtr psidOwner,
        IntPtr psidGroup,
        IntPtr pDacl,
        IntPtr pSacl);

    /// <summary>Безопасная обёртка: никогда не бросает исключений.</summary>
    public static bool TryTakeOwnership(string hive, string keyPath, out string error)
    {
        error = string.Empty;
        try
        {
            if (!OperatingSystem.IsWindows())
            {
                error = "Смена владельца ключей реестра доступна только в Windows";
                return false;
            }

            TakeOwnership(hive, keyPath);
            return true;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return false;
        }
    }

    /// <summary>
    /// Делает группу «Администраторы» владельцем ключа и выдаёт полный доступ
    /// администраторам и текущему пользователю. Требует прав администратора.
    /// </summary>
    public static void TakeOwnership(string hive, string keyPath)
    {
        if (string.IsNullOrWhiteSpace(keyPath))
            throw new ArgumentException("Пустой путь к ключу реестра", nameof(keyPath));

        var objectName = BuildObjectName(hive, keyPath);

        EnablePrivilege("SeTakeOwnershipPrivilege");
        EnablePrivilege("SeRestorePrivilege");

        var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        var currentUser = WindowsIdentity.GetCurrent().User ?? admins;

        // Шаг 1: сменить владельца на группу «Администраторы»
        using (var adminPinned = new PinnedSid(admins))
        {
            var rc = SetNamedSecurityInfo(
                objectName,
                SeRegistryKey,
                OwnerSecurityInformation,
                adminPinned.Pointer,
                IntPtr.Zero,
                IntPtr.Zero,
                IntPtr.Zero);

            if (rc != 0)
            {
                throw new Win32Exception((int)rc,
                    $"Не удалось сменить владельца ключа {hive}\\{keyPath} (нужны права администратора)");
            }
        }

        // Шаг 2: новый DACL — полный доступ администраторам и текущему пользователю
        var acl = new byte[512];
        var aclHandle = GCHandle.Alloc(acl, GCHandleType.Pinned);
        try
        {
            var aclPtr = aclHandle.AddrOfPinnedObject();

            if (!InitializeAcl(aclPtr, acl.Length, AclRevision))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "InitializeAcl failed");

            using (var adminPinned = new PinnedSid(admins))
            {
                if (!AddAccessAllowedAce(aclPtr, AclRevision, KeyAllAccess, adminPinned.Pointer))
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "AddAccessAllowedAce failed");
            }

            if (!currentUser.Equals(admins))
            {
                using var userPinned = new PinnedSid(currentUser);
                if (!AddAccessAllowedAce(aclPtr, AclRevision, KeyAllAccess, userPinned.Pointer))
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "AddAccessAllowedAce failed");
            }

            var rc = SetNamedSecurityInfo(
                objectName,
                SeRegistryKey,
                DaclSecurityInformation,
                IntPtr.Zero,
                IntPtr.Zero,
                aclPtr,
                IntPtr.Zero);

            if (rc != 0)
            {
                throw new Win32Exception((int)rc, $"Не удалось выдать права на ключ {hive}\\{keyPath}");
            }
        }
        finally
        {
            aclHandle.Free();
        }
    }

    private static void EnablePrivilege(string name)
    {
        if (!OpenProcessToken(GetCurrentProcess(), TokenAdjustPrivileges | TokenQuery, out var token))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "OpenProcessToken failed");

        try
        {
            if (!LookupPrivilegeValue(null, name, out var luid))
                throw new Win32Exception(Marshal.GetLastWin32Error(), $"Право {name} не найдено в системе");

            var privileges = new TokenPrivileges
            {
                PrivilegeCount = 1,
                Privilege = new LuidAndAttributes { Luid = luid, Attributes = SePrivilegeEnabled }
            };

            if (!AdjustTokenPrivileges(token, false, ref privileges, 0, IntPtr.Zero, IntPtr.Zero))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "AdjustTokenPrivileges failed");

            if (Marshal.GetLastWin32Error() == ErrorNotAllAssigned)
            {
                throw new Win32Exception(
                    $"Нет права {name} — запустите ScanSysDefence от имени администратора и повторите попытку");
            }
        }
        finally
        {
            CloseHandle(token);
        }
    }

    private static string BuildObjectName(string hive, string keyPath)
    {
        var prefix = hive.ToUpperInvariant() switch
        {
            "HKCU" or "HKEY_CURRENT_USER" => "CURRENT_USER",
            "HKCR" or "HKEY_CLASSES_ROOT" => "CLASSES_ROOT",
            "HKU" or "HKEY_USERS" => "USERS",
            "HKCC" => "CURRENT_CONFIG",
            _ => "MACHINE"
        };

        return $"{prefix}\\{keyPath}";
    }

    private sealed class PinnedSid : IDisposable
    {
        private readonly IntPtr _sidPtr;

        public IntPtr Pointer => _sidPtr;

        public PinnedSid(SecurityIdentifier sid)
        {
            var bytes = new byte[sid.BinaryLength];
            sid.GetBinaryForm(bytes, 0);
            _sidPtr = Marshal.AllocHGlobal(bytes.Length);
            Marshal.Copy(bytes, 0, _sidPtr, bytes.Length);
        }

        public void Dispose()
        {
            if (_sidPtr != IntPtr.Zero) Marshal.FreeHGlobal(_sidPtr);
        }
    }
}

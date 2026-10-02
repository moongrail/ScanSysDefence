using System.Management;

namespace ScanSysDefence.Core.Utils;

/// <summary>
/// Безопасное чтение свойств WMI-объектов.
/// Некоторые WMI-провайдеры возвращают значения-строки из ValueMap («Share Process»),
/// а часть свойств может отсутствовать у отдельных экземпляров — при обычном
/// обращении это приводит к FormatException/ManagementException. Все методы
/// никогда не бросают исключений.
/// </summary>
public static class WmiSafe
{
    private static readonly Dictionary<string, uint> ServiceTypeValueMap = new(StringComparer.OrdinalIgnoreCase)
    {
        ["Kernel Driver"] = 1,
        ["File System Driver"] = 2,
        ["Adapter"] = 4,
        ["Recognizer Driver"] = 8,
        ["Own Process"] = 16,
        ["Share Process"] = 32,
        ["Interactive Process"] = 256
    };

    private static readonly Dictionary<string, uint> StartModeValueMap = new(StringComparer.OrdinalIgnoreCase)
    {
        ["Boot"] = 0,
        ["System"] = 1,
        ["Auto"] = 2,
        ["Manual"] = 3,
        ["Disabled"] = 4
    };

    public static string Str(ManagementBaseObject obj, string property, string fallback = "")
    {
        try
        {
            return ParseString(obj[property]) ?? fallback;
        }
        catch
        {
            return fallback;
        }
    }

    public static uint UInt32(ManagementBaseObject obj, string property, uint fallback = 0)
    {
        try
        {
            return ParseUInt32(obj[property]) ?? fallback;
        }
        catch
        {
            return fallback;
        }
    }

    public static int Int32(ManagementBaseObject obj, string property, int fallback = 0)
    {
        try
        {
            return ParseInt32(obj[property]) ?? fallback;
        }
        catch
        {
            return fallback;
        }
    }

    public static bool Bool(ManagementBaseObject obj, string property, bool fallback = false)
    {
        try
        {
            return ParseBool(obj[property]) ?? fallback;
        }
        catch
        {
            return fallback;
        }
    }

    public static string? ParseString(object? value)
    {
        if (value == null || value is DBNull) return null;
        return value.ToString();
    }

    public static uint? ParseUInt32(object? value)
    {
        switch (value)
        {
            case null:
            case DBNull:
                return null;
            case uint u:
                return u;
            case int i:
                return i >= 0 ? (uint)i : null;
            case ushort us:
                return us;
            case byte b:
                return b;
            case ulong ul:
                return ul <= uint.MaxValue ? (uint)ul : null;
            case long l:
                return l is >= 0 and <= uint.MaxValue ? (uint)l : null;
            case bool bo:
                return bo ? 1u : 0u;
            case string s:
                if (uint.TryParse(s, out var parsed)) return parsed;
                if (ServiceTypeValueMap.TryGetValue(s.Trim(), out var st)) return st;
                if (StartModeValueMap.TryGetValue(s.Trim(), out var sm)) return sm;
                return null;
            default:
                return null;
        }
    }

    public static int? ParseInt32(object? value)
    {
        switch (value)
        {
            case null:
            case DBNull:
                return null;
            case int i:
                return i;
            case uint u:
                return u <= int.MaxValue ? (int)u : null;
            case ushort us:
                return us;
            case byte b:
                return b;
            case ulong ul:
                return ul <= int.MaxValue ? (int)ul : null;
            case long l:
                return l is >= int.MinValue and <= int.MaxValue ? (int)l : null;
            case string s:
                return int.TryParse(s, out var parsed) ? parsed : null;
            default:
                return null;
        }
    }

    public static bool? ParseBool(object? value)
    {
        switch (value)
        {
            case null:
            case DBNull:
                return null;
            case bool b:
                return b;
            case string s:
                return bool.TryParse(s, out var parsed) ? parsed : null;
            case int i:
                return i != 0;
            case uint u:
                return u != 0;
            default:
                return null;
        }
    }
}

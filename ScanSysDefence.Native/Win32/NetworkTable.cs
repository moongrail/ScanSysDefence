using System;
using System.Collections.Generic;
using System.Net;
using System.Runtime.InteropServices;

namespace ScanSysDefence.Native.Win32;

public class OwningProcessEndpoint
{
    public int ProcessId { get; set; }
    public IPAddress LocalAddress { get; set; } = IPAddress.None;
    public int LocalPort { get; set; }
    public IPAddress RemoteAddress { get; set; } = IPAddress.None;
    public int RemotePort { get; set; }
    public string State { get; set; } = string.Empty;
    public string Protocol { get; set; } = "TCP";
}

public static class NetworkTable
{
    private const int AF_INET = 2;
    private const int TCP_TABLE_OWNER_PID_ALL = 5;
    private const int UDP_TABLE_OWNER_PID = 1;

    private enum MibTcpState
    {
        Closed = 1,
        Listen = 2,
        SynSent = 3,
        SynRcvd = 4,
        Estab = 5,
        FinWait1 = 6,
        FinWait2 = 7,
        CloseWait = 8,
        Closing = 9,
        LastAck = 10,
        TimeWait = 11,
        DeleteTcb = 12
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MibTcpRowOwnerPid
    {
        public uint State;
        public uint LocalAddr;
        public uint LocalPort;
        public uint RemoteAddr;
        public uint RemotePort;
        public uint OwningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MibUdpRowOwnerPid
    {
        public uint LocalAddr;
        public uint LocalPort;
        public uint OwningPid;
    }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern int GetExtendedTcpTable(
        IntPtr pTcpTable, ref int pdwSize, bool bOrder, int ulAf, int tableClass, uint reserved);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern int GetExtendedUdpTable(
        IntPtr pUdpTable, ref int pdwSize, bool bOrder, int ulAf, int tableClass, uint reserved);

    public static List<OwningProcessEndpoint> GetTcpEndpoints()
    {
        var result = new List<OwningProcessEndpoint>();
        int size = 0;
        GetExtendedTcpTable(IntPtr.Zero, ref size, false, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
        var buffer = Marshal.AllocHGlobal(size);
        try
        {
            int ret = GetExtendedTcpTable(buffer, ref size, false, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
            if (ret != 0) return result;

            int rowCount = Marshal.ReadInt32(buffer);
            IntPtr rowPtr = IntPtr.Add(buffer, 4);
            int rowSize = Marshal.SizeOf<MibTcpRowOwnerPid>();

            for (int i = 0; i < rowCount; i++)
            {
                var row = Marshal.PtrToStructure<MibTcpRowOwnerPid>(rowPtr);
                result.Add(new OwningProcessEndpoint
                {
                    ProcessId = (int)row.OwningPid,
                    LocalAddress = UIntToIp(row.LocalAddr),
                    LocalPort = PortFromNetworkOrder(row.LocalPort),
                    RemoteAddress = UIntToIp(row.RemoteAddr),
                    RemotePort = PortFromNetworkOrder(row.RemotePort),
                    State = StateToString((MibTcpState)row.State),
                    Protocol = "TCP"
                });
                rowPtr = IntPtr.Add(rowPtr, rowSize);
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
        return result;
    }

    public static List<OwningProcessEndpoint> GetUdpEndpoints()
    {
        var result = new List<OwningProcessEndpoint>();
        int size = 0;
        GetExtendedUdpTable(IntPtr.Zero, ref size, false, AF_INET, UDP_TABLE_OWNER_PID, 0);
        var buffer = Marshal.AllocHGlobal(size);
        try
        {
            int ret = GetExtendedUdpTable(buffer, ref size, false, AF_INET, UDP_TABLE_OWNER_PID, 0);
            if (ret != 0) return result;

            int rowCount = Marshal.ReadInt32(buffer);
            IntPtr rowPtr = IntPtr.Add(buffer, 4);
            int rowSize = Marshal.SizeOf<MibUdpRowOwnerPid>();

            for (int i = 0; i < rowCount; i++)
            {
                var row = Marshal.PtrToStructure<MibUdpRowOwnerPid>(rowPtr);
                result.Add(new OwningProcessEndpoint
                {
                    ProcessId = (int)row.OwningPid,
                    LocalAddress = UIntToIp(row.LocalAddr),
                    LocalPort = PortFromNetworkOrder(row.LocalPort),
                    Protocol = "UDP",
                    State = "Listen"
                });
                rowPtr = IntPtr.Add(rowPtr, rowSize);
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
        return result;
    }

    private static IPAddress UIntToIp(uint address) => new(BitConverter.GetBytes(address));

    private static int PortFromNetworkOrder(uint portWithZeroHighBytes)
    {
        // Port is stored in the two low-order bytes in network byte order
        int raw = (int)(portWithZeroHighBytes & 0xFFFF);
        return ((raw & 0xFF) << 8) | ((raw >> 8) & 0xFF);
    }

    private static string StateToString(MibTcpState state) => state switch
    {
        MibTcpState.Closed => "CLOSED",
        MibTcpState.Listen => "LISTEN",
        MibTcpState.SynSent => "SYN_SENT",
        MibTcpState.SynRcvd => "SYN_RCVD",
        MibTcpState.Estab => "ESTABLISHED",
        MibTcpState.FinWait1 => "FIN_WAIT1",
        MibTcpState.FinWait2 => "FIN_WAIT2",
        MibTcpState.CloseWait => "CLOSE_WAIT",
        MibTcpState.Closing => "CLOSING",
        MibTcpState.LastAck => "LAST_ACK",
        MibTcpState.TimeWait => "TIME_WAIT",
        MibTcpState.DeleteTcb => "DELETE_TCB",
        _ => state.ToString()
    };
}

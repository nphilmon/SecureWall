using System.Net;
using System.Runtime.InteropServices;
using SecureWall.Core.Interfaces;
using SecureWall.Core.Logic;
using SecureWall.Core.Models;
using SecureWall.Infrastructure.Windows;

namespace SecureWall.Security.Network;

/// <summary>API documentée IP Helper (iphlpapi) : tables TCP/UDP avec PID propriétaire.</summary>
public static class IpHelper
{
    const int AfInet = 2, AfInet6 = 23;
    const int TcpTableOwnerPidAll = 5, UdpTableOwnerPid = 1;

    [DllImport("iphlpapi.dll", SetLastError = true)]
    static extern uint GetExtendedTcpTable(IntPtr table, ref int size, bool sort, int af, int tableClass, uint reserved);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    static extern uint GetExtendedUdpTable(IntPtr table, ref int size, bool sort, int af, int tableClass, uint reserved);

    public readonly record struct Tcp4Row(uint State, uint LocalAddr, uint LocalPortRaw, uint RemoteAddr, uint RemotePortRaw, int Pid);

    static byte[] Fetch(Func<IntPtr, int, (uint rc, int size)> call)
    {
        var size = 0;
        var buf = Marshal.AllocHGlobal(1);
        try
        {
            for (var i = 0; i < 5; i++)
            {
                Marshal.FreeHGlobal(buf);
                size = Math.Max(size, 4096);
                buf = Marshal.AllocHGlobal(size);
                var (rc, needed) = call(buf, size);
                if (rc == 0)
                {
                    var data = new byte[needed];
                    Marshal.Copy(buf, data, 0, needed);
                    return data;
                }
                if (rc != 122 /* ERROR_INSUFFICIENT_BUFFER */) return Array.Empty<byte>();
                size = needed + 4096;
            }
            return Array.Empty<byte>();
        }
        finally { Marshal.FreeHGlobal(buf); }
    }

    static byte[] FetchTcp(int af) => Fetch((p, s) =>
    {
        var sz = s;
        var rc = GetExtendedTcpTable(p, ref sz, false, af, TcpTableOwnerPidAll, 0);
        return (rc, sz);
    });

    static byte[] FetchUdp(int af) => Fetch((p, s) =>
    {
        var sz = s;
        var rc = GetExtendedUdpTable(p, ref sz, false, af, UdpTableOwnerPid, 0);
        return (rc, sz);
    });

    static int Port(uint raw) => (int)(((raw & 0xFF) << 8) | ((raw >> 8) & 0xFF));
    static uint U32(byte[] b, int o) => BitConverter.ToUInt32(b, o);

    public static List<Tcp4Row> ReadTcp4()
    {
        var b = FetchTcp(AfInet);
        var rows = new List<Tcp4Row>();
        if (b.Length < 4) return rows;
        var n = (int)U32(b, 0);
        for (var i = 0; i < n && 4 + (i + 1) * 24 <= b.Length; i++)
        {
            var o = 4 + i * 24;
            rows.Add(new Tcp4Row(U32(b, o), U32(b, o + 4), U32(b, o + 8), U32(b, o + 12), U32(b, o + 16), (int)U32(b, o + 20)));
        }
        return rows;
    }

    public static List<NetConnection> ReadAll()
    {
        var list = new List<NetConnection>(512);

        // TCP IPv4 — MIB_TCPROW_OWNER_PID : 6 x uint
        foreach (var r in ReadTcp4())
        {
            var remote = new IPAddress(r.RemoteAddr);
            var listening = r.State == 2;
            list.Add(Make("TCP", new IPAddress(r.LocalAddr), Port(r.LocalPortRaw), remote, Port(r.RemotePortRaw), (int)r.State, r.Pid, listening));
        }

        // TCP IPv6 — MIB_TCP6ROW_OWNER_PID : addr[16], scope, port, addr[16], scope, port, state, pid
        var b6 = FetchTcp(AfInet6);
        if (b6.Length >= 4)
        {
            var n = (int)U32(b6, 0);
            for (var i = 0; i < n && 4 + (i + 1) * 56 <= b6.Length; i++)
            {
                var o = 4 + i * 56;
                var local = new IPAddress(b6.AsSpan(o, 16), U32(b6, o + 16));
                var remote = new IPAddress(b6.AsSpan(o + 24, 16), U32(b6, o + 40));
                var state = (int)U32(b6, o + 48);
                list.Add(Make("TCP", local, Port(U32(b6, o + 20)), remote, Port(U32(b6, o + 44)), state, (int)U32(b6, o + 52), state == 2));
            }
        }

        // UDP IPv4 — MIB_UDPROW_OWNER_PID : addr, port, pid
        var u4 = FetchUdp(AfInet);
        if (u4.Length >= 4)
        {
            var n = (int)U32(u4, 0);
            for (var i = 0; i < n && 4 + (i + 1) * 12 <= u4.Length; i++)
            {
                var o = 4 + i * 12;
                list.Add(Make("UDP", new IPAddress(U32(u4, o)), Port(U32(u4, o + 4)), null, 0, 0, (int)U32(u4, o + 8), false));
            }
        }

        // UDP IPv6 — MIB_UDP6ROW_OWNER_PID : addr[16], scope, port, pid
        var u6 = FetchUdp(AfInet6);
        if (u6.Length >= 4)
        {
            var n = (int)U32(u6, 0);
            for (var i = 0; i < n && 4 + (i + 1) * 28 <= u6.Length; i++)
            {
                var o = 4 + i * 28;
                list.Add(Make("UDP", new IPAddress(u6.AsSpan(o, 16), U32(u6, o + 16)), Port(U32(u6, o + 20)), null, 0, 0, (int)U32(u6, o + 24), false));
            }
        }
        return list;
    }

    static string StateText(int s, string proto) => proto == "UDP" ? "Sans connexion" : s switch
    {
        1 => "Fermée", 2 => "À l'écoute", 3 => "SYN envoyé", 4 => "SYN reçu", 5 => "Établie", 6 => "FIN-WAIT-1", 7 => "FIN-WAIT-2",
        8 => "CLOSE-WAIT", 9 => "CLOSING", 10 => "LAST-ACK", 11 => "TIME-WAIT", 12 => "Suppression", _ => "Inconnu",
    };

    static NetConnection Make(string proto, IPAddress local, int lport, IPAddress? remote, int rport, int state, int pid, bool listening)
    {
        var remoteStr = remote == null || remote.Equals(IPAddress.Any) || remote.Equals(IPAddress.IPv6Any) ? "" : remote.ToString();
        return new NetConnection
        {
            Protocol = proto, LocalAddress = local.ToString(), LocalPort = lport,
            RemoteAddress = remoteStr, RemotePort = remoteStr == "" ? 0 : rport,
            State = StateText(state, proto), Pid = pid, IsListening = listening,
            IsEstablished = proto == "TCP" && state == 5,
            IsExternal = remote != null && NetworkAddressClassifier.IsExternal(remote),
        };
    }
}

public sealed class IpHelperConnectionSource : IConnectionSource
{
    public IReadOnlyList<NetConnection> Read() => IpHelper.ReadAll();
}

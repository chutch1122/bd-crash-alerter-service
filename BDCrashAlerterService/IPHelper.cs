using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.Contracts;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;

using word = System.UInt16;
using dword = System.UInt32;

namespace BDCrashAlerterService
{
    // From: http://www.codeproject.com/Articles/4298/Getting-active-TCP-UDP-connections-on-a-box
    /// <summary>
    /// This is the managed class for the routines in IPHLPAPI
    /// </summary>
    public static class IPHelper
    {

        #region nested types
        /// <summary>
        /// This class contains all native declarations.
        /// </summary>
        private static class NativeMethods
        {

            #region consts

            public const int MIB_TCP_STATE_CLOSED = 1;
            public const int MIB_TCP_STATE_LISTEN = 2;
            public const int MIB_TCP_STATE_SYN_SENT = 3;
            public const int MIB_TCP_STATE_SYN_RCVD = 4;
            public const int MIB_TCP_STATE_ESTAB = 5;
            public const int MIB_TCP_STATE_FIN_WAIT1 = 6;
            public const int MIB_TCP_STATE_FIN_WAIT2 = 7;
            public const int MIB_TCP_STATE_CLOSE_WAIT = 8;
            public const int MIB_TCP_STATE_CLOSING = 9;
            public const int MIB_TCP_STATE_LAST_ACK = 10;
            public const int MIB_TCP_STATE_TIME_WAIT = 11;
            public const int MIB_TCP_STATE_DELETE_TCB = 12;

            public enum AfInet : int
            {
                Unspecified = 0,
                Inet = 2,
                Ipx = 6,
                AppleTalk = 16,
                NetBios = 17,
                Inet6 = 23,
                Irda = 26,
                Bluetooth = 32,
            }

            public enum UdpTableClass : int
            {
                Basic,
                OwnerPid,
                OwnerPidModule,
            }

            public enum TcpTableClass : int
            {
                BasicListener,
                BasicConnections,
                BasicAll,
                OwnerPidListener,
                OwnerPidConnections,
                OwnerPidAll,
                OwnerModuleListener,
                OwnerModuleConnections,
                OwnerModuleAll,
            }

            public const int NO_ERROR = 0;
            public const int ERROR_NOT_SUPPORTED = 0x32;
            public const int ERROR_INSUFFICIENT_BUFFER = 122;
            #endregion

            #region structs

            [StructLayout(LayoutKind.Sequential)]
            public struct MIB_UDPROW
            {
                public readonly dword dwLocalAddr;
                public readonly dword dwLocalPort;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct MIB_TCPROW
            {
                public readonly dword dwState;
                public readonly dword dwLocalAddr;
                public readonly dword dwLocalPort;
                public readonly dword dwRemoteAddr;
                public readonly dword dwRemotePort;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct MIB_UDPROW_OWNER_PID
            {
                public readonly dword dwLocalAddr;
                public readonly dword dwLocalPort;
                public readonly dword dwOwningPid;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct MIB_TCPROW_OWNER_PID
            {
                public readonly dword dwState;
                public readonly dword dwLocalAddr;
                public readonly dword dwLocalPort;
                public readonly dword dwRemoteAddr;
                public readonly dword dwRemotePort;
                public readonly dword dwOwningPid;
            }

            #endregion

            #region native calls

            [DllImport("iphlpapi.dll", SetLastError = true, EntryPoint = "GetUdpTable")]
            public static extern int GetUdpTable(IntPtr pUdpTable, ref dword pdwSize, bool bOrder);

            [DllImport("iphlpapi.dll", SetLastError = true, EntryPoint = "GetTcpTable")]
            public static extern int GetTcpTable(IntPtr pTcpTable, ref dword pdwSize, bool bOrder);

            [DllImport("iphlpapi.dll", SetLastError = true, EntryPoint = "GetExtendedUdpTable")]
            public static extern int GetExtendedUdpTable(IntPtr pUdpTable, ref dword pdwSize, bool bOrder, AfInet ulAf, UdpTableClass udpTableClass, dword reserved = 0);

            [DllImport("iphlpapi.dll", SetLastError = true, EntryPoint = "GetExtendedTcpTable")]
            public static extern int GetExtendedTcpTable(IntPtr pTcpTable, ref dword pdwSize, bool bOrder, AfInet ulAf, TcpTableClass tcpTableClass, dword reserved = 0);

            #endregion

        } // end NativeMethods


        /// <summary>
        /// The state of a connection.
        /// </summary>
        public enum ConnectionState
        {
            Unknown = 0,
            Established = NativeMethods.MIB_TCP_STATE_ESTAB,
            Listening = NativeMethods.MIB_TCP_STATE_LISTEN,
            SynSent = NativeMethods.MIB_TCP_STATE_SYN_SENT,
            SynReceived = NativeMethods.MIB_TCP_STATE_SYN_RCVD,
            Closed = NativeMethods.MIB_TCP_STATE_CLOSED,
            Closing = NativeMethods.MIB_TCP_STATE_CLOSING,
            CloseWait = NativeMethods.MIB_TCP_STATE_CLOSE_WAIT,
            FinWait1 = NativeMethods.MIB_TCP_STATE_FIN_WAIT1,
            FinWait2 = NativeMethods.MIB_TCP_STATE_FIN_WAIT2,
            LastAck = NativeMethods.MIB_TCP_STATE_LAST_ACK,
            TimeWait = NativeMethods.MIB_TCP_STATE_TIME_WAIT,
            DeleteTcb = NativeMethods.MIB_TCP_STATE_DELETE_TCB,
        }

        /// <summary>
        /// The protocol used.
        /// </summary>
        public enum ConnectionProtocol
        {
            Unknown,
            Tcp,
            Udp,
        }

        /// <summary>
        /// A connection.
        /// </summary>
        public class Connection
        {
            /// <summary>
            /// Gets the local endpoint, ie. adress and port.
            /// </summary>
            public IPEndPoint Local { get; private set; }
            /// <summary>
            /// Gets the remote endpoint, ie. adress and port.
            /// </summary>
            public IPEndPoint Remote { get; private set; }
            /// <summary>
            /// Gets the connection state.
            /// </summary>
            public ConnectionState State { get; private set; }
            /// <summary>
            /// Gets the connection protocol.
            /// </summary>
            public ConnectionProtocol Protocol { get; private set; }
            /// <summary>
            /// Gets the source process, if known.
            /// </summary>
            public Process SourceProcess { get; private set; }

            internal Connection(ConnectionProtocol protocol, IPAddress localAdress, int localPort, IPAddress remoteAdress, int remotePort, ConnectionState state, Process sourceProcess)
              : this(
                protocol,
                new IPEndPoint(localAdress, localPort),
                new IPEndPoint(remoteAdress, remotePort),
                state,
                sourceProcess
                )
            {
            }

            internal Connection(ConnectionProtocol protocol, IPEndPoint local, IPEndPoint remote, ConnectionState state, Process sourceProcess)
            {
                this.State = state;
                this.SourceProcess = sourceProcess;
                this.Remote = remote;
                this.Protocol = protocol;
                this.Local = local;
            }

            public override string ToString()
            {
                return string.Format("{0}({1}): {2} -> {3}", this.Protocol, this.State, this.Local, this.Remote);
            }
        }

        #endregion

        /// <summary>
        /// Gets the active connections.
        /// </summary>
        /// <returns>An array of all active connections.</returns>
        public static Connection[] GetActiveConnections()
        {
            return (GetTcpTable().Concat(GetUdpTable()).ToArray());
        }

        /// <summary>
        /// Gets the TCP table.
        /// Note: Tries the new method first and if this is unsupported on your system, uses the old one.
        /// </summary>
        /// <returns>An array with all active TCP connections.</returns>
        public static Connection[] GetTcpTable()
        {
            try
            {
                return (_GetTcpTableNew());
            }
            catch (Win32Exception e)
            {
                if (e.NativeErrorCode == NativeMethods.ERROR_NOT_SUPPORTED)
                    return (_GetTcpTableOld());
                throw;
            }
        }

        /// <summary>
        /// Gets the UDP table.
        /// Note: Tries the new method first and if this is unsupported on your system, uses the old one.
        /// </summary>
        /// <returns>An array with all active UDP connections.</returns>
        public static Connection[] GetUdpTable()
        {
            try
            {
                return (_GetUdpTableNew());
            }
            catch (Win32Exception e)
            {
                if (e.NativeErrorCode == NativeMethods.ERROR_NOT_SUPPORTED)
                    return (_GetUdpTableOld());
                throw;
            }
        }

        /// <summary>
        /// Gets the TCP table using the pre-Vista method and without process id's.
        /// </summary>
        /// <returns>An array with all active TCP connections.</returns>
        private static Connection[] _GetTcpTableOld()
        {
            return (_GetTable<NativeMethods.MIB_TCPROW>(
              (pointer, size) => {
                  var status = NativeMethods.GetTcpTable(pointer, ref size, false);
                  return (Tuple.Create(size, status));
              },
              row => new Connection(ConnectionProtocol.Tcp, new IPAddress(row.dwLocalAddr), _ConvertPort(row.dwLocalPort), new IPAddress(row.dwRemoteAddr), _ConvertPort(row.dwRemotePort), (ConnectionState)row.dwState, null)
            ));
        }

        /// <summary>
        /// Gets the UDP table using the pre-Vista method and without process id's.
        /// </summary>
        /// <returns>An array with all active UDP connections.</returns>
        private static Connection[] _GetUdpTableOld()
        {
            return (_GetTable<NativeMethods.MIB_UDPROW>(
              (pointer, size) => {
                  var status = NativeMethods.GetUdpTable(pointer, ref size, false);
                  return (Tuple.Create(size, status));
              },
              row => new Connection(ConnectionProtocol.Udp, new IPAddress(row.dwLocalAddr), _ConvertPort(row.dwLocalPort), IPAddress.None, 0, ConnectionState.Unknown, null)
            ));
        }

        /// <summary>
        /// Gets the TCP table using the Vista+ method and with process id's.
        /// </summary>
        /// <returns>An array with all active TCP connections.</returns>
        private static Connection[] _GetTcpTableNew()
        {
            return (_GetTable<NativeMethods.MIB_TCPROW_OWNER_PID>(
              (pointer, size) => {
                  var status = NativeMethods.GetExtendedTcpTable(pointer, ref size, false, NativeMethods.AfInet.Inet, NativeMethods.TcpTableClass.OwnerPidAll);
                  return (Tuple.Create(size, status));
              },
              row => {
                  Process process = null;
                  try { process = Process.GetProcessById((int)row.dwOwningPid); } catch (Exception) { }
                  return new Connection(ConnectionProtocol.Tcp, new IPAddress(row.dwLocalAddr), _ConvertPort(row.dwLocalPort), new IPAddress(row.dwRemoteAddr), _ConvertPort(row.dwRemotePort), (ConnectionState)row.dwState, process);
                }
            ));
        }

        /// <summary>
        /// Gets the UDP table using the Vista+ method and with process id's.
        /// </summary>
        /// <returns>An array with all active UDP connections.</returns>
        private static Connection[] _GetUdpTableNew()
        {
            return (_GetTable<NativeMethods.MIB_UDPROW_OWNER_PID>(
              (pointer, size) => {
                  var status = NativeMethods.GetExtendedUdpTable(pointer, ref size, false, NativeMethods.AfInet.Inet, NativeMethods.UdpTableClass.OwnerPid);
                  return (Tuple.Create(size, status));
              },
              row => new Connection(ConnectionProtocol.Udp, new IPAddress(row.dwLocalAddr), _ConvertPort(row.dwLocalPort), IPAddress.None, 0, ConnectionState.Unknown, Process.GetProcessById((int)row.dwOwningPid))
            ));
        }

        /// <summary>
        /// Gets a connection table.
        /// Note: Asks for space requirements first, allocates buffer, calls, casts, processes, deallocates, returns.
        /// </summary>
        /// <typeparam name="TRowtype">The type of the rows.</typeparam>
        /// <param name="call">The call to get the table.</param>
        /// <param name="rowProcessor">The row processor.</param>
        /// <returns>The connections from the table.</returns>
        private static Connection[] _GetTable<TRowtype>(Func<IntPtr, dword, Tuple<dword, int>> call, Func<TRowtype, Connection> rowProcessor)
        {
            Contract.Requires(call != null);
            Contract.Requires(rowProcessor != null);

            // get size of table first
            var tuple = call(IntPtr.Zero, 0);
            var size = tuple.Item1;
            var status = tuple.Item2;

            if (status == NativeMethods.NO_ERROR)
                return (new Connection[0]);

            while (status == NativeMethods.ERROR_INSUFFICIENT_BUFFER)
            {

                // allocate buffer and make sure it is de-allocated in every case
                var buffer = IntPtr.Zero;
                try
                {
                    buffer = Marshal.AllocHGlobal((int)size);
                    tuple = call(buffer, size);
                    size = tuple.Item1;
                    status = tuple.Item2;

                    if (status != NativeMethods.NO_ERROR) continue;

                    // the first 32-Bits of the buffer are always the number of table entries in each table type
                    var count = Marshal.ReadInt32(buffer);
                    var rowPointer = (long)buffer + 4;

                    var result = new Connection[count];
                    var rowType = typeof(TRowtype);
                    var rowSizeInBytes = Marshal.SizeOf(rowType);

                    // convert each entry to a connection instance
                    for (var i = 0; i < result.Length; ++i)
                    {
                        var row = (TRowtype)Marshal.PtrToStructure((IntPtr)rowPointer, rowType);
                        result[i] = rowProcessor(row);

                        // move pointer to next entry
                        rowPointer = rowPointer + rowSizeInBytes;
                    }

                    return (result);
                }
                finally
                {

                    // free buffer if allocated
                    if (buffer != IntPtr.Zero)
                        Marshal.FreeHGlobal(buffer);
                }

            } // retry as long as the buffer is too small

            // we failed somehow in all cases when we land here
            throw new Win32Exception(status);
        }

        /// <summary>
        /// Convert the strangely Motorola port number DWord. (Swaps low and high bytes)
        /// </summary>
        /// <param name="port">The port dword.</param>
        /// <returns>The real port number</returns>
        private static int _ConvertPort(dword port)
        {
            var result = ((port & 0xff) << 8) | ((port >> 8) & 0xff);
            return (int)result;
        }
    }
}

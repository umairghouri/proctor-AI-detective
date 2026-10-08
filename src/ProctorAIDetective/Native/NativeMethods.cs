using System;
using System.Collections.Generic;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;

namespace ProctorAIDetective.Native
{
    /// <summary>Win32 RECT. Public because window facts expose bounds.</summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct RECT
    {
        public int Left;
        public int Top;
        public int Right;
        public int Bottom;

        public int Width { get { return Right - Left; } }
        public int Height { get { return Bottom - Top; } }
        public bool IsEmpty { get { return Right <= Left || Bottom <= Top; } }

        public override string ToString()
        {
            return "(" + Left + "," + Top + ")-(" + Right + "," + Bottom + ") " + Width + "x" + Height;
        }
    }

    /// <summary>
    /// SafeHandle for process handles. Derives from the CriticalFinalizerObject-backed
    /// <see cref="SafeHandle"/>, so the handle is released even if the app is torn down
    /// mid-scan and never leaks on an exception path.
    /// </summary>
    public sealed class SafeProcessHandle : SafeHandle
    {
        /// <summary>Required public parameterless ctor: the marshaller constructs this as a P/Invoke return value.</summary>
        public SafeProcessHandle() : base(IntPtr.Zero, true) { }

        public override bool IsInvalid
        {
            get { return handle == IntPtr.Zero || handle == new IntPtr(-1); }
        }

        protected override bool ReleaseHandle()
        {
            return NativeMethods.CloseHandle(handle);
        }
    }

    /// <summary>One row of the extended TCP table, already decoded into usable managed values.</summary>
    public sealed class TcpConnectionInfo
    {
        /// <summary>Owning process id. 0 when the owner could not be attributed (e.g. a TIME_WAIT remnant).</summary>
        public int Pid { get; set; }

        /// <summary>"IPv4" or "IPv6".</summary>
        public string Family { get; set; } = "";

        public string LocalAddress { get; set; } = "";
        public int LocalPort { get; set; }
        public string RemoteAddress { get; set; } = "";
        public int RemotePort { get; set; }

        /// <summary>MIB_TCP_STATE. 2 = LISTEN, 5 = ESTABLISHED.</summary>
        public uint State { get; set; }

        public bool IsEstablished
        {
            get { return State == Win32Constants.MIB_TCP_STATE_ESTAB; }
        }

        public override string ToString()
        {
            return Family + " pid=" + Pid + " " + LocalAddress + ":" + LocalPort
                 + " -> " + RemoteAddress + ":" + RemotePort + " state=" + State;
        }
    }

    /// <summary>One node of the Windows DNS resolver cache, as `ipconfig /displaydns` reads it.</summary>
    public sealed class DnsCacheEntry
    {
        /// <summary>The cached name, exactly as stored (already lower-cased by the resolver).</summary>
        public string Name { get; set; } = "";

        /// <summary>DNS record type: 1 = A, 5 = CNAME, 28 = AAAA.</summary>
        public int RecordType { get; set; }

        public override string ToString()
        {
            return Name + " (type " + RecordType + ")";
        }
    }

    /// <summary>
    /// The whole raw P/Invoke surface, plus thin non-throwing wrappers for the three calls
    /// that are easy to get wrong (bitness-dependent GetWindowLongPtr, the two-call
    /// GetExtendedTcpTable buffer dance, and the undocumented DNS cache table).
    ///
    /// Every entry point is the explicit -W Unicode export where one exists.
    /// </summary>
    [SuppressUnmanagedCodeSecurity]
    public static class NativeMethods
    {
        // ============================================================ user32: window enumeration

        /// <summary>
        /// EnumWindows/EnumChildWindows callback. Return true to continue, false to stop.
        ///
        /// The delegate INSTANCE must stay rooted for the whole duration of the native call.
        /// A collected delegate leaves native code calling a freed thunk, which is a hard
        /// process crash, not an exception. Hold it in a local and GC.KeepAlive it.
        /// </summary>
        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

        // BOOL EnumWindows(WNDENUMPROC lpEnumFunc, LPARAM lParam);
        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);

        // BOOL EnumChildWindows(HWND hWndParent, WNDENUMPROC lpEnumFunc, LPARAM lParam);
        // The return value carries no information - do NOT test it.
        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool EnumChildWindows(IntPtr hWndParent, EnumWindowsProc lpEnumFunc, IntPtr lParam);

        // int GetWindowTextW(HWND, LPWSTR, int nMaxCount);
        [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "GetWindowTextW")]
        public static extern int GetWindowText(IntPtr hWnd, [Out] StringBuilder lpString, int nMaxCount);

        // int GetWindowTextLengthW(HWND);  -- characters, excluding the terminator.
        [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "GetWindowTextLengthW")]
        public static extern int GetWindowTextLength(IntPtr hWnd);

        // int GetClassNameW(HWND, LPWSTR, int nMaxCount);
        [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "GetClassNameW")]
        public static extern int GetClassName(IntPtr hWnd, [Out] StringBuilder lpClassName, int nMaxCount);

        // BOOL IsWindowVisible(HWND);  -- sets no last error.
        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool IsWindowVisible(IntPtr hWnd);

        // BOOL IsWindow(HWND);  -- cheap liveness check before a second query on the same handle.
        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool IsWindow(IntPtr hWnd);

        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool IsWindowEnabled(IntPtr hWnd);

        // DWORD GetWindowThreadProcessId(HWND, LPDWORD lpdwProcessId);
        // One call gives both: return value is the thread id, out param the pid.
        [DllImport("user32.dll", SetLastError = true)]
        public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);

        // BOOL GetWindowRect(HWND, LPRECT);
        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);

        // HWND GetWindow(HWND, UINT uCmd);  -- call with GW_OWNER.
        [DllImport("user32.dll", SetLastError = true)]
        public static extern IntPtr GetWindow(IntPtr hWnd, uint uCmd);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern IntPtr GetParent(IntPtr hWnd);

        [DllImport("user32.dll")]
        public static extern IntPtr GetForegroundWindow();

        // ============================================================ user32: window styles
        //
        // THE 32-BIT TRAP: "GetWindowLongPtrW" is not an exported symbol on 32-bit Windows.
        // The SDK #defines GetWindowLongPtr -> GetWindowLong there, so a single P/Invoke to
        // GetWindowLongPtrW throws EntryPointNotFoundException in a 32-bit process. This
        // assembly is AnyCPU, so it WILL run 32-bit on a 32-bit OS. Two private imports
        // behind one wrapper that dispatches on IntPtr.Size is the only correct shape.

        [DllImport("user32.dll", EntryPoint = "GetWindowLongPtrW", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr GetWindowLongPtr64(IntPtr hWnd, int nIndex);

        [DllImport("user32.dll", EntryPoint = "GetWindowLongW", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern int GetWindowLong32(IntPtr hWnd, int nIndex);

        /// <summary>
        /// Bitness-correct GetWindowLongPtr. Returns 0 on failure (the same value a window
        /// with no bits set returns, so treat 0 as "nothing interesting", never as an error).
        /// Never throws.
        /// </summary>
        public static long GetWindowLongPtr(IntPtr hWnd, int nIndex)
        {
            try
            {
                if (IntPtr.Size == 8)
                    return GetWindowLongPtr64(hWnd, nIndex).ToInt64();

                // On 32-bit the style word is a signed int; mask to 32 bits so that
                // WS_POPUP (0x80000000, the sign bit) does not sign-extend to 0xFFFFFFFF80000000
                // and break every subsequent bit test.
                return (uint)GetWindowLong32(hWnd, nIndex);
            }
            catch (EntryPointNotFoundException)
            {
                return 0;
            }
        }

        // ============================================================ user32: display affinity
        //
        // BOOL GetWindowDisplayAffinity(HWND hWnd, DWORD *pdwAffinity);
        //
        // Fully cross-process, no elevation required: 633/633 other-process top-level windows
        // answered from a medium-integrity caller. On FAILURE pdwAffinity is UNDEFINED - the
        // wrapper below forces it to WDA_NONE and reports the failure separately.
        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetWindowDisplayAffinity(IntPtr hWnd, out uint pdwAffinity);

        // BOOL SetWindowDisplayAffinity(HWND, DWORD);
        // MSDN: the window must belong to the CURRENT process. Present only so this app can
        // protect its own UI; it can never be used against a third-party window.
        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SetWindowDisplayAffinity(IntPtr hWnd, uint dwAffinity);

        /// <summary>
        /// Read a window's display affinity. Never throws.
        /// </summary>
        /// <param name="affinity">
        /// The affinity on success. FORCED to WDA_NONE on failure, because the out param is
        /// undefined then - but the caller must record the window as "query failed", not as
        /// "not hidden".
        /// </param>
        /// <param name="win32Error">
        /// 0 on success. On failure, commonly 1400 (ERROR_INVALID_WINDOW_HANDLE) because the
        /// window died between EnumWindows and the query. That is routine, not a problem.
        /// </param>
        /// <returns>True when <paramref name="affinity"/> is meaningful.</returns>
        public static bool TryGetWindowDisplayAffinity(IntPtr hWnd, out uint affinity, out int win32Error)
        {
            try
            {
                if (GetWindowDisplayAffinity(hWnd, out affinity))
                {
                    win32Error = Win32Constants.ERROR_SUCCESS;
                    return true;
                }

                win32Error = Marshal.GetLastWin32Error();
                affinity = Win32Constants.WDA_NONE;   // the out value is undefined on failure
                return false;
            }
            catch (Exception)
            {
                affinity = Win32Constants.WDA_NONE;
                win32Error = Win32Constants.ERROR_GEN_FAILURE;
                return false;
            }
        }

        // ============================================================ dwmapi
        //
        // HRESULT DwmGetWindowAttribute(HWND, DWORD dwAttribute, PVOID pvAttribute, DWORD cbAttribute);
        // PreserveSig = true: windows that do not support the attribute return E_INVALIDARG,
        // and taking a COMException on every such window would be both slow and wrong.

        [DllImport("dwmapi.dll", PreserveSig = true)]
        public static extern int DwmGetWindowAttribute(IntPtr hwnd, int dwAttribute, out int pvAttribute, int cbAttribute);

        [DllImport("dwmapi.dll", PreserveSig = true)]
        public static extern int DwmGetWindowAttribute(IntPtr hwnd, int dwAttribute, out RECT pvAttribute, int cbAttribute);

        [DllImport("dwmapi.dll", PreserveSig = true)]
        public static extern int DwmIsCompositionEnabled([MarshalAs(UnmanagedType.Bool)] out bool pfEnabled);

        /// <summary>
        /// Read DWMWA_CLOAKED. Never throws.
        ///
        /// Remember when scoring: DWM_CLOAKED_SHELL is the NORMAL state of a suspended UWP
        /// window (22 observed on an idle desktop). Only DWM_CLOAKED_APP *without*
        /// DWM_CLOAKED_SHELL is even weakly interesting.
        /// </summary>
        /// <param name="cloaked">The cloak flags; 0 when the HRESULT is not S_OK.</param>
        /// <returns>The HRESULT. S_OK means <paramref name="cloaked"/> is meaningful; E_INVALIDARG means the window does not support the attribute.</returns>
        public static int TryGetCloakedState(IntPtr hWnd, out int cloaked)
        {
            try
            {
                int hr = DwmGetWindowAttribute(hWnd, Win32Constants.DWMWA_CLOAKED, out cloaked, sizeof(int));
                if (hr != Win32Constants.S_OK) cloaked = 0;
                return hr;
            }
            catch (Exception)
            {
                cloaked = 0;
                return Win32Constants.E_INVALIDARG;
            }
        }

        // ============================================================ kernel32: process access

        // HANDLE OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern SafeProcessHandle OpenProcess(
            uint dwDesiredAccess,
            [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle,
            uint dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CloseHandle(IntPtr hObject);

        // BOOL QueryFullProcessImageNameW(HANDLE, DWORD dwFlags, LPWSTR lpExeName, PDWORD lpdwSize);
        //
        // lpdwSize is [in, out] and counts CHARACTERS, not bytes:
        //   IN  = buffer capacity, OUT = characters written excluding the terminator.
        // It must be `ref uint`. Passing it by value silently corrupts the call.
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "QueryFullProcessImageNameW")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool QueryFullProcessImageName(
            SafeProcessHandle hProcess,
            uint dwFlags,
            [Out] StringBuilder lpExeName,
            ref uint lpdwSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool IsWow64Process(SafeProcessHandle hProcess, [MarshalAs(UnmanagedType.Bool)] out bool wow64Process);

        [DllImport("kernel32.dll")]
        public static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool IsWow64Process(IntPtr hProcess, [MarshalAs(UnmanagedType.Bool)] out bool wow64Process);

        /// <summary>
        /// True when this 32-bit process is running under WOW64 on 64-bit Windows. Matters
        /// because a 32-bit process sees a redirected view of %WINDIR%\System32 and of parts
        /// of the registry, so "file not found" from a WOW64 process is not proof of absence.
        /// Never throws.
        /// </summary>
        public static bool IsCurrentProcessWow64()
        {
            if (IntPtr.Size == 8) return false;   // a 64-bit process is never under WOW64
            try
            {
                bool wow64;
                return IsWow64Process(GetCurrentProcess(), out wow64) && wow64;
            }
            catch (Exception) { return false; }
        }

        // ============================================================ ntdll: true OS version
        //
        // Environment.OSVersion obeys the application manifest's compatibility shim and can
        // under-report on an unmanifested host. RtlGetVersion never lies, which matters
        // because the build number decides whether WDA_EXCLUDEFROMCAPTURE even EXISTS - and
        // on a build below 19041 its absence proves nothing at all.

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct RTL_OSVERSIONINFOW
        {
            public uint dwOSVersionInfoSize;
            public uint dwMajorVersion;
            public uint dwMinorVersion;
            public uint dwBuildNumber;
            public uint dwPlatformId;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
            public string? szCSDVersion;
        }

        [DllImport("ntdll.dll", EntryPoint = "RtlGetVersion")]
        private static extern int RtlGetVersion(ref RTL_OSVERSIONINFOW versionInfo);

        /// <summary>
        /// True OS build number, from RtlGetVersion, falling back to Environment.OSVersion.
        /// Never throws.
        /// </summary>
        public static int GetOsBuildNumber()
        {
            try
            {
                RTL_OSVERSIONINFOW vi = new RTL_OSVERSIONINFOW();
                vi.dwOSVersionInfoSize = (uint)Marshal.SizeOf(typeof(RTL_OSVERSIONINFOW));
                vi.szCSDVersion = "";
                if (RtlGetVersion(ref vi) == Win32Constants.S_OK && vi.dwBuildNumber > 0)
                    return (int)vi.dwBuildNumber;
            }
            catch (Exception) { /* ntdll export missing is not survivable-worthy news */ }

            try { return Environment.OSVersion.Version.Build; }
            catch (Exception) { return 0; }
        }

        /// <summary>Human-readable OS version, e.g. "Windows 10.0.26200 (64-bit)". Never throws.</summary>
        public static string GetOsVersionString()
        {
            try
            {
                RTL_OSVERSIONINFOW vi = new RTL_OSVERSIONINFOW();
                vi.dwOSVersionInfoSize = (uint)Marshal.SizeOf(typeof(RTL_OSVERSIONINFOW));
                vi.szCSDVersion = "";
                if (RtlGetVersion(ref vi) == Win32Constants.S_OK && vi.dwBuildNumber > 0)
                {
                    return "Windows " + vi.dwMajorVersion + "." + vi.dwMinorVersion + "." + vi.dwBuildNumber
                         + (Environment.Is64BitOperatingSystem ? " (64-bit)" : " (32-bit)");
                }
            }
            catch (Exception) { }

            try { return "Windows " + Environment.OSVersion.Version; }
            catch (Exception) { return "Windows (version unavailable)"; }
        }

        /// <summary>
        /// True when this build can actually honour WDA_EXCLUDEFROMCAPTURE (Windows 10 2004 /
        /// build 19041+). On older builds the OS silently downgrades it to WDA_MONITOR, so a
        /// scan there must say "cannot distinguish", not "nothing hiding".
        /// </summary>
        public static bool SupportsExcludeFromCapture
        {
            get { return GetOsBuildNumber() >= Win32Constants.WDA_EXCLUDEFROMCAPTURE_MIN_BUILD; }
        }

        // ============================================================ iphlpapi: TCP table
        //
        // Layouts confirmed at runtime with Marshal.SizeOf / Marshal.OffsetOf on this machine:
        //   MIB_TCPROW_OWNER_PID  = 24 bytes (six DWORDs, no padding)
        //   MIB_TCP6ROW_OWNER_PID = 56 bytes, offsets 0/16/20/24/40/44/48/52
        // Both tables begin with a DWORD row count, so the first row starts at offset 4.

#pragma warning disable 0649 // fields are populated by the interop marshaller, never from source
        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_TCPROW_OWNER_PID
        {
            public uint dwState;        //  0
            public uint dwLocalAddr;    //  4
            public uint dwLocalPort;    //  8
            public uint dwRemoteAddr;   // 12
            public uint dwRemotePort;   // 16
            public uint dwOwningPid;    // 20
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_TCP6ROW_OWNER_PID
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public byte[]? ucLocalAddr;     //  0
            public uint dwLocalScopeId;     // 16
            public uint dwLocalPort;        // 20
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public byte[]? ucRemoteAddr;    // 24
            public uint dwRemoteScopeId;    // 40
            public uint dwRemotePort;       // 44
            public uint dwState;            // 48
            public uint dwOwningPid;        // 52
        }

#pragma warning restore 0649

        // DWORD GetExtendedTcpTable(PVOID, PDWORD pdwSize, BOOL bOrder, ULONG ulAf,
        //                           TCP_TABLE_CLASS TableClass, ULONG Reserved);
        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern uint GetExtendedTcpTable(
            IntPtr pTcpTable,
            ref uint pdwSize,
            [MarshalAs(UnmanagedType.Bool)] bool bOrder,
            int ulAf,
            int tableClass,
            uint reserved);

        /// <summary>
        /// Decode a port from a MIB table DWORD. The port lives BIG-ENDIAN in the low 16 bits,
        /// so a naive cast yields a byte-swapped nonsense port (443 reads as 47873).
        /// Verified against live sockets: 0x01BB -> 443, not 0xBB01.
        /// </summary>
        private static int DecodePort(uint dw)
        {
            return (int)(((dw & 0xFF) << 8) | ((dw >> 8) & 0xFF));
        }

        private static string FormatIPv4(uint addr)
        {
            // The DWORD is already in network byte order, i.e. little-endian memory holds a.b.c.d.
            return (addr & 0xFF) + "." + ((addr >> 8) & 0xFF) + "." + ((addr >> 16) & 0xFF) + "." + ((addr >> 24) & 0xFF);
        }

        private static string FormatIPv6(byte[]? bytes)
        {
            if (bytes == null || bytes.Length != 16) return "::";
            try
            {
                return new System.Net.IPAddress(bytes).ToString();
            }
            catch (Exception)
            {
                StringBuilder sb = new StringBuilder(39);
                for (int i = 0; i < 16; i += 2)
                {
                    if (i > 0) sb.Append(':');
                    sb.Append(((bytes[i] << 8) | bytes[i + 1]).ToString("x"));
                }
                return sb.ToString();
            }
        }

        /// <summary>
        /// Every TCP connection on the machine, IPv4 and IPv6, joined to its owning pid.
        /// Uses the standard two-call buffer-size pattern. Never throws.
        /// </summary>
        /// <param name="failureNote">
        /// Null when both families were read. Otherwise a human-readable note the caller
        /// should append to ScanReport.Limitations - a partial table is a blind spot, not a
        /// clean result.
        /// </param>
        public static IReadOnlyList<TcpConnectionInfo> GetTcpConnections(out string? failureNote)
        {
            List<TcpConnectionInfo> rows = new List<TcpConnectionInfo>(256);
            List<string> problems = new List<string>(2);

            CollectTcpFamily(Win32Constants.AF_INET, rows, problems);
            CollectTcpFamily(Win32Constants.AF_INET6, rows, problems);

            failureNote = problems.Count == 0 ? null : string.Join("; ", problems.ToArray());
            return rows;
        }

        private static void CollectTcpFamily(int family, List<TcpConnectionInfo> rows, List<string> problems)
        {
            string familyName = family == Win32Constants.AF_INET ? "IPv4" : "IPv6";
            IntPtr buffer = IntPtr.Zero;
            try
            {
                uint size = 0;

                // Call 1: ask for the required size. Expected return is ERROR_INSUFFICIENT_BUFFER.
                uint rc = GetExtendedTcpTable(IntPtr.Zero, ref size, false, family,
                                              Win32Constants.TCP_TABLE_OWNER_PID_ALL, 0);
                if (rc != Win32Constants.ERROR_INSUFFICIENT_BUFFER && rc != Win32Constants.ERROR_SUCCESS)
                {
                    problems.Add("TCP table (" + familyName + ") unavailable: Win32 error " + rc);
                    return;
                }
                if (size == 0) return;   // nothing to read

                // The table can grow between the two calls; allow a little headroom and retry once.
                for (int attempt = 0; attempt < 2; attempt++)
                {
                    uint capacity = size + 4096;
                    buffer = Marshal.AllocHGlobal((int)capacity);
                    uint actual = capacity;

                    rc = GetExtendedTcpTable(buffer, ref actual, false, family,
                                             Win32Constants.TCP_TABLE_OWNER_PID_ALL, 0);
                    if (rc == Win32Constants.ERROR_SUCCESS)
                    {
                        ReadTcpTable(buffer, family, familyName, rows);
                        return;
                    }

                    Marshal.FreeHGlobal(buffer);
                    buffer = IntPtr.Zero;

                    if (rc != Win32Constants.ERROR_INSUFFICIENT_BUFFER)
                    {
                        problems.Add("TCP table (" + familyName + ") read failed: Win32 error " + rc);
                        return;
                    }
                    size = actual;
                }

                problems.Add("TCP table (" + familyName + ") kept growing between sizing and reading");
            }
            catch (Exception ex)
            {
                problems.Add("TCP table (" + familyName + ") threw " + ex.GetType().Name + ": " + ex.Message);
            }
            finally
            {
                if (buffer != IntPtr.Zero) Marshal.FreeHGlobal(buffer);
            }
        }

        private static void ReadTcpTable(IntPtr buffer, int family, string familyName, List<TcpConnectionInfo> rows)
        {
            int count = Marshal.ReadInt32(buffer);
            if (count <= 0 || count > 200000) return;   // a sane bound against a corrupt header

            long cursor = buffer.ToInt64() + 4;   // the DWORD row count precedes the rows

            for (int i = 0; i < count; i++)
            {
                if (family == Win32Constants.AF_INET)
                {
                    MIB_TCPROW_OWNER_PID r = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(new IntPtr(cursor));

                    rows.Add(new TcpConnectionInfo
                    {
                        Pid = unchecked((int)r.dwOwningPid),
                        Family = familyName,
                        LocalAddress = FormatIPv4(r.dwLocalAddr),
                        LocalPort = DecodePort(r.dwLocalPort),
                        RemoteAddress = FormatIPv4(r.dwRemoteAddr),
                        RemotePort = DecodePort(r.dwRemotePort),
                        State = r.dwState
                    });

                    cursor += Win32Constants.MIB_TCPROW_OWNER_PID_SIZE;
                }
                else
                {
                    MIB_TCP6ROW_OWNER_PID r = Marshal.PtrToStructure<MIB_TCP6ROW_OWNER_PID>(new IntPtr(cursor));

                    rows.Add(new TcpConnectionInfo
                    {
                        Pid = unchecked((int)r.dwOwningPid),
                        Family = familyName,
                        LocalAddress = FormatIPv6(r.ucLocalAddr),
                        LocalPort = DecodePort(r.dwLocalPort),
                        RemoteAddress = FormatIPv6(r.ucRemoteAddr),
                        RemotePort = DecodePort(r.dwRemotePort),
                        State = r.dwState
                    });

                    cursor += Win32Constants.MIB_TCP6ROW_OWNER_PID_SIZE;
                }
            }
        }

        // ============================================================ dnsapi: resolver cache
        //
        // WHY NOT DnsQuery_W + DNS_QUERY_NO_WIRE_QUERY: measured 48% recall against entries
        // Get-DnsClientCache proved were cached. It returned 9701 (DNS_ERROR_RECORD_DOES_NOT_EXIST)
        // for names that WERE in the cache - a silent false negative - and specifically missed
        // www.parakeet-ai.com. A detector that misses the thing it is looking for and says
        // "clear" is worse than no detector.
        //
        // DnsGetCacheDataTable is undocumented (it is what `ipconfig /displaydns` calls) but
        // measured 100% recall in 0.1 ms. Verified on this machine: returns 1, head pointer
        // non-null, 174 nodes walked cleanly.
        //
        // FREEING: DnsFree(node, DnsFreeFlat=0) per node. Verified safe. DnsFreeRecordList (1)
        // ACCESS-VIOLATES on these nodes - it is not an alternative.

#pragma warning disable 0649 // fields are populated by the interop marshaller, never from source
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct DNS_CACHE_ENTRY
        {
            public IntPtr Next;
            [MarshalAs(UnmanagedType.LPWStr)] public string? Name;
            public ushort Type;
            public ushort DataLength;
            public uint Flags;
        }

#pragma warning restore 0649

        // Undocumented. Returns non-zero on success and writes the head of a singly-linked list.
        [DllImport("dnsapi.dll", EntryPoint = "DnsGetCacheDataTable", SetLastError = true)]
        private static extern int DnsGetCacheDataTable(out IntPtr ppCacheEntries);

        // void DnsFree(PVOID pData, DNS_FREE_TYPE FreeType);
        [DllImport("dnsapi.dll", EntryPoint = "DnsFree")]
        private static extern void DnsFree(IntPtr pData, int freeType);

        /// <summary>
        /// Read the Windows DNS resolver cache. Never throws: the export is undocumented and
        /// may vanish in a future Windows build, so the caller must degrade gracefully rather
        /// than treat an empty list as "nothing was ever resolved".
        /// </summary>
        /// <param name="failureNote">
        /// Null on success. Otherwise a human-readable note for ScanReport.Limitations -
        /// an unreadable cache is a blind spot, not evidence of absence.
        /// </param>
        public static IReadOnlyList<DnsCacheEntry> GetDnsCacheEntries(out string? failureNote)
        {
            List<DnsCacheEntry> entries = new List<DnsCacheEntry>(256);
            failureNote = null;

            IntPtr head = IntPtr.Zero;
            try
            {
                int rc = DnsGetCacheDataTable(out head);
                if (rc == 0 || head == IntPtr.Zero)
                {
                    failureNote = "DNS resolver cache could not be read (DnsGetCacheDataTable returned " + rc
                                + "); recently-visited hostnames are a blind spot for this scan.";
                    return entries;
                }

                IntPtr node = head;
                int guard = 0;
                while (node != IntPtr.Zero && guard < 100000)
                {
                    DNS_CACHE_ENTRY e = Marshal.PtrToStructure<DNS_CACHE_ENTRY>(node);
                    IntPtr next = e.Next;   // capture BEFORE freeing this node

                    if (!string.IsNullOrEmpty(e.Name))
                    {
                        entries.Add(new DnsCacheEntry
                        {
                            Name = e.Name ?? string.Empty,
                            RecordType = e.Type
                        });
                    }

                    guard++;

                    // DnsFreeFlat, per node, as the node is consumed. Verified non-crashing.
                    try { DnsFree(node, Win32Constants.DNS_FREE_FLAT); }
                    catch (Exception) { /* a failed free is a leak, never a reason to abort the scan */ }

                    node = next;
                }

                head = IntPtr.Zero;   // every node, head included, has now been freed
            }
            catch (EntryPointNotFoundException)
            {
                failureNote = "DnsGetCacheDataTable is not available on this Windows build; "
                            + "recently-visited hostnames are a blind spot for this scan.";
            }
            catch (Exception ex)
            {
                failureNote = "DNS resolver cache read failed (" + ex.GetType().Name + ": " + ex.Message
                            + "); recently-visited hostnames are a blind spot for this scan.";
            }

            return entries;
        }

        // ============================================================ small window helpers

        /// <summary>Window title text. Returns "" on any failure. Never throws.</summary>
        public static string GetWindowTitle(IntPtr hWnd)
        {
            try
            {
                int len = GetWindowTextLength(hWnd);
                if (len <= 0) len = 0;
                if (len > 8192) len = 8192;           // defensive: a hostile title is still only a string

                StringBuilder sb = new StringBuilder(len + 2);
                int written = GetWindowText(hWnd, sb, sb.Capacity);
                return written > 0 ? sb.ToString() : string.Empty;
            }
            catch (Exception) { return string.Empty; }
        }

        /// <summary>Window class name. Returns "" on any failure. Never throws.</summary>
        public static string GetWindowClassName(IntPtr hWnd)
        {
            try
            {
                StringBuilder sb = new StringBuilder(256);
                int written = GetClassName(hWnd, sb, sb.Capacity);
                return written > 0 ? sb.ToString() : string.Empty;
            }
            catch (Exception) { return string.Empty; }
        }

        /// <summary>Owning process id for a window, or 0. Never throws.</summary>
        public static int GetWindowPid(IntPtr hWnd)
        {
            try
            {
                uint pid;
                GetWindowThreadProcessId(hWnd, out pid);
                return unchecked((int)pid);
            }
            catch (Exception) { return 0; }
        }

        /// <summary>True when DWM composition is on. Never throws.</summary>
        public static bool IsDwmCompositionEnabled()
        {
            try
            {
                bool enabled;
                return DwmIsCompositionEnabled(out enabled) == Win32Constants.S_OK && enabled;
            }
            catch (Exception) { return false; }
        }
    }
}

namespace PDetector.Native
{
    /// <summary>
    /// Every raw Win32 numeric value this app depends on, in one place, each with the
    /// verified fact that justifies it.
    ///
    /// "Verified" here means empirically confirmed on Windows 11 build 26200 against live
    /// processes and windows, not merely copied from a header. Where observed behaviour and
    /// the documentation disagree, the comment says so and the observed behaviour wins.
    /// </summary>
    public static class Win32Constants
    {
        // ------------------------------------------------------------------ GetWindowLongPtr indices
        // winuser.h. Negative indices address the window's own fields rather than extra bytes.

        /// <summary>Window style (WS_*). Verified: GetWindowLongPtr(hWnd, -16) returns WS_VISIBLE|WS_POPUP etc.</summary>
        public const int GWL_STYLE = -16;

        /// <summary>Extended window style (WS_EX_*). Verified: -20 returns 0x80000 for layered windows.</summary>
        public const int GWL_EXSTYLE = -20;

        /// <summary>Owner window handle. Readable cross-process without elevation.</summary>
        public const int GWLP_HWNDPARENT = -8;

        /// <summary>Child-window identifier. Only meaningful for child windows.</summary>
        public const int GWLP_ID = -12;

        // ------------------------------------------------------------------ Extended window styles
        // All verified by reading GWL_EXSTYLE across 633 live top-level windows: every one of
        // these bits was observed in the wild, which is exactly why no single bit is evidence.

        /// <summary>0x8. Always-on-top. Observed on 40+ perfectly ordinary windows; never evidence alone.</summary>
        public const long WS_EX_TOPMOST = 0x00000008L;

        /// <summary>0x20. Click-through (hit-testing passes beneath). Overlay building block.</summary>
        public const long WS_EX_TRANSPARENT = 0x00000020L;

        /// <summary>0x80. Hidden from the taskbar and Alt-Tab. Extremely common on helper windows.</summary>
        public const long WS_EX_TOOLWINDOW = 0x00000080L;

        /// <summary>0x40000. Forces a taskbar button even for a tool window.</summary>
        public const long WS_EX_APPWINDOW = 0x00040000L;

        /// <summary>0x80000. Layered (per-pixel alpha). 581 of 633 windows were NOT layered, which is why display affinity must never be gated on this bit.</summary>
        public const long WS_EX_LAYERED = 0x00080000L;

        /// <summary>0x200000. No redirection surface: the window is never composited into the DWM redirection bitmap, so it cannot be captured by bitmap-copy screenshotters. Common on DirectComposition apps.</summary>
        public const long WS_EX_NOREDIRECTIONBITMAP = 0x00200000L;

        /// <summary>0x2000000. Double-buffered compositing. Benign on its own.</summary>
        public const long WS_EX_COMPOSITED = 0x02000000L;

        /// <summary>0x8000000. Never takes foreground focus when clicked. Overlay building block.</summary>
        public const long WS_EX_NOACTIVATE = 0x08000000L;

        // ------------------------------------------------------------------ Window styles (subset)

        /// <summary>0x10000000. Mirrors IsWindowVisible for the window itself (not its ancestors).</summary>
        public const long WS_VISIBLE = 0x10000000L;

        /// <summary>0x40000000. Child window; excluded from EnumWindows, reachable via EnumChildWindows.</summary>
        public const long WS_CHILD = 0x40000000L;

        /// <summary>0x80000000. Popup window. Note this is the sign bit of a 32-bit style word.</summary>
        public const long WS_POPUP = 0x80000000L;

        // ------------------------------------------------------------------ GetWindow commands

        /// <summary>4. Retrieves the owner window. An owned tool window is normal; an UNOWNED topmost tool window is not.</summary>
        public const uint GW_OWNER = 4;

        // ------------------------------------------------------------------ Display affinity
        //
        // The decisive fact for this whole app: GetWindowDisplayAffinity is fully CROSS-PROCESS
        // and needs NO elevation. 633 of 633 other-process top-level windows returned success
        // from a non-elevated medium-integrity process, including reading 0x11 out of a window
        // owned by an ELEVATED process. MSDN's remark that it "succeeds only when the window is
        // layered" is wrong in practice: 581 NON-layered windows all succeeded.

        /// <summary>0x0. Normal window, fully capturable. Also the value we force on query FAILURE, since the out param is undefined then.</summary>
        public const uint WDA_NONE = 0x00000000;

        /// <summary>0x1. Monitor-only: a screen capture yields a BLACK rectangle where the window is. Windows 7+.</summary>
        public const uint WDA_MONITOR = 0x00000001;

        /// <summary>
        /// 0x11, NOT 0x02. The value deliberately includes the WDA_MONITOR bit. The window is
        /// entirely ABSENT from capture - no black box, the capture shows what is behind it.
        /// This is what Electron's setContentProtection sets, and what ParakeetAI uses.
        /// </summary>
        public const uint WDA_EXCLUDEFROMCAPTURE = 0x00000011;

        /// <summary>19041. Windows 10 version 2004. Below this build WDA_EXCLUDEFROMCAPTURE does not exist, so its absence proves nothing.</summary>
        public const int WDA_EXCLUDEFROMCAPTURE_MIN_BUILD = 19041;

        // ------------------------------------------------------------------ DWM window attributes
        // DWMWINDOWATTRIBUTE is 1-BASED: DWMWA_NCRENDERING_ENABLED == 1, so DWMWA_CLOAKED == 14.

        /// <summary>1. Non-client rendering enabled. Used only to probe whether DWM answers for a window at all.</summary>
        public const int DWMWA_NCRENDERING_ENABLED = 1;

        /// <summary>9. True window bounds excluding the invisible resize border. Differs from GetWindowRect.</summary>
        public const int DWMWA_EXTENDED_FRAME_BOUNDS = 9;

        /// <summary>14. Reads the cloak state. Returns E_INVALIDARG for windows that do not support it, hence PreserveSig=true.</summary>
        public const int DWMWA_CLOAKED = 14;

        /// <summary>0x1. Cloaked by the owning app itself. Only CLOAKED_APP *without* CLOAKED_SHELL is weakly interesting.</summary>
        public const int DWM_CLOAKED_APP = 0x00000001;

        /// <summary>0x2. Cloaked by the Shell. This is the NORMAL state of a suspended UWP window - 22 observed on an idle desktop - so flagging it produces constant false positives.</summary>
        public const int DWM_CLOAKED_SHELL = 0x00000002;

        /// <summary>0x4. Cloak state inherited from the owner window. Carries no independent information.</summary>
        public const int DWM_CLOAKED_INHERITED = 0x00000004;

        // ------------------------------------------------------------------ Process access rights

        /// <summary>
        /// 0x1000. Vista+. The right access right for identification: paired with
        /// QueryFullProcessImageNameW it resolved 259 of ~430 paths non-elevated and 428
        /// elevated, versus Process.MainModule's 167 and 412. Strictly better, and it never throws.
        /// </summary>
        public const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

        /// <summary>0x400. Pre-Vista equivalent. Fails against many processes PROCESS_QUERY_LIMITED_INFORMATION can open; kept only for completeness.</summary>
        public const uint PROCESS_QUERY_INFORMATION = 0x0400;

        /// <summary>0x10. Needed by Process.MainModule's module walk. Deliberately NOT requested: it is what makes MainModule fail.</summary>
        public const uint PROCESS_VM_READ = 0x0010;

        /// <summary>0x0. Ask QueryFullProcessImageNameW for the Win32 path (C:\...) rather than the NT device path.</summary>
        public const uint PROCESS_NAME_WIN32 = 0x00000000;

        /// <summary>0x1. NT device path form (\Device\HarddiskVolume3\...). Used only when the Win32 form is unavailable.</summary>
        public const uint PROCESS_NAME_NATIVE = 0x00000001;

        // ------------------------------------------------------------------ Win32 error codes
        // Every one of these is an EXPECTED outcome that must degrade quietly, never throw.

        /// <summary>0. Success. Note: a successful call does not reset the thread's last error, so only read the error after a FAILED call.</summary>
        public const int ERROR_SUCCESS = 0;

        /// <summary>2. Image file gone from disk between enumeration and inspection.</summary>
        public const int ERROR_FILE_NOT_FOUND = 2;

        /// <summary>5. OpenProcess denied. Routine: a non-elevated caller cannot open roughly 40% of processes. Never an error to report to the user.</summary>
        public const int ERROR_ACCESS_DENIED = 5;

        /// <summary>6. Handle already closed or never valid.</summary>
        public const int ERROR_INVALID_HANDLE = 6;

        /// <summary>87. Bad argument; also what we synthesise for pid 0 (Idle) and pid 4 (System), which have no image path.</summary>
        public const int ERROR_INVALID_PARAMETER = 87;

        /// <summary>31. ERROR_GEN_FAILURE. Used here as the synthetic error code when a P/Invoke itself threw rather than returning a Win32 failure.</summary>
        public const int ERROR_GEN_FAILURE = 31;

        /// <summary>122. Buffer too small. Both QueryFullProcessImageNameW and GetExtendedTcpTable use this to report the required size in the two-call pattern.</summary>
        public const int ERROR_INSUFFICIENT_BUFFER = 122;

        /// <summary>299. Partial read across a process boundary. Seen on bitness mismatches.</summary>
        public const int ERROR_PARTIAL_COPY = 299;

        /// <summary>
        /// 1400. The window died between EnumWindows and the query. Completely routine on a
        /// live desktop - it is the dominant failure for GetWindowDisplayAffinity - and must be
        /// recorded as "query failed", never as "not hidden" and never as a thrown exception.
        /// </summary>
        public const int ERROR_INVALID_WINDOW_HANDLE = 1400;

        // ------------------------------------------------------------------ HRESULT / NTSTATUS

        /// <summary>0. HRESULT success, and also STATUS_SUCCESS for RtlGetVersion.</summary>
        public const int S_OK = 0;

        /// <summary>0x80070057. What DwmGetWindowAttribute returns for a window that does not support the attribute. Expected, not an error.</summary>
        public const int E_INVALIDARG = unchecked((int)0x80070057);

        /// <summary>0x80092009. CRYPT_E_NOT_FOUND. X509Certificate.CreateFromSignedFile THROWS this for a file with no EMBEDDED signature - including catalog-signed Microsoft binaries that are perfectly trusted. It means "no embedded signature", never "unsigned" and never "untrusted".</summary>
        public const int CRYPT_E_NOT_FOUND = unchecked((int)0x80092009);

        // ------------------------------------------------------------------ Address families

        /// <summary>2. AF_INET. First argument family for GetExtendedTcpTable.</summary>
        public const int AF_INET = 2;

        /// <summary>23. AF_INET6 on Windows (NOT 10, which is the Linux value).</summary>
        public const int AF_INET6 = 23;

        /// <summary>5. TCP_TABLE_OWNER_PID_ALL: every connection in every state, with the owning pid. The only table class that joins sockets to processes.</summary>
        public const int TCP_TABLE_OWNER_PID_ALL = 5;

        /// <summary>24 bytes, confirmed at runtime by Marshal.SizeOf. Six DWORDs, no padding.</summary>
        public const int MIB_TCPROW_OWNER_PID_SIZE = 24;

        /// <summary>56 bytes, confirmed at runtime, with field offsets 0/16/20/24/40/44/48/52.</summary>
        public const int MIB_TCP6ROW_OWNER_PID_SIZE = 56;

        /// <summary>5. MIB_TCP_STATE_ESTAB - an actually-live connection, as opposed to LISTEN or TIME_WAIT.</summary>
        public const uint MIB_TCP_STATE_ESTAB = 5;

        // ------------------------------------------------------------------ DNS

        /// <summary>
        /// 0. DNS_FREE_TYPE.DnsFreeFlat - the ONLY correct way to release a node returned by
        /// DnsGetCacheDataTable. Verified: freeing with DnsFreeRecordList (1) access-violates.
        /// </summary>
        public const int DNS_FREE_FLAT = 0;

        /// <summary>1. DnsFreeRecordList. Named here only so nobody reaches for it: it CRASHES on cache-table nodes.</summary>
        public const int DNS_FREE_RECORD_LIST = 1;

        /// <summary>1. DNS_TYPE_A. The record type carried in a cache-table node's Type field.</summary>
        public const int DNS_TYPE_A = 1;

        /// <summary>28. DNS_TYPE_AAAA.</summary>
        public const int DNS_TYPE_AAAA = 28;

        /// <summary>5. DNS_TYPE_CNAME.</summary>
        public const int DNS_TYPE_CNAME = 5;
    }
}

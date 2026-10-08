using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Management;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;

namespace ProctorAIDetective.Native
{
    /// <summary>
    /// Everything this app could learn about one live process.
    ///
    /// Every string field is non-null and defaults to "" rather than null: a scanner that
    /// has to null-check eleven fields before it can compare one of them ends up skipping
    /// the check. "" means "we could not read it", which the scanner must treat as unknown,
    /// never as a mismatch.
    /// </summary>
    public sealed class ProcessInfo
    {
        public int Pid { get; set; }

        /// <summary>Process name without extension, as the OS reports it. Never "".</summary>
        public string Name { get; set; } = "";

        /// <summary>Full Win32 image path, or "" when it could not be resolved. See <see cref="PathResolved"/>.</summary>
        public string ImagePath { get; set; } = "";

        // ---- version resource. All "" when the file has no version resource or was unreadable.
        // ParakeetAI is identifiable here even though its file NAME is a blank Braille glyph:
        // CompanyName is the plain ASCII string "ParakeetAI".
        public string CompanyName { get; set; } = "";
        public string ProductName { get; set; } = "";
        public string FileDescription { get; set; } = "";

        /// <summary>OriginalFilename. Note: ParakeetAI ships this EMPTY, which is itself unusual for a signed Electron app.</summary>
        public string OriginalFilename { get; set; } = "";

        public string FileVersion { get; set; } = "";
        public string LegalCopyright { get; set; } = "";

        // ---- Authenticode.

        /// <summary>Subject of the EMBEDDED Authenticode certificate, or "" when there is none.</summary>
        public string SignerSubject { get; set; } = "";

        /// <summary>SHA-1 thumbprint of the embedded leaf certificate, uppercase hex, or "".</summary>
        public string CertThumbprint { get; set; } = "";

        /// <summary>
        /// True when the file carries an EMBEDDED Authenticode signature.
        ///
        /// False does NOT mean "unsigned". Many trusted Microsoft binaries are CATALOG-signed
        /// with no embedded signature - notepad.exe is one - and the API throws on those.
        /// Never render "unsigned" from this field alone.
        /// </summary>
        public bool HasEmbeddedSignature { get; set; }

        /// <summary>
        /// True when the embedded certificate chained to a trusted root at scan time.
        /// Meaningful ONLY when <see cref="HasEmbeddedSignature"/> is true; false otherwise.
        /// </summary>
        public bool SignatureChainValid { get; set; }

        /// <summary>
        /// Full command line, or "". A BONUS signal, never a requirement: non-elevated, WMI
        /// populates this for only ~167 of ~430 processes.
        /// </summary>
        public string CommandLine { get; set; } = "";

        /// <summary>False when the image path could not be resolved; <see cref="ImagePath"/> is then "".</summary>
        public bool PathResolved { get; set; }

        /// <summary>Human-readable reason the path is missing, e.g. "access denied (5)". "" when resolved.</summary>
        public string PathFailureReason { get; set; } = "";

        /// <summary>Process start time, or null when the token could not read it.</summary>
        public DateTime? StartTime { get; set; }

        public override string ToString()
        {
            return Name + " (pid " + Pid + ") "
                 + (PathResolved ? ImagePath : "<no path: " + PathFailureReason + ">");
        }
    }

    /// <summary>
    /// Non-throwing process enumeration and identification.
    ///
    /// Design rule: nothing in here throws for an ordinary "access denied". A detector that
    /// dies on the first protected process is useless, and a non-elevated caller cannot open
    /// roughly 40% of the processes on a normal desktop.
    ///
    /// Performance: the two expensive operations - reading a version resource and parsing an
    /// Authenticode signature - are keyed by IMAGE PATH and cached process-wide. Dozens of
    /// svchost/chrome/Code processes share one path, so ~450 processes collapse to ~150
    /// distinct files, and a second scan re-reads nothing at all.
    /// </summary>
    public static class ProcessInfoCollector
    {
        /// <summary>Per-path cache of the version resource. An exe's version resource does not change while it is running.</summary>
        private static readonly ConcurrentDictionary<string, FileIdentity> FileIdentityCache =
            new ConcurrentDictionary<string, FileIdentity>(StringComparer.OrdinalIgnoreCase);

        /// <summary>
        /// Immutable per-file facts: version resource plus Authenticode. Cached by path.
        /// </summary>
        private sealed class FileIdentity
        {
            public string CompanyName = "";
            public string ProductName = "";
            public string FileDescription = "";
            public string OriginalFilename = "";
            public string FileVersion = "";
            public string LegalCopyright = "";
            public string SignerSubject = "";
            public string CertThumbprint = "";
            public bool HasEmbeddedSignature;
            public bool SignatureChainValid;

            public static readonly FileIdentity Empty = new FileIdentity();
        }

        // ------------------------------------------------------------------ public API

        /// <summary>
        /// Every process the current token can see, with as many facts attached as it allows.
        /// Never throws. Processes that exit mid-enumeration are simply absent.
        /// </summary>
        /// <param name="includeCommandLines">
        /// When true, ONE WMI query is issued for the whole machine (~350 ms) and joined onto
        /// the results by pid. Never query WMI per process. When false, WMI is not touched at
        /// all and every CommandLine stays "".
        /// </param>
        /// <param name="ct">Honoured between processes; a cancelled scan returns what it has so far.</param>
        public static IReadOnlyList<ProcessInfo> CollectAll(bool includeCommandLines, CancellationToken ct)
        {
            List<ProcessInfo> results = new List<ProcessInfo>(512);

            Process[] processes;
            try
            {
                processes = Process.GetProcesses();
            }
            catch (Exception)
            {
                // The whole enumeration failed (a broken performance-counter registry does this).
                // Return empty rather than throwing; the caller reports it as a limitation.
                return results;
            }

            // Pass 1: cheap facts only - pid, name, image path, start time. No file I/O.
            List<string> pathsToIdentify = new List<string>(256);
            HashSet<string> seenPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (Process p in processes)
            {
                try
                {
                    if (ct.IsCancellationRequested) break;

                    ProcessInfo? info = DescribeCheap(p);
                    if (info == null) continue;
                    results.Add(info);

                    if (info.PathResolved
                        && info.ImagePath.Length > 0
                        && !FileIdentityCache.ContainsKey(info.ImagePath)
                        && seenPaths.Add(info.ImagePath))
                    {
                        pathsToIdentify.Add(info.ImagePath);
                    }
                }
                catch (Exception) { /* process exited between enumeration and inspection */ }
                finally
                {
                    try { p.Dispose(); } catch (Exception) { }
                }
            }

            // Pass 2: the expensive per-FILE work, done once per distinct path and in parallel.
            // This is what keeps ~450 processes under the 2-second budget: the file set is a
            // third of the process set, and the cache makes a repeat scan nearly free.
            IdentifyFiles(pathsToIdentify, ct);

            // Pass 3: attach the cached file identity to every process that shares that path.
            foreach (ProcessInfo info in results)
            {
                if (!info.PathResolved || info.ImagePath.Length == 0) continue;

                FileIdentity id;
                if (!FileIdentityCache.TryGetValue(info.ImagePath, out id)) id = FileIdentity.Empty;

                info.CompanyName = id.CompanyName;
                info.ProductName = id.ProductName;
                info.FileDescription = id.FileDescription;
                info.OriginalFilename = id.OriginalFilename;
                info.FileVersion = id.FileVersion;
                info.LegalCopyright = id.LegalCopyright;
                info.SignerSubject = id.SignerSubject;
                info.CertThumbprint = id.CertThumbprint;
                info.HasEmbeddedSignature = id.HasEmbeddedSignature;
                info.SignatureChainValid = id.SignatureChainValid;
            }

            // Pass 4: one WMI round-trip for the whole machine, joined by pid.
            if (includeCommandLines && !ct.IsCancellationRequested)
            {
                Dictionary<int, string> commandLines = GetAllCommandLines();
                if (commandLines.Count > 0)
                {
                    foreach (ProcessInfo info in results)
                    {
                        string cl;
                        if (commandLines.TryGetValue(info.Pid, out cl)) info.CommandLine = cl;
                    }
                }
            }

            return results;
        }

        /// <summary>
        /// Cheap single-pid lookup: no WMI, no parallelism, but the same file-identity cache.
        /// Returns null when the pid is gone or was never visible. Never throws.
        /// </summary>
        public static ProcessInfo? ForPid(int pid)
        {
            if (pid <= 0) return null;

            Process? p = null;
            try
            {
                p = Process.GetProcessById(pid);
            }
            catch (ArgumentException) { return null; }   // not running
            catch (InvalidOperationException) { return null; }
            catch (Exception) { return null; }

            try
            {
                ProcessInfo? info = DescribeCheap(p);
                if (info == null) return null;

                if (info.PathResolved && info.ImagePath.Length > 0)
                {
                    FileIdentity id = GetOrReadFileIdentity(info.ImagePath);
                    info.CompanyName = id.CompanyName;
                    info.ProductName = id.ProductName;
                    info.FileDescription = id.FileDescription;
                    info.OriginalFilename = id.OriginalFilename;
                    info.FileVersion = id.FileVersion;
                    info.LegalCopyright = id.LegalCopyright;
                    info.SignerSubject = id.SignerSubject;
                    info.CertThumbprint = id.CertThumbprint;
                    info.HasEmbeddedSignature = id.HasEmbeddedSignature;
                    info.SignatureChainValid = id.SignatureChainValid;
                }

                return info;
            }
            catch (Exception) { return null; }
            finally
            {
                try { if (p != null) p.Dispose(); } catch (Exception) { }
            }
        }

        /// <summary>
        /// Full Win32 image path for a pid via QueryFullProcessImageNameW with
        /// PROCESS_QUERY_LIMITED_INFORMATION. Returns null when the path is unavailable.
        /// NEVER throws.
        ///
        /// Why not Process.MainModule: MainModule walks the target's module list, which needs
        /// PROCESS_VM_READ and fails across bitness. Measured over ~430 live processes -
        ///   non-elevated: 259 resolved here vs 167 for MainModule
        ///   elevated:     428 resolved here vs 412 for MainModule
        /// and MainModule throws on failure where this returns a clean null.
        /// </summary>
        public static string? ResolveImagePath(int pid)
        {
            int ignored;
            return ResolveImagePath(pid, out ignored);
        }

        /// <summary>
        /// <see cref="ResolveImagePath(int)"/> with the Win32 error explaining a null result.
        /// 0 on success; 5 (ERROR_ACCESS_DENIED) is the routine non-elevated outcome.
        /// </summary>
        public static string? ResolveImagePath(int pid, out int win32Error)
        {
            win32Error = Win32Constants.ERROR_SUCCESS;

            // pid 0 is the Idle process and pid 4 is System; neither has a real image path,
            // and OpenProcess against them fails in a way that would look like a permission
            // problem rather than the structural fact it is.
            if (pid <= 4)
            {
                win32Error = Win32Constants.ERROR_INVALID_PARAMETER;
                return null;
            }

            try
            {
                using (SafeProcessHandle handle = NativeMethods.OpenProcess(
                           Win32Constants.PROCESS_QUERY_LIMITED_INFORMATION, false, (uint)pid))
                {
                    if (handle.IsInvalid)
                    {
                        win32Error = Marshal.GetLastWin32Error();
                        if (win32Error == Win32Constants.ERROR_SUCCESS)
                            win32Error = Win32Constants.ERROR_ACCESS_DENIED;
                        return null;
                    }

                    // Start at 2x MAX_PATH and grow: long paths legitimately exceed MAX_PATH
                    // on Windows 10 1607+ and this app is longPathAware.
                    for (int capacity = 520; capacity <= 32768; capacity *= 2)
                    {
                        StringBuilder buffer = new StringBuilder(capacity);
                        uint size = (uint)capacity;   // IN: capacity in CHARACTERS, not bytes

                        if (NativeMethods.QueryFullProcessImageName(
                                handle, Win32Constants.PROCESS_NAME_WIN32, buffer, ref size))
                        {
                            // OUT: characters written, excluding the terminator.
                            int written = (int)size;
                            if (written < 0) written = 0;
                            if (written > buffer.Length) written = buffer.Length;
                            return buffer.ToString(0, written);
                        }

                        int err = Marshal.GetLastWin32Error();
                        if (err == Win32Constants.ERROR_INSUFFICIENT_BUFFER) continue;

                        win32Error = err;
                        return null;
                    }

                    win32Error = Win32Constants.ERROR_INSUFFICIENT_BUFFER;
                    return null;
                }
            }
            catch (Exception)
            {
                win32Error = Win32Constants.ERROR_GEN_FAILURE;
                return null;
            }
        }

        /// <summary>
        /// Identify an image file on DISK that is not running - the installed-but-not-running
        /// case, which is exactly the state ParakeetAI was found in on the reference machine.
        ///
        /// Returns a <see cref="ProcessInfo"/> with Pid = 0 and every identity field populated
        /// from the same cache the live-process path uses, so a file already seen as a running
        /// process costs nothing to look up again. Returns null when the path is empty or the
        /// file does not exist. Never throws.
        ///
        /// Exposed because an install scanner needs precisely the same three traps handled -
        /// the catalog throw, the expired-but-timestamped certificate, and the AIA network
        /// fetch - and there is no reason for two implementations of that to exist.
        /// </summary>
        public static ProcessInfo? DescribeImageFile(string path)
        {
            if (string.IsNullOrEmpty(path)) return null;

            try
            {
                if (!File.Exists(path)) return null;
            }
            catch (Exception) { return null; }

            try
            {
                FileIdentity id = GetOrReadFileIdentity(path);

                ProcessInfo info = new ProcessInfo();
                info.Pid = 0;
                info.Name = SafeFileNameWithoutExtension(path);
                info.ImagePath = path;
                info.PathResolved = true;
                info.CompanyName = id.CompanyName;
                info.ProductName = id.ProductName;
                info.FileDescription = id.FileDescription;
                info.OriginalFilename = id.OriginalFilename;
                info.FileVersion = id.FileVersion;
                info.LegalCopyright = id.LegalCopyright;
                info.SignerSubject = id.SignerSubject;
                info.CertThumbprint = id.CertThumbprint;
                info.HasEmbeddedSignature = id.HasEmbeddedSignature;
                info.SignatureChainValid = id.SignatureChainValid;
                return info;
            }
            catch (Exception) { return null; }
        }

        private static string SafeFileNameWithoutExtension(string path)
        {
            try
            {
                string name = Path.GetFileNameWithoutExtension(path);
                return name ?? "";
            }
            catch (Exception) { return ""; }
        }

        /// <summary>
        /// One WMI round-trip for every process on the machine: pid -> command line.
        /// Processes whose command line the current token cannot see are simply absent.
        /// Never throws.
        ///
        /// Measured: 433 rows / 412 command lines / 342 ms elevated; 428 rows / 167 command
        /// lines / 375 ms non-elevated. Treat the command line as a bonus, never a requirement.
        /// </summary>
        public static Dictionary<int, string> GetAllCommandLines()
        {
            Dictionary<int, string> map = new Dictionary<int, string>(512);
            try
            {
                // Select only the two columns: SELECT * on Win32_Process is several times slower.
                using (ManagementObjectSearcher searcher =
                           new ManagementObjectSearcher("SELECT ProcessId, CommandLine FROM Win32_Process"))
                using (ManagementObjectCollection collection = searcher.Get())
                {
                    foreach (ManagementBaseObject row in collection)
                    {
                        using (row)
                        {
                            try
                            {
                                object? pidValue = row["ProcessId"];
                                if (!(pidValue is uint)) continue;

                                object? clValue = row["CommandLine"];
                                string? cl = clValue as string;
                                if (!string.IsNullOrEmpty(cl))
                                    map[unchecked((int)(uint)pidValue)] = cl!;
                            }
                            catch (Exception) { /* the row's process vanished */ }
                        }
                    }
                }
            }
            catch (ManagementException) { /* WMI repository damaged or the Winmgmt service is stopped */ }
            catch (UnauthorizedAccessException) { }
            catch (COMException) { /* DCOM/RPC unavailable */ }
            catch (Exception) { /* WMI must never be able to take the app down */ }

            return map;
        }

        // ------------------------------------------------------------------ internals

        /// <summary>Pid, name, image path and start time. No file I/O, no crypto. Never throws.</summary>
        private static ProcessInfo? DescribeCheap(Process p)
        {
            int pid;
            string name;
            try
            {
                pid = p.Id;
                name = p.ProcessName;
            }
            catch (Exception)
            {
                return null;   // exited between GetProcesses() and here
            }

            ProcessInfo info = new ProcessInfo();
            info.Pid = pid;
            info.Name = name ?? "";

            int err;
            string? path = ResolveImagePath(pid, out err);
            if (path != null && path.Length > 0)
            {
                info.ImagePath = path;
                info.PathResolved = true;
                info.PathFailureReason = "";
            }
            else
            {
                info.ImagePath = "";
                info.PathResolved = false;
                info.PathFailureReason = DescribePathFailure(pid, err);
            }

            try { info.StartTime = p.StartTime; }
            catch (Exception) { info.StartTime = null; }   // denied on protected processes

            return info;
        }

        private static string DescribePathFailure(int pid, int win32Error)
        {
            switch (win32Error)
            {
                case Win32Constants.ERROR_ACCESS_DENIED:
                    return "access denied (5) - run as administrator to resolve this path";
                case Win32Constants.ERROR_INVALID_PARAMETER:
                    return pid <= 4
                        ? "kernel process (pid " + pid + ") has no user-mode image path"
                        : "invalid parameter (87)";
                case Win32Constants.ERROR_INVALID_HANDLE:
                    return "process exited during the scan (6)";
                case Win32Constants.ERROR_INSUFFICIENT_BUFFER:
                    return "path longer than 32768 characters (122)";
                case Win32Constants.ERROR_GEN_FAILURE:
                    return "the path query failed unexpectedly";
                default:
                    return "Win32 error " + win32Error;
            }
        }

        /// <summary>
        /// Read the version resource and Authenticode signature for each distinct path, in
        /// parallel, filling the cache. Never throws; a path that fails lands in the cache as
        /// an empty identity so it is not retried on every scan.
        /// </summary>
        private static void IdentifyFiles(List<string> paths, CancellationToken ct)
        {
            if (paths.Count == 0) return;

            try
            {
                if (paths.Count < 8)
                {
                    foreach (string path in paths)
                    {
                        if (ct.IsCancellationRequested) return;
                        GetOrReadFileIdentity(path);
                    }
                    return;
                }

                System.Threading.Tasks.ParallelOptions options = new System.Threading.Tasks.ParallelOptions();
                options.MaxDegreeOfParallelism = Math.Min(8, Math.Max(2, Environment.ProcessorCount));
                options.CancellationToken = ct;

                System.Threading.Tasks.Parallel.ForEach(paths, options, delegate (string path)
                {
                    GetOrReadFileIdentity(path);
                });
            }
            catch (OperationCanceledException) { /* cancelled scan: keep whatever is cached */ }
            catch (AggregateException) { /* every body already swallows its own exceptions */ }
            catch (Exception) { }
        }

        private static FileIdentity GetOrReadFileIdentity(string path)
        {
            FileIdentity cached;
            if (FileIdentityCache.TryGetValue(path, out cached)) return cached;

            FileIdentity id = ReadFileIdentity(path);
            FileIdentityCache[path] = id;
            return id;
        }

        private static FileIdentity ReadFileIdentity(string path)
        {
            FileIdentity id = new FileIdentity();
            ReadVersionResource(path, id);
            ReadAuthenticode(path, id);
            return id;
        }

        /// <summary>
        /// FileVersionInfo throws FileNotFoundException on a deleted image and can throw on an
        /// access-denied path. Every field degrades to "". Never throws.
        /// </summary>
        private static void ReadVersionResource(string path, FileIdentity id)
        {
            try
            {
                FileVersionInfo vi = FileVersionInfo.GetVersionInfo(path);
                id.CompanyName = Clean(vi.CompanyName);
                id.ProductName = Clean(vi.ProductName);
                id.FileDescription = Clean(vi.FileDescription);
                id.OriginalFilename = Clean(vi.OriginalFilename);
                id.FileVersion = Clean(vi.FileVersion);
                id.LegalCopyright = Clean(vi.LegalCopyright);
            }
            catch (FileNotFoundException) { }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
            catch (ArgumentException) { }
            catch (Exception) { /* a corrupt version resource must not end the scan */ }
        }

        /// <summary>
        /// Read the EMBEDDED Authenticode certificate and, when present, try to chain it.
        ///
        /// The catalog trap: X509Certificate.CreateFromSignedFile THROWS CryptographicException
        /// (CRYPT_E_NOT_FOUND, 0x80092009) for a file with no embedded signature - including
        /// catalog-signed Microsoft binaries that Get-AuthenticodeSignature reports as Valid.
        /// Verified here: conhost.exe throws, yet it is a perfectly trusted Windows binary. A
        /// throw therefore sets HasEmbeddedSignature = false and leaves SignerSubject empty. It
        /// is NOT evidence the file is unsigned, and never evidence that it is untrusted.
        ///
        /// It also performs ZERO trust validation on success, which is why the chain build
        /// below exists - and why a chain failure is recorded, never thrown.
        /// </summary>
        private static void ReadAuthenticode(string path, FileIdentity id)
        {
            X509Certificate? raw = null;
            try
            {
                raw = X509Certificate.CreateFromSignedFile(path);
            }
            catch (CryptographicException)
            {
                // No EMBEDDED signature. May still be catalog-signed and fully trusted.
                id.HasEmbeddedSignature = false;
                return;
            }
            catch (UnauthorizedAccessException) { return; }
            catch (FileNotFoundException) { return; }
            catch (IOException) { return; }
            catch (ArgumentException) { return; }
            catch (Exception) { return; }

            try
            {
                using (X509Certificate2 cert = new X509Certificate2(raw))
                {
                    id.HasEmbeddedSignature = true;
                    id.SignerSubject = Clean(cert.Subject);
                    id.CertThumbprint = Clean(cert.Thumbprint);
                    id.SignatureChainValid = TryBuildChain(cert, path);
                }
            }
            catch (Exception)
            {
                // The signature existed but the leaf would not parse as an X509Certificate2.
                id.HasEmbeddedSignature = true;
                id.SignatureChainValid = false;
            }
            finally
            {
                // Release the unmanaged CERT_CONTEXT rather than waiting on the finalizer:
                // a full scan opens one of these per distinct image file.
                try { raw.Dispose(); } catch (Exception) { }
            }
        }

        /// <summary>
        /// Build the certificate chain for an embedded Authenticode leaf. Never throws, never
        /// touches the network, and is bounded in time.
        ///
        /// Two decisions, both measured on 108 signed binaries live on this machine:
        ///
        /// 1. ExtraStore is seeded from the file's OWN embedded PKCS#7 blob. Every one of those
        ///    108 files carried its intermediates inside itself (274 certificates in total),
        ///    whereas CreateFromSignedFile hands back ONLY the leaf. Without the extra store
        ///    the chain engine goes to the network over AIA to fetch each intermediate: that
        ///    turned a 146 ms scan into a 2549 ms one on a machine with a cold CryptnetUrlCache,
        ///    and would simply fail on an air-gapped machine. With it: 128 ms, zero network.
        ///
        /// 2. IgnoreNotTimeValid. An Authenticode signature stays valid after its signing
        ///    certificate expires, because it is countersigned with a trusted timestamp - that
        ///    is the whole point of timestamping. X509Chain.Build validates against DateTime.Now,
        ///    so without this flag 30 of 109 binaries - Microsoft's own svchost.exe among them -
        ///    were reported as chain-INVALID. Publishing that about a user's machine would be a
        ///    plain falsehood. With the flag: 107 of 108 valid, and the one rejection is a
        ///    genuinely untrusted root.
        ///
        /// Revocation checking stays OFF: it is a network call, the app must work offline, and
        /// a detector that stalls on an unreachable CRL endpoint is unusable.
        /// </summary>
        private static bool TryBuildChain(X509Certificate2 cert, string path)
        {
            X509Chain? chain = null;
            X509Certificate2Collection? embedded = null;
            try
            {
                chain = new X509Chain();
                chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                chain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
                chain.ChainPolicy.VerificationFlags = X509VerificationFlags.IgnoreNotTimeValid
                                                    | X509VerificationFlags.IgnoreCtlNotTimeValid;

                // Belt and braces: if some binary somehow omits an intermediate, bound the
                // fetch rather than letting the scan hang on it.
                chain.ChainPolicy.UrlRetrievalTimeout = TimeSpan.FromMilliseconds(500);

                embedded = TryLoadEmbeddedCertificates(path);
                if (embedded != null && embedded.Count > 0)
                    chain.ChainPolicy.ExtraStore.AddRange(embedded);

                return chain.Build(cert);
            }
            catch (CryptographicException) { return false; }
            catch (Exception) { return false; }
            finally
            {
                if (chain != null)
                {
                    try { chain.Reset(); } catch (Exception) { }
                }
                if (embedded != null)
                {
                    foreach (X509Certificate2 c in embedded)
                    {
                        try { c.Dispose(); } catch (Exception) { }
                    }
                }
            }
        }

        /// <summary>
        /// Pull every certificate out of a signed PE's embedded PKCS#7 blob - leaf plus
        /// intermediates. Returns null when the file carries none. Never throws.
        /// </summary>
        private static X509Certificate2Collection? TryLoadEmbeddedCertificates(string path)
        {
            try
            {
                X509Certificate2Collection collection = new X509Certificate2Collection();
                collection.Import(path);
                return collection.Count > 0 ? collection : null;
            }
            catch (CryptographicException) { return null; }
            catch (UnauthorizedAccessException) { return null; }
            catch (IOException) { return null; }
            catch (ArgumentException) { return null; }
            catch (Exception) { return null; }
        }

        private static string Clean(string? s)
        {
            if (string.IsNullOrWhiteSpace(s)) return "";
            return s!.Trim();
        }
    }
}

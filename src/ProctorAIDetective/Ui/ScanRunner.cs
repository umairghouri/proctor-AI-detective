using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Reflection;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;

using ProctorAIDetective.Core;
using ProctorAIDetective.Native;
using ProctorAIDetective.Scanners;

namespace ProctorAIDetective.Ui
{
    /// <summary>
    /// Runs every <see cref="IScanner"/> and produces one scored <see cref="ScanReport"/>.
    ///
    /// Everything here happens off the UI thread. <see cref="Progress"/> is raised from a
    /// background thread, so a WinForms subscriber must marshal to the UI thread itself - the
    /// runner deliberately knows nothing about SynchronizationContext, so it is equally usable
    /// from the headless <c>--scan</c> path.
    ///
    /// Three properties of this orchestration are load-bearing:
    ///
    ///   1. ONE BAD SCANNER CANNOT KILL THE SCAN. Every scanner already promises not to throw;
    ///      this layer assumes that promise will be broken one day and catches anyway. A failed
    ///      scanner becomes a Limitation that says the area is UNEXAMINED - never a silent gap
    ///      that reads like a clean result.
    ///
    ///   2. A HUNG SCANNER CANNOT FREEZE THE APP. Each scanner runs on its own background
    ///      thread and is waited on with a deadline. net48 has no safe way to stop a thread
    ///      (Thread.Abort is unreliable and corrupts locks), so an over-running scanner is
    ///      ABANDONED, not killed - which means its output must not be able to corrupt the real
    ///      report after we have walked away. Hence the staging report below.
    ///
    ///   3. SCANNERS STILL SEE EACH OTHER'S FINDINGS. WindowScanner attributes a hidden window
    ///      to a vendor partly by looking for an existing strong attribution on the same pid,
    ///      which ProcessScanner produced. So each staging report is SEEDED with the signals
    ///      collected so far, and only the signals added beyond that seed are merged back.
    /// </summary>
    public sealed class ScanRunner
    {
        /// <summary>
        /// Raised on a background thread as the scan advances: (message, percent 0-100).
        /// Subscribers in a UI must marshal to the UI thread.
        /// </summary>
        public event Action<string, int>? Progress;

        /// <summary>
        /// Notes gathered before the scan started - typically how the signature database loaded.
        /// Copied into <see cref="ScanReport.Limitations"/> first, so the reader sees which
        /// signature set produced the verdict before reading the verdict.
        /// </summary>
        public List<string> PreflightNotes { get; } = new List<string>();

        /// <summary>
        /// Scanners to run, in order. Pre-populated with the production set; exposed so a test
        /// or a future headless mode can run a subset without reaching into private state.
        /// </summary>
        public List<IScanner> Scanners { get; } = new List<IScanner>();

        /// <summary>
        /// Extra wall-clock allowed beyond <see cref="ScanContext.ScannerTimeoutMs"/> before the
        /// watchdog gives up on a scanner. The scanners budget themselves against the same
        /// number, so firing the watchdog at exactly the budget would routinely abandon work
        /// that was one instruction from finishing and report a blind spot that does not exist.
        /// </summary>
        public const int WatchdogGraceMs = 1500;

        public ScanRunner()
        {
            foreach (IScanner s in DefaultScanners()) Scanners.Add(s);
        }

        /// <summary>
        /// The production scanner set, in execution order. Process first: it is the only one that
        /// produces Definitive vendor attribution, and WindowScanner reads those signals to
        /// decide whether a hidden window belongs to a known vendor.
        /// </summary>
        public static IScanner[] DefaultScanners()
        {
            return new IScanner[]
            {
                new ProcessScanner(),
                new WindowScanner(),
                new BrowserScanner(),
                new NetworkScanner()
            };
        }

        // ================================================================== context

        /// <summary>
        /// Builds a <see cref="ScanContext"/> with the signature database loaded and the
        /// allowlist built from it. Never throws: a missing or corrupt signatures.json falls
        /// back to the built-in set and says so in <paramref name="notes"/>.
        /// </summary>
        public static ScanContext CreateContext(List<string>? notes)
        {
            string ignored;
            return CreateContext(notes, out ignored);
        }

        /// <summary>
        /// As <see cref="CreateContext(List{string})"/>, and reports the file actually used.
        /// </summary>
        public static ScanContext CreateContext(List<string>? notes, out string signatureSource)
        {
            signatureSource = SignatureLoader.EmbeddedSourcePath;
            var context = new ScanContext();

            try
            {
                string source;
                string? error;
                List<string> warnings;
                SignatureSet set = SignatureLoader.Load(out source, out error, out warnings);

                signatureSource = source;
                context.Signatures = set;
                context.Allowlist = new Allowlist(set.Allowlist);

                if (notes != null)
                {
                    notes.Add("Signature database: " + SignatureLoader.Summarise(set, source));

                    if (!string.IsNullOrEmpty(error))
                    {
                        notes.Add("The signature database could not be read, so the smaller "
                                + "built-in set was used instead. " + error
                                + " Detection coverage is narrower than a full signature file "
                                + "would give; treat a clean result from this scan with extra care.");
                    }

                    foreach (string w in warnings)
                        notes.Add("Signature database warning: " + w);
                }
            }
            catch (Exception ex)
            {
                if (notes != null)
                {
                    notes.Add("The signature database could not be loaded at all ("
                            + ex.GetType().Name + ": " + ex.Message
                            + "). This scan ran with an empty signature set and can only report "
                            + "generic behaviour, not any specific product.");
                }
            }

            try { context.Elevated = IsElevated(); }
            catch (Exception) { context.Elevated = false; }

            return context;
        }

        /// <summary>
        /// True when this process holds the Administrators role. Never throws.
        /// Elevation is OPTIONAL enrichment: it widens process-path resolution, and nothing
        /// else. The decisive capture-evasion read is cross-process without it.
        /// </summary>
        public static bool IsElevated()
        {
            try
            {
                using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
                {
                    var principal = new WindowsPrincipal(identity);
                    return principal.IsInRole(WindowsBuiltInRole.Administrator);
                }
            }
            catch (Exception)
            {
                return false;
            }
        }

        /// <summary>Version string for the report header. Never throws.</summary>
        public static string AppVersion()
        {
            try
            {
                Assembly asm = Assembly.GetExecutingAssembly();

                string location = "";
                try { location = asm.Location ?? ""; }
                catch (Exception) { location = ""; }

                if (location.Length > 0)
                {
                    FileVersionInfo fvi = FileVersionInfo.GetVersionInfo(location);
                    if (!string.IsNullOrEmpty(fvi.FileVersion)) return fvi.FileVersion!;
                }

                Version? v = asm.GetName().Version;
                if (v != null) return v.ToString();
            }
            catch (Exception) { }

            return "unknown";
        }

        // ================================================================== running

        /// <summary>
        /// Runs the whole scan on a background thread and returns the scored report.
        /// The returned task completes successfully even when individual scanners fail; the
        /// failures are recorded in <see cref="ScanReport.Limitations"/>.
        /// </summary>
        public Task<ScanReport> RunAsync(ScanContext context)
        {
            ScanContext ctx = context ?? new ScanContext();
            return Task.Factory.StartNew(
                () => Run(ctx),
                CancellationToken.None,
                TaskCreationOptions.LongRunning,
                TaskScheduler.Default);
        }

        /// <summary>
        /// Synchronous scan. Safe to call directly from a headless entry point; never call it
        /// from a UI thread, because it blocks for the full scan duration.
        /// </summary>
        public ScanReport Run(ScanContext context)
        {
            ScanContext ctx = context ?? new ScanContext();
            var report = new ScanReport();
            var total = Stopwatch.StartNew();

            try
            {
                PopulateHeader(report, ctx);
            }
            catch (Exception ex)
            {
                report.Limitations.Add("The report header could not be filled in completely ("
                                     + ex.GetType().Name + ").");
            }

            foreach (string note in PreflightNotes)
                if (!string.IsNullOrEmpty(note)) report.Limitations.Add(note);

            Raise("Preparing", 2);

            var toRun = new List<IScanner>();
            foreach (IScanner s in Scanners) if (s != null) toRun.Add(s);

            bool cancelled = false;
            for (int i = 0; i < toRun.Count; i++)
            {
                if (IsCancelled(ctx)) { cancelled = true; break; }

                IScanner scanner = toRun[i];
                string display = SafeDisplayName(scanner);

                // 5% .. 90% spread across the scanners, so the bar never implies "nearly done"
                // while a scanner is still running.
                int percent = 5 + (int)(85.0 * i / Math.Max(1, toRun.Count));
                Raise(display, percent);

                RunOne(scanner, ctx, report);
            }

            if (cancelled || IsCancelled(ctx))
            {
                report.Limitations.Add("The scan was cancelled before every check had run. "
                                     + "Checks that did not run are missing from this report; "
                                     + "treat them as unexamined, not as clean.");
            }

            Raise("Scoring the evidence", 92);
            try
            {
                // Neutralise mainstream-assistant signals BEFORE scoring, in one place, so no
                // scanner can accidentally let "ChatGPT is open" count towards a stealth verdict.
                CategoryPolicy.Apply(report, ctx.Signatures);

                ScoreEngine.Score(report);
            }
            catch (Exception ex)
            {
                // ScoreEngine already guards each axis; this is the belt on top of the braces.
                report.Limitations.Add("Scoring failed outright (" + ex.GetType().Name + ": "
                                     + ex.Message + "). Every verdict below is unanswered rather "
                                     + "than clean; read the evidence list directly.");
            }

            report.FinishedUtc = DateTime.UtcNow;
            total.Stop();
            try { report.Timings["total"] = total.ElapsedMilliseconds; }
            catch (Exception) { }

            Raise("Scan complete", 100);
            return report;
        }

        /// <summary>
        /// Runs one scanner on its own thread, under a deadline, into a private staging report
        /// that is merged back only if the scanner actually finished.
        /// </summary>
        private void RunOne(IScanner scanner, ScanContext context, ScanReport report)
        {
            string id = SafeId(scanner);
            string display = SafeDisplayName(scanner);

            int budget = context.ScannerTimeoutMs > 0 ? context.ScannerTimeoutMs : 8000;
            var sw = Stopwatch.StartNew();

            // A private report per scanner. If the watchdog fires we walk away from the thread,
            // and it keeps writing - into this object, which nothing will ever read again. The
            // real report cannot be mutated by an abandoned scanner.
            var staging = new ScanReport();
            int seeded = 0;
            try
            {
                CopyHeader(report, staging);
                staging.Signals.AddRange(report.Signals);
                seeded = staging.Signals.Count;
            }
            catch (Exception)
            {
                seeded = staging.Signals.Count;
            }

            Exception? failure = null;
            bool finished = false;

            try
            {
                using (var done = new ManualResetEventSlim(false))
                {
                    var thread = new Thread(delegate ()
                    {
                        try
                        {
                            scanner.Scan(context, staging);
                        }
                        catch (Exception ex)
                        {
                            failure = ex;
                        }
                        finally
                        {
                            try { done.Set(); } catch (Exception) { }
                        }
                    });

                    thread.IsBackground = true;   // never blocks process exit
                    thread.Name = "proctor-" + id;
                    try { thread.Priority = ThreadPriority.BelowNormal; } catch (Exception) { }
                    thread.Start();

                    finished = done.Wait(budget + WatchdogGraceMs);
                }
            }
            catch (Exception ex)
            {
                // Could not even start the thread. Record it and carry on with the next scanner.
                failure = ex;
                finished = false;
            }

            sw.Stop();

            if (!finished)
            {
                report.Limitations.Add("The \"" + display + "\" check did not finish within "
                    + budget.ToString(CultureInfo.InvariantCulture) + " ms and was abandoned. "
                    + "Anything it would have found is missing from this report, so treat that "
                    + "area as unexamined rather than clean."
                    + (failure != null ? " (It failed while starting: " + failure.GetType().Name + ".)" : ""));

                try { report.Timings[id] = sw.ElapsedMilliseconds; } catch (Exception) { }
                return;
            }

            if (failure != null)
            {
                report.Limitations.Add("The \"" + display + "\" check failed ("
                    + failure.GetType().Name + ": " + Short(failure.Message) + "). "
                    + "Whatever it had already found is included below, but the check did not "
                    + "complete: treat that area as unexamined rather than clean.");
            }

            try
            {
                Merge(report, staging, seeded);
            }
            catch (Exception ex)
            {
                report.Limitations.Add("The results of the \"" + display + "\" check could not be "
                    + "merged into this report (" + ex.GetType().Name + "). They are missing.");
            }

            // Outer wall-clock wins over any self-measurement the scanner wrote: it is the number
            // that includes thread start-up, which is what the diagnostics pane is actually for.
            try { report.Timings[id] = sw.ElapsedMilliseconds; } catch (Exception) { }
        }

        /// <summary>
        /// Folds a finished scanner's staging report into the real one.
        /// Counters use += because exactly one scanner writes each of them, and because the
        /// window scanner itself accumulates with += into a report that starts at zero.
        /// </summary>
        private static void Merge(ScanReport main, ScanReport staging, int seeded)
        {
            for (int i = seeded; i < staging.Signals.Count; i++)
            {
                Signal s = staging.Signals[i];
                if (s != null) main.Signals.Add(s);
            }

            foreach (string l in staging.Limitations)
            {
                if (string.IsNullOrEmpty(l)) continue;
                if (!main.Limitations.Contains(l)) main.Limitations.Add(l);
            }

            foreach (KeyValuePair<string, long> kv in staging.Timings)
                main.Timings[kv.Key] = kv.Value;   // indexer, not Add: a duplicate key must not throw

            main.WindowsScanned += staging.WindowsScanned;
            main.WindowsQueryFailed += staging.WindowsQueryFailed;
            main.ProcessesScanned += staging.ProcessesScanned;
            main.ProcessPathsUnresolved += staging.ProcessPathsUnresolved;
        }

        // ================================================================== header

        private static void PopulateHeader(ScanReport report, ScanContext context)
        {
            report.StartedUtc = DateTime.UtcNow;

            try { report.MachineName = Environment.MachineName; }
            catch (Exception) { report.MachineName = "(unavailable)"; }

            try
            {
                string domain = Environment.UserDomainName ?? "";
                string user = Environment.UserName ?? "";
                report.UserName = domain.Length > 0 ? domain + "\\" + user : user;
            }
            catch (Exception) { report.UserName = "(unavailable)"; }

            try
            {
                string os = NativeMethods.GetOsVersionString();
                int build = NativeMethods.GetOsBuildNumber();
                if (build > 0)
                    os += " build " + build.ToString(CultureInfo.InvariantCulture);
                report.OsVersion = os;
            }
            catch (Exception) { report.OsVersion = "(unavailable)"; }

            bool elevated;
            try { elevated = IsElevated(); }
            catch (Exception) { elevated = false; }

            report.Elevated = elevated;
            context.Elevated = elevated;   // scanners read this to decide how hard to try

            try { report.AppVersion = AppVersion(); }
            catch (Exception) { report.AppVersion = "unknown"; }

            try
            {
                report.SignatureVersion = context.Signatures != null
                    ? context.Signatures.Version
                    : "(none)";
            }
            catch (Exception) { report.SignatureVersion = "(none)"; }
        }

        private static void CopyHeader(ScanReport from, ScanReport to)
        {
            to.StartedUtc = from.StartedUtc;
            to.MachineName = from.MachineName;
            to.UserName = from.UserName;
            to.OsVersion = from.OsVersion;
            to.Elevated = from.Elevated;
            to.AppVersion = from.AppVersion;
            to.SignatureVersion = from.SignatureVersion;
        }

        // ================================================================== plumbing

        private void Raise(string message, int percent)
        {
            Action<string, int>? handler = Progress;
            if (handler == null) return;

            int p = percent < 0 ? 0 : (percent > 100 ? 100 : percent);
            try { handler(message ?? "", p); }
            catch (Exception) { /* a broken subscriber must not break the scan */ }
        }

        private static bool IsCancelled(ScanContext context)
        {
            try { return context.Cancel.IsCancellationRequested; }
            catch (Exception) { return false; }
        }

        private static string SafeId(IScanner scanner)
        {
            try
            {
                string id = scanner.Id;
                if (!string.IsNullOrEmpty(id)) return id;
            }
            catch (Exception) { }
            return scanner.GetType().Name;
        }

        private static string SafeDisplayName(IScanner scanner)
        {
            try
            {
                string name = scanner.DisplayName;
                if (!string.IsNullOrEmpty(name)) return name;
            }
            catch (Exception) { }
            return SafeId(scanner);
        }

        private static string Short(string? message)
        {
            if (string.IsNullOrEmpty(message)) return "no message";
            string m = message!.Replace("\r", " ").Replace("\n", " ").Trim();
            if (m.Length <= 160) return m;
            return m.Substring(0, 157) + "...";
        }
    }
}

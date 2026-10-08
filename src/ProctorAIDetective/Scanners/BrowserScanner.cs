using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Windows.Automation;
using ProctorAIDetective.Core;
using ProctorAIDetective.Native;

namespace ProctorAIDetective.Scanners
{
    /// <summary>
    /// Looks for the vendor's WEB app rather than its desktop app: a site open in a browser tab,
    /// a dedicated <c>--app=</c> window, a browser window title, or a vendor browser extension.
    ///
    /// WHY THIS SCANNER EXISTS AT ALL
    /// ------------------------------
    /// Every product in this class ships a browser build as well as a desktop build, and the
    /// browser build leaves none of the desktop fingerprints: no Authenticode signer to read, no
    /// blank-named executable, no registered URL scheme. The only process on the machine is a
    /// perfectly legitimate, correctly-signed copy of Chrome. If this scanner did not exist, a
    /// candidate with parakeet-ai.com open in a background tab would come back completely Clear.
    ///
    /// WHAT IT EMITS (all four are defined in the project brief)
    ///   G1  a browser process command line carries --app=&lt;url&gt; for a vendor URL   Strong
    ///   G2  a tab name or the address bar holds a vendor URL (UI Automation)       Strong
    ///   G3  the browser window title - i.e. the ACTIVE tab - names the vendor      Moderate
    ///   H1  a vendor browser extension id exists on disk                           Moderate, Installed
    ///
    /// ATTRIBUTION RULE. <see cref="Signal.Attribution"/> answers "is this Parakeet AI
    /// specifically?", so only a match against the PRIMARY vendor signature carries a non-zero
    /// attribution. A hit on a competitor (Cluely, Interview Coder, ...) is strong CLASS evidence
    /// and exactly zero attribution evidence - it would be a straightforward falsehood to let
    /// "cluely.com is open" push the "Parakeet AI is running" number upwards.
    ///
    /// NOT IMPLEMENTED ON PURPOSE: BROWSER HISTORY. See the note above the extension region.
    /// </summary>
    public sealed class BrowserScanner : IScanner
    {
        public string Id
        {
            get { return "browser"; }
        }

        public string DisplayName
        {
            get { return "Browser tabs, app windows and extensions"; }
        }

        /// <summary>Per-window UI Automation ceiling. First attach to Chromium measured ~126 ms.</summary>
        private const int UiaPerWindowTimeoutMs = 2500;

        /// <summary>Leave this much of the budget for signal assembly after the last probe.</summary>
        private const int BudgetTailMs = 200;

        /// <summary>Signature fragments shorter than this are ignored: too collision-prone.</summary>
        private const int MinFragmentLength = 4;

        // =================================================================== entry point

        /// <summary>
        /// MUST NOT throw. Every stage is independently guarded; a stage that fails records a
        /// Limitation naming the blind spot it leaves and the next stage still runs.
        /// </summary>
        public void Scan(ScanContext context, ScanReport report)
        {
            if (report == null) return;
            if (context == null)
            {
                report.Limitations.Add("Browser scan skipped: no scan context was supplied.");
                return;
            }

            Stopwatch total = Stopwatch.StartNew();
            int budgetMs = context.ScannerTimeoutMs > 0 ? context.ScannerTimeoutMs : 8000;

            List<Signal> emitted = new List<Signal>();
            HashSet<string> seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            // (pid|vendor) and (hwnd|vendor) already explained by a stronger signal. Used so the
            // same open tab is not counted three times by three different observation methods -
            // the score engine's noisy-OR has no way to know they are one fact.
            HashSet<string> coveredByG1 = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            HashSet<string> coveredByG2 = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            try
            {
                List<VendorTarget> targets = BuildTargets(context);
                if (targets.Count == 0)
                {
                    report.Limitations.Add(
                        "Browser scan skipped: the signature database lists no web fragments to look for.");
                    return;
                }

                // ---------------------------------------------------------- 1. window titles
                List<BrowserWindow> windows = new List<BrowserWindow>();
                Stopwatch stage = Stopwatch.StartNew();
                try
                {
                    windows = EnumerateBrowserWindows(report);
                }
                catch (Exception ex)
                {
                    report.Limitations.Add(
                        "Browser window enumeration failed (" + Describe(ex) +
                        "); browser window titles were not examined.");
                }
                finally
                {
                    report.Timings["browser.windows"] = stage.ElapsedMilliseconds;
                }

                if (IsCancelled(context, report, total)) return;

                // ---------------------------------------------------------- 2. G1: --app= URLs
                stage = Stopwatch.StartNew();
                try
                {
                    ScanAppWindows(context, report, targets, emitted, seen, coveredByG1);
                }
                catch (Exception ex)
                {
                    report.Limitations.Add(
                        "Could not read browser command lines (" + Describe(ex) +
                        "); a site opened as a dedicated app window would not have been seen.");
                }
                finally
                {
                    report.Timings["browser.cmdline"] = stage.ElapsedMilliseconds;
                }

                if (IsCancelled(context, report, total)) return;

                // ---------------------------------------------------------- 3. G2: UIA tabs
                if (context.DeepBrowserScan)
                {
                    stage = Stopwatch.StartNew();
                    try
                    {
                        ScanTabsViaUia(context, report, targets, windows, emitted, seen,
                                       coveredByG2, total, budgetMs);
                    }
                    catch (Exception ex)
                    {
                        report.Limitations.Add(
                            "Browser tab reading failed (" + Describe(ex) +
                            "); only the active tab of each window was examined, via its title.");
                    }
                    finally
                    {
                        report.Timings["browser.uia"] = stage.ElapsedMilliseconds;
                    }
                }
                else if (windows.Count > 0)
                {
                    report.Limitations.Add(
                        "Deep browser scan is off, so only browser window titles and command lines " +
                        "were read. A window title shows the ACTIVE tab only: a site sitting in a " +
                        "background tab of any of the " + windows.Count.ToString(CultureInfo.InvariantCulture) +
                        " browser window(s) found would not have been seen.");
                }

                if (IsCancelled(context, report, total)) return;

                // ---------------------------------------------------------- 4. G3: window titles
                try
                {
                    ScanWindowTitles(targets, windows, emitted, seen, coveredByG1, coveredByG2);
                }
                catch (Exception ex)
                {
                    report.Limitations.Add("Browser window title matching failed (" + Describe(ex) + ").");
                }

                // ---------------------------------------------------------- 5. H1: extensions
                stage = Stopwatch.StartNew();
                try
                {
                    ScanExtensions(report, targets, emitted, seen);
                }
                catch (Exception ex)
                {
                    report.Limitations.Add(
                        "Browser extension folders could not be enumerated (" + Describe(ex) +
                        "); an installed vendor extension would not have been seen.");
                }
                finally
                {
                    report.Timings["browser.extensions"] = stage.ElapsedMilliseconds;
                }
            }
            catch (Exception ex)
            {
                // Belt and braces: a scanner that throws must never take the scan down.
                report.Limitations.Add("The browser scanner failed unexpectedly (" + Describe(ex) +
                                       "); browser-based use of these tools was not examined.");
            }
            finally
            {
                // The allowlist is applied to EVERY signal, including ones produced on a failure
                // path, so the audit export can always show what it did.
                foreach (Signal s in emitted)
                {
                    try
                    {
                        if (context.Allowlist != null) context.Allowlist.Apply(s);
                    }
                    catch (Exception)
                    {
                        // Apply() is documented not to throw; if it ever does, the signal simply
                        // keeps its default x1.0 pass-through rather than being lost.
                    }
                    report.Signals.Add(s);
                }
            }
        }

        private static bool IsCancelled(ScanContext context, ScanReport report, Stopwatch total)
        {
            if (!context.Cancel.IsCancellationRequested) return false;
            report.Limitations.Add(
                "Browser scan was cancelled after " +
                total.ElapsedMilliseconds.ToString(CultureInfo.InvariantCulture) + " ms; it is incomplete.");
            return true;
        }

        private static string Describe(Exception ex)
        {
            return ex.GetType().Name + ": " + (ex.Message ?? "");
        }

        // =================================================================== G1: --app= windows

        // --app=https://app.example.com/   or   --app="https://app.example.com/"
        private static readonly Regex AppSwitch = new Regex(
            "--app=(?:\"(?<q>[^\"]+)\"|(?<u>[^\\s\"]+))",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

        /// <summary>
        /// A site opened as a dedicated app / PWA window. The URL is baked into the process
        /// command line at launch and stays there for the life of that process, so unlike a tab it
        /// is unambiguous, attributable to a pid, and visible whether or not the window is focused.
        /// An app window also has NO tab strip and NO omnibox and its title is just the app name,
        /// so UIA and title matching both come up empty here while the command line says it outright.
        ///
        /// KNOWN LIMIT, stated rather than papered over: if the browser was ALREADY running when
        /// the app window was opened, Chromium hands the switch to the existing browser process
        /// over IPC and the short-lived relay process exits, so the surviving process's command
        /// line may not contain it. G1 is therefore proof when present and says nothing when absent.
        /// Installed PWAs launched from the Start menu use --app-id=&lt;extension id&gt;, which carries
        /// no URL at all and is deliberately not matched here.
        /// </summary>
        private static void ScanAppWindows(
            ScanContext context,
            ScanReport report,
            List<VendorTarget> targets,
            List<Signal> emitted,
            HashSet<string> seen,
            HashSet<string> coveredByG1)
        {
            Dictionary<int, string> commandLines = ProcessInfoCollector.GetAllCommandLines();
            if (commandLines.Count == 0)
            {
                report.Limitations.Add(
                    "No process command lines were readable (WMI returned nothing), so a site " +
                    "opened as a dedicated browser app window could not be detected.");
                return;
            }

            Dictionary<int, string> pidToName = BuildPidNameMap();

            // vendorKey|url  ->  the processes carrying it. One browser can host several windows,
            // and Chromium helper processes inherit switches, so group before emitting.
            Dictionary<string, AppWindowHit> hits = new Dictionary<string, AppWindowHit>(StringComparer.OrdinalIgnoreCase);

            foreach (KeyValuePair<int, string> entry in commandLines)
            {
                if (context.Cancel.IsCancellationRequested) return;

                string processName;
                if (!pidToName.TryGetValue(entry.Key, out processName)) continue;

                BrowserInfo? browser = BrowserCatalog.FromProcessName(processName);
                if (browser == null) continue;

                string commandLine = entry.Value ?? "";
                if (commandLine.Length == 0) continue;
                if (commandLine.IndexOf("--app=", StringComparison.OrdinalIgnoreCase) < 0) continue;

                // Renderer/GPU/utility children inherit the parent's switches. They are the same
                // fact, not extra facts; remember whether a hit came from a real browser process.
                bool isHelper = commandLine.IndexOf("--type=", StringComparison.OrdinalIgnoreCase) >= 0;

                foreach (Match m in AppSwitch.Matches(commandLine))
                {
                    string url = m.Groups["q"].Success ? m.Groups["q"].Value : m.Groups["u"].Value;
                    if (string.IsNullOrWhiteSpace(url)) continue;

                    foreach (VendorTarget target in targets)
                    {
                        string matched;
                        // An --app= URL must BE the vendor's site. An embedded redirect inside
                        // somebody else's URL is not a dedicated window for the vendor.
                        if (MatchUrl(url, target, out matched) != UrlMatchKind.Host) continue;

                        string key = target.Vendor.Key + "|" + url.Trim().ToLowerInvariant();
                        AppWindowHit hit;
                        if (!hits.TryGetValue(key, out hit))
                        {
                            hit = new AppWindowHit(target, url.Trim(), matched);
                            hits[key] = hit;
                        }
                        hit.ProcessCount++;
                        if (!isHelper && hit.Pid == 0)
                        {
                            hit.Pid = entry.Key;
                            hit.ProcessName = processName;
                            hit.BrowserName = browser.DisplayName;
                        }
                        else if (hit.Pid == 0)
                        {
                            hit.HelperPid = entry.Key;
                            hit.ProcessName = processName;
                            hit.BrowserName = browser.DisplayName;
                        }
                    }
                }
            }

            foreach (AppWindowHit hit in hits.Values)
            {
                int pid = hit.Pid != 0 ? hit.Pid : hit.HelperPid;
                VendorSignature vendor = hit.Target.Vendor;

                StringBuilder detail = new StringBuilder();
                detail.Append(hit.BrowserName).Append(" is running a dedicated application window for ")
                      .Append(hit.Url).Append(". ");
                detail.Append("The switch \"--app=").Append(hit.Url)
                      .Append("\" appears in the command line of ")
                      .Append(hit.ProcessName).Append(" (pid ")
                      .Append(pid.ToString(CultureInfo.InvariantCulture)).Append(")");
                if (hit.ProcessCount > 1)
                {
                    detail.Append(" and ").Append((hit.ProcessCount - 1).ToString(CultureInfo.InvariantCulture))
                          .Append(" of its helper process(es)");
                }
                detail.Append(". ");
                detail.Append("The URL matched the signature fragment \"").Append(hit.MatchedFragment)
                      .Append("\" for ").Append(vendor.Name).Append(". ");
                detail.Append("A command line is fixed at process launch, so this is a window open ")
                      .Append("for this exact origin right now, not a record of a past visit.");

                string path = ResolvePathSafe(pid);
                if (path.Length > 0) detail.Append(" Browser executable: ").Append(path).Append(".");

                Signal s = NewSignal(
                    "G1.app-window",
                    vendor.Name + " opened as a browser app window",
                    detail.ToString(),
                    Tier.Strong,
                    vendor.PrimaryTarget ? 80 : 0,
                    70,
                    StateAxis.Running,
                    vendor,
                    hit.Url,
                    pid);

                if (Add(emitted, seen, "G1|" + pid.ToString(CultureInfo.InvariantCulture) + "|" +
                        vendor.Key + "|" + hit.Url, s))
                {
                    coveredByG1.Add(pid.ToString(CultureInfo.InvariantCulture) + "|" + vendor.Key);
                }
            }
        }

        private sealed class AppWindowHit
        {
            public AppWindowHit(VendorTarget target, string url, string matchedFragment)
            {
                Target = target;
                Url = url;
                MatchedFragment = matchedFragment;
            }

            public VendorTarget Target;
            public string Url;
            public string MatchedFragment;
            public int Pid;
            public int HelperPid;
            public int ProcessCount;
            public string ProcessName = "";
            public string BrowserName = "";
        }

        // =================================================================== G2: UIA tabs

        /// <summary>
        /// Reads each browser window's tab strip and address bar over UI Automation. This is the
        /// only signal in the whole product that can see a site in a BACKGROUND tab, which is the
        /// case that matters: anyone hiding something puts it on a second tab, not the active one.
        ///
        /// Every probe goes through <see cref="StaTimeoutRunner"/>. UIA is a blocking cross-process
        /// COM call and a busy browser can wedge it for tens of seconds; the runner abandons the
        /// thread rather than aborting it, and trips a circuit breaker so one wedged browser does
        /// not cost a leaked thread per window.
        /// </summary>
        private static void ScanTabsViaUia(
            ScanContext context,
            ScanReport report,
            List<VendorTarget> targets,
            List<BrowserWindow> windows,
            List<Signal> emitted,
            HashSet<string> seen,
            HashSet<string> coveredByG2,
            Stopwatch total,
            int budgetMs)
        {
            if (windows.Count == 0) return;

            StaTimeoutRunner runner = new StaTimeoutRunner();
            int probed = 0;
            int failed = 0;
            int skippedForBudget = 0;
            List<string> tabStripUnreadable = new List<string>();

            foreach (BrowserWindow w in windows)
            {
                if (context.Cancel.IsCancellationRequested) break;

                long remaining = budgetMs - total.ElapsedMilliseconds - BudgetTailMs;
                if (remaining < 300)
                {
                    skippedForBudget++;
                    continue;
                }

                if (runner.CircuitOpen) break;

                int perWindow = (int)Math.Min(UiaPerWindowTimeoutMs, remaining);
                IntPtr hwnd = w.Handle;

                UiaWindowSnapshot snapshot;
                Exception? error;
                bool ok = runner.TryRun<UiaWindowSnapshot>(
                    delegate { return UiaBrowserReader.Read(hwnd); },
                    TimeSpan.FromMilliseconds(perWindow),
                    out snapshot,
                    out error);

                if (!ok || snapshot == null)
                {
                    failed++;
                    continue;
                }

                probed++;

                // A tabbed browser window ALWAYS has at least one tab. Zero readable TabItems
                // therefore means "the tab strip could not be read", never "there are no other
                // tabs" - and the difference matters, because the whole value of this signal is
                // seeing BACKGROUND tabs. Verified live on Chrome: a window whose renderer was
                // busy exposed its omnibox but published no tab strip at all in the accessibility
                // tree (TopContainerView held the address bar and nothing else), and six probes
                // over 1.5 s never changed that. Reporting that window as examined would be a
                // false reassurance, so it is recorded as an unexamined area instead.
                //
                // An app / PWA window genuinely has no tab strip, so the omnibox is used to tell
                // the two cases apart: no omnibox means it was never a tabbed window.
                if (snapshot.TabTitles.Count == 0 && !string.IsNullOrEmpty(snapshot.OmniboxUrl))
                {
                    tabStripUnreadable.Add(w.Browser.DisplayName + " pid " +
                                           w.Pid.ToString(CultureInfo.InvariantCulture));
                }

                MatchSnapshot(targets, w, snapshot, emitted, seen, coveredByG2);
            }

            string? circuit = runner.CircuitReason;
            if (circuit != null) report.Limitations.Add(circuit);

            if (skippedForBudget > 0)
            {
                report.Limitations.Add(
                    skippedForBudget.ToString(CultureInfo.InvariantCulture) +
                    " browser window(s) were not examined because the browser scanner ran out of its " +
                    budgetMs.ToString(CultureInfo.InvariantCulture) +
                    " ms budget. Their background tabs were not read.");
            }

            if (tabStripUnreadable.Count > 0)
            {
                report.Limitations.Add(
                    "The tab strip of " + tabStripUnreadable.Count.ToString(CultureInfo.InvariantCulture) +
                    " browser window(s) could not be read (" + string.Join("; ", tabStripUnreadable.ToArray()) +
                    "): the browser answered UI Automation with its address bar but published no tab " +
                    "list at all. Only the active tab of those windows was examined. A site sitting " +
                    "in one of their background tabs would NOT have been found - this is an " +
                    "unexamined area, not a clean result.");
            }

            if (failed > 0 && circuit == null)
            {
                report.Limitations.Add(
                    "UI Automation could not read " + failed.ToString(CultureInfo.InvariantCulture) +
                    " of " + windows.Count.ToString(CultureInfo.InvariantCulture) +
                    " browser window(s). For those windows only the active tab's title was examined; " +
                    "a site in one of their background tabs would not have been seen.");
            }

            report.Timings["browser.uia.windows"] = probed;
        }

        private static void MatchSnapshot(
            List<VendorTarget> targets,
            BrowserWindow w,
            UiaWindowSnapshot snapshot,
            List<Signal> emitted,
            HashSet<string> seen,
            HashSet<string> coveredByG2)
        {
            foreach (VendorTarget target in targets)
            {
                VendorSignature vendor = target.Vendor;

                // Collect every place inside this one window where the vendor turned up. They are
                // all the same fact - "this window has the site open" - so they become one signal
                // with a detail line that lists the evidence, not three competing signals.
                List<string> evidence = new List<string>();
                string subject = "";

                // True once something names the vendor directly, rather than via a redirect target.
                bool directEvidence = false;

                string omniboxMatch;
                UrlMatchKind omniboxKind = MatchUrl(snapshot.OmniboxUrl, target, out omniboxMatch);
                if (omniboxKind != UrlMatchKind.None)
                {
                    if (omniboxKind == UrlMatchKind.Host) directEvidence = true;
                    subject = Shorten((snapshot.OmniboxUrl ?? "").Trim());
                    evidence.Add(omniboxKind == UrlMatchKind.Host
                        ? "the address bar reads \"" + subject + "\", whose host is \"" + omniboxMatch +
                          "\", and that is this window's ACTIVE tab"
                        : "the address bar reads \"" + subject + "\", which is a page on another site " +
                          "that carries an embedded link back to \"" + omniboxMatch + "\" - the shape of " +
                          "a sign-in hand-off to that site, not the site itself");
                }

                string docUrlMatch;
                UrlMatchKind docKind = MatchUrl(snapshot.DocumentUrl, target, out docUrlMatch);
                if (docKind != UrlMatchKind.None)
                {
                    if (docKind == UrlMatchKind.Host) directEvidence = true;
                    string docUrl = Shorten((snapshot.DocumentUrl ?? "").Trim());
                    if (subject.Length == 0) subject = docUrl;
                    evidence.Add(docKind == UrlMatchKind.Host
                        ? "the rendered document's URL is \"" + docUrl + "\" (host \"" + docUrlMatch +
                          "\"), i.e. the ACTIVE tab"
                        : "the rendered document's URL \"" + docUrl +
                          "\" carries an embedded link to \"" + docUrlMatch + "\"");
                }

                // Whether a matching tab is the ACTIVE one is decided by logic, not by comparing
                // decorated strings. A window's title bar always shows its ACTIVE tab's title, so:
                // if the title bar does NOT name the vendor, then a tab that DOES name the vendor
                // cannot be the active tab - it is provably a background tab. That is the claim
                // worth making, and it is airtight.
                //
                // The earlier string-similarity version got this WRONG on live Edge, which
                // decorates tab-strip names ("... - Memory usage - 175 MB") and injects the
                // profile name into the title bar ("... - Personal"), so the active tab matched
                // neither way round and was reported as a background tab. Stating "background"
                // about the tab someone is actually looking at is a false claim, and this tool
                // cannot afford those.
                bool titleBarNamesVendor = MatchText(w.ActiveTabTitle, target) != null
                                        || MatchText(w.NormalizedTitle, target) != null;

                foreach (string tab in snapshot.TabTitles)
                {
                    string? tabMatch = MatchText(tab, target);
                    if (tabMatch == null) continue;

                    directEvidence = true;
                    if (subject.Length == 0) subject = tab;
                    evidence.Add("a tab in the tab strip is named \"" + Shorten(tab) +
                                 "\" (matched \"" + tabMatch + "\"), and it is " +
                                 (titleBarNamesVendor
                                     ? "either the ACTIVE tab or one of several matching tabs - this " +
                                       "window's title bar also names the vendor, so the two cannot be " +
                                       "told apart without selecting the tab"
                                     : "provably a BACKGROUND tab: this window's title bar shows \"" +
                                       Shorten(w.ActiveTabTitle) + "\", a title bar always shows the " +
                                       "ACTIVE tab, and that title does not name the vendor"));
                }

                if (evidence.Count == 0) continue;

                StringBuilder detail = new StringBuilder();
                detail.Append("In a ").Append(w.Browser.DisplayName)
                      .Append(" window (pid ").Append(w.Pid.ToString(CultureInfo.InvariantCulture))
                      .Append(", window handle 0x").Append(w.Handle.ToInt64().ToString("X", CultureInfo.InvariantCulture))
                      .Append("), read over UI Automation: ");
                for (int i = 0; i < evidence.Count; i++)
                {
                    if (i > 0) detail.Append("; ");
                    detail.Append(evidence[i]);
                }
                detail.Append(". Tab strip held ")
                      .Append(snapshot.TabTitles.Count.ToString(CultureInfo.InvariantCulture))
                      .Append(" readable tab name(s). ");
                detail.Append("Matched against the ").Append(vendor.Name)
                      .Append(" web signature.");

                string path = ResolvePathSafe(w.Pid);
                if (path.Length > 0) detail.Append(" Browser executable: ").Append(path).Append(".");

                // A sign-in hand-off is real evidence but it is not the site being open, so when
                // that is the ONLY thing seen the signal is reported one tier lower rather than
                // dressed up as a tab. Direct evidence - the host in the address bar, or a tab
                // named after the vendor - keeps the full Strong weight the brief specifies.
                Signal s = directEvidence
                    ? NewSignal(
                        "G2.tab-url",
                        vendor.Name + " open in a " + w.Browser.DisplayName + " tab",
                        detail.ToString(),
                        Tier.Strong,
                        vendor.PrimaryTarget ? 75 : 0,
                        65,
                        StateAxis.Running,
                        vendor, subject, w.Pid)
                    : NewSignal(
                        "G2.signin-handoff",
                        "Sign-in hand-off to " + vendor.Name + " in " + w.Browser.DisplayName,
                        detail.ToString(),
                        Tier.Moderate,
                        vendor.PrimaryTarget ? 55 : 0,
                        50,
                        StateAxis.Running,
                        vendor, subject, w.Pid);

                if (Add(emitted, seen,
                        "G2|" + w.Handle.ToInt64().ToString(CultureInfo.InvariantCulture) + "|" + vendor.Key, s))
                {
                    coveredByG2.Add(w.Handle.ToInt64().ToString(CultureInfo.InvariantCulture) + "|" + vendor.Key);
                }
            }
        }

        // =================================================================== G3: window titles

        /// <summary>
        /// The cheapest signal: the browser's own window title. Costs a few milliseconds for the
        /// whole desktop and needs no accessibility, no WMI and no elevation.
        /// </summary>
        private static void ScanWindowTitles(
            List<VendorTarget> targets,
            List<BrowserWindow> windows,
            List<Signal> emitted,
            HashSet<string> seen,
            HashSet<string> coveredByG1,
            HashSet<string> coveredByG2)
        {
            foreach (BrowserWindow w in windows)
            {
                foreach (VendorTarget target in targets)
                {
                    VendorSignature vendor = target.Vendor;

                    // Already proved by a stronger, more specific observation of the same window
                    // or the same process. Re-reporting it would let one open tab be counted twice
                    // by the score engine, which has no way to tell they are one fact.
                    if (coveredByG2.Contains(w.Handle.ToInt64().ToString(CultureInfo.InvariantCulture) + "|" + vendor.Key)) continue;
                    if (coveredByG1.Contains(w.Pid.ToString(CultureInfo.InvariantCulture) + "|" + vendor.Key)) continue;

                    string? matched = MatchText(w.ActiveTabTitle, target);
                    if (matched == null) matched = MatchText(w.NormalizedTitle, target);
                    if (matched == null) continue;

                    StringBuilder detail = new StringBuilder();
                    detail.Append("A ").Append(w.Browser.DisplayName)
                          .Append(" window (pid ").Append(w.Pid.ToString(CultureInfo.InvariantCulture))
                          .Append(") has the title \"").Append(w.RawTitle).Append("\", ");
                    detail.Append("whose page portion, after the browser brand suffix is removed, is \"").Append(Shorten(w.ActiveTabTitle))
                          .Append("\" and contains \"").Append(matched)
                          .Append("\" from the ").Append(vendor.Name).Append(" signature. ");
                    if (w.OtherTabCount.HasValue)
                    {
                        detail.Append("The browser also reported ")
                              .Append(w.OtherTabCount.Value.ToString(CultureInfo.InvariantCulture))
                              .Append(" further page(s) open in this window. ");
                    }
                    detail.Append("A browser window title only ever reveals that window's ACTIVE tab, ")
                          .Append("so this says nothing at all about the other tabs, and the absence ")
                          .Append("of a title match is not evidence that a site is closed. ");
                    detail.Append("A page title is also content any website can set to any string, ")
                          .Append("which is why this is Moderate and not Strong.");
                    if (w.IsForeground) detail.Append(" This was the foreground window at scan time.");

                    Signal s = NewSignal(
                        "G3.window-title",
                        vendor.Name + " named in a " + w.Browser.DisplayName + " window title",
                        detail.ToString(),
                        Tier.Moderate,
                        vendor.PrimaryTarget ? 55 : 0,
                        50,
                        StateAxis.Running,
                        vendor,
                        w.ActiveTabTitle.Length > 0 ? w.ActiveTabTitle : w.RawTitle,
                        w.Pid);

                    Add(emitted, seen,
                        "G3|" + w.Handle.ToInt64().ToString(CultureInfo.InvariantCulture) + "|" + vendor.Key, s);
                }
            }
        }

        // =================================================================== H1: extensions

        // ---------------------------------------------------------------------------------
        // BROWSER HISTORY IS DELIBERATELY NOT READ.
        //
        // This is where a reader would reasonably expect a History probe to sit, next to the
        // other per-profile reads, and the reference prototype does contain one. It is left out,
        // for three reasons in increasing order of weight:
        //
        //   1. Wrong question. History answers "was this site visited at some point", which is
        //      the one thing this product must not conflate with "is it running right now".
        //      A link clicked last Tuesday is not evidence about this interview.
        //   2. Wrong dependency. The History file is a SQLite database. Reading it on net48
        //      means shipping System.Data.SQLite - a native, per-architecture dependency - and
        //      the whole point of targeting net48 is a single ~1 MB exe with nothing to install.
        //   3. Wrong intrusion. Enumerating a person's browsing history is categorically more
        //      invasive than asking what is open right now, and it is disproportionate to the
        //      question being answered. A tool that makes accusations about people should take
        //      the least invasive reading that settles the question.
        // ---------------------------------------------------------------------------------

        /// <summary>
        /// An installed vendor extension. State is Installed and NOT Running on purpose: an
        /// extension sitting in a profile folder proves the software is present, not that anyone
        /// is using it this minute, and Chromium leaves stale extension folders behind after an
        /// uninstall until it garbage-collects them.
        ///
        /// Parakeet AI ships no browser extension, so with the current signature database this
        /// can only ever fire for a competitor (Sensei Copilot is the one entry that has an id).
        /// </summary>
        private static void ScanExtensions(
            ScanReport report,
            List<VendorTarget> targets,
            List<Signal> emitted,
            HashSet<string> seen)
        {
            bool anyIds = false;
            foreach (VendorTarget t in targets)
            {
                if (t.ExtensionIds.Count > 0) { anyIds = true; break; }
            }
            if (!anyIds) return;

            foreach (KeyValuePair<string, string> root in ChromiumUserDataRoots())
            {
                string browserName = root.Key;
                string userData = root.Value;

                List<string> profiles;
                try
                {
                    if (!Directory.Exists(userData)) continue;
                    profiles = EnumerateProfiles(userData);
                }
                catch (Exception ex)
                {
                    report.Limitations.Add("Could not list " + browserName + " profiles (" + Describe(ex) + ").");
                    continue;
                }

                foreach (string profileDir in profiles)
                {
                    string extensionsDir;
                    try
                    {
                        extensionsDir = Path.Combine(profileDir, "Extensions");
                        if (!Directory.Exists(extensionsDir)) continue;
                    }
                    catch (Exception)
                    {
                        continue;
                    }

                    string profileLabel = browserName + " / " + SafeLeafName(profileDir);

                    foreach (VendorTarget target in targets)
                    {
                        foreach (string id in target.ExtensionIds)
                        {
                            string dir;
                            try
                            {
                                dir = Path.Combine(extensionsDir, id);
                                if (!Directory.Exists(dir)) continue;
                            }
                            catch (Exception)
                            {
                                continue;
                            }

                            VendorSignature vendor = target.Vendor;

                            StringBuilder detail = new StringBuilder();
                            detail.Append("The browser extension id \"").Append(id)
                                  .Append("\", listed in the ").Append(vendor.Name)
                                  .Append(" signature, exists on disk at ").Append(dir).Append(" (")
                                  .Append(profileLabel).Append("). ");
                            detail.Append("This proves the extension is INSTALLED in that browser profile. ")
                                  .Append("It is not evidence that it is in use, or that the browser is even ")
                                  .Append("open: Chromium keeps the folder after an extension is disabled and ")
                                  .Append("until it garbage-collects an uninstalled one.");

                            Signal s = NewSignal(
                                "H1.extension",
                                vendor.Name + " browser extension installed",
                                detail.ToString(),
                                Tier.Moderate,
                                vendor.PrimaryTarget ? 50 : 0,
                                45,
                                StateAxis.Installed,
                                vendor,
                                id,
                                0);

                            Add(emitted, seen, "H1|" + profileLabel + "|" + id, s);
                        }
                    }
                }
            }
        }

        /// <summary>
        /// Chromium-family profile roots. Firefox is absent on purpose: its add-ons are XPI
        /// packages keyed by an entirely different id scheme under %APPDATA%\Mozilla, so the
        /// signature database's Chrome Web Store ids cannot match there and pretending to check
        /// would be a false reassurance.
        /// </summary>
        private static IEnumerable<KeyValuePair<string, string>> ChromiumUserDataRoots()
        {
            string local = SafeFolder(Environment.SpecialFolder.LocalApplicationData);
            string roaming = SafeFolder(Environment.SpecialFolder.ApplicationData);

            if (local.Length > 0)
            {
                yield return Pair("Chrome", Path.Combine(local, "Google", "Chrome", "User Data"));
                yield return Pair("Edge", Path.Combine(local, "Microsoft", "Edge", "User Data"));
                yield return Pair("Brave", Path.Combine(local, "BraveSoftware", "Brave-Browser", "User Data"));
                yield return Pair("Vivaldi", Path.Combine(local, "Vivaldi", "User Data"));
                yield return Pair("Chromium", Path.Combine(local, "Chromium", "User Data"));
            }

            if (roaming.Length > 0)
            {
                // Opera keeps its profile in Roaming and directly at the profile root.
                yield return Pair("Opera", Path.Combine(roaming, "Opera Software", "Opera Stable"));
                yield return Pair("Opera GX", Path.Combine(roaming, "Opera Software", "Opera GX Stable"));
            }
        }

        private static KeyValuePair<string, string> Pair(string a, string b)
        {
            return new KeyValuePair<string, string>(a, b);
        }

        private static string SafeFolder(Environment.SpecialFolder folder)
        {
            try { return Environment.GetFolderPath(folder) ?? ""; }
            catch (Exception) { return ""; }
        }

        private static List<string> EnumerateProfiles(string userDataPath)
        {
            List<string> result = new List<string>();
            string[] dirs;
            try { dirs = Directory.GetDirectories(userDataPath); }
            catch (Exception) { dirs = new string[0]; }

            foreach (string dir in dirs)
            {
                string name = SafeLeafName(dir);
                if (name.Equals("Default", StringComparison.OrdinalIgnoreCase) ||
                    name.StartsWith("Profile ", StringComparison.OrdinalIgnoreCase))
                {
                    result.Add(dir);
                }
            }

            // Opera does not use a Default sub-folder; its profile IS the root.
            try
            {
                if (Directory.Exists(Path.Combine(userDataPath, "Extensions"))) result.Add(userDataPath);
            }
            catch (Exception) { }

            return result;
        }

        private static string SafeLeafName(string path)
        {
            try { return Path.GetFileName(path.TrimEnd('\\', '/')) ?? ""; }
            catch (Exception) { return ""; }
        }

        // =================================================================== signal plumbing

        private static Signal NewSignal(
            string id, string title, string detail, Tier tier,
            int attribution, int classScore, StateAxis state,
            VendorSignature vendor, string subject, int pid)
        {
            Signal s = new Signal();
            s.Id = id;
            s.Title = title;
            s.Detail = detail;
            s.Tier = tier;
            s.Attribution = attribution;
            s.ClassScore = classScore;
            s.State = state;
            s.VendorKey = vendor.Key;
            s.Subject = subject;

            // SubjectPath and Signer are deliberately left empty.
            //
            // The subject of a browser signal is the SITE, not the browser binary. If the browser's
            // image path were put here, Allowlist.Apply would key on "chrome.exe" / "msedge.exe" -
            // both of which signatures.json allowlists as VERIFIED with signer Google / Microsoft -
            // and hard-suppress the signal to x0.00. Those allowlist rows exist because Chrome and
            // Edge legitimately set capture protection for DRM video playback; they are a statement
            // about the browser's window behaviour, not a statement that nothing Chrome displays can
            // ever be of interest. Applying them here would mean a Parakeet AI tab open in Chrome
            // scored zero and vanished from the report, which is the exact bypass this product must
            // not have. The browser process name, pid and executable path are all named in Detail,
            // so nothing is hidden from the reader.
            s.SubjectPath = "";
            s.Signer = "";

            s.Pid = pid;
            s.Source = "browser";
            return s;
        }

        /// <summary>
        /// Keep a URL readable in the evidence grid. Real OAuth URLs run to several hundred
        /// characters and would bury the one fact the reader needs; the head and tail are what
        /// identify the page, so the middle is what goes. Nothing is silently dropped - the
        /// elision is marked.
        /// </summary>
        private static string Shorten(string value)
        {
            const int Max = 180;
            if (value == null) return "";
            if (value.Length <= Max) return value;
            return value.Substring(0, 120) + " [..." +
                   (value.Length - 150).ToString(CultureInfo.InvariantCulture) +
                   " characters omitted...] " + value.Substring(value.Length - 30);
        }

        private static bool Add(List<Signal> emitted, HashSet<string> seen, string key, Signal s)
        {
            if (!seen.Add(key)) return false;
            emitted.Add(s);
            return true;
        }

        private static string ResolvePathSafe(int pid)
        {
            if (pid <= 0) return "";
            try
            {
                string? p = ProcessInfoCollector.ResolveImagePath(pid);
                return p ?? "";
            }
            catch (Exception)
            {
                return "";
            }
        }

        // =================================================================== signature targets

        /// <summary>One vendor's web-facing signature, pre-split into the shapes we match on.</summary>
        private sealed class VendorTarget
        {
            public VendorTarget(VendorSignature vendor)
            {
                Vendor = vendor;
            }

            public readonly VendorSignature Vendor;

            /// <summary>Web fragments that parse as host names: matched host-wise, sub-domains included.</summary>
            public readonly List<string> HostFragments = new List<string>();

            /// <summary>Web fragments plus window-title markers: matched as substrings of a title.</summary>
            public readonly List<string> TextFragments = new List<string>();

            public readonly List<string> ExtensionIds = new List<string>();
        }

        /// <summary>
        /// Honour <see cref="ScanContext.ReportClassWide"/>: with it off we look only for the
        /// primary target, so the report cannot fill up with competitors the user did not ask about.
        /// </summary>
        private static List<VendorTarget> BuildTargets(ScanContext context)
        {
            List<VendorTarget> targets = new List<VendorTarget>();
            SignatureSet set = context.Signatures ?? new SignatureSet();

            foreach (VendorSignature vendor in set.Vendors)
            {
                if (vendor == null) continue;
                if (!context.ReportClassWide && !vendor.PrimaryTarget) continue;

                VendorTarget t = new VendorTarget(vendor);

                foreach (string fragment in Safe(vendor.WebFragments))
                {
                    string f = (fragment ?? "").Trim();
                    if (f.Length < MinFragmentLength) continue;
                    t.TextFragments.Add(f);
                    if (LooksLikeHost(f)) t.HostFragments.Add(f);
                }

                foreach (string marker in Safe(vendor.WindowTitleContains))
                {
                    string m = (marker ?? "").Trim();
                    if (m.Length < MinFragmentLength) continue;
                    if (!t.TextFragments.Contains(m)) t.TextFragments.Add(m);
                }

                foreach (string id in Safe(vendor.ExtensionIds))
                {
                    string e = (id ?? "").Trim();
                    if (IsValidExtensionId(e)) t.ExtensionIds.Add(e);
                }

                if (t.TextFragments.Count > 0 || t.ExtensionIds.Count > 0)
                    targets.Add(t);
            }

            return targets;
        }

        private static IEnumerable<string> Safe(List<string>? list)
        {
            if (list == null) yield break;
            foreach (string s in list) yield return s ?? "";
        }

        /// <summary>A Chrome Web Store id: exactly 32 characters, each in 'a'..'p'.</summary>
        private static bool IsValidExtensionId(string? id)
        {
            if (id == null || id.Length != 32) return false;
            for (int i = 0; i < id.Length; i++)
            {
                char c = char.ToLowerInvariant(id[i]);
                if (c < 'a' || c > 'p') return false;
            }
            return true;
        }

        private static bool LooksLikeHost(string fragment)
        {
            if (fragment.IndexOf('.') <= 0) return false;
            if (fragment.IndexOf(' ') >= 0) return false;
            if (fragment.IndexOf('/') >= 0) return false;
            return fragment[fragment.Length - 1] != '.';
        }

        /// <summary>How a URL matched a vendor. The distinction is the whole false-positive story.</summary>
        private enum UrlMatchKind
        {
            /// <summary>No match.</summary>
            None = 0,
            /// <summary>The browsed host IS the vendor's host (or a sub-domain of it).</summary>
            Host = 1,
            /// <summary>
            /// The browsed host is someone else, but the URL carries an embedded absolute URL
            /// pointing at the vendor - the shape of an SSO / OAuth hand-off, e.g.
            /// accounts.google.com/...?redirect_uri=https%3A%2F%2Fwww.parakeet-ai.com%2F.
            /// </summary>
            EmbeddedHost = 2
        }

        /// <summary>
        /// Match a URL against a vendor.
        ///
        /// A PLAIN SUBSTRING TEST HERE IS A FALSE-POSITIVE FACTORY, and this was found by testing
        /// rather than reasoned about: on this machine an accounts.google.com sign-in URL matched
        /// "parakeet-ai.com" because the string sat in its redirect_uri query parameter. That
        /// particular case was genuine (an OAuth hand-off TO the vendor), but the identical test
        /// also fires on "google.com/search?q=parakeet-ai.com" - i.e. on someone who merely
        /// SEARCHED for the name - and reporting that as "the site is open" at Strong confidence
        /// would be an accusation built on a mention.
        ///
        /// So the URL is only matched two ways: the host itself, or an embedded absolute URL whose
        /// host matches. A bare mention in a query string or path matches nothing.
        /// </summary>
        private static UrlMatchKind MatchUrl(string? url, VendorTarget target, out string matchedFragment)
        {
            matchedFragment = "";
            if (string.IsNullOrWhiteSpace(url)) return UrlMatchKind.None;
            if (target.HostFragments.Count == 0) return UrlMatchKind.None;

            string? host = UrlMatcher.ExtractHost(url);
            if (host != null)
            {
                foreach (string h in target.HostFragments)
                {
                    if (UrlMatcher.HostMatches(host, h))
                    {
                        matchedFragment = h;
                        return UrlMatchKind.Host;
                    }
                }
            }

            foreach (string embedded in UrlMatcher.EmbeddedHosts(url!))
            {
                foreach (string h in target.HostFragments)
                {
                    if (UrlMatcher.HostMatches(embedded, h))
                    {
                        matchedFragment = h;
                        return UrlMatchKind.EmbeddedHost;
                    }
                }
            }

            return UrlMatchKind.None;
        }

        /// <summary>
        /// Titles of search-results pages. A tab called "parakeet-ai.com - Google Search" means
        /// the person TYPED the name into a search box, which is not the same fact as having the
        /// product open, and is emphatically not worth a Strong signal in a tool that makes
        /// accusations about people. Matched after <see cref="TitleNormalizer"/>.
        /// </summary>
        private static readonly string[] SearchResultTitleSuffixes =
        {
            " - Google Search", " - Google Zoeken", " - Recherche Google",
            " - Bing", " at DuckDuckGo", " - Yahoo Search Results", " - Yahoo Suche",
            " - Ecosia", " - Startpage", " - Brave Search", " - Yandex",
            " - Qwant", " - Search", " - Search Results", " - Mojeek", " - Perplexity",
        };

        private static bool LooksLikeSearchResultsPage(string title)
        {
            foreach (string suffix in SearchResultTitleSuffixes)
                if (title.EndsWith(suffix, StringComparison.OrdinalIgnoreCase)) return true;
            return false;
        }

        /// <summary>
        /// Returns the fragment that matched a title / tab name, or null. Search-results pages are
        /// excluded: see <see cref="SearchResultTitleSuffixes"/>.
        /// </summary>
        private static string? MatchText(string? text, VendorTarget target)
        {
            if (string.IsNullOrWhiteSpace(text)) return null;
            if (LooksLikeSearchResultsPage(text!)) return null;

            foreach (string f in target.TextFragments)
                if (text!.IndexOf(f, StringComparison.OrdinalIgnoreCase) >= 0) return f;
            return null;
        }

        // =================================================================== window enumeration

        private sealed class BrowserWindow
        {
            public BrowserWindow(BrowserInfo browser)
            {
                Browser = browser;
            }

            public IntPtr Handle;
            public int Pid;
            public string ProcessName = "";
            public readonly BrowserInfo Browser;
            public string RawTitle = "";
            public string NormalizedTitle = "";
            public string ActiveTabTitle = "";
            public int? OtherTabCount;
            public bool IsForeground;
        }

        private static Dictionary<int, string> BuildPidNameMap()
        {
            Dictionary<int, string> map = new Dictionary<int, string>(512);
            Process[] processes;
            try { processes = Process.GetProcesses(); }
            catch (Exception) { return map; }

            foreach (Process p in processes)
            {
                try { map[p.Id] = p.ProcessName; }
                catch (Exception) { /* exited between enumeration and read */ }
                finally
                {
                    try { p.Dispose(); } catch (Exception) { }
                }
            }
            return map;
        }

        private static List<BrowserWindow> EnumerateBrowserWindows(ScanReport report)
        {
            List<BrowserWindow> results = new List<BrowserWindow>();
            Dictionary<int, string> pidToName = BuildPidNameMap();

            IntPtr foreground = IntPtr.Zero;
            try { foreground = NativeMethods.GetForegroundWindow(); } catch (Exception) { }

            NativeMethods.EnumWindowsProc callback = delegate (IntPtr hWnd, IntPtr lParam)
            {
                try
                {
                    if (!NativeMethods.IsWindowVisible(hWnd)) return true;

                    int pid = NativeMethods.GetWindowPid(hWnd);
                    if (pid <= 0) return true;

                    string procName;
                    if (!pidToName.TryGetValue(pid, out procName)) return true;

                    BrowserInfo? browser = BrowserCatalog.FromProcessName(procName);
                    if (browser == null) return true;

                    // Chromium creates a swarm of invisible helper top-level windows; the real
                    // browser frame is Chrome_WidgetWin_1. Firefox uses MozillaWindowClass.
                    string className = NativeMethods.GetWindowClassName(hWnd);
                    if (browser.IsChromium &&
                        !className.StartsWith("Chrome_WidgetWin", StringComparison.Ordinal))
                        return true;
                    if (browser.Kind == BrowserKind.Firefox &&
                        !className.StartsWith("Mozilla", StringComparison.Ordinal))
                        return true;

                    string raw = NativeMethods.GetWindowTitle(hWnd);
                    if (string.IsNullOrWhiteSpace(raw)) return true;

                    string normalized = TitleNormalizer.Normalize(raw);
                    int? others;
                    string tabTitle = ParseTitle(normalized, browser, out others);

                    BrowserWindow w = new BrowserWindow(browser);
                    w.Handle = hWnd;
                    w.Pid = pid;
                    w.ProcessName = procName;
                    w.RawTitle = raw;
                    w.NormalizedTitle = normalized;
                    w.ActiveTabTitle = tabTitle;
                    w.OtherTabCount = others;
                    w.IsForeground = (hWnd == foreground);
                    results.Add(w);
                }
                catch (Exception)
                {
                    // One bad window must never abort the enumeration.
                }
                return true;
            };

            try
            {
                NativeMethods.EnumWindows(callback, IntPtr.Zero);
            }
            catch (Exception ex)
            {
                report.Limitations.Add("Window enumeration failed inside the browser scanner (" +
                                       Describe(ex) + ").");
            }
            finally
            {
                GC.KeepAlive(callback);
            }

            return results;
        }

        // "<tab> and 12 more pages - Personal - Microsoft Edge" (Edge; Chrome does NOT do this)
        private static readonly Regex MoreTabs = new Regex(
            @"\s+and\s+(?<n>\d+)\s+more\s+(?:pages?|tabs?)\s*$",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

        private static readonly Regex EdgeProfileTail = new Regex(
            @"^(?<head>.*?more\s+(?:pages?|tabs?))\s+-\s+[^-]{1,64}$",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

        private static readonly Regex PrivacyTail = new Regex(
            @"\s*[-–—]\s*(InPrivate|Incognito|Private Browsing)\s*$",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

        /// <summary>
        /// Strip the brand suffix, Edge's injected profile name and the "and N more pages"
        /// fragment, leaving the ACTIVE tab's own title.
        /// </summary>
        private static string ParseTitle(string normalizedTitle, BrowserInfo browser, out int? otherTabs)
        {
            otherTabs = null;
            string title = normalizedTitle ?? "";

            foreach (string suffix in browser.TitleSuffixes)
            {
                if (title.EndsWith(suffix, StringComparison.OrdinalIgnoreCase))
                {
                    title = title.Substring(0, title.Length - suffix.Length);
                    break;
                }
            }

            // Edge inserts the profile name after the "and N more pages" marker. Only strip a
            // trailing " - <something>" when that marker is still present, otherwise a legitimate
            // hyphenated page title would be eaten.
            if (browser.Kind == BrowserKind.Edge)
            {
                Match m = EdgeProfileTail.Match(title);
                if (m.Success) title = m.Groups["head"].Value;
            }

            Match more = MoreTabs.Match(title);
            if (more.Success)
            {
                int n;
                if (int.TryParse(more.Groups["n"].Value, NumberStyles.Integer,
                                 CultureInfo.InvariantCulture, out n))
                {
                    otherTabs = n;
                }
                title = title.Substring(0, more.Index);
            }

            title = PrivacyTail.Replace(title, "");
            return title.Trim();
        }

        // =================================================================== browser catalog

        private enum BrowserKind { Unknown, Chrome, Edge, Firefox, Brave, Opera, Vivaldi, Chromium }

        private sealed class BrowserInfo
        {
            public BrowserInfo(BrowserKind kind, string processName, string displayName,
                               bool isChromium, string[] titleSuffixes)
            {
                Kind = kind;
                ProcessName = processName;
                DisplayName = displayName;
                IsChromium = isChromium;
                TitleSuffixes = titleSuffixes;
            }

            public readonly BrowserKind Kind;
            public readonly string ProcessName;
            public readonly string DisplayName;
            public readonly bool IsChromium;
            public readonly string[] TitleSuffixes;
        }

        /// <summary>
        /// The browsers we recognise. Title suffixes are written in plain ASCII with an ordinary
        /// space and hyphen because they are matched AFTER <see cref="TitleNormalizer"/> has folded
        /// the real Unicode the browsers actually emit down to this shape.
        /// </summary>
        private static class BrowserCatalog
        {
            public static readonly BrowserInfo[] All = new BrowserInfo[]
            {
                new BrowserInfo(BrowserKind.Chrome, "chrome", "Google Chrome", true,
                    new string[] { " - Google Chrome" }),

                // Edge really emits "Microsoft​ Edge" - a ZERO WIDTH SPACE between the two
                // words. EndsWith("Microsoft Edge") silently fails on the raw title; Normalize()
                // strips U+200B first, which is what makes this entry work.
                new BrowserInfo(BrowserKind.Edge, "msedge", "Microsoft Edge", true,
                    new string[] { " - Microsoft Edge" }),

                // Firefox separates with an EM DASH (U+2014); Normalize() folds it to " - ".
                new BrowserInfo(BrowserKind.Firefox, "firefox", "Mozilla Firefox", false,
                    new string[] { " - Mozilla Firefox", " - Firefox",
                                   " - Firefox Developer Edition", " - Firefox Nightly",
                                   " - Mozilla Firefox Private Browsing" }),

                new BrowserInfo(BrowserKind.Brave, "brave", "Brave", true,
                    new string[] { " - Brave", " - Brave Browser" }),

                new BrowserInfo(BrowserKind.Opera, "opera", "Opera", true,
                    new string[] { " - Opera", " - Opera GX", " - Opera Air",
                                   " - Opera Crypto Browser" }),

                new BrowserInfo(BrowserKind.Vivaldi, "vivaldi", "Vivaldi", true,
                    new string[] { " - Vivaldi" }),

                new BrowserInfo(BrowserKind.Chromium, "chromium", "Chromium", true,
                    new string[] { " - Chromium" }),
            };

            private static readonly Dictionary<string, BrowserInfo> ByProcess = BuildIndex();

            private static Dictionary<string, BrowserInfo> BuildIndex()
            {
                Dictionary<string, BrowserInfo> map =
                    new Dictionary<string, BrowserInfo>(StringComparer.OrdinalIgnoreCase);
                foreach (BrowserInfo b in All) map[b.ProcessName] = b;

                // Channel and fork variants that still are the same browser.
                map["opera_gx"] = Find(BrowserKind.Opera);
                map["opera_air"] = Find(BrowserKind.Opera);
                map["brave_browser"] = Find(BrowserKind.Brave);
                map["firefox-bin"] = Find(BrowserKind.Firefox);
                return map;
            }

            private static BrowserInfo Find(BrowserKind kind)
            {
                foreach (BrowserInfo b in All) if (b.Kind == kind) return b;
                return All[0];
            }

            /// <summary>
            /// msedgewebview2 is deliberately NOT treated as a browser: it is the embedded
            /// WebView2 runtime that dozens of ordinary desktop apps host, it has no tab strip and
            /// no omnibox, and counting it would attribute other applications' embedded content to
            /// "the user has Edge open".
            /// </summary>
            public static BrowserInfo? FromProcessName(string? processName)
            {
                if (string.IsNullOrWhiteSpace(processName)) return null;

                string name = processName!.Trim();
                int slash = name.LastIndexOfAny(new char[] { '\\', '/' });
                if (slash >= 0 && slash < name.Length - 1) name = name.Substring(slash + 1);
                if (name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                    name = name.Substring(0, name.Length - 4);

                BrowserInfo info;
                return ByProcess.TryGetValue(name, out info) ? info : null;
            }
        }

        /// <summary>
        /// Folds the Unicode that real browsers put into window titles down to a predictable
        /// ASCII shape, so the suffix table above can be written in plain text.
        ///
        /// VERIFIED on a live machine:
        ///   Edge  : "... - Claude and 12 more pages - Personal - Microsoft​ Edge"
        ///           U+200B ZERO WIDTH SPACE between "Microsoft" and "Edge". Without stripping it,
        ///           EndsWith("Microsoft Edge") returns false and Edge is never recognised.
        ///   Chrome: "Imagine Dragons - Enemy ... - YouTube - Google Chrome"
        ///           Chrome does NOT append "and N more pages" even with 8 tabs open; that is an
        ///           Edge-only behaviour, and Edge also injects the profile name after it.
        /// </summary>
        private static class TitleNormalizer
        {
            private static readonly char[] Invisible =
            {
                '​', // ZERO WIDTH SPACE          <- Edge
                '‌', // ZERO WIDTH NON-JOINER
                '‍', // ZERO WIDTH JOINER
                '‎', // LEFT-TO-RIGHT MARK
                '‏', // RIGHT-TO-LEFT MARK
                '⁠', // WORD JOINER
                '﻿', // ZERO WIDTH NO-BREAK SPACE / BOM
            };

            private static readonly char[] Dashes =
            {
                '‐', '‑', '‒', '–',
                '—', // EM DASH                   <- Firefox
                '―', '−', '﹘', '﹣', '－',
            };

            private static readonly Regex Whitespace = new Regex(@"\s+", RegexOptions.CultureInvariant);

            public static string Normalize(string? raw)
            {
                if (string.IsNullOrEmpty(raw)) return "";

                StringBuilder sb = new StringBuilder(raw!.Length);
                foreach (char ch in raw)
                {
                    if (Array.IndexOf(Invisible, ch) >= 0) continue;
                    if (Array.IndexOf(Dashes, ch) >= 0) { sb.Append('-'); continue; }
                    if (ch == ' ' || ch == ' ' || ch == ' ') { sb.Append(' '); continue; }
                    sb.Append(ch);
                }

                return Whitespace.Replace(sb.ToString(), " ").Trim();
            }
        }

        // =================================================================== URL matching

        /// <summary>
        /// Host comparison that tolerates what the browsers actually hand us.
        ///
        /// VERIFIED: Chrome's omnibox returns "youtube.com/watch?v=..." with NO scheme while
        /// Edge's returns "https://claude.ai/chat/...". Uri.TryCreate(Absolute) fails on the
        /// former, so a scheme is prepended before parsing.
        /// </summary>
        private static class UrlMatcher
        {
            /// <summary>Lower-cased host with "www." stripped, or null when unparseable.</summary>
            public static string? ExtractHost(string? url)
            {
                if (string.IsNullOrWhiteSpace(url)) return null;

                string candidate = url!.Trim();

                if (candidate.IndexOf("://", StringComparison.Ordinal) < 0)
                {
                    // Plainly search text, not a URL.
                    if (candidate.IndexOf(' ') >= 0) return null;
                    candidate = "https://" + candidate;
                }

                Uri? uri;
                if (!Uri.TryCreate(candidate, UriKind.Absolute, out uri) || uri == null) return null;
                if (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps) return null;

                string host = uri.Host.ToLowerInvariant().TrimEnd('.');
                if (host.StartsWith("www.", StringComparison.Ordinal)) host = host.Substring(4);
                return host.Length == 0 ? null : host;
            }

            /// <summary>
            /// Hosts of absolute URLs embedded INSIDE another URL, e.g. the redirect_uri of an
            /// OAuth hand-off. The query string is URL-decoded first (twice at most - some
            /// identity providers double-encode), then every "scheme://host" occurrence after the
            /// first is read off. Bounded work: the input is capped and at most 8 hosts come back.
            /// </summary>
            public static IEnumerable<string> EmbeddedHosts(string url)
            {
                string decoded = url;
                for (int pass = 0; pass < 2; pass++)
                {
                    string next;
                    try { next = Uri.UnescapeDataString(decoded); }
                    catch (Exception) { break; }   // malformed percent-escapes
                    if (string.Equals(next, decoded, StringComparison.Ordinal)) break;
                    decoded = next;
                    if (decoded.Length > 8192) break;
                }

                int found = 0;
                int index = decoded.IndexOf("://", StringComparison.Ordinal);

                // Skip the URL's OWN scheme: that host is handled by ExtractHost.
                if (index >= 0) index = decoded.IndexOf("://", index + 3, StringComparison.Ordinal);

                while (index >= 0 && found < 8)
                {
                    int start = index + 3;
                    int end = start;
                    while (end < decoded.Length)
                    {
                        char c = decoded[end];
                        if (c == '/' || c == '?' || c == '#' || c == '&' || c == '"' || c == '\'' ||
                            c == '<' || c == '>' || c == ',' || c == ' ' || c == '\t') break;
                        end++;
                    }

                    if (end > start)
                    {
                        string host = decoded.Substring(start, end - start);
                        int at = host.LastIndexOf('@');          // strip userinfo
                        if (at >= 0 && at < host.Length - 1) host = host.Substring(at + 1);
                        int colon = host.IndexOf(':');           // strip port
                        if (colon > 0) host = host.Substring(0, colon);

                        host = host.ToLowerInvariant().TrimEnd('.');
                        if (host.StartsWith("www.", StringComparison.Ordinal)) host = host.Substring(4);
                        if (host.Length > 0 && host.IndexOf('.') > 0)
                        {
                            found++;
                            yield return host;
                        }
                    }

                    index = decoded.IndexOf("://", end, StringComparison.Ordinal);
                }
            }

            /// <summary>True when <paramref name="host"/> equals or is a sub-domain of the target.</summary>
            public static bool HostMatches(string host, string target)
            {
                if (string.IsNullOrWhiteSpace(target)) return false;

                string t = target.Trim().TrimEnd('.').ToLowerInvariant();
                if (t.StartsWith("www.", StringComparison.Ordinal)) t = t.Substring(4);
                if (t.Length == 0) return false;

                if (string.Equals(host, t, StringComparison.Ordinal)) return true;
                return host.EndsWith("." + t, StringComparison.Ordinal);
            }
        }

        // =================================================================== UI Automation

        private sealed class UiaWindowSnapshot
        {
            public UiaWindowSnapshot(string? omniboxUrl, List<string> tabTitles,
                                     string? documentUrl, string? error)
            {
                OmniboxUrl = omniboxUrl;
                TabTitles = tabTitles;
                DocumentUrl = documentUrl;
                Error = error;
            }

            public readonly string? OmniboxUrl;
            public readonly List<string> TabTitles;
            public readonly string? DocumentUrl;
            public readonly string? Error;
        }

        /// <summary>
        /// Reads a browser window's tab strip and address bar over UI Automation.
        ///
        /// EMPIRICALLY VERIFIED, and every one of these was found by testing rather than by
        /// reading documentation:
        ///
        ///  * --force-renderer-accessibility IS NOT NEEDED. AutomationElement.FromHandle sends
        ///    WM_GETOBJECT; Chromium answers and enables accessibility on demand. Measured ~126 ms
        ///    for the first attach to a browser and 1-20 ms afterwards. You could not pass that
        ///    switch anyway - you cannot relaunch the user's browser.
        ///
        ///  * A DEEP TabItem SEARCH IS A TRAP. On Chrome,
        ///    root.FindAll(TreeScope.Descendants, ControlType.TabItem) returned 15 items of which
        ///    7 were YouTube's IN-PAGE filter chips ("All", "Related", "For you"). FindFirst for
        ///    ControlType.Tab matched the PAGE's tablist, not the browser's. A detector that
        ///    trusts those numbers invents tabs out of page content. The fix below is a
        ///    breadth-first walk of BROWSER CHROME ONLY that STOPS DESCENDING at
        ///    ControlType.Document, which is exactly where web content begins.
        ///
        ///  * THE CacheRequest MUST BE ACTIVE BEFORE FromHandle. An element acquired outside the
        ///    active request carries no cached data, so the first GetCachedPropertyValue throws
        ///    and the walk silently returns zero tabs while the omnibox still works, because the
        ///    omnibox has a non-cached fallback path. That bug cost a whole live debugging round.
        ///
        ///  * EDGE EXPOSES ZERO INDIVIDUAL TabItems - its tab-strip Pane is empty in the
        ///    accessibility tree - while its omnibox reads perfectly. Tab enumeration can
        ///    therefore NEVER be a hard requirement: the omnibox and the window title are the
        ///    fallbacks, and all three are tried on every window.
        ///
        ///  * MATCH THE OMNIBOX ON NAME, NEVER ON AutomationId. The id was "view_1012" in Chrome
        ///    and "view_1017" in Edge - a generated ordinal that changes between builds and even
        ///    between windows of the same build.
        ///
        /// Must only ever be called through <see cref="StaTimeoutRunner"/>: every call below is a
        /// blocking cross-process RPC into a browser that may be busy.
        /// </summary>
        private static class UiaBrowserReader
        {
            private static readonly string[] AddressBarNames =
            {
                "Address and search bar",                  // Chrome + Edge (verified live)
                "Address bar",
                "Search or enter web address",             // older Chromium / Edge
                "Search with Google or enter address",     // Firefox
                "Search with DuckDuckGo or enter address", // Firefox, alternate engine
                "Search with Bing or enter address",
                "Enter address",
            };

            /// <summary>The omnibox sits roughly 6-9 levels down; 12 is headroom, not a guess.</summary>
            private const int MaxChromeDepth = 12;

            /// <summary>Safety valve so a pathological tree cannot burn the whole timeout.</summary>
            private const int MaxNodesVisited = 4000;

            public static UiaWindowSnapshot Read(IntPtr hwnd)
            {
                List<string> tabs = new List<string>();
                string? omnibox = null;
                AutomationElement? root = null;

                try
                {
                    // One CacheRequest for the whole walk: each cached property arrives in the
                    // SAME cross-process round trip as the element. Without it every .Current.X
                    // is its own RPC and a 20-tab window costs hundreds of them.
                    //
                    // AutomationElementMode.Full (the default) is deliberate: .None yields
                    // cache-only elements that cannot serve ValuePattern, and ValuePattern is how
                    // the omnibox is read during the same walk.
                    CacheRequest cache = new CacheRequest();
                    cache.TreeScope = TreeScope.Element | TreeScope.Children;
                    cache.AutomationElementMode = AutomationElementMode.Full;
                    cache.Add(AutomationElement.NameProperty);
                    cache.Add(AutomationElement.ControlTypeProperty);

                    using (cache.Activate())
                    {
                        // CRITICAL: the root must be obtained INSIDE the active CacheRequest.
                        root = AutomationElement.FromHandle(hwnd);
                        omnibox = WalkChromeOnly(root, tabs);
                    }
                }
                catch (ElementNotAvailableException)
                {
                    return new UiaWindowSnapshot(null, tabs, null, "window closed during the scan");
                }
                catch (Exception ex)
                {
                    return new UiaWindowSnapshot(omnibox, tabs, null, ex.GetType().Name);
                }

                if (root == null) return new UiaWindowSnapshot(omnibox, tabs, null, "no automation root");

                if (omnibox == null) omnibox = TryReadAddressBar(root);

                return new UiaWindowSnapshot(omnibox, tabs, TryReadDocumentUrl(root), null);
            }

            /// <summary>
            /// Breadth-first over BROWSER CHROME ONLY. Descent stops at ControlType.Document, the
            /// boundary between browser UI and web content, which is what keeps in-page tab
            /// widgets out of the tab list. Returns the omnibox value if it was found on the way.
            /// </summary>
            private static string? WalkChromeOnly(AutomationElement root, List<string> tabs)
            {
                string? omnibox = null;

                Queue<KeyValuePair<AutomationElement, int>> queue =
                    new Queue<KeyValuePair<AutomationElement, int>>();
                queue.Enqueue(new KeyValuePair<AutomationElement, int>(root, 0));

                int visited = 0;
                while (queue.Count > 0 && visited < MaxNodesVisited)
                {
                    KeyValuePair<AutomationElement, int> entry = queue.Dequeue();
                    AutomationElement element = entry.Key;
                    int depth = entry.Value;
                    visited++;

                    ControlType? controlType = GetProperty(element, AutomationElement.ControlTypeProperty) as ControlType;
                    if (controlType == null) continue;

                    string name = GetProperty(element, AutomationElement.NameProperty) as string ?? "";

                    // Web content begins here: do not descend, do not collect.
                    if (controlType == ControlType.Document) continue;

                    if (controlType == ControlType.TabItem)
                    {
                        if (!string.IsNullOrWhiteSpace(name)) tabs.Add(name);
                        continue; // a tab has no browser-chrome children worth walking
                    }

                    if (omnibox == null && controlType == ControlType.Edit && IsAddressBarName(name))
                        omnibox = ReadValue(element);

                    if (depth >= MaxChromeDepth) continue;

                    AutomationElementCollection? children = null;
                    try
                    {
                        children = element.CachedChildren;
                    }
                    catch (Exception)
                    {
                        // Element drifted outside the cache scope - fall back to a live query.
                        try { children = element.FindAll(TreeScope.Children, Condition.TrueCondition); }
                        catch (Exception) { children = null; }
                    }

                    if (children == null) continue;

                    foreach (AutomationElement child in children)
                        queue.Enqueue(new KeyValuePair<AutomationElement, int>(child, depth + 1));
                }

                return omnibox;
            }

            /// <summary>
            /// Read a property from the cache, falling back to a live read. The fallback matters:
            /// elements outside the CacheRequest's TreeScope have no cached data and letting that
            /// throw would truncate the walk.
            /// </summary>
            private static object? GetProperty(AutomationElement element, AutomationProperty property)
            {
                try
                {
                    object cached = element.GetCachedPropertyValue(property);
                    if (cached != null && cached != AutomationElement.NotSupported) return cached;
                }
                catch (InvalidOperationException)
                {
                    // Property not in the CacheRequest, or the element predates it.
                }
                catch (ElementNotAvailableException)
                {
                    return null;
                }
                catch (Exception)
                {
                    return null;
                }

                try
                {
                    object live = element.GetCurrentPropertyValue(property);
                    return live == AutomationElement.NotSupported ? null : live;
                }
                catch (Exception)
                {
                    return null;
                }
            }

            private static bool IsAddressBarName(string name)
            {
                if (string.IsNullOrWhiteSpace(name)) return false;

                foreach (string candidate in AddressBarNames)
                    if (name.Equals(candidate, StringComparison.OrdinalIgnoreCase)) return true;

                // Localised builds: loose fallback on both words.
                return name.IndexOf("address", StringComparison.OrdinalIgnoreCase) >= 0
                    && name.IndexOf("bar", StringComparison.OrdinalIgnoreCase) >= 0;
            }

            /// <summary>Direct lookup of the address bar, used when the chrome walk missed it.</summary>
            private static string? TryReadAddressBar(AutomationElement root)
            {
                foreach (string candidate in AddressBarNames)
                {
                    try
                    {
                        AndCondition condition = new AndCondition(
                            new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.Edit),
                            new PropertyCondition(AutomationElement.NameProperty, candidate));

                        AutomationElement element = root.FindFirst(TreeScope.Descendants, condition);
                        if (element == null) continue;

                        string? value = ReadValue(element);
                        if (!string.IsNullOrWhiteSpace(value)) return value;
                    }
                    catch (Exception)
                    {
                        // try the next name
                    }
                }
                return null;
            }

            private static string? ReadValue(AutomationElement element)
            {
                try
                {
                    object pattern;
                    if (element.TryGetCurrentPattern(ValuePattern.Pattern, out pattern))
                    {
                        ValuePattern? value = pattern as ValuePattern;
                        if (value != null) return value.Current.Value;
                    }
                }
                catch (Exception)
                {
                    // ValuePattern needs a live element; a cache-only element throws here.
                }
                return null;
            }

            /// <summary>
            /// The URL of the web Document node - the ACTIVE tab's real address, independent of
            /// whatever the omnibox is displaying (the omnibox shows what the user has typed if
            /// they are mid-edit). Chrome exposed it through ValuePattern once accessibility was
            /// live; Edge returned an empty Document on first attach. A bonus, never a requirement.
            /// </summary>
            private static string? TryReadDocumentUrl(AutomationElement root)
            {
                try
                {
                    AutomationElement doc = root.FindFirst(TreeScope.Descendants,
                        new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.Document));
                    return doc == null ? null : ReadValue(doc);
                }
                catch (Exception)
                {
                    return null;   // no document, or the window went away
                }
            }
        }
    }
}

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;
using ProctorAIDetective.Core;
using ProctorAIDetective.Native;

namespace ProctorAIDetective.Scanners
{
    /// <summary>
    /// The decisive scanner. Enumerates every top-level window on the current desktop and asks
    /// the one question an AI-assistant overlay cannot answer honestly: "are you hiding from
    /// screen capture?"
    ///
    /// GetWindowDisplayAffinity is cross-process and needs no elevation - verified first-hand,
    /// 646/646 other-process top-level windows answered from a medium-integrity caller - so a
    /// window that was handed WDA_EXCLUDEFROMCAPTURE is visible on the physical monitor and
    /// absent from every capture API, and this process can read that fact directly.
    ///
    /// ATTRIBUTION DISCIPLINE. Every behavioural signal this scanner emits carries
    /// Attribution = 0 by construction. A hidden window proves that *something* is evading
    /// capture; it never proves *who*. 1Password, Zoom's share toolbar and a DRM video surface
    /// all hide windows legitimately, so letting a hidden window raise the "is this Parakeet"
    /// score would make the tool an accusation generator. Identity is the process scanner's
    /// job; the single exception here is B1, which reads a vendor's own name out of a window
    /// title and is deliberately capped at Tier.Moderate because the vendor ships a
    /// user-toggleable blank-branding mode.
    /// </summary>
    public sealed class WindowScanner : IScanner
    {
        public string Id { get { return "window"; } }

        public string DisplayName { get { return "Windows and capture evasion"; } }

        private const string SourceId = "window";

        // Signal kinds, used as the dedupe key and as the Signal.Id prefix.
        private const string KindCaptureExcluded = "C1";
        private const string KindCaptureMonitor = "C2";
        private const string KindOverlay = "D1";
        private const string KindAppCloaked = "D2";
        private const string KindTitle = "B1";

        /// <summary>Titles and detail strings are truncated to this before going in a Signal.</summary>
        private const int MaxQuotedLength = 160;

        // ==================================================================== IScanner

        /// <summary>
        /// Never throws. Every failure path appends to <paramref name="report"/>.Limitations and
        /// returns whatever was collected before the failure.
        /// </summary>
        public void Scan(ScanContext context, ScanReport report)
        {
            if (context == null || report == null) return;

            try
            {
                ScanCore(context, report);
            }
            catch (Exception ex)
            {
                // A scanner that throws takes the whole scan down with it. Degrade instead.
                report.Limitations.Add(
                    "Window scan failed and was abandoned (" + ex.GetType().Name + ": " + OneLine(ex.Message) +
                    "). Capture-evasion findings from windows are therefore incomplete; treat the window axis " +
                    "as unanswered rather than clean.");
            }
        }

        private void ScanCore(ScanContext context, ScanReport report)
        {
            SignatureSet signatures = context.Signatures ?? new SignatureSet();
            HashSet<int> invisible = BuildInvisibleSet(signatures);

            // --- build-level capability note -------------------------------------------------
            // WDA_EXCLUDEFROMCAPTURE is a Windows 10 2004 (build 19041) feature. On older builds
            // SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE) silently degrades to WDA_MONITOR,
            // so the strongest signal this scanner can produce simply does not exist there and
            // saying nothing would read as a clean result.
            int build = SafeOsBuild();
            if (build > 0 && build < Win32Constants.WDA_EXCLUDEFROMCAPTURE_MIN_BUILD)
            {
                report.Limitations.Add(
                    "This Windows build (" + build.ToString(CultureInfo.InvariantCulture) + ") predates build " +
                    Win32Constants.WDA_EXCLUDEFROMCAPTURE_MIN_BUILD.ToString(CultureInfo.InvariantCulture) +
                    ", so WDA_EXCLUDEFROMCAPTURE is not supported here. The strongest capture-evasion signal " +
                    "(C1) cannot occur on this machine; WDA_MONITOR (C2), which renders a window as a black " +
                    "box in captures, is the strongest obtainable result.");
            }

            // --- enumerate -------------------------------------------------------------------
            List<IntPtr> handles = EnumerateTopLevelHandles(report);
            report.WindowsScanned = handles.Count;
            if (handles.Count == 0) return;

            if (context.Cancel.IsCancellationRequested)
            {
                report.Limitations.Add("Window scan was cancelled before any window was inspected.");
                return;
            }

            // --- owning processes, collected ONCE and joined by pid --------------------------
            // Never per window: ~650 windows map to ~110 distinct pids, and a per-window
            // process lookup would re-read the same signed binaries dozens of times.
            Dictionary<int, ProcessInfo> byPid = CollectProcesses(context, report);

            int selfPid = SafeCurrentProcessId();

            // --- inspect ---------------------------------------------------------------------
            Dictionary<string, Bucket> buckets = new Dictionary<string, Bucket>(StringComparer.Ordinal);

            int queryFailed = 0;
            int queryFailedStaleHandle = 0;
            Dictionary<int, int> queryFailureCodes = new Dictionary<int, int>();
            bool cancelled = false;

            for (int i = 0; i < handles.Count; i++)
            {
                if (context.Cancel.IsCancellationRequested) { cancelled = true; break; }

                WindowFacts w;
                try
                {
                    w = Describe(handles[i]);
                }
                catch (Exception)
                {
                    // Describe is already defensive; this is belt-and-braces for a window that
                    // dies between two of its own calls.
                    continue;
                }

                if (!w.AffinityOk)
                {
                    queryFailed++;
                    if (w.AffinityError == Win32Constants.ERROR_INVALID_WINDOW_HANDLE)
                    {
                        // Routine: the window died between EnumWindows and the query. Still a
                        // window we could not answer for, so it is counted - but it is not a
                        // symptom of anything and does not earn its own limitation line.
                        queryFailedStaleHandle++;
                    }
                    else
                    {
                        int n;
                        queryFailureCodes.TryGetValue(w.AffinityError, out n);
                        queryFailureCodes[w.AffinityError] = n + 1;
                    }
                }

                // Never report our own UI. The app is allowed to set WDA_EXCLUDEFROMCAPTURE on
                // its own result window so a screen-share cannot read the verdict over the
                // user's shoulder; detecting that would be a guaranteed self-accusation.
                if (selfPid != 0 && w.Pid == selfPid) continue;

                ProcessInfo? owner;
                byPid.TryGetValue(w.Pid, out owner);

                Classify(w, owner, signatures, invisible, buckets);
            }

            if (cancelled)
                report.Limitations.Add("Window scan was cancelled partway through; window findings are incomplete.");

            // --- blind spots ------------------------------------------------------------------
            report.WindowsQueryFailed += queryFailed;

            if (queryFailed > 0)
            {
                StringBuilder lim = new StringBuilder();
                lim.Append("Display affinity could not be read for ")
                   .Append(queryFailed.ToString(CultureInfo.InvariantCulture))
                   .Append(" of ")
                   .Append(handles.Count.ToString(CultureInfo.InvariantCulture))
                   .Append(" top-level windows. Those windows are recorded as UNKNOWN, not as \"not hidden\": ")
                   .Append("a window hiding from capture could be among them.");

                if (queryFailedStaleHandle > 0)
                {
                    lim.Append(' ')
                       .Append(queryFailedStaleHandle.ToString(CultureInfo.InvariantCulture))
                       .Append(" of those failed with ERROR_INVALID_WINDOW_HANDLE (1400), which simply means the ")
                       .Append("window closed between enumeration and the query.");
                }

                if (queryFailureCodes.Count > 0)
                {
                    lim.Append(" Other failures: ").Append(FormatErrorCounts(queryFailureCodes)).Append('.');
                }

                report.Limitations.Add(lim.ToString());
            }

            if (byPid.Count == 0)
            {
                report.Limitations.Add(
                    "No process list could be obtained, so window findings name only a pid - the owning " +
                    "process name, image path and Authenticode signer are unavailable, and the allowlist " +
                    "could not vet them.");
            }

            // --- emit -------------------------------------------------------------------------
            foreach (Bucket b in buckets.Values)
            {
                Signal? s = BuildSignal(b, report, invisible);
                if (s == null) continue;

                try { context.Allowlist.Apply(s); }
                catch (Exception) { /* allowlist must never be able to break a scan */ }

                report.Signals.Add(s);
            }
        }

        // ==================================================================== classification

        private static void Classify(
            WindowFacts w,
            ProcessInfo? owner,
            SignatureSet signatures,
            HashSet<int> invisible,
            Dictionary<string, Bucket> buckets)
        {
            // ---- C1 / C2: display affinity ---------------------------------------------------
            // Deliberately NOT gated on WS_EX_LAYERED. MSDN claims the query succeeds only for
            // layered windows; 581 non-layered windows on this machine disproved that, and
            // gating on it would make this scanner find precisely nothing.
            if (w.AffinityOk && w.Affinity != Win32Constants.WDA_NONE)
            {
                if (w.Affinity == Win32Constants.WDA_EXCLUDEFROMCAPTURE)
                    Record(buckets, KindCaptureExcluded, "", w, owner, signatures);
                else
                    Record(buckets, KindCaptureMonitor, "", w, owner, signatures);
            }

            // ---- D1: invisible click-through overlay ------------------------------------------
            if (IsClickThroughOverlay(w, invisible))
                Record(buckets, KindOverlay, "", w, owner, signatures);

            // ---- D2: app-cloaked ---------------------------------------------------------------
            // DWM_CLOAKED_SHELL is the normal state of a suspended UWP window (22 on an idle
            // desktop). Emitting it would bury the report in noise, so only a cloak the APP
            // asked for, with no shell bit, counts.
            if (w.CloakHr == Win32Constants.S_OK
                && (w.Cloaked & Win32Constants.DWM_CLOAKED_APP) != 0
                && (w.Cloaked & Win32Constants.DWM_CLOAKED_SHELL) == 0)
            {
                Record(buckets, KindAppCloaked, "", w, owner, signatures);
            }

            // ---- B1: window title names a known vendor ------------------------------------------
            if (w.Title.Length > 0)
            {
                string flattened = FlattenInvisible(w.Title, invisible);

                foreach (VendorSignature v in signatures.Vendors)
                {
                    if (v == null || v.WindowTitleContains == null) continue;

                    string? hit = null;
                    foreach (string fragment in v.WindowTitleContains)
                    {
                        if (string.IsNullOrEmpty(fragment)) continue;

                        if (w.Title.IndexOf(fragment, StringComparison.OrdinalIgnoreCase) >= 0)
                        {
                            hit = fragment;
                            break;
                        }

                        // Also match with invisible codepoints flattened to spaces, so
                        // "Parakeet<U+2800>AI" cannot slip past a search for "Parakeet AI".
                        // That substitution is the exact evasion this product exists to catch.
                        string flatFragment = FlattenInvisible(fragment, invisible);
                        if (flatFragment.Length > 0
                            && flattened.IndexOf(flatFragment, StringComparison.OrdinalIgnoreCase) >= 0)
                        {
                            hit = fragment;
                            break;
                        }
                    }

                    if (hit == null) continue;

                    Bucket b = Record(buckets, KindTitle, v.Key, w, owner, signatures);
                    b.Vendor = v;
                    if (b.MatchedFragment.Length == 0) b.MatchedFragment = hit;
                }
            }
        }

        /// <summary>
        /// D1's shape test. A bare topmost window is not interesting - thousands of ordinary
        /// windows are topmost - so TOPMOST must be joined by at least two of
        /// {LAYERED, TRANSPARENT, NOACTIVATE}, and the window must additionally be on screen,
        /// have real size, and carry no title the user could read to identify it.
        /// </summary>
        private static bool IsClickThroughOverlay(WindowFacts w, HashSet<int> invisible)
        {
            if (!w.Visible) return false;
            if (w.Bounds.IsEmpty) return false;
            if (!IsBlank(w.Title, invisible)) return false;

            long ex = w.ExStyle;
            if ((ex & Win32Constants.WS_EX_TOPMOST) == 0) return false;

            bool layered = (ex & Win32Constants.WS_EX_LAYERED) != 0;
            bool transparent = (ex & Win32Constants.WS_EX_TRANSPARENT) != 0;
            bool noActivate = (ex & Win32Constants.WS_EX_NOACTIVATE) != 0;
            bool toolWindow = (ex & Win32Constants.WS_EX_TOOLWINDOW) != 0;

            if (!layered && !transparent) return false;
            if (!noActivate && !toolWindow) return false;

            int corroborating = (layered ? 1 : 0) + (transparent ? 1 : 0) + (noActivate ? 1 : 0);
            return corroborating >= 2;
        }

        // ==================================================================== signal building

        private static Signal? BuildSignal(Bucket b, ScanReport report, HashSet<int> invisible)
        {
            WindowFacts w = b.Representative;
            ProcessInfo? p = b.Owner;

            string processName = p != null && p.Name.Length > 0
                ? Visible(p.Name, invisible)
                : "pid " + b.Pid.ToString(CultureInfo.InvariantCulture);

            string imagePath = p != null && p.PathResolved ? p.ImagePath : "";
            string signer = p != null ? p.SignerSubject : "";

            Signal s = new Signal();
            s.Source = SourceId;
            s.Pid = b.Pid;
            s.Subject = processName;
            s.SubjectPath = imagePath;
            s.Signer = signer;

            switch (b.Kind)
            {
                case KindCaptureExcluded:
                {
                    // Does the OWNING process independently look like a known vendor? If so the
                    // hidden window is far more than generic evasion - but attribution still
                    // stays 0 here and is carried by the process scanner's own identity signal.
                    string vendorNote = "";
                    string vendorKey = IdentifyOwner(p, b.Signatures, report, b.Pid, out vendorNote);

                    s.Id = "C1.capture_excluded";
                    s.Title = "Window hidden from screen capture";
                    s.Tier = Tier.Strong;
                    s.Attribution = 0;
                    s.ClassScore = vendorKey.Length > 0 ? 90 : 75;
                    s.State = StateAxis.Evading | StateAxis.Running;
                    s.VendorKey = vendorKey;

                    StringBuilder d = new StringBuilder();
                    d.Append("GetWindowDisplayAffinity returned WDA_EXCLUDEFROMCAPTURE (0x")
                     .Append(w.Affinity.ToString("X8", CultureInfo.InvariantCulture))
                     .Append(") for this window. It is drawn on the physical monitor but is omitted entirely ")
                     .Append("from every screen-capture, screen-share and screenshot API, so it is invisible ")
                     .Append("to a remote viewer while being fully visible to the person at the keyboard.");

                    if (vendorKey.Length > 0)
                    {
                        d.Append(" The owning process independently matches a known vendor signature (")
                         .Append(vendorNote)
                         .Append("), so the class score is raised from 75 to 90. Attribution stays 0 here by ")
                         .Append("design: a hidden window is never, on its own, proof of WHO hid it.");
                    }
                    else
                    {
                        d.Append(" Attribution is 0 by design: this proves something is evading capture, ")
                         .Append("not which product it is.");
                    }

                    AppendWindowFacts(d, b, invisible);
                    s.Detail = d.ToString();
                    break;
                }

                case KindCaptureMonitor:
                {
                    bool exact = w.Affinity == Win32Constants.WDA_MONITOR;

                    s.Id = "C2.capture_monitor";
                    s.Title = "Window blanked out of screen capture";
                    s.Tier = Tier.Moderate;
                    s.Attribution = 0;
                    s.ClassScore = 45;
                    s.State = StateAxis.Evading | StateAxis.Running;

                    StringBuilder d = new StringBuilder();
                    d.Append("GetWindowDisplayAffinity returned ")
                     .Append(exact ? "WDA_MONITOR" : "an undocumented display affinity")
                     .Append(" (0x")
                     .Append(w.Affinity.ToString("X8", CultureInfo.InvariantCulture))
                     .Append(") for this window. Content set to WDA_MONITOR is shown on the monitor but ")
                     .Append("renders as a solid black box in any capture or screen-share. ")
                     .Append("This is also what a request for WDA_EXCLUDEFROMCAPTURE silently degrades to on ")
                     .Append("Windows builds before ")
                     .Append(Win32Constants.WDA_EXCLUDEFROMCAPTURE_MIN_BUILD.ToString(CultureInfo.InvariantCulture))
                     .Append(", so on an older machine this can be an attempt at full capture exclusion. ")
                     .Append("Legitimate DRM video surfaces also use it. Attribution is 0 by design.");

                    AppendWindowFacts(d, b, invisible);
                    s.Detail = d.ToString();
                    break;
                }

                case KindOverlay:
                {
                    s.Id = "D1.clickthrough_overlay";
                    s.Title = "Invisible click-through overlay window";
                    s.Tier = Tier.Moderate;
                    s.Attribution = 0;
                    s.ClassScore = 40;
                    s.State = StateAxis.Evading;

                    StringBuilder d = new StringBuilder();
                    d.Append("A visible, titleless, non-zero-size top-level window floats above every other ")
                     .Append("window and does not behave like something the user can interact with. ")
                     .Append("Extended styles set: ")
                     .Append(NameExStyles(w.ExStyle))
                     .Append(". WS_EX_TOPMOST keeps it above all other windows; ")
                     .Append("WS_EX_LAYERED allows per-pixel transparency; ")
                     .Append("WS_EX_TRANSPARENT passes mouse clicks straight through to whatever is beneath; ")
                     .Append("WS_EX_NOACTIVATE means it never takes focus; ")
                     .Append("WS_EX_TOOLWINDOW keeps it out of Alt-Tab and the taskbar. ")
                     .Append("That combination is the standard shape of a heads-up overlay. ")
                     .Append("Attribution is 0 by design: IMEs, notification toasts and game overlays share ")
                     .Append("this shape.");

                    AppendWindowFacts(d, b, invisible);
                    s.Detail = d.ToString();
                    break;
                }

                case KindAppCloaked:
                {
                    s.Id = "D2.app_cloaked";
                    s.Title = "Window cloaked by its own application";
                    s.Tier = Tier.Weak;
                    s.Attribution = 0;
                    s.ClassScore = 20;
                    s.State = StateAxis.Evading;

                    StringBuilder d = new StringBuilder();
                    d.Append("DWMWA_CLOAKED reports DWM_CLOAKED_APP (0x")
                     .Append(w.Cloaked.ToString("X", CultureInfo.InvariantCulture))
                     .Append(") with no DWM_CLOAKED_SHELL bit: the application itself asked the desktop ")
                     .Append("compositor to stop rendering this window, rather than the shell suspending it. ")
                     .Append("Shell-cloaked windows - the normal state of every suspended Store app, of which ")
                     .Append("there are routinely twenty or more on an idle desktop - are excluded from this ")
                     .Append("signal entirely. Weak on its own: hidden tray helpers and splash screens do this ")
                     .Append("too. Attribution is 0 by design.");

                    AppendWindowFacts(d, b, invisible);
                    s.Detail = d.ToString();
                    break;
                }

                case KindTitle:
                {
                    VendorSignature? v = b.Vendor;
                    if (v == null) return null;

                    bool primary = v.PrimaryTarget;
                    string vendorName = v.Name.Length > 0 ? v.Name : v.Key;

                    s.Id = "B1.window_title";
                    s.Title = "Window title names " + vendorName;
                    s.Tier = Tier.Moderate;              // never higher - see below
                    s.Attribution = primary ? 50 : 0;
                    s.ClassScore = 45;
                    s.State = StateAxis.Running;
                    s.VendorKey = v.Key;

                    StringBuilder d = new StringBuilder();
                    d.Append("A top-level window title contains \"")
                     .Append(Quote(b.MatchedFragment, invisible))
                     .Append("\", which is a registered window-title signature for ")
                     .Append(vendorName)
                     .Append(". Full title: \"")
                     .Append(Quote(w.Title, invisible))
                     .Append("\". Capped at Moderate on purpose: the vendor ships both a branded and a ")
                     .Append("blank-branding asset set, so the visible identity of its window is a product ")
                     .Append("mode the user can switch off, and a title is trivially editable by anyone. ")
                     .Append(primary
                         ? "Attribution 50: this names the primary target, but a title alone is not proof of it."
                         : "Attribution 0: this names a different product in the same class, not the primary target.");

                    AppendWindowFacts(d, b, invisible);
                    s.Detail = d.ToString();
                    break;
                }

                default:
                    return null;
            }

            return s;
        }

        /// <summary>
        /// Append the literal, hand-checkable facts about the representative window, plus the
        /// dedupe count. Everything here is something a reviewer can verify with Spy++.
        /// </summary>
        private static void AppendWindowFacts(StringBuilder d, Bucket b, HashSet<int> invisible)
        {
            WindowFacts w = b.Representative;
            ProcessInfo? p = b.Owner;

            d.Append("  [window 0x")
             .Append(w.Handle.ToInt64().ToString("X", CultureInfo.InvariantCulture))
             .Append(" class='").Append(Quote(w.ClassName, invisible))
             .Append("' title='").Append(Quote(w.Title, invisible))
             .Append("' visible=").Append(w.Visible ? "yes" : "no")
             .Append(" bounds=").Append(w.Bounds.Left.ToString(CultureInfo.InvariantCulture))
             .Append(',').Append(w.Bounds.Top.ToString(CultureInfo.InvariantCulture))
             .Append(' ').Append(w.Bounds.Width.ToString(CultureInfo.InvariantCulture))
             .Append('x').Append(w.Bounds.Height.ToString(CultureInfo.InvariantCulture))
             .Append(" ex-style=0x").Append(w.ExStyle.ToString("X8", CultureInfo.InvariantCulture));

            string exNames = NameExStyles(w.ExStyle);
            if (exNames.Length > 0) d.Append(" (").Append(exNames).Append(')');

            d.Append(" affinity=").Append(AffinityName(w))
             .Append(" cloak=").Append(CloakName(w));

            d.Append("]  [process pid=").Append(b.Pid.ToString(CultureInfo.InvariantCulture));

            if (p != null)
            {
                d.Append(" name='").Append(Quote(p.Name, invisible)).Append('\'');

                if (p.PathResolved && p.ImagePath.Length > 0)
                    d.Append(" image='").Append(Quote(p.ImagePath, invisible)).Append('\'');
                else
                    d.Append(" image=<unresolved").Append(p.PathFailureReason.Length > 0
                        ? ": " + OneLine(p.PathFailureReason)
                        : "").Append('>');

                if (p.SignerSubject.Length > 0)
                    d.Append(" signer='").Append(Quote(p.SignerSubject, invisible)).Append('\'');
                else if (p.HasEmbeddedSignature)
                    d.Append(" signer=<present but unreadable>");
                else
                    d.Append(" signer=<no embedded Authenticode signature; may still be catalog-signed>");

                if (p.CompanyName.Length > 0)
                    d.Append(" company='").Append(Quote(p.CompanyName, invisible)).Append('\'');
            }
            else
            {
                d.Append(" <owning process could not be described; it may have exited>");
            }

            d.Append(']');

            if (b.Count > 1)
            {
                d.Append("  [").Append(b.Count.ToString(CultureInfo.InvariantCulture))
                 .Append(" top-level windows owned by this process trip this signal; one representative is ")
                 .Append("shown rather than ")
                 .Append(b.Count.ToString(CultureInfo.InvariantCulture))
                 .Append(" near-identical rows]");
            }
        }

        /// <summary>
        /// Decide whether the owning process independently looks like a known vendor. Used ONLY
        /// to raise C1's class score; it never produces attribution here.
        ///
        /// Two independent routes, so the answer does not depend on scanner ordering:
        ///   1. a Strong-or-better identity signal already in the report for the same pid, from
        ///      a DIFFERENT scanner, and
        ///   2. a direct match of the owning process against the signature set.
        ///
        /// Window titles and bare process names are deliberately NOT used - both are free text
        /// the user controls, and B1 already covers titles at a capped tier. Route 1 enforces
        /// that with two filters, and both were earned the hard way: during cross-process bait
        /// testing a throwaway app whose window was merely TITLED "ParakeetAI bait window" had
        /// its hidden window promoted from class 75 to class 90 and stamped with the parakeet
        /// vendor key, because this scanner's own Moderate-tier B1 title signal was sitting in
        /// report.Signals for the same pid. Renaming a window is a two-line change for anyone;
        /// it must never corroborate anything.
        /// </summary>
        private static string IdentifyOwner(
            ProcessInfo? p, SignatureSet signatures, ScanReport report, int pid, out string reason)
        {
            reason = "";

            // Route 1: another scanner already attributed this pid to a vendor on hard evidence.
            try
            {
                foreach (Signal existing in report.Signals)
                {
                    if (existing.Pid != pid) continue;
                    if (existing.VendorKey.Length == 0) continue;
                    if (existing.Attribution <= 0) continue;
                    if (existing.IsSuppressed) continue;

                    // Never corroborate with this scanner's own output: B1 is a window title,
                    // and a window title is free text.
                    if (string.Equals(existing.Source, SourceId, StringComparison.Ordinal)) continue;

                    // Only hard identity counts. Moderate means "suggestive"; promoting a
                    // capture-excluded window on suggestive evidence is how a tool starts
                    // naming the wrong product.
                    if (existing.Tier < Tier.Strong) continue;

                    reason = "signal " + existing.Id + " from the " + existing.Source +
                             " scanner already attributes pid " +
                             pid.ToString(CultureInfo.InvariantCulture) + " to " + existing.VendorKey +
                             " at tier " + existing.Tier;
                    return existing.VendorKey;
                }
            }
            catch (Exception) { /* fall through to route 2 */ }

            // Route 2: match the owning binary ourselves, on keys the user cannot edit.
            if (p == null) return "";

            foreach (VendorSignature v in signatures.Vendors)
            {
                if (v == null) continue;

                if (p.CertThumbprint.Length > 0 && v.CertThumbprints != null)
                {
                    foreach (string t in v.CertThumbprints)
                    {
                        if (string.IsNullOrEmpty(t)) continue;
                        if (string.Equals(NormalizeThumbprint(t), NormalizeThumbprint(p.CertThumbprint),
                                StringComparison.OrdinalIgnoreCase))
                        {
                            reason = "signing-certificate thumbprint " + NormalizeThumbprint(p.CertThumbprint) +
                                     " is a registered " + v.Key + " certificate";
                            return v.Key;
                        }
                    }
                }

                if (p.SignerSubject.Length > 0 && v.SignerContains != null)
                {
                    foreach (string sc in v.SignerContains)
                    {
                        if (string.IsNullOrEmpty(sc)) continue;
                        if (p.SignerSubject.IndexOf(sc, StringComparison.OrdinalIgnoreCase) >= 0)
                        {
                            reason = "Authenticode signer \"" + OneLine(p.SignerSubject) + "\" contains \"" + sc + "\"";
                            return v.Key;
                        }
                    }
                }

                if (p.CompanyName.Length > 0 && v.CompanyNames != null)
                {
                    foreach (string cn in v.CompanyNames)
                    {
                        if (string.IsNullOrEmpty(cn)) continue;
                        if (string.Equals(cn, p.CompanyName, StringComparison.OrdinalIgnoreCase))
                        {
                            reason = "VersionInfo CompanyName is \"" + OneLine(p.CompanyName) + "\"";
                            return v.Key;
                        }
                    }
                }

                if (p.LegalCopyright.Length > 0 && v.CopyrightContains != null)
                {
                    foreach (string cc in v.CopyrightContains)
                    {
                        if (string.IsNullOrEmpty(cc)) continue;
                        if (p.LegalCopyright.IndexOf(cc, StringComparison.OrdinalIgnoreCase) >= 0)
                        {
                            reason = "VersionInfo LegalCopyright \"" + OneLine(p.LegalCopyright) +
                                     "\" contains \"" + cc + "\"";
                            return v.Key;
                        }
                    }
                }

                if (p.PathResolved && p.ImagePath.Length > 0 && v.PathFragments != null)
                {
                    foreach (string pf in v.PathFragments)
                    {
                        if (string.IsNullOrEmpty(pf)) continue;
                        if (p.ImagePath.IndexOf(pf, StringComparison.OrdinalIgnoreCase) >= 0)
                        {
                            reason = "image path contains the registered " + v.Key + " fragment \"" + pf + "\"";
                            return v.Key;
                        }
                    }
                }
            }

            return "";
        }

        // ==================================================================== enumeration

        private static List<IntPtr> EnumerateTopLevelHandles(ScanReport report)
        {
            List<IntPtr> handles = new List<IntPtr>(768);

            try
            {
                // Collect handles ONLY inside the callback. Doing real work there means a managed
                // exception would have to unwind through a native frame, which is undefined
                // behaviour; describing the windows afterwards keeps the callback infallible.
                NativeMethods.EnumWindowsProc callback = delegate (IntPtr hWnd, IntPtr lParam)
                {
                    handles.Add(hWnd);
                    return true;
                };

                bool ok = NativeMethods.EnumWindows(callback, IntPtr.Zero);

                // Read the error immediately: any managed work in between can clobber it.
                int err = ok ? 0 : Marshal.GetLastWin32Error();

                // Keep the delegate rooted until the synchronous native call has returned, so
                // the GC cannot collect the thunk while user32 is still calling into it.
                GC.KeepAlive(callback);

                if (!ok && handles.Count == 0)
                {
                    report.Limitations.Add(
                        "EnumWindows failed (win32 error " + err.ToString(CultureInfo.InvariantCulture) +
                        ") and returned no windows at all; no capture-evasion check could be performed.");
                }
            }
            catch (Exception ex)
            {
                report.Limitations.Add(
                    "Top-level window enumeration failed (" + ex.GetType().Name + "): " + OneLine(ex.Message) +
                    ". No capture-evasion check could be performed.");
            }

            return handles;
        }

        private static WindowFacts Describe(IntPtr hWnd)
        {
            WindowFacts w = new WindowFacts();
            w.Handle = hWnd;

            w.Pid = NativeMethods.GetWindowPid(hWnd);
            w.Title = NativeMethods.GetWindowTitle(hWnd);
            w.ClassName = NativeMethods.GetWindowClassName(hWnd);

            try { w.Visible = NativeMethods.IsWindowVisible(hWnd); }
            catch (Exception) { w.Visible = false; }

            w.Style = NativeMethods.GetWindowLongPtr(hWnd, Win32Constants.GWL_STYLE);
            w.ExStyle = NativeMethods.GetWindowLongPtr(hWnd, Win32Constants.GWL_EXSTYLE);

            try
            {
                RECT r;
                if (NativeMethods.GetWindowRect(hWnd, out r)) w.Bounds = r;
            }
            catch (Exception) { /* leave the default empty rect */ }

            uint affinity;
            int affErr;
            w.AffinityOk = NativeMethods.TryGetWindowDisplayAffinity(hWnd, out affinity, out affErr);
            w.Affinity = affinity;          // already forced to WDA_NONE on failure
            w.AffinityError = affErr;

            int cloaked;
            w.CloakHr = NativeMethods.TryGetCloakedState(hWnd, out cloaked);
            w.Cloaked = cloaked;

            return w;
        }

        private static Dictionary<int, ProcessInfo> CollectProcesses(ScanContext context, ScanReport report)
        {
            Dictionary<int, ProcessInfo> byPid = new Dictionary<int, ProcessInfo>();

            try
            {
                // includeCommandLines: false - a command line tells us nothing about a window,
                // and the WMI round-trip costs ~350 ms. The process scanner owns that query.
                IReadOnlyList<ProcessInfo> all = ProcessInfoCollector.CollectAll(false, context.Cancel);
                for (int i = 0; i < all.Count; i++)
                {
                    ProcessInfo pi = all[i];
                    if (pi == null) continue;
                    byPid[pi.Pid] = pi;
                }
            }
            catch (Exception ex)
            {
                report.Limitations.Add(
                    "Could not enumerate processes while scanning windows (" + ex.GetType().Name + "): " +
                    OneLine(ex.Message) + ". Window findings will name a pid but not the owning program.");
            }

            return byPid;
        }

        // ==================================================================== bucketing

        /// <summary>
        /// One row per (pid, kind, vendor). Forty windows of one process tripping the same test
        /// is one finding about that process, not forty findings - and a report that reads as
        /// forty findings is a report nobody finishes reading.
        /// </summary>
        private static Bucket Record(
            Dictionary<string, Bucket> buckets, string kind, string vendorKey,
            WindowFacts w, ProcessInfo? owner, SignatureSet signatures)
        {
            string key = w.Pid.ToString(CultureInfo.InvariantCulture) + "|" + kind + "|" + vendorKey;

            Bucket? b;
            if (!buckets.TryGetValue(key, out b) || b == null)
            {
                b = new Bucket();
                b.Kind = kind;
                b.Pid = w.Pid;
                b.Owner = owner;
                b.Representative = w;
                b.Count = 1;
                b.Signatures = signatures;
                buckets[key] = b;
                return b;
            }

            b.Count++;
            if (IsBetterRepresentative(w, b.Representative)) b.Representative = w;
            return b;
        }

        /// <summary>
        /// Pick the window a human would recognise: on-screen beats off-screen, bigger beats
        /// smaller, titled beats untitled.
        /// </summary>
        private static bool IsBetterRepresentative(WindowFacts candidate, WindowFacts current)
        {
            if (candidate.Visible != current.Visible) return candidate.Visible;

            long ca = Area(candidate.Bounds);
            long qa = Area(current.Bounds);
            if (ca != qa) return ca > qa;

            return candidate.Title.Length > current.Title.Length;
        }

        private static long Area(RECT r)
        {
            long wd = r.Width;
            long ht = r.Height;
            if (wd <= 0 || ht <= 0) return 0;
            return wd * ht;
        }

        // ==================================================================== rendering helpers

        /// <summary>
        /// Render a string so that characters which paint nothing cannot hide in it.
        ///
        /// The primary target's executable is literally named U+2800 BRAILLE PATTERN BLANK, which
        /// renders as empty space in Task Manager, in Explorer and in any report that prints the
        /// name raw. Note that String.Trim() does NOT remove U+2800 - it is Unicode category So,
        /// not whitespace - so the blankness survives every ordinary sanitisation.
        ///
        /// Plain ASCII space is left alone in a string that has other visible content, because
        /// escaping every space turns "Visual Studio Code" into unreadable noise. In a string
        /// that is ENTIRELY blank, every character is escaped - there is nothing else to show.
        ///
        /// This mirrors the Visible() renderer in ProcessScanner; it is duplicated here rather
        /// than shared so neither scanner can break the other's build.
        /// </summary>
        private static string Visible(string? s, HashSet<int> invisible)
        {
            if (s == null) return "<null>";
            if (s.Length == 0) return "<empty>";

            bool allBlank = IsBlank(s, invisible);

            StringBuilder sb = new StringBuilder(s.Length + 16);
            for (int i = 0; i < s.Length; i++)
            {
                char ch = s[i];
                bool escape;

                if (ch < 0x20 || ch == 0x7F) escape = true;
                else if (ch == ' ') escape = allBlank;
                else escape = invisible.Contains(ch);

                if (escape)
                    sb.Append("<U+").Append(((int)ch).ToString("X4", CultureInfo.InvariantCulture)).Append('>');
                else
                    sb.Append(ch);
            }

            return sb.ToString();
        }

        /// <summary>True when every character paints nothing: empty, whitespace, or an invisible codepoint.</summary>
        private static bool IsBlank(string? s, HashSet<int> invisible)
        {
            if (string.IsNullOrEmpty(s)) return true;

            for (int i = 0; i < s!.Length; i++)
            {
                char ch = s[i];
                if (char.IsWhiteSpace(ch)) continue;
                if (ch < 0x20 || ch == 0x7F) continue;
                if (invisible.Contains(ch)) continue;
                return false;
            }
            return true;
        }

        /// <summary>
        /// Replace every blank-rendering character with a single space and collapse runs, so a
        /// title padded with U+2800 or zero-width joiners still matches a plain signature string.
        /// </summary>
        private static string FlattenInvisible(string s, HashSet<int> invisible)
        {
            if (s.Length == 0) return "";

            StringBuilder sb = new StringBuilder(s.Length);
            bool lastWasSpace = false;

            for (int i = 0; i < s.Length; i++)
            {
                char ch = s[i];
                bool blank = char.IsWhiteSpace(ch) || ch < 0x20 || ch == 0x7F || invisible.Contains(ch);

                if (blank)
                {
                    if (!lastWasSpace && sb.Length > 0) sb.Append(' ');
                    lastWasSpace = true;
                }
                else
                {
                    sb.Append(ch);
                    lastWasSpace = false;
                }
            }

            return sb.ToString().Trim();
        }

        /// <summary>Visible() plus a length cap, for anything embedded in a quoted Detail string.</summary>
        private static string Quote(string? s, HashSet<int> invisible)
        {
            string rendered = Visible(s, invisible);
            if (rendered.Length <= MaxQuotedLength) return rendered;
            return rendered.Substring(0, MaxQuotedLength) + "...";
        }

        private static string NameExStyles(long ex)
        {
            StringBuilder sb = new StringBuilder();
            AppendFlag(sb, ex, Win32Constants.WS_EX_TOPMOST, "WS_EX_TOPMOST");
            AppendFlag(sb, ex, Win32Constants.WS_EX_LAYERED, "WS_EX_LAYERED");
            AppendFlag(sb, ex, Win32Constants.WS_EX_TRANSPARENT, "WS_EX_TRANSPARENT");
            AppendFlag(sb, ex, Win32Constants.WS_EX_NOACTIVATE, "WS_EX_NOACTIVATE");
            AppendFlag(sb, ex, Win32Constants.WS_EX_TOOLWINDOW, "WS_EX_TOOLWINDOW");
            AppendFlag(sb, ex, Win32Constants.WS_EX_APPWINDOW, "WS_EX_APPWINDOW");
            AppendFlag(sb, ex, Win32Constants.WS_EX_NOREDIRECTIONBITMAP, "WS_EX_NOREDIRECTIONBITMAP");
            AppendFlag(sb, ex, Win32Constants.WS_EX_COMPOSITED, "WS_EX_COMPOSITED");
            return sb.ToString();
        }

        private static void AppendFlag(StringBuilder sb, long value, long bit, string name)
        {
            if ((value & bit) == 0) return;
            if (sb.Length > 0) sb.Append('|');
            sb.Append(name);
        }

        private static string AffinityName(WindowFacts w)
        {
            if (!w.AffinityOk)
            {
                return "<unknown: query failed, win32 error " +
                       w.AffinityError.ToString(CultureInfo.InvariantCulture) + ">";
            }

            if (w.Affinity == Win32Constants.WDA_NONE) return "WDA_NONE";
            if (w.Affinity == Win32Constants.WDA_MONITOR) return "WDA_MONITOR";
            if (w.Affinity == Win32Constants.WDA_EXCLUDEFROMCAPTURE) return "WDA_EXCLUDEFROMCAPTURE";

            return "0x" + w.Affinity.ToString("X8", CultureInfo.InvariantCulture);
        }

        private static string CloakName(WindowFacts w)
        {
            if (w.CloakHr != Win32Constants.S_OK)
            {
                return w.CloakHr == Win32Constants.E_INVALIDARG
                    ? "<attribute unsupported by this window>"
                    : "<unreadable, hr=0x" + w.CloakHr.ToString("X8", CultureInfo.InvariantCulture) + ">";
            }

            if (w.Cloaked == 0) return "not cloaked";

            StringBuilder sb = new StringBuilder();
            if ((w.Cloaked & Win32Constants.DWM_CLOAKED_APP) != 0) AppendPiece(sb, "DWM_CLOAKED_APP");
            if ((w.Cloaked & Win32Constants.DWM_CLOAKED_SHELL) != 0) AppendPiece(sb, "DWM_CLOAKED_SHELL");
            if ((w.Cloaked & Win32Constants.DWM_CLOAKED_INHERITED) != 0) AppendPiece(sb, "DWM_CLOAKED_INHERITED");
            if (sb.Length == 0) sb.Append("0x").Append(w.Cloaked.ToString("X", CultureInfo.InvariantCulture));
            return sb.ToString();
        }

        private static void AppendPiece(StringBuilder sb, string s)
        {
            if (sb.Length > 0) sb.Append('|');
            sb.Append(s);
        }

        private static string FormatErrorCounts(Dictionary<int, int> codes)
        {
            StringBuilder sb = new StringBuilder();
            foreach (KeyValuePair<int, int> kv in codes)
            {
                if (sb.Length > 0) sb.Append(", ");
                sb.Append(kv.Value.ToString(CultureInfo.InvariantCulture))
                  .Append(" x win32 error ")
                  .Append(kv.Key.ToString(CultureInfo.InvariantCulture));
            }
            return sb.ToString();
        }

        private static string OneLine(string? s)
        {
            if (string.IsNullOrEmpty(s)) return "";
            return s!.Replace('\r', ' ').Replace('\n', ' ').Trim();
        }

        private static string NormalizeThumbprint(string t)
        {
            StringBuilder sb = new StringBuilder(t.Length);
            for (int i = 0; i < t.Length; i++)
            {
                char c = t[i];
                if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))
                    sb.Append(char.ToUpperInvariant(c));
            }
            return sb.ToString();
        }

        /// <summary>
        /// Codepoints that paint nothing, from the signature file. The hard-coded fallback is
        /// deliberately minimal - it exists only so a missing or truncated signature file cannot
        /// silently disable blank-name rendering.
        /// </summary>
        private static HashSet<int> BuildInvisibleSet(SignatureSet signatures)
        {
            HashSet<int> set = new HashSet<int>();

            try
            {
                if (signatures.InvisibleCodepoints != null)
                {
                    foreach (int cp in signatures.InvisibleCodepoints)
                        if (cp > 0 && cp <= 0xFFFF) set.Add(cp);
                }
            }
            catch (Exception) { /* fall through to the defaults */ }

            // U+2800 BRAILLE PATTERN BLANK is the one the primary target actually ships.
            set.Add(0x2800);
            set.Add(0x200B);   // ZERO WIDTH SPACE
            set.Add(0x200C);   // ZERO WIDTH NON-JOINER
            set.Add(0x200D);   // ZERO WIDTH JOINER
            set.Add(0xFEFF);   // ZERO WIDTH NO-BREAK SPACE
            set.Add(0x00A0);   // NO-BREAK SPACE
            set.Add(0x3164);   // HANGUL FILLER
            set.Add(0x2000);   // EN QUAD
            set.Add(0x3000);   // IDEOGRAPHIC SPACE

            return set;
        }

        private static int SafeOsBuild()
        {
            try { return NativeMethods.GetOsBuildNumber(); }
            catch (Exception) { return 0; }
        }

        private static int SafeCurrentProcessId()
        {
            try
            {
                using (Process p = Process.GetCurrentProcess()) return p.Id;
            }
            catch (Exception) { return 0; }
        }

        // ==================================================================== data

        /// <summary>Everything observed about one top-level window, in one pass.</summary>
        private sealed class WindowFacts
        {
            public IntPtr Handle;
            public int Pid;
            public string Title = "";
            public string ClassName = "";
            public bool Visible;
            public long Style;
            public long ExStyle;
            public RECT Bounds;

            /// <summary>False means UNKNOWN, never "not hidden". <see cref="Affinity"/> is only meaningful when true.</summary>
            public bool AffinityOk;
            public uint Affinity;
            public int AffinityError;

            /// <summary><see cref="Cloaked"/> is only meaningful when this is S_OK.</summary>
            public int CloakHr;
            public int Cloaked;
        }

        /// <summary>One emitted row: a (pid, kind, vendor) group with a representative window.</summary>
        private sealed class Bucket
        {
            public string Kind = "";
            public int Pid;
            public ProcessInfo? Owner;
            public WindowFacts Representative = new WindowFacts();
            public int Count;

            public VendorSignature? Vendor;
            public string MatchedFragment = "";

            /// <summary>Set by the emitter so C1 can cross-check the owner against vendor identities.</summary>
            public SignatureSet Signatures = new SignatureSet();
        }
    }
}

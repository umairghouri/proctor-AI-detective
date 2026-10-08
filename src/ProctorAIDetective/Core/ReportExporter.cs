using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;

namespace ProctorAIDetective.Core
{
    /// <summary>
    /// Turns a <see cref="ScanReport"/> into the two artefacts a reviewer actually keeps: a
    /// machine-readable JSON file and a human-readable text file.
    ///
    /// The export is deliberately exhaustive. A tool that makes claims about people has to be
    /// arguable, and you cannot argue with a verdict whose inputs you cannot see. In particular
    /// SUPPRESSED signals are exported in full, with the allowlist outcome, the reason and the
    /// multiplier that zeroed them: an allowlist that silently deletes evidence is an invisible
    /// policy, and an invisible policy cannot be challenged by the person it is applied to.
    ///
    /// Everything is written through <see cref="MiniJson"/>, which escapes every non-ASCII
    /// codepoint. That matters more here than anywhere else in the app: the single most
    /// important datum this tool produces is "the executable is named U+2800", and an export
    /// that carried that as three invisible UTF-8 bytes would lose the evidence the moment it
    /// was pasted into a ticket, an email or an HR file. In JSON it leaves as the literal six
    /// characters ⠀; in the text report it leaves as the literal token &lt;U+2800&gt;.
    /// </summary>
    public static class ReportExporter
    {
        /// <summary>Schema tag, so a future reader can tell which layout it is looking at.</summary>
        public const string FormatVersion = "proctor-ai-detective-report-1";

        /// <summary>
        /// Shown always, at the top of the window and at the top of every export. Never behind a
        /// link, never in fine print: the limits of the evidence travel with the evidence.
        /// </summary>
        public const string Disclaimer =
            "This tool inspects one Windows user session on one device at one moment. It cannot " +
            "see a second laptop, a phone or tablet, a virtual machine, another user account, or " +
            "a person off camera. A clean result is NOT evidence that no assistance was used. A " +
            "detection is evidence that specific software is present or running - not a finding " +
            "of misconduct. Review the evidence yourself before drawing any conclusion, and " +
            "never let this report act automatically on anyone.";

        /// <summary>Printed verbatim wherever a SUSPICIOUS verdict is shown.</summary>
        public const string SuspiciousNote =
            "This is a prompt to ask a question, not a finding of misconduct.";

        /// <summary>Printed whenever any finding came from the behavioural (window/overlay) scanner.</summary>
        public const string BehaviouralCaveat =
            "Hidden windows and overlays are used by a great deal of legitimate software - " +
            "password managers, conferencing tools, screen recorders and GPU overlays all do it. " +
            "Those findings say a tool of this kind is present, not which tool it is.";

        private const string QRunningAttribution = "Is Parakeet AI running on this machine right now?";
        private const string QRunningClass = "Is a capture-evading AI assistant running right now?";
        private const string QInstalledAttribution = "Is Parakeet AI installed on this machine?";
        private const string QEvadingClass = "Is anything hiding itself from screen capture?";

        // ================================================================== JSON

        /// <summary>
        /// Full JSON export. Never throws: a report that cannot be serialised still yields a
        /// valid JSON object carrying the failure, because an export that silently produced
        /// nothing would be worse than one that says it broke.
        /// </summary>
        public static string ToJson(ScanReport report)
        {
            try
            {
                return MiniJson.Write(BuildJson(report), true);
            }
            catch (Exception ex)
            {
                try
                {
                    return MiniJson.Write(MiniJson.Obj()
                        .Add("format", FormatVersion)
                        .Add("error", "This report could not be serialised: "
                                      + ex.GetType().Name + ": " + ex.Message)
                        .Add("warning", "The scan itself may have succeeded. Do not read this "
                                      + "file as a clean result."), true);
                }
                catch (Exception)
                {
                    return "{\"format\":\"" + FormatVersion + "\",\"error\":\"report serialisation failed\"}";
                }
            }
        }

        private static JsonObjectBuilder BuildJson(ScanReport? report)
        {
            var root = MiniJson.Obj();
            root.Add("format", FormatVersion);
            root.Add("disclaimer", Disclaimer);

            if (report == null)
            {
                root.Add("error", "No scan report was produced.");
                return root;
            }

            root.Add("tool", MiniJson.Obj()
                .Add("name", "Proctor AI Detective")
                .Add("appVersion", report.AppVersion)
                .Add("signatureVersion", report.SignatureVersion));

            long durationMs = 0;
            try
            {
                if (report.FinishedUtc > report.StartedUtc)
                    durationMs = (long)(report.FinishedUtc - report.StartedUtc).TotalMilliseconds;
            }
            catch (Exception) { durationMs = 0; }

            root.Add("scan", MiniJson.Obj()
                .Add("startedUtc", report.StartedUtc)
                .Add("finishedUtc", report.FinishedUtc)
                .Add("durationMs", durationMs)
                .Add("machineName", report.MachineName)
                .Add("userName", report.UserName)
                .Add("osVersion", report.OsVersion)
                .Add("elevated", report.Elevated));

            root.Add("verdicts", MiniJson.Obj()
                .Add("runningAttribution", AxisJson(QRunningAttribution, report.RunningAttribution))
                .Add("runningClass", AxisJson(QRunningClass, report.RunningClass))
                .Add("installedAttribution", AxisJson(QInstalledAttribution, report.InstalledAttribution))
                .Add("evadingClass", AxisJson(QEvadingClass, report.EvadingClass)));

            int suppressed = 0;
            int downRanked = 0;
            int masquerade = 0;
            var signals = new List<JsonObjectBuilder>();
            foreach (Signal s in report.Signals)
            {
                if (s == null) continue;
                if (s.Allowlist == AllowlistOutcome.Suppressed) suppressed++;
                else if (s.Allowlist == AllowlistOutcome.DownRanked) downRanked++;
                else if (s.Allowlist == AllowlistOutcome.Masquerade) masquerade++;
                signals.Add(SignalJson(s));
            }

            root.Add("counts", MiniJson.Obj()
                .Add("signals", signals.Count)
                .Add("signalsSuppressedByAllowlist", suppressed)
                .Add("signalsDownRankedByAllowlist", downRanked)
                .Add("signalsEscalatedAsMasquerade", masquerade)
                .Add("windowsScanned", report.WindowsScanned)
                .Add("windowsDisplayAffinityQueryFailed", report.WindowsQueryFailed)
                .Add("processesScanned", report.ProcessesScanned)
                .Add("processPathsUnresolved", report.ProcessPathsUnresolved));

            // Exported in full, suppressed rows included. See the class remarks.
            root.Add("signals", signals);

            var assistantList = new List<JsonObjectBuilder>();
            foreach (AssistantPresence a in Assistants(report))
            {
                assistantList.Add(MiniJson.Obj()
                    .Add("vendorKey", a.VendorKey)
                    .Add("name", a.Name)
                    .Add("how", a.How)
                    .Add("running", a.Running)
                    .Add("installed", a.Installed)
                    .Add("inBrowser", a.InBrowser)
                    .Add("pid", a.Pid)
                    .Add("signals", a.SignalCount));
            }
            root.Add("generalAssistants", MiniJson.Obj()
                .Add("note", "Mainstream AI assistants. By category policy these score 0 on every "
                           + "axis and have not influenced any verdict. Reported as an observation "
                           + "only; presence is not evidence of misconduct.")
                .Add("seen", assistantList));

            root.Add("limitations", new List<string>(report.Limitations));
            root.Add("timings", TimingsJson(report.Timings));

            root.Add("notes", MiniJson.Obj()
                .Add("suppressedSignalsAreIncluded",
                     "Signals with allowlist = Suppressed scored zero and did not contribute to any "
                     + "verdict. They are exported so the allowlist can be audited and challenged.")
                .Add("behavioural", BehaviouralCaveat)
                .Add("suspicious", SuspiciousNote));

            return root;
        }

        private static JsonObjectBuilder AxisJson(string question, AxisResult? axis)
        {
            AxisResult a = axis ?? new AxisResult();
            return MiniJson.Obj()
                .Add("question", question)
                .Add("score", a.Score)
                .Add("verdict", VerdictWord(a.Verdict))
                .Add("rationale", a.Rationale);
        }

        private static JsonObjectBuilder SignalJson(Signal s)
        {
            return MiniJson.Obj()
                .Add("id", s.Id)
                .Add("title", s.Title)
                .Add("detail", s.Detail)
                .Add("tier", TierWord(s.Tier))
                .Add("state", StateList(s.State))
                .Add("source", s.Source)
                .Add("vendorKey", s.VendorKey)
                .Add("category", s.Category)
                .Add("subject", s.Subject)
                .Add("subjectPath", s.SubjectPath)
                .Add("signer", s.Signer)
                .Add("pid", s.Pid)
                .Add("attribution", s.Attribution)
                .Add("classScore", s.ClassScore)
                .Add("allowlist", AllowlistWord(s.Allowlist))
                .Add("allowlistReason", s.AllowlistReason)
                .Add("multiplier", s.Multiplier)
                .Add("effectiveAttribution", s.EffectiveAttribution)
                .Add("effectiveClass", s.EffectiveClass)
                .Add("suppressed", s.IsSuppressed);
        }

        private static JsonObjectBuilder TimingsJson(Dictionary<string, long>? timings)
        {
            var b = MiniJson.Obj();
            if (timings == null) return b;

            // Sorted so two exports of the same scan diff cleanly; Dictionary order is not stable.
            var keys = new List<string>(timings.Keys);
            keys.Sort(StringComparer.OrdinalIgnoreCase);
            foreach (string k in keys) b.Add(k, timings[k]);
            return b;
        }

        // ================================================================== text

        private const int TextWidth = 92;

        /// <summary>
        /// Human-readable export. Same content as the JSON, laid out to be pasted into a ticket
        /// or printed. Never throws.
        /// </summary>
        public static string ToText(ScanReport report)
        {
            try
            {
                return BuildText(report);
            }
            catch (Exception ex)
            {
                return "Proctor AI Detective report" + Environment.NewLine
                     + "This report could not be formatted: " + ex.GetType().Name + ": " + ex.Message
                     + Environment.NewLine
                     + "The scan itself may have succeeded. Do not read this file as a clean result."
                     + Environment.NewLine;
            }
        }

        private static string BuildText(ScanReport? report)
        {
            var sb = new StringBuilder(8192);
            string nl = Environment.NewLine;

            Rule(sb, '=');
            sb.Append("PROCTOR AI DETECTIVE - SCAN REPORT").Append(nl);
            Rule(sb, '=');
            sb.Append(nl);

            Wrap(sb, Disclaimer, TextWidth, "");
            sb.Append(nl);

            if (report == null)
            {
                sb.Append("No scan report was produced.").Append(nl);
                return sb.ToString();
            }

            // ---- header
            Rule(sb, '-');
            sb.Append("SCAN").Append(nl);
            Rule(sb, '-');
            Field(sb, "Started (UTC)", Iso(report.StartedUtc));
            Field(sb, "Finished (UTC)", Iso(report.FinishedUtc));
            Field(sb, "Duration", DurationText(report));
            Field(sb, "Machine", Visible(report.MachineName));
            Field(sb, "User", Visible(report.UserName));
            Field(sb, "Operating system", Visible(report.OsVersion));
            Field(sb, "Elevated", report.Elevated
                ? "yes (administrator)"
                : "no (standard rights - process attribution is less complete; the capture-evasion check is unaffected)");
            Field(sb, "App version", Visible(report.AppVersion));
            Field(sb, "Signature set", Visible(report.SignatureVersion));
            sb.Append(nl);

            // ---- the three sentences
            Rule(sb, '-');
            sb.Append("VERDICT").Append(nl);
            Rule(sb, '-');
            bool anySuspicious = false;
            anySuspicious |= AxisText(sb, "Running now", report.RunningAttribution);
            anySuspicious |= AxisText(sb, "Installed", report.InstalledAttribution);
            anySuspicious |= AxisText(sb, "Hiding from screen capture", report.EvadingClass);
            sb.Append(nl);
            AxisText(sb, "Any tool of this class running", report.RunningClass);
            sb.Append(nl);

            string situation = SituationLine(report);
            if (situation.Length > 0)
            {
                Wrap(sb, situation, TextWidth, "");
                sb.Append(nl);
            }

            string assistants = AssistantsLine(report);
            if (assistants.Length > 0)
            {
                Wrap(sb, assistants, TextWidth, "");
                sb.Append(nl);
            }

            if (anySuspicious || IsSuspicious(report.RunningClass))
            {
                Wrap(sb, SuspiciousNote, TextWidth, "");
                sb.Append(nl);
            }

            if (HasBehaviouralSignal(report))
            {
                Wrap(sb, BehaviouralCaveat, TextWidth, "");
                sb.Append(nl);
            }

            // ---- evidence
            Rule(sb, '-');
            sb.Append("EVIDENCE (").Append(report.Signals.Count.ToString(CultureInfo.InvariantCulture))
              .Append(report.Signals.Count == 1 ? " signal" : " signals").Append(")").Append(nl);
            Rule(sb, '-');

            if (report.Signals.Count == 0)
            {
                Wrap(sb, "No signals were produced. That is not the same as a clean machine: read "
                       + "the limitations below for what this scan could not see.", TextWidth, "");
                sb.Append(nl);
            }
            else
            {
                int n = 0;
                foreach (Signal s in report.Signals)
                {
                    if (s == null) continue;
                    n++;
                    SignalText(sb, n, s);
                }
            }

            // ---- blind spots
            Rule(sb, '-');
            sb.Append("WHAT THIS SCAN COULD NOT SEE").Append(nl);
            Rule(sb, '-');
            Field(sb, "Top-level windows scanned", Num(report.WindowsScanned));
            Field(sb, "Capture-affinity queries failed", Num(report.WindowsQueryFailed)
                  + (report.WindowsQueryFailed > 0
                     ? "  (recorded as UNKNOWN, not as \"not hidden\")"
                     : ""));
            Field(sb, "Processes scanned", Num(report.ProcessesScanned));
            Field(sb, "Process paths unresolved", Num(report.ProcessPathsUnresolved));
            sb.Append(nl);

            if (report.Limitations.Count == 0)
            {
                sb.Append("No limitations were recorded for this scan.").Append(nl);
            }
            else
            {
                foreach (string l in report.Limitations)
                {
                    sb.Append("  - ");
                    Wrap(sb, l ?? "", TextWidth - 4, "    ");
                }
            }
            sb.Append(nl);

            // ---- timings
            if (report.Timings.Count > 0)
            {
                Rule(sb, '-');
                sb.Append("TIMINGS (milliseconds)").Append(nl);
                Rule(sb, '-');
                var keys = new List<string>(report.Timings.Keys);
                keys.Sort(StringComparer.OrdinalIgnoreCase);
                foreach (string k in keys) Field(sb, k, Num64(report.Timings[k]));
                sb.Append(nl);
            }

            Rule(sb, '=');
            Wrap(sb, "End of report. The JSON export of this same scan carries every field above "
                   + "in machine-readable form, including signals the allowlist suppressed.",
                 TextWidth, "");

            return sb.ToString();
        }

        private static void SignalText(StringBuilder sb, int index, Signal s)
        {
            string nl = Environment.NewLine;

            sb.Append(nl);
            sb.Append('[').Append(index.ToString(CultureInfo.InvariantCulture)).Append("] ")
              .Append(Visible(s.Title));
            if (s.IsSuppressed) sb.Append("   *** SUPPRESSED BY ALLOWLIST - scored zero ***");
            sb.Append(nl);

            Field(sb, "  Signal id", Visible(s.Id));
            Field(sb, "  Confidence", TierWord(s.Tier));
            Field(sb, "  Proves", StateWords(s.State));
            Field(sb, "  Found by", Visible(s.Source) + " scanner");
            if (s.VendorKey.Length > 0) Field(sb, "  Attributed to", Visible(s.VendorKey));
            if (s.Subject.Length > 0) Field(sb, "  Subject", Visible(s.Subject));
            if (s.Pid > 0) Field(sb, "  Process id", Num(s.Pid));
            if (s.SubjectPath.Length > 0) Field(sb, "  Image path", Visible(s.SubjectPath));
            if (s.Signer.Length > 0) Field(sb, "  Signed by", Visible(s.Signer));

            Field(sb, "  Score", "attribution " + Num(s.Attribution)
                               + ", class " + Num(s.ClassScore)
                               + "  ->  effective attribution " + Num(s.EffectiveAttribution)
                               + ", effective class " + Num(s.EffectiveClass));
            Field(sb, "  Allowlist", AllowlistWord(s.Allowlist)
                                   + " (x" + s.Multiplier.ToString("0.00", CultureInfo.InvariantCulture) + ")"
                                   + (s.AllowlistReason.Length > 0 ? ": " + Visible(s.AllowlistReason) : ""));

            sb.Append("  Observed:").Append(nl);
            Wrap(sb, Visible(s.Detail), TextWidth - 4, "    ");
        }

        /// <summary>Returns true when this axis landed on SUSPICIOUS.</summary>
        private static bool AxisText(StringBuilder sb, string caption, AxisResult? axis)
        {
            AxisResult a = axis ?? new AxisResult();
            string nl = Environment.NewLine;

            sb.Append("  ").Append(Pad(caption + ":", 32))
              .Append(VerdictWord(a.Verdict).ToUpperInvariant())
              .Append("   (score ").Append(Num(a.Score)).Append("/100)").Append(nl);

            if (!string.IsNullOrEmpty(a.Rationale))
                Wrap(sb, a.Rationale, TextWidth - 6, "      ");

            return a.Verdict == Verdict.Suspicious;
        }

        // ================================================================== shared helpers

        /// <summary>
        /// Everything the scan saw from the general-assistant category, grouped by product and
        /// ordered running-first. Returns an empty list when nothing was seen.
        ///
        /// These carry no score and move no verdict (see <see cref="CategoryPolicy"/>). They are
        /// surfaced on their own line because "ChatGPT is open" is a legitimate thing for someone
        /// invigilating a closed-book assessment to want to know, and burying it in a table of
        /// zero-weight rows would hide it. Equally, it must never be read as a detection, so the
        /// wording stays flatly descriptive.
        /// </summary>
        public static List<AssistantPresence> Assistants(ScanReport? report)
        {
            var found = new List<AssistantPresence>();
            if (report == null) return found;

            var byVendor = new Dictionary<string, AssistantPresence>(StringComparer.OrdinalIgnoreCase);

            foreach (Signal s in report.Signals)
            {
                if (!CategoryPolicy.IsGeneralAssistant(s)) continue;
                if (s.VendorKey.Length == 0) continue;

                AssistantPresence? a;
                if (!byVendor.TryGetValue(s.VendorKey, out a))
                {
                    a = new AssistantPresence();
                    a.VendorKey = s.VendorKey;
                    a.Name = s.VendorName.Length > 0 ? s.VendorName : s.VendorKey;
                    byVendor[s.VendorKey] = a;
                    found.Add(a);
                }

                if ((s.State & StateAxis.Running) != 0) a.Running = true;
                if ((s.State & StateAxis.Installed) != 0) a.Installed = true;

                if (s.Source == "browser") a.InBrowser = true;
                if (s.Source == "network" && s.Id.StartsWith("F1.", StringComparison.Ordinal)) a.DnsOnly = true;
                if (s.Pid != 0 && a.Pid == 0) a.Pid = s.Pid;

                a.SignalCount++;
            }

            found.Sort(delegate (AssistantPresence x, AssistantPresence y)
            {
                if (x.Running != y.Running) return x.Running ? -1 : 1;
                return string.Compare(x.Name, y.Name, StringComparison.OrdinalIgnoreCase);
            });

            return found;
        }

        /// <summary>One mainstream AI assistant the scan noticed. Carries no score by design.</summary>
        public sealed class AssistantPresence
        {
            public string VendorKey = "";
            public string Name = "";
            public bool Running;
            public bool Installed;
            public bool InBrowser;
            public bool DnsOnly;
            public int Pid;
            public int SignalCount;

            /// <summary>How this one was seen, in plain words.</summary>
            public string How
            {
                get
                {
                    if (Running && InBrowser) return "running, and open in a browser";
                    if (Running) return "running";
                    if (InBrowser) return "open in a browser";
                    if (Installed) return "installed, not running";
                    if (DnsOnly) return "name resolved recently, no process seen";
                    return "seen";
                }
            }
        }

        /// <summary>
        /// The assistants line as one sentence, or "" when nothing was seen. Deliberately states
        /// the limit of the claim in the same breath as the observation.
        /// </summary>
        public static string AssistantsLine(ScanReport? report)
        {
            List<AssistantPresence> a = Assistants(report);
            if (a.Count == 0) return "";

            var sb = new StringBuilder();
            sb.Append("General AI assistants seen: ");
            for (int i = 0; i < a.Count; i++)
            {
                if (i > 0) sb.Append(i == a.Count - 1 ? " and " : ", ");
                sb.Append(a[i].Name).Append(" (").Append(a[i].How).Append(")");
            }
            sb.Append(". These are ordinary productivity tools that do not hide from screen ")
              .Append("capture, so they score nothing and have not affected any verdict above. ")
              .Append("Listed only because an invigilator running a closed-book assessment may ")
              .Append("want to know; their presence is not evidence of misconduct.");
            return sb.ToString();
        }

        /// <summary>
        /// The one-sentence plain-English situation, when the axes combine into something a
        /// reader would otherwise have to assemble themselves. The important case is the real
        /// one on a machine like the development box: installed and auto-starting, but not
        /// running - which must read as a fact, not as an accusation.
        /// </summary>
        public static string SituationLine(ScanReport? report)
        {
            if (report == null) return "";

            Verdict running = VerdictOf(report.RunningAttribution);
            Verdict installed = VerdictOf(report.InstalledAttribution);
            Verdict evading = VerdictOf(report.EvadingClass);
            Verdict runClass = VerdictOf(report.RunningClass);

            if (installed == Verdict.Detected && running == Verdict.Clear)
            {
                return "In plain terms: Parakeet AI is installed on this machine, but nothing "
                     + "found suggests it was running when this scan ran. Installed software is "
                     + "not evidence of use.";
            }
            if (running == Verdict.Detected)
            {
                return "In plain terms: Parakeet AI appears to be running on this machine right "
                     + "now. That is a statement about software, not about a person.";
            }
            if (running == Verdict.Clear && installed == Verdict.Clear
                && evading == Verdict.Clear && runClass == Verdict.Clear)
            {
                return "In plain terms: this scan found nothing. Read that as \"this one session "
                     + "on this one device showed nothing at this one moment\", not as proof that "
                     + "no assistance was used.";
            }
            if (evading != Verdict.Clear && running == Verdict.Clear)
            {
                return "In plain terms: something on this machine is hiding itself from screen "
                     + "capture, but nothing ties it to Parakeet AI specifically. A great deal of "
                     + "ordinary software does this.";
            }
            return "";
        }

        /// <summary>True when any signal came from the behavioural (window and overlay) scanner.</summary>
        public static bool HasBehaviouralSignal(ScanReport? report)
        {
            if (report == null) return false;
            foreach (Signal s in report.Signals)
            {
                if (s == null) continue;
                if (string.Equals(s.Source, "window", StringComparison.OrdinalIgnoreCase)) return true;
            }
            return false;
        }

        public static bool IsSuspicious(AxisResult? a)
        {
            return a != null && a.Verdict == Verdict.Suspicious;
        }

        /// <summary>Verdict of an axis, treating a missing axis as Clear rather than throwing.</summary>
        public static Verdict VerdictOf(AxisResult? a)
        {
            return a == null ? Verdict.Clear : a.Verdict;
        }

        /// <summary>Score of an axis, treating a missing axis as 0.</summary>
        public static int ScoreOf(AxisResult? a)
        {
            return a == null ? 0 : a.Score;
        }

        public static string VerdictWord(Verdict v)
        {
            switch (v)
            {
                case Verdict.Detected: return "Detected";
                case Verdict.Suspicious: return "Suspicious";
                default: return "Clear";
            }
        }

        public static string TierWord(Tier t)
        {
            switch (t)
            {
                case Tier.Definitive: return "Definitive";
                case Tier.Strong: return "Strong";
                case Tier.Moderate: return "Moderate";
                default: return "Weak";
            }
        }

        public static string AllowlistWord(AllowlistOutcome o)
        {
            switch (o)
            {
                case AllowlistOutcome.Suppressed: return "Suppressed";
                case AllowlistOutcome.DownRanked: return "Down-ranked";
                case AllowlistOutcome.Masquerade: return "Masquerade";
                default: return "Not listed";
            }
        }

        /// <summary>Flags enum rendered as a reader-facing phrase rather than "Installed, Running".</summary>
        public static string StateWords(StateAxis state)
        {
            List<string> parts = StateList(state);
            if (parts.Count == 0) return "nothing on its own (context only)";
            return string.Join(", ", parts.ToArray());
        }

        public static List<string> StateList(StateAxis state)
        {
            var parts = new List<string>(3);
            if ((state & StateAxis.Installed) != 0) parts.Add("Installed");
            if ((state & StateAxis.Running) != 0) parts.Add("Running");
            if ((state & StateAxis.Evading) != 0) parts.Add("Evading");
            return parts;
        }

        // ---------------------------------------------------------------- invisible text

        /// <summary>
        /// Renders text so that nothing in it can be invisible on screen or in an export.
        ///
        /// This exists because the primary target's executable is literally named U+2800 BRAILLE
        /// PATTERN BLANK. Printing that raw into a grid cell would show an empty cell, and the
        /// person reading the report would conclude the field was missing rather than that the
        /// filename is the evidence. Blank-rendering codepoints become the literal token
        /// &lt;U+2800&gt;.
        ///
        /// The blank list is compiled in on purpose and is NOT read from signatures.json.
        /// Detection reads the file, so a new evasion codepoint needs no rebuild; DISPLAY must
        /// not, because a rendering helper that can start printing nothing because someone
        /// edited a data file is a rendering helper that will one day hide the evidence.
        ///
        /// CR, LF and TAB are passed through: multi-line Detail text is legitimate.
        /// An ordinary space is passed through too, unless the WHOLE string is blanks - in which
        /// case spaces are escaped as well, so a name made of spaces still shows something.
        /// </summary>
        public static string Visible(string? text)
        {
            if (string.IsNullOrEmpty(text)) return "";
            string s = text!;

            bool allBlank = true;
            for (int i = 0; i < s.Length; i++)
            {
                char c = s[i];
                if (c == '\r' || c == '\n' || c == '\t') continue;
                if (c == ' ' || IsBlankGlyph(c)) continue;
                allBlank = false;
                break;
            }

            bool needsWork = allBlank;
            if (!needsWork)
            {
                for (int i = 0; i < s.Length; i++)
                {
                    if (IsBlankGlyph(s[i])) { needsWork = true; break; }
                }
            }
            if (!needsWork) return s;

            var sb = new StringBuilder(s.Length + 16);
            for (int i = 0; i < s.Length; i++)
            {
                char c = s[i];
                if (c == '\r' || c == '\n' || c == '\t') { sb.Append(c); continue; }
                if (IsBlankGlyph(c) || (allBlank && c == ' '))
                {
                    sb.Append("<U+")
                      .Append(((int)c).ToString("X4", CultureInfo.InvariantCulture))
                      .Append('>');
                    continue;
                }
                sb.Append(c);
            }
            return sb.ToString();
        }

        /// <summary>
        /// True for codepoints that render as nothing (or as a blank cell) in a normal UI font.
        /// Space, CR, LF and TAB are handled by the caller and are deliberately excluded here.
        /// </summary>
        private static bool IsBlankGlyph(char c)
        {
            if (c == '\r' || c == '\n' || c == '\t') return false;
            if (char.IsControl(c)) return true;

            if (c == '\u00A0') return true;                       // no-break space
            if (c == '\u00AD') return true;                       // soft hyphen
            if (c == '\u034F') return true;                       // combining grapheme joiner
            if (c == '\u061C') return true;                       // arabic letter mark
            if (c == '\u115F' || c == '\u1160') return true;      // hangul filler
            if (c == '\u17B4' || c == '\u17B5') return true;      // khmer inherent vowels
            if (c >= '\u180B' && c <= '\u180E') return true;      // mongolian selectors / vowel separator
            if (c >= '\u2000' && c <= '\u200F') return true;      // spaces, ZWSP/ZWNJ/ZWJ, bidi marks
            if (c >= '\u2028' && c <= '\u202F') return true;      // separators, bidi embedding, NNBSP
            if (c >= '\u205F' && c <= '\u206F') return true;      // MMSP, word joiner, invisible operators
            if (c == '\u2800') return true;                       // BRAILLE PATTERN BLANK - the one that matters
            if (c == '\u3000' || c == '\u3164') return true;      // ideographic space, hangul filler
            if (c == '\uFEFF') return true;                       // zero width no-break space / BOM
            if (c == '\uFFA0') return true;                       // halfwidth hangul filler
            if (c >= '\uFFF9' && c <= '\uFFFB') return true;      // interlinear annotation
            return false;
        }

        // ---------------------------------------------------------------- text layout

        private static void Rule(StringBuilder sb, char c)
        {
            sb.Append(new string(c, TextWidth)).Append(Environment.NewLine);
        }

        private static void Field(StringBuilder sb, string caption, string value)
        {
            sb.Append(Pad(caption + ":", 34)).Append(value).Append(Environment.NewLine);
        }

        private static string Pad(string s, int width)
        {
            if (s.Length >= width) return s + " ";
            return s + new string(' ', width - s.Length);
        }

        private static string Num(int v) { return v.ToString(CultureInfo.InvariantCulture); }
        private static string Num64(long v) { return v.ToString(CultureInfo.InvariantCulture); }

        private static string Iso(DateTime t)
        {
            try { return t.ToString("yyyy-MM-dd HH:mm:ss'Z'", CultureInfo.InvariantCulture); }
            catch (Exception) { return "(unavailable)"; }
        }

        private static string DurationText(ScanReport r)
        {
            try
            {
                if (r.FinishedUtc <= r.StartedUtc) return "(incomplete)";
                double ms = (r.FinishedUtc - r.StartedUtc).TotalMilliseconds;
                return ms.ToString("0", CultureInfo.InvariantCulture) + " ms";
            }
            catch (Exception) { return "(unavailable)"; }
        }

        /// <summary>
        /// Word-wraps into <paramref name="sb"/> at <paramref name="width"/> columns, prefixing
        /// every produced line with <paramref name="indent"/>. Existing line breaks are honoured.
        /// </summary>
        private static void Wrap(StringBuilder sb, string text, int width, string indent)
        {
            string nl = Environment.NewLine;
            if (width < 20) width = 20;
            if (text == null) text = "";

            string[] hard = text.Replace("\r\n", "\n").Replace('\r', '\n').Split('\n');
            foreach (string paragraph in hard)
            {
                if (paragraph.Length == 0) { sb.Append(nl); continue; }

                string[] words = paragraph.Split(' ');
                var line = new StringBuilder(width + 8);
                foreach (string w in words)
                {
                    if (w.Length == 0) continue;
                    if (line.Length > 0 && line.Length + 1 + w.Length > width)
                    {
                        sb.Append(indent).Append(line.ToString()).Append(nl);
                        line.Length = 0;
                    }
                    if (line.Length > 0) line.Append(' ');
                    line.Append(w);
                }
                if (line.Length > 0) sb.Append(indent).Append(line.ToString()).Append(nl);
            }
        }
    }
}

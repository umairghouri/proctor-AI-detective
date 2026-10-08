using System;
using System.Collections.Generic;

namespace ProctorAIDetective.Core
{
    /// <summary>
    /// Confidence tier of a single piece of evidence. Drives the aggregation caps in
    /// <see cref="ScoreEngine"/>: a pile of Weak signals can never reach DETECTED, and a
    /// single Definitive signal always does.
    /// </summary>
    public enum Tier
    {
        Weak = 0,
        Moderate = 1,
        Strong = 2,
        Definitive = 3
    }

    /// <summary>
    /// What a signal actually proves about the subject's state. Kept separate from the
    /// confidence score because "installed" and "running right now" are different questions
    /// and a single number cannot express both without misleading the reader.
    /// </summary>
    [Flags]
    public enum StateAxis
    {
        None = 0,
        /// <summary>Artifacts prove the software is present on disk / registered.</summary>
        Installed = 1,
        /// <summary>The software is executing at scan time.</summary>
        Running = 2,
        /// <summary>Something is actively hiding itself from screen capture.</summary>
        Evading = 4
    }

    /// <summary>
    /// How the allowlist treated a signal. An allowlisted process NAME carrying the wrong
    /// signature is MORE suspicious than an unknown process, so the allowlist escalates
    /// rather than suppresses on mismatch.
    /// </summary>
    public enum AllowlistOutcome
    {
        /// <summary>No allowlist entry matched; score passes through unchanged (x1.0).</summary>
        NotListed = 0,
        /// <summary>Name, signer and path all matched a verified entry; suppressed (x0.0).</summary>
        Suppressed = 1,
        /// <summary>Matched an entry we could not verify; down-ranked but never hidden (x0.35).</summary>
        DownRanked = 2,
        /// <summary>Name matched but signer/path did not. Masquerade: escalated (x1.75).</summary>
        Masquerade = 3
    }

    /// <summary>
    /// One observation made by one scanner. Immutable once produced.
    ///
    /// The two score fields are the core false-positive control:
    ///   <see cref="Attribution"/> answers "is this Parakeet AI specifically?"
    ///   <see cref="ClassScore"/>  answers "is this a tool of the capture-evading copilot class?"
    /// Signals that observe behaviour only (a hidden window, an overlay) MUST set
    /// Attribution = 0. That makes it structurally impossible for the app to accuse someone
    /// of running Parakeet because 1Password hid a window.
    /// </summary>
    public sealed class Signal
    {
        /// <summary>Stable identifier, e.g. "A1.signer". Used in exports and tests.</summary>
        public string Id { get; set; } = "";

        /// <summary>Short human-readable label shown in the evidence grid.</summary>
        public string Title { get; set; } = "";

        /// <summary>
        /// What was actually observed, in literal terms a reviewer can check by hand.
        /// Never a conclusion — state the fact, not the inference.
        /// </summary>
        public string Detail { get; set; } = "";

        public Tier Tier { get; set; } = Tier.Weak;

        /// <summary>0-100. Evidence that this is Parakeet AI specifically. Behavioural signals must use 0.</summary>
        public int Attribution { get; set; }

        /// <summary>0-100. Evidence that this is a tool of the capture-evading AI-copilot class.</summary>
        public int ClassScore { get; set; }

        public StateAxis State { get; set; } = StateAxis.None;

        /// <summary>Vendor key this signal points at ("parakeet", "cluely", ...) or "" when generic.</summary>
        public string VendorKey { get; set; } = "";

        /// <summary>
        /// Vendor category, stamped by <see cref="CategoryPolicy"/> after the scan:
        /// "interview-copilot" for the capture-evading class this app hunts, "general-assistant"
        /// for mainstream AI tools whose scores are forced to zero, "" for behavioural signals
        /// that belong to no vendor.
        /// </summary>
        public string Category { get; set; } = "";

        /// <summary>
        /// Vendor display name ("Claude (Anthropic)"), stamped alongside <see cref="Category"/>.
        /// Empty for behavioural signals that belong to no vendor.
        /// </summary>
        public string VendorName { get; set; } = "";

        /// <summary>Process name, window title, or hostname the signal is about.</summary>
        public string Subject { get; set; } = "";

        /// <summary>Full image path when known; empty when the scanner could not resolve it.</summary>
        public string SubjectPath { get; set; } = "";

        /// <summary>Authenticode signer subject when known; empty when unsigned/unreadable.</summary>
        public string Signer { get; set; } = "";

        /// <summary>Owning process id, or 0 when not applicable.</summary>
        public int Pid { get; set; }

        /// <summary>Scanner that produced this signal, e.g. "window", "process", "browser", "network".</summary>
        public string Source { get; set; } = "";

        public AllowlistOutcome Allowlist { get; set; } = AllowlistOutcome.NotListed;

        /// <summary>Why the allowlist reached its outcome. Always populated when Allowlist != NotListed.</summary>
        public string AllowlistReason { get; set; } = "";

        /// <summary>Multiplier the allowlist applied: 1.0 / 0.0 / 0.35 / 1.75.</summary>
        public double Multiplier { get; set; } = 1.0;

        /// <summary>Effective attribution after the allowlist multiplier, clamped to 0-100.</summary>
        public int EffectiveAttribution
        {
            get { return Clamp((int)Math.Round(Attribution * Multiplier)); }
        }

        /// <summary>Effective class score after the allowlist multiplier, clamped to 0-100.</summary>
        public int EffectiveClass
        {
            get { return Clamp((int)Math.Round(ClassScore * Multiplier)); }
        }

        /// <summary>True when the allowlist zeroed this signal. Still exported, so the allowlist is auditable.</summary>
        public bool IsSuppressed
        {
            get { return Allowlist == AllowlistOutcome.Suppressed; }
        }

        private static int Clamp(int v)
        {
            if (v < 0) return 0;
            if (v > 100) return 100;
            return v;
        }
    }

    /// <summary>Overall judgement on one axis.</summary>
    public enum Verdict
    {
        Clear = 0,
        Suspicious = 1,
        Detected = 2
    }

    /// <summary>Scored result for a single axis (attribution or class) on a single state.</summary>
    public sealed class AxisResult
    {
        public int Score { get; set; }
        public Verdict Verdict { get; set; }
        /// <summary>Plain-language reason naming the signals that drove the score.</summary>
        public string Rationale { get; set; } = "";
    }

    /// <summary>
    /// Everything one scan produced. The UI renders Running as the headline (the user's actual
    /// question is "is it running"), with Installed and Evading as separate sentences.
    /// </summary>
    public sealed class ScanReport
    {
        public DateTime StartedUtc { get; set; }
        public DateTime FinishedUtc { get; set; }
        public string MachineName { get; set; } = "";
        public string UserName { get; set; } = "";
        public string OsVersion { get; set; } = "";
        public bool Elevated { get; set; }
        public string AppVersion { get; set; } = "";
        public string SignatureVersion { get; set; } = "";

        public List<Signal> Signals { get; } = new List<Signal>();

        /// <summary>Non-fatal problems: a scanner that failed, a permission denied, a blind spot.</summary>
        public List<string> Limitations { get; } = new List<string>();

        /// <summary>Per-scanner wall-clock in ms, for the diagnostics pane.</summary>
        public Dictionary<string, long> Timings { get; } = new Dictionary<string, long>();

        // Headline: is Parakeet AI running right now?
        public AxisResult RunningAttribution { get; set; } = new AxisResult();
        // Is some tool of this class running right now?
        public AxisResult RunningClass { get; set; } = new AxisResult();
        // Is Parakeet AI installed on this machine?
        public AxisResult InstalledAttribution { get; set; } = new AxisResult();
        // Is anything actively hiding from screen capture?
        public AxisResult EvadingClass { get; set; } = new AxisResult();

        /// <summary>Windows whose display affinity could not be read. A stated blind spot, not a clean result.</summary>
        public int WindowsQueryFailed { get; set; }
        public int WindowsScanned { get; set; }
        public int ProcessesScanned { get; set; }
        public int ProcessPathsUnresolved { get; set; }
    }

    /// <summary>Contract every scanner implements. Scanners never throw; they report via Limitations.</summary>
    public interface IScanner
    {
        /// <summary>Stable scanner id used in Signal.Source and ScanReport.Timings.</summary>
        string Id { get; }

        /// <summary>Human label for the progress UI.</summary>
        string DisplayName { get; }

        /// <summary>
        /// Run the scan. MUST NOT throw: catch everything and append to <paramref name="report"/>.Limitations.
        /// MUST NOT touch the UI thread. Appends its findings to report.Signals.
        /// </summary>
        void Scan(ScanContext context, ScanReport report);
    }
}

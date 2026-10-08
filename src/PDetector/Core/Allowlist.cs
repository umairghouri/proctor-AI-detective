using System;
using System.Collections.Generic;

namespace PDetector.Core
{
    /// <summary>
    /// The result of asking the allowlist about one subject.
    ///
    /// <para><see cref="Multiplier"/> is DERIVED from <see cref="Outcome"/> rather than stored, so the
    /// two can never drift apart and <c>default(AllowlistDecision)</c> is a safe pass-through
    /// (NotListed, x1.00) instead of an accidental x0.00 suppression.</para>
    /// </summary>
    public readonly struct AllowlistDecision
    {
        private readonly string? _reason;

        public AllowlistDecision(AllowlistOutcome outcome, string reason, AllowlistEntry? matchedEntry)
        {
            Outcome = outcome;
            _reason = reason;
            MatchedEntry = matchedEntry;
        }

        /// <summary>How the allowlist treated the subject.</summary>
        public AllowlistOutcome Outcome { get; }

        /// <summary>The entry that produced the outcome, or null when nothing matched.</summary>
        public AllowlistEntry? MatchedEntry { get; }

        /// <summary>Score multiplier implied by <see cref="Outcome"/>: 1.00 / 0.00 / 0.35 / 1.75.</summary>
        public double Multiplier
        {
            get
            {
                switch (Outcome)
                {
                    case AllowlistOutcome.Suppressed: return Allowlist.MultiplierSuppressed;
                    case AllowlistOutcome.DownRanked: return Allowlist.MultiplierDownRanked;
                    case AllowlistOutcome.Masquerade: return Allowlist.MultiplierMasquerade;
                    default: return Allowlist.MultiplierNotListed;
                }
            }
        }

        /// <summary>Plain-language explanation naming exactly what matched or failed to match.</summary>
        public string Reason
        {
            get { return _reason ?? ""; }
        }
    }

    /// <summary>
    /// The single most important false-positive control in the app.
    ///
    /// <para>Plenty of entirely legitimate software hides windows from screen capture: the Zoom
    /// share toolbar, password managers, DRM video playback in a browser, the UAC secure desktop.
    /// Without an allowlist this tool would accuse everybody of everything.</para>
    ///
    /// <para>But an allowlist keyed on a process NAME is a trivial bypass: rename your binary
    /// nvcontainer.exe and you are invisible. So this allowlist is keyed on the TRIPLE
    /// (name, signer, path) and is a TRIPWIRE rather than a bypass:</para>
    /// <list type="bullet">
    ///   <item>name matches nothing ................................... NotListed,  x1.00</item>
    ///   <item>name + signer + path match, entry Verified ............. Suppressed, x0.00</item>
    ///   <item>name + signer + path match, entry NOT Verified ......... DownRanked, x0.35</item>
    ///   <item>name matches but signer or path CONTRADICTS the entry .. Masquerade, x1.75</item>
    /// </list>
    ///
    /// <para>The escalation is the whole point. An allowlisted name wearing the wrong certificate is
    /// MORE suspicious than a process nobody has ever heard of.</para>
    ///
    /// <para>A masquerade must raise the CLASS score only, never Attribution: a thing pretending to
    /// be NVIDIA is not evidence of Parakeet AI specifically. <see cref="Signal.Multiplier"/> is a
    /// single field applied to both scores, so that asymmetry is enforced one level up in
    /// <see cref="ScoreEngine"/>, which ignores the masquerade multiplier on the attribution axes.</para>
    /// </summary>
    public sealed class Allowlist
    {
        public const double MultiplierNotListed = 1.00;
        public const double MultiplierSuppressed = 0.00;
        public const double MultiplierDownRanked = 0.35;
        public const double MultiplierMasquerade = 1.75;

        /// <summary>Outcome of checking one constrained field (signer or path) of one entry.</summary>
        private enum FieldCheck
        {
            /// <summary>The entry leaves this field empty, so it is deliberately NOT checked.</summary>
            NotChecked,
            /// <summary>Observed value contains the expected substring.</summary>
            Match,
            /// <summary>Observed value is known and CONTRADICTS the expected substring.</summary>
            Mismatch,
            /// <summary>The entry requires this field but it could not be read at all.</summary>
            Unreadable
        }

        private readonly List<AllowlistEntry> _entries;
        private readonly Dictionary<string, List<AllowlistEntry>> _byName;
        private readonly bool _unreadableIsMasquerade;

        /// <param name="entries">Entries from signatures.json. Null, and null elements, are tolerated.</param>
        /// <param name="unreadableEvidenceIsMasquerade">
        /// Policy for the one case the written rule does not cover: the name matches, the entry demands
        /// a signer (or path), and NO signer (or path) could be read at all.
        ///
        /// Default FALSE, which treats that as DownRanked (x0.35) rather than Masquerade (x1.75),
        /// because "unreadable" is not "wrong". This matters enormously in practice:
        /// X509Certificate.CreateFromSignedFile THROWS on CATALOG-signed files, which is how most
        /// in-box Windows binaries are signed, and ctfmon.exe, explorer.exe, TextInputHost.exe and
        /// ApplicationFrameHost.exe are all on this allowlist and all catalog-signed. Escalating an
        /// unreadable signature to x1.75 would escalate half of Windows on every single scan.
        /// Down-ranking still refuses to hard-suppress, so a signature-stripped impostor wearing an
        /// allowlisted name keeps 35% of its score instead of walking off with a free bypass.
        /// Set TRUE only if the caller can tell "no embedded signature" apart from "catalog-signed".
        /// </param>
        public Allowlist(List<AllowlistEntry> entries, bool unreadableEvidenceIsMasquerade = false)
        {
            _unreadableIsMasquerade = unreadableEvidenceIsMasquerade;

            _entries = new List<AllowlistEntry>();
            if (entries != null)
            {
                foreach (var e in entries)
                {
                    if (e != null) _entries.Add(e);
                }
            }

            _byName = new Dictionary<string, List<AllowlistEntry>>(StringComparer.OrdinalIgnoreCase);
            foreach (var e in _entries)
            {
                string key = NormalizeProcessName(e.ProcessName);
                if (key.Length == 0) continue;

                List<AllowlistEntry> bucket;
                if (!_byName.TryGetValue(key, out bucket))
                {
                    bucket = new List<AllowlistEntry>();
                    _byName[key] = bucket;
                }
                bucket.Add(e);
            }
        }

        /// <summary>Every entry loaded, for the audit export and the diagnostics pane.</summary>
        public IReadOnlyList<AllowlistEntry> Entries
        {
            get { return _entries; }
        }

        /// <summary>
        /// Decide how a subject should be treated. Never throws.
        /// </summary>
        /// <param name="processName">
        /// Process name, with or without ".exe", with or without a directory prefix.
        /// Process.ProcessName yields "chrome" while signatures.json says "chrome.exe", so both sides
        /// are normalised before comparison.
        /// </param>
        /// <param name="signerSubject">Authenticode signer subject, or null/empty when unknown.</param>
        /// <param name="imagePath">Full image path, or null/empty when it could not be resolved.</param>
        public AllowlistDecision Evaluate(string processName, string? signerSubject, string? imagePath)
        {
            string key = NormalizeProcessName(processName);
            if (key.Length == 0)
                return new AllowlistDecision(AllowlistOutcome.NotListed, "", null);

            List<AllowlistEntry> candidates;
            if (!_byName.TryGetValue(key, out candidates) || candidates.Count == 0)
                return new AllowlistDecision(AllowlistOutcome.NotListed, "", null);

            string shownName = Display(processName);

            // One name can appear on more than one entry. Classify every candidate, then resolve by
            // precedence: a genuine full match beats a mismatch against a DIFFERENT entry, because the
            // process really is the legitimate thing that one of the entries describes.
            AllowlistEntry? fullVerified = null;
            AllowlistEntry? fullUnverified = null;
            AllowlistEntry? unconfirmed = null;
            AllowlistEntry? masquerade = null;
            string unconfirmedReason = "";
            string masqueradeReason = "";

            foreach (var e in candidates)
            {
                // NOTE THE SUBTLETY: an empty ExpectedSigner means the signer is NOT checked, so such an
                // entry can NEVER produce a Masquerade on signer grounds - Check() returns NotChecked,
                // which counts as satisfied. Identically for ExpectedPathFragment. An entry with BOTH
                // fields empty therefore matches on name alone and can only ever Suppress or DownRank.
                // That is a deliberate data decision in signatures.json, not an accident here.
                FieldCheck signer = Check(e.ExpectedSigner, signerSubject);
                FieldCheck path = Check(e.ExpectedPathFragment, imagePath);

                bool signerContradicts = signer == FieldCheck.Mismatch
                                         || (signer == FieldCheck.Unreadable && _unreadableIsMasquerade);
                bool pathContradicts = path == FieldCheck.Mismatch
                                       || (path == FieldCheck.Unreadable && _unreadableIsMasquerade);

                if (signerContradicts || pathContradicts)
                {
                    if (masquerade == null)
                    {
                        masquerade = e;
                        masqueradeReason = BuildMasqueradeReason(shownName, e, signer, path, signerSubject, imagePath);
                    }
                    continue;
                }

                if (signer == FieldCheck.Unreadable || path == FieldCheck.Unreadable)
                {
                    if (unconfirmed == null)
                    {
                        unconfirmed = e;
                        unconfirmedReason = BuildUnconfirmedReason(shownName, e, signer, path);
                    }
                    continue;
                }

                // Everything this entry constrains is satisfied: a full match.
                if (e.Verified)
                {
                    if (fullVerified == null) fullVerified = e;
                }
                else
                {
                    if (fullUnverified == null) fullUnverified = e;
                }
            }

            if (fullVerified != null)
                return new AllowlistDecision(AllowlistOutcome.Suppressed, BuildSuppressedReason(shownName, fullVerified), fullVerified);

            if (fullUnverified != null)
                return new AllowlistDecision(AllowlistOutcome.DownRanked, BuildUnverifiedReason(shownName, fullUnverified), fullUnverified);

            if (unconfirmed != null)
                return new AllowlistDecision(AllowlistOutcome.DownRanked, unconfirmedReason, unconfirmed);

            if (masquerade != null)
                return new AllowlistDecision(AllowlistOutcome.Masquerade, masqueradeReason, masquerade);

            return new AllowlistDecision(AllowlistOutcome.NotListed, "", null);
        }

        /// <summary>
        /// Stamp a signal with its allowlist outcome. Never throws.
        /// The process name is taken from <see cref="Signal.SubjectPath"/> when there is one (a full
        /// path is unambiguous) and from <see cref="Signal.Subject"/> otherwise.
        /// </summary>
        public void Apply(Signal signal)
        {
            if (signal == null) return;

            string name = NormalizeProcessName(signal.SubjectPath);
            if (name.Length == 0) name = NormalizeProcessName(signal.Subject);

            AllowlistDecision d = Evaluate(name, signal.Signer, signal.SubjectPath);

            signal.Allowlist = d.Outcome;
            signal.Multiplier = d.Multiplier;
            // Contract: AllowlistReason is always populated when Allowlist != NotListed, and left empty
            // otherwise so the evidence grid is not padded with "not on the allowlist" on every row.
            signal.AllowlistReason = d.Outcome == AllowlistOutcome.NotListed ? "" : d.Reason;
        }

        // ------------------------------------------------------------------ matching helpers

        private static FieldCheck Check(string expected, string? observed)
        {
            if (string.IsNullOrEmpty(expected)) return FieldCheck.NotChecked;
            if (observed == null || observed.Trim().Length == 0) return FieldCheck.Unreadable;
            return observed.IndexOf(expected, StringComparison.OrdinalIgnoreCase) >= 0
                ? FieldCheck.Match
                : FieldCheck.Mismatch;
        }

        /// <summary>
        /// Reduce a process name to a comparable key: drop any directory, drop a trailing ".exe", drop
        /// surrounding quotes and whitespace. Applied to BOTH sides, so "chrome", "chrome.exe",
        /// "CHROME.EXE" and "C:\Program Files\Google\Chrome\Application\chrome.exe" all compare equal.
        /// </summary>
        private static string NormalizeProcessName(string? raw)
        {
            if (raw == null) return "";

            string s = raw.Trim().Trim('"').Trim();
            if (s.Length == 0) return "";

            int slash = s.LastIndexOfAny(new[] { '\\', '/' });
            if (slash >= 0)
            {
                if (slash == s.Length - 1) return "";
                s = s.Substring(slash + 1);
            }

            if (s.Length > 4 && s.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                s = s.Substring(0, s.Length - 4);

            return s.Trim();
        }

        // ------------------------------------------------------------------ reason text

        /// <summary>Human label for an entry: the thing it expects, so reasons read naturally.</summary>
        private static string EntryLabel(AllowlistEntry e)
        {
            if (!string.IsNullOrEmpty(e.ExpectedSigner)) return e.ExpectedSigner;
            if (!string.IsNullOrEmpty(e.ExpectedPathFragment)) return e.ExpectedPathFragment;
            return string.IsNullOrEmpty(e.ProcessName) ? "unnamed" : e.ProcessName;
        }

        private static string Expectations(AllowlistEntry e)
        {
            bool hasSigner = !string.IsNullOrEmpty(e.ExpectedSigner);
            bool hasPath = !string.IsNullOrEmpty(e.ExpectedPathFragment);

            if (hasSigner && hasPath)
                return "signer contains '" + e.ExpectedSigner + "' and path contains '" + e.ExpectedPathFragment + "'";
            if (hasSigner)
                return "signer contains '" + e.ExpectedSigner + "'";
            if (hasPath)
                return "path contains '" + e.ExpectedPathFragment + "'";
            return "name only; this entry constrains neither signer nor path";
        }

        private static string BuildSuppressedReason(string shownName, AllowlistEntry e)
        {
            string note = string.IsNullOrEmpty(e.Note) ? "" : " " + e.Note;
            return "'" + shownName + "' matches a first-hand verified allowlist entry ("
                   + Expectations(e)
                   + "), so this is expected behaviour for legitimate software and the evidence is "
                   + "suppressed (x0.00)." + note;
        }

        private static string BuildUnverifiedReason(string shownName, AllowlistEntry e)
        {
            string note = string.IsNullOrEmpty(e.Note) ? "" : " " + e.Note;
            return "'" + shownName + "' matches an allowlist entry (" + Expectations(e)
                   + "), but that entry has never been confirmed first-hand, so the evidence is "
                   + "down-ranked to 35% rather than hidden." + note;
        }

        private static string BuildUnconfirmedReason(string shownName, AllowlistEntry e,
                                                     FieldCheck signer, FieldCheck path)
        {
            var missing = new List<string>();
            if (signer == FieldCheck.Unreadable)
                missing.Add("no Authenticode signer could be read, and the entry expects '" + e.ExpectedSigner + "'");
            if (path == FieldCheck.Unreadable)
                missing.Add("the image path could not be resolved, and the entry expects '" + e.ExpectedPathFragment + "'");

            return "'" + shownName + "' matches an allowlist entry by name, but " + Join(missing)
                   + ". Unreadable is not the same as wrong, so the entry could not be confirmed and the "
                   + "evidence is down-ranked to 35% rather than suppressed or escalated.";
        }

        private static string BuildMasqueradeReason(string shownName, AllowlistEntry e,
                                                    FieldCheck signer, FieldCheck path,
                                                    string? signerSubject, string? imagePath)
        {
            var problems = new List<string>();

            if (signer == FieldCheck.Mismatch)
                problems.Add("the signer is '" + Display(signerSubject) + "' and not '" + e.ExpectedSigner + "'");
            else if (signer == FieldCheck.Unreadable)
                problems.Add("no signer could be read where '" + e.ExpectedSigner + "' was required");

            if (path == FieldCheck.Mismatch)
                problems.Add("the image path is '" + Display(imagePath) + "' and does not contain '" + e.ExpectedPathFragment + "'");
            else if (path == FieldCheck.Unreadable)
                problems.Add("no image path could be resolved where '" + e.ExpectedPathFragment + "' was required");

            return "Process name '" + shownName + "' matches the " + EntryLabel(e)
                   + " allowlist entry, but " + Join(problems)
                   + ". An allowlisted name wearing the wrong credentials is more suspicious than an "
                   + "unknown process, so this evidence is escalated (x1.75) instead of suppressed.";
        }

        private static string Join(List<string> parts)
        {
            if (parts.Count == 0) return "the entry could not be confirmed";
            if (parts.Count == 1) return parts[0];
            return string.Join(", and ", parts.ToArray());
        }

        /// <summary>Trim a value for display so a pathological string cannot blow up the UI.</summary>
        private static string Display(string? value)
        {
            if (value == null) return "(unknown)";
            string s = value.Trim();
            if (s.Length == 0) return "(unknown)";
            if (s.Length > 120) s = s.Substring(0, 117) + "...";
            return s;
        }
    }
}

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace ProctorAIDetective.Core
{
    /// <summary>
    /// Turns a pile of <see cref="Signal"/>s into four answers a human can act on.
    ///
    /// <para>The arithmetic is deliberately boring and auditable, because this tool makes claims
    /// about people:</para>
    /// <list type="number">
    ///   <item>Pick the signals whose <see cref="StateAxis"/> matches the question being asked.</item>
    ///   <item>Inside each <see cref="Tier"/>, combine with noisy-OR:
    ///         <c>100 * (1 - PRODUCT(1 - s/100))</c>. Independent hints accumulate, nothing is
    ///         double-counted, and the result can approach but never exceed 100.</item>
    ///   <item>Cap each tier: Weak at 30 (absolute), a LONE Moderate at 25.</item>
    ///   <item>Noisy-OR the four tier subtotals together and round.</item>
    ///   <item>Any unsuppressed Definitive signal that actually scores on this axis floors the
    ///         total at 70.</item>
    ///   <item>70+ is Detected, 25+ is Suspicious, below that is Clear.</item>
    /// </list>
    ///
    /// <para>The caps are the safety property, and they are structural rather than advisory:</para>
    /// <list type="bullet">
    ///   <item>any number of Weak signals, alone, tops out at 30 - never a detection;</item>
    ///   <item>a lone Moderate signal lands on exactly 25 - the Suspicious boundary, never more;</item>
    ///   <item>a single unsuppressed Definitive signal always reaches at least 70.</item>
    /// </list>
    /// </summary>
    public static class ScoreEngine
    {
        /// <summary>Score at or above which an axis reads Detected.</summary>
        public const int DetectedThreshold = 70;

        /// <summary>Score at or above which an axis reads Suspicious.</summary>
        public const int SuspiciousThreshold = 25;

        /// <summary>Absolute ceiling on the Weak tier, however many weak signals there are.</summary>
        public const int WeakTierCap = 30;

        /// <summary>Ceiling applied when exactly ONE Moderate signal contributes.</summary>
        public const int LoneModerateCap = 25;

        /// <summary>Floor applied when an unsuppressed Definitive signal scores on the axis.</summary>
        public const int DefinitiveFloor = 70;

        /// <summary>
        /// Populate the four axis results on <paramref name="report"/>. Never throws: a failure on one
        /// axis is reported as an unanswered question in Limitations, never as a clean result.
        /// </summary>
        public static void Score(ScanReport report)
        {
            if (report == null) return;

            report.RunningAttribution = ScoreAxisSafe(
                report, StateAxis.Running, true, "Is Parakeet AI running right now?",
                "Parakeet AI appears to be running on this machine right now.",
                "There are signs that Parakeet AI might be running on this machine right now, but not enough to say so.",
                "Nothing found suggests Parakeet AI is running on this machine right now.");

            report.RunningClass = ScoreAxisSafe(
                report, StateAxis.Running, false, "Is a capture-evading AI assistant running right now?",
                "A screen-capture-evading AI assistant appears to be running on this machine right now.",
                "Something running on this machine behaves a little like a screen-capture-evading AI assistant, but the evidence is thin.",
                "Nothing running on this machine looks like a screen-capture-evading AI assistant.");

            report.InstalledAttribution = ScoreAxisSafe(
                report, StateAxis.Installed, true, "Is Parakeet AI installed on this machine?",
                "Parakeet AI is installed on this machine.",
                "There are traces that suggest Parakeet AI may be installed on this machine.",
                "No trace of a Parakeet AI installation was found on this machine.");

            report.EvadingClass = ScoreAxisSafe(
                report, StateAxis.Evading, false, "Is anything hiding itself from screen capture?",
                "Something on this machine is actively hiding itself from screen capture.",
                "Something on this machine may be hiding itself from screen capture.",
                "Nothing on this machine was seen hiding itself from screen capture.");
        }

        private static AxisResult ScoreAxisSafe(ScanReport report, StateAxis axis, bool attribution,
                                                string question, string yes, string maybe, string no)
        {
            try
            {
                return ScoreAxis(report.Signals, axis, attribution, yes, maybe, no);
            }
            catch (Exception ex)
            {
                report.Limitations.Add("Scoring failed for \"" + question + "\" (" + ex.GetType().Name
                                       + "). Treat that question as unanswered, not as a clean result.");
                return new AxisResult
                {
                    Score = 0,
                    Verdict = Verdict.Clear,
                    Rationale = "This question could not be scored because the calculation failed. "
                                + "Treat it as unanswered rather than as a clean result."
                };
            }
        }

        // --------------------------------------------------------------------- the arithmetic

        private static AxisResult ScoreAxis(List<Signal> signals, StateAxis axis, bool attribution,
                                            string yes, string maybe, string no)
        {
            // 1. Select the signals that speak to this question, and score each one through the
            //    allowlist. Suppressed signals score 0 here but stay in report.Signals, so the
            //    allowlist is always auditable from the exported evidence.
            var contributions = new List<(Signal Signal, int Value)>();
            int relevant = 0;
            int suppressed = 0;
            bool masquerade = false;

            if (signals != null)
            {
                foreach (var s in signals)
                {
                    if (s == null) continue;
                    if ((s.State & axis) == 0) continue;

                    relevant++;
                    if (s.IsSuppressed) suppressed++;

                    int value = ValueOf(s, attribution);
                    if (value <= 0) continue;

                    if (s.Allowlist == AllowlistOutcome.Masquerade) masquerade = true;
                    contributions.Add((s, value));
                }
            }

            // 2. Noisy-OR inside each tier. Only contributing signals (value > 0) are group members,
            //    so a suppressed signal cannot silently turn a lone Moderate into a pair and lift the
            //    cap off it.
            var weakValues = ValuesOfTier(contributions, Tier.Weak);
            var moderateValues = ValuesOfTier(contributions, Tier.Moderate);
            var strongValues = ValuesOfTier(contributions, Tier.Strong);
            var definitiveValues = ValuesOfTier(contributions, Tier.Definitive);

            double weak = NoisyOr(weakValues);
            double moderate = NoisyOr(moderateValues);
            double strong = NoisyOr(strongValues);
            double definitive = NoisyOr(definitiveValues);

            // 3. Tier caps.
            bool weakCapped = weak > WeakTierCap;
            if (weakCapped) weak = WeakTierCap;

            bool loneModerateCapped = moderateValues.Count == 1 && moderate > LoneModerateCap;
            if (loneModerateCapped) moderate = LoneModerateCap;

            // 4. Combine the four tier subtotals the same way, then round.
            double totalRaw = NoisyOr(new[] { weak, moderate, strong, definitive });
            int total = ClampScore((int)Math.Round(totalRaw, MidpointRounding.AwayFromZero));

            // 5. A definitive signal that actually scores on THIS axis floors the total. The
            //    "actually scores" part matters: a behavioural signal carries Attribution = 0 by
            //    design, so a definitive hidden-window finding can never floor the ATTRIBUTION axis
            //    and accuse someone of running Parakeet because 1Password hid a window.
            bool definitiveFloored = false;
            foreach (var c in contributions)
            {
                if (c.Signal.Tier == Tier.Definitive && !c.Signal.IsSuppressed && c.Value > 0)
                {
                    if (total < DefinitiveFloor)
                    {
                        total = DefinitiveFloor;
                        definitiveFloored = true;
                    }
                    break;
                }
            }

            // 6. Verdict.
            Verdict verdict = total >= DetectedThreshold ? Verdict.Detected
                            : total >= SuspiciousThreshold ? Verdict.Suspicious
                            : Verdict.Clear;

            return new AxisResult
            {
                Score = total,
                Verdict = verdict,
                Rationale = BuildRationale(verdict, total, contributions, relevant, suppressed,
                                           masquerade, weakCapped, loneModerateCapped, definitiveFloored,
                                           yes, maybe, no)
            };
        }

        /// <summary>
        /// The score one signal contributes to one axis, after the allowlist.
        /// </summary>
        private static int ValueOf(Signal s, bool attribution)
        {
            if (s.IsSuppressed) return 0;

            if (!attribution) return ClampScore(s.EffectiveClass);

            // A masquerade escalation says "something is wearing a trusted vendor's name without that
            // vendor's signature". That is evidence about the CLASS of tool, never evidence about
            // Parakeet AI specifically, so the x1.75 is not allowed to inflate an attribution score.
            // Signal.Multiplier is one field applied to both scores, so the asymmetry is enforced here.
            if (s.Allowlist == AllowlistOutcome.Masquerade) return ClampScore(s.Attribution);

            return ClampScore(s.EffectiveAttribution);
        }

        private static List<int> ValuesOfTier(List<(Signal Signal, int Value)> contributions, Tier tier)
        {
            var values = new List<int>();
            foreach (var c in contributions)
            {
                if (c.Signal.Tier == tier) values.Add(c.Value);
            }
            return values;
        }

        /// <summary>
        /// Noisy-OR over a set of 0-100 scores: <c>100 * (1 - PRODUCT(1 - s/100))</c>.
        /// Two independent 50s make 75, not 100 and not 50. Zero and negative inputs are inert.
        /// </summary>
        private static double NoisyOr(IEnumerable<int> values)
        {
            double survives = 1.0;
            foreach (int v in values)
            {
                int c = ClampScore(v);
                if (c <= 0) continue;
                survives *= 1.0 - (c / 100.0);
            }
            return 100.0 * (1.0 - survives);
        }

        /// <summary>Same operation over already-combined tier subtotals.</summary>
        private static double NoisyOr(IEnumerable<double> values)
        {
            double survives = 1.0;
            foreach (double v in values)
            {
                if (v <= 0.0) continue;
                double c = v > 100.0 ? 100.0 : v;
                survives *= 1.0 - (c / 100.0);
            }
            return 100.0 * (1.0 - survives);
        }

        private static int ClampScore(int v)
        {
            if (v < 0) return 0;
            if (v > 100) return 100;
            return v;
        }

        // --------------------------------------------------------------------- plain English

        private static string BuildRationale(Verdict verdict, int total,
                                             List<(Signal Signal, int Value)> contributions,
                                             int relevant, int suppressed, bool masquerade,
                                             bool weakCapped, bool loneModerateCapped,
                                             bool definitiveFloored,
                                             string yes, string maybe, string no)
        {
            var sb = new StringBuilder();

            sb.Append(verdict == Verdict.Detected ? yes : verdict == Verdict.Suspicious ? maybe : no);
            sb.Append(" Confidence score ").Append(total)
              .Append(" out of 100 (70 or more counts as detected, 25 or more as worth a second look).");

            if (contributions.Count > 0)
            {
                var ranked = contributions
                    .OrderByDescending(c => (int)c.Signal.Tier)
                    .ThenByDescending(c => c.Value)
                    .ToList();

                int shown = Math.Min(3, ranked.Count);
                sb.Append(shown == 1 ? " The finding behind this: " : " The findings that weighed most: ");
                for (int i = 0; i < shown; i++)
                {
                    if (i > 0) sb.Append(i == shown - 1 ? "; and " : "; ");
                    sb.Append(Describe(ranked[i].Signal)).Append(" (")
                      .Append(TierWord(ranked[i].Signal.Tier)).Append(" evidence, rated ")
                      .Append(ranked[i].Value).Append(" out of 100)");
                }
                sb.Append('.');

                int rest = ranked.Count - shown;
                if (rest > 0)
                {
                    sb.Append(' ').Append(rest).Append(rest == 1 ? " further finding" : " further findings")
                      .Append(" also counted towards the score.");
                }
            }
            else if (relevant > 0)
            {
                sb.Append(" Findings were recorded for this question but none of them counted towards the score.");
            }
            else
            {
                sb.Append(" No check produced any evidence for this question.");
            }

            if (weakCapped)
            {
                sb.Append(" Several low-confidence hints were found, but together they are allowed to contribute at most ")
                  .Append(WeakTierCap).Append(" points, so hints alone can never add up to a detection.");
            }

            if (loneModerateCapped)
            {
                sb.Append(" Only one medium-confidence finding supports this, so no more than ")
                  .Append(LoneModerateCap)
                  .Append(" points of it are allowed to count: enough to flag, never enough to accuse.");
            }

            if (definitiveFloored)
            {
                sb.Append(" One of the findings is conclusive on its own, which is enough to report a detection "
                          + "whatever the other numbers say.");
            }

            if (masquerade)
            {
                sb.Append(" At least one finding was escalated because a program was using a trusted program's "
                          + "name without that vendor's digital signature.");
            }

            if (suppressed > 0)
            {
                sb.Append(' ').Append(suppressed)
                  .Append(suppressed == 1 ? " finding was" : " findings were")
                  .Append(" set aside as known-good software on the allowlist; ")
                  .Append(suppressed == 1 ? "it is" : "they are")
                  .Append(" still listed in the evidence table.");
            }

            return sb.ToString();
        }

        private static string Describe(Signal s)
        {
            string label = !string.IsNullOrWhiteSpace(s.Title) ? s.Title.Trim()
                         : !string.IsNullOrWhiteSpace(s.Id) ? s.Id.Trim()
                         : "an unnamed finding";
            if (label.Length > 120) label = label.Substring(0, 117) + "...";

            string subject = s.Subject == null ? "" : s.Subject.Trim();
            if (subject.Length > 60) subject = subject.Substring(0, 57) + "...";

            return subject.Length > 0 ? "\"" + label + "\" for " + subject : "\"" + label + "\"";
        }

        private static string TierWord(Tier tier)
        {
            switch (tier)
            {
                case Tier.Definitive: return "conclusive";
                case Tier.Strong: return "strong";
                case Tier.Moderate: return "medium-confidence";
                default: return "low-confidence";
            }
        }

        // --------------------------------------------------------------------- self test

        /// <summary>
        /// Prove the scoring invariants at runtime. Returns a list of failures; empty means every
        /// invariant held. Cheap enough to run on every start-up and to surface in the diagnostics
        /// pane, because a caps bug here is the difference between a tool and an accusation machine.
        /// </summary>
        public static List<string> SelfTest()
        {
            var failures = new List<string>();

            try
            {
                // ---- INVARIANT 1: a single Weak signal alone can never produce Detected.
                {
                    var r = Run(Sig("w1", Tier.Weak, StateAxis.Evading, 0, 100));
                    Expect(failures, "INV1 single weak capped at 30", r.EvadingClass.Score == WeakTierCap, r.EvadingClass.Score, WeakTierCap);
                    Expect(failures, "INV1 single weak is not Detected", r.EvadingClass.Verdict == Verdict.Suspicious, r.EvadingClass.Verdict, Verdict.Suspicious);
                }

                // ---- INVARIANT 2: ANY number of Weak signals alone can never produce Detected.
                {
                    var many = new List<Signal>();
                    for (int i = 0; i < 12; i++) many.Add(Sig("w" + i, Tier.Weak, StateAxis.Evading, 0, 90));
                    var r = Run(many.ToArray());
                    Expect(failures, "INV2 twelve weak signals still capped at 30", r.EvadingClass.Score == WeakTierCap, r.EvadingClass.Score, WeakTierCap);
                    Expect(failures, "INV2 twelve weak signals are not Detected", r.EvadingClass.Verdict != Verdict.Detected, r.EvadingClass.Verdict, "not Detected");
                }

                // ---- INVARIANT 3: a single unsuppressed Definitive signal alone ALWAYS Detects.
                {
                    var r = Run(Sig("d1", Tier.Definitive, StateAxis.Running, 40, 0));
                    Expect(failures, "INV3 lone definitive floored to 70", r.RunningAttribution.Score == DefinitiveFloor, r.RunningAttribution.Score, DefinitiveFloor);
                    Expect(failures, "INV3 lone definitive is Detected", r.RunningAttribution.Verdict == Verdict.Detected, r.RunningAttribution.Verdict, Verdict.Detected);

                    var r2 = Run(Sig("d2", Tier.Definitive, StateAxis.Running, 95, 0));
                    Expect(failures, "INV3 strong definitive scores 95", r2.RunningAttribution.Score == 95, r2.RunningAttribution.Score, 95);
                    Expect(failures, "INV3 strong definitive is Detected", r2.RunningAttribution.Verdict == Verdict.Detected, r2.RunningAttribution.Verdict, Verdict.Detected);
                }

                // ---- INVARIANT 4: a single Moderate signal alone caps at exactly 25.
                {
                    var r = Run(Sig("m1", Tier.Moderate, StateAxis.Running, 0, 100));
                    Expect(failures, "INV4 lone moderate capped at 25", r.RunningClass.Score == LoneModerateCap, r.RunningClass.Score, LoneModerateCap);
                    Expect(failures, "INV4 lone moderate is Suspicious", r.RunningClass.Verdict == Verdict.Suspicious, r.RunningClass.Verdict, Verdict.Suspicious);
                    Expect(failures, "INV4 lone moderate is never Detected", r.RunningClass.Verdict != Verdict.Detected, r.RunningClass.Verdict, "not Detected");
                }

                // ---- Two moderate signals are a pair, so the lone-moderate cap must lift: 50,50 -> 75.
                {
                    var r = Run(Sig("m1", Tier.Moderate, StateAxis.Running, 0, 50),
                                Sig("m2", Tier.Moderate, StateAxis.Running, 0, 50));
                    Expect(failures, "two moderates noisy-OR to 75", r.RunningClass.Score == 75, r.RunningClass.Score, 75);
                    Expect(failures, "two moderates reach Detected", r.RunningClass.Verdict == Verdict.Detected, r.RunningClass.Verdict, Verdict.Detected);
                }

                // ---- Noisy-OR arithmetic: three weak 10s -> 100*(1-0.9^3) = 27.1 -> 27, under the cap.
                {
                    var r = Run(Sig("w1", Tier.Weak, StateAxis.Evading, 0, 10),
                                Sig("w2", Tier.Weak, StateAxis.Evading, 0, 10),
                                Sig("w3", Tier.Weak, StateAxis.Evading, 0, 10));
                    Expect(failures, "noisy-OR of 10/10/10 is 27", r.EvadingClass.Score == 27, r.EvadingClass.Score, 27);
                }

                // ---- Suppressed signals contribute nothing, but are still exported.
                {
                    var s = Sig("d1", Tier.Definitive, StateAxis.Running, 95, 95);
                    s.Allowlist = AllowlistOutcome.Suppressed;
                    s.Multiplier = Allowlist.MultiplierSuppressed;
                    var r = Run(s);
                    Expect(failures, "suppressed definitive scores 0 on attribution", r.RunningAttribution.Score == 0, r.RunningAttribution.Score, 0);
                    Expect(failures, "suppressed definitive scores 0 on class", r.RunningClass.Score == 0, r.RunningClass.Score, 0);
                    Expect(failures, "suppressed definitive does not floor to 70", r.RunningAttribution.Verdict == Verdict.Clear, r.RunningAttribution.Verdict, Verdict.Clear);
                    Expect(failures, "suppressed signal is still exported", r.Signals.Count == 1, r.Signals.Count, 1);
                }

                // ---- A suppressed sibling must not lift the cap off a lone moderate signal.
                {
                    var live = Sig("m1", Tier.Moderate, StateAxis.Running, 0, 100);
                    var dead = Sig("m2", Tier.Moderate, StateAxis.Running, 0, 100);
                    dead.Allowlist = AllowlistOutcome.Suppressed;
                    dead.Multiplier = Allowlist.MultiplierSuppressed;
                    var r = Run(live, dead);
                    Expect(failures, "suppressed sibling does not lift the lone-moderate cap", r.RunningClass.Score == LoneModerateCap, r.RunningClass.Score, LoneModerateCap);
                }

                // ---- Allowlist outcomes and multipliers.
                {
                    var list = TestAllowlist();

                    var zoom = list.Evaluate("Zoom.exe", "CN=Zoom Video Communications, Inc., O=Zoom", @"C:\Program Files\Zoom\bin\Zoom.exe");
                    Expect(failures, "verified full match suppresses", zoom.Outcome == AllowlistOutcome.Suppressed, zoom.Outcome, AllowlistOutcome.Suppressed);
                    Expect(failures, "suppressed multiplier is 0.00", Math.Abs(zoom.Multiplier) < 0.0001, zoom.Multiplier, 0.0);

                    var noExt = list.Evaluate("zoom", "CN=Zoom Video Communications, Inc.", @"C:\Program Files\Zoom\bin\Zoom.exe");
                    Expect(failures, "name matching ignores case and a missing .exe", noExt.Outcome == AllowlistOutcome.Suppressed, noExt.Outcome, AllowlistOutcome.Suppressed);

                    var slack = list.Evaluate("Slack.exe", "CN=Slack Technologies, LLC", @"C:\Users\x\AppData\Local\slack\Slack.exe");
                    Expect(failures, "unverified full match down-ranks", slack.Outcome == AllowlistOutcome.DownRanked, slack.Outcome, AllowlistOutcome.DownRanked);
                    Expect(failures, "down-ranked multiplier is 0.35", Math.Abs(slack.Multiplier - 0.35) < 0.0001, slack.Multiplier, 0.35);

                    var unknown = list.Evaluate("somethingelse.exe", "CN=Whoever", @"C:\x\somethingelse.exe");
                    Expect(failures, "unlisted name passes through", unknown.Outcome == AllowlistOutcome.NotListed, unknown.Outcome, AllowlistOutcome.NotListed);
                    Expect(failures, "pass-through multiplier is 1.00", Math.Abs(unknown.Multiplier - 1.0) < 0.0001, unknown.Multiplier, 1.0);

                    var fake = list.Evaluate("nvcontainer.exe", "CN=Totally Legit Ltd", @"C:\Users\x\AppData\Local\Temp\nvcontainer.exe");
                    Expect(failures, "allowlisted name with the wrong signer masquerades", fake.Outcome == AllowlistOutcome.Masquerade, fake.Outcome, AllowlistOutcome.Masquerade);
                    Expect(failures, "masquerade multiplier is 1.75", Math.Abs(fake.Multiplier - 1.75) < 0.0001, fake.Multiplier, 1.75);
                    Expect(failures, "masquerade reason names the expected signer", fake.Reason.IndexOf("NVIDIA", StringComparison.OrdinalIgnoreCase) >= 0, "reason without 'NVIDIA'", "reason naming NVIDIA");
                    Expect(failures, "masquerade reason names the observed signer", fake.Reason.IndexOf("Totally Legit", StringComparison.OrdinalIgnoreCase) >= 0, "reason without the observed signer", "reason naming the observed signer");

                    // An entry with an empty ExpectedSigner does not check the signer at all, so it can
                    // never masquerade on signer grounds however odd the signature looks.
                    var obs = list.Evaluate("obs64.exe", "CN=Someone Nobody Has Heard Of", @"C:\Program Files\obs-studio\bin\64bit\obs64.exe");
                    Expect(failures, "empty ExpectedSigner never masquerades on signer grounds", obs.Outcome == AllowlistOutcome.Suppressed, obs.Outcome, AllowlistOutcome.Suppressed);

                    // An unreadable signature is not a wrong signature: down-rank, do not escalate.
                    var unreadable = list.Evaluate("nvcontainer.exe", null, @"C:\Program Files\NVIDIA Corporation\nvcontainer.exe");
                    Expect(failures, "unreadable signer down-ranks rather than escalating", unreadable.Outcome == AllowlistOutcome.DownRanked, unreadable.Outcome, AllowlistOutcome.DownRanked);

                    // Path pinning: the right name and signer in the wrong directory is a masquerade.
                    var wrongPath = list.Evaluate("ctfmon.exe", "CN=Microsoft Windows", @"C:\Users\x\AppData\Local\Temp\ctfmon.exe");
                    Expect(failures, "allowlisted name in the wrong directory masquerades", wrongPath.Outcome == AllowlistOutcome.Masquerade, wrongPath.Outcome, AllowlistOutcome.Masquerade);
                }

                // ---- Masquerade x1.75 is applied to the CLASS score, and never to Attribution.
                {
                    var list = TestAllowlist();
                    var s = Sig("x1", Tier.Strong, StateAxis.Running | StateAxis.Evading, 40, 40);
                    s.Subject = "nvcontainer.exe";
                    s.SubjectPath = @"C:\Users\x\AppData\Local\Temp\nvcontainer.exe";
                    s.Signer = "CN=Totally Legit Ltd";
                    list.Apply(s);

                    Expect(failures, "Apply stamps the masquerade outcome", s.Allowlist == AllowlistOutcome.Masquerade, s.Allowlist, AllowlistOutcome.Masquerade);
                    Expect(failures, "Apply stamps the 1.75 multiplier", Math.Abs(s.Multiplier - 1.75) < 0.0001, s.Multiplier, 1.75);
                    Expect(failures, "Apply records a reason", s.AllowlistReason.Length > 0, "(empty)", "a reason");

                    var r = Run(s);
                    Expect(failures, "masquerade raises the class score 40 -> 70", r.RunningClass.Score == 70, r.RunningClass.Score, 70);
                    Expect(failures, "masquerade reaches Detected on the class axis", r.RunningClass.Verdict == Verdict.Detected, r.RunningClass.Verdict, Verdict.Detected);
                    Expect(failures, "masquerade leaves attribution at 40", r.RunningAttribution.Score == 40, r.RunningAttribution.Score, 40);
                    Expect(failures, "masquerade does not accuse a specific vendor", r.RunningAttribution.Verdict == Verdict.Suspicious, r.RunningAttribution.Verdict, Verdict.Suspicious);
                }

                // ---- The real situation on the development machine: Parakeet AI is installed and
                //      registered to autostart, but is NOT running. Installed must read Detected while
                //      Running reads Clear. This is the axis-separation invariant.
                {
                    var signer = Sig("A1.signer", Tier.Definitive, StateAxis.Installed, 95, 60);
                    signer.Title = "Installed binary signed by PARAKEETAI d.o.o.";
                    signer.Subject = "parakeetai-desktop";

                    var scheme = Sig("A3.urlscheme", Tier.Strong, StateAxis.Installed, 80, 40);
                    scheme.Title = "URL scheme parakeetai registered to a local executable";

                    var autostart = Sig("A7.autostart", Tier.Moderate, StateAxis.Installed, 55, 30);
                    autostart.Title = "Registered to start automatically at logon";

                    var r = Run(signer, scheme, autostart);

                    Expect(failures, "installed-and-not-running: Installed is Detected", r.InstalledAttribution.Verdict == Verdict.Detected, r.InstalledAttribution.Verdict, Verdict.Detected);
                    Expect(failures, "installed-and-not-running: Installed scores 99", r.InstalledAttribution.Score == 99, r.InstalledAttribution.Score, 99);
                    Expect(failures, "installed-and-not-running: Running attribution is 0", r.RunningAttribution.Score == 0, r.RunningAttribution.Score, 0);
                    Expect(failures, "installed-and-not-running: Running attribution is Clear", r.RunningAttribution.Verdict == Verdict.Clear, r.RunningAttribution.Verdict, Verdict.Clear);
                    Expect(failures, "installed-and-not-running: Running class is Clear", r.RunningClass.Verdict == Verdict.Clear, r.RunningClass.Verdict, Verdict.Clear);
                    Expect(failures, "installed-and-not-running: Evading is Clear", r.EvadingClass.Verdict == Verdict.Clear, r.EvadingClass.Verdict, Verdict.Clear);
                    Expect(failures, "every axis has a rationale", r.RunningAttribution.Rationale.Length > 0 && r.InstalledAttribution.Rationale.Length > 0, "(empty rationale)", "a rationale");
                }

                // ---- A behavioural signal carries Attribution = 0, so it must never move the
                //      attribution axis even at Definitive tier.
                {
                    var hidden = Sig("B1.excludefromcapture", Tier.Definitive, StateAxis.Running | StateAxis.Evading, 0, 90);
                    var r = Run(hidden);
                    Expect(failures, "behavioural definitive leaves attribution at 0", r.RunningAttribution.Score == 0, r.RunningAttribution.Score, 0);
                    Expect(failures, "behavioural definitive leaves attribution Clear", r.RunningAttribution.Verdict == Verdict.Clear, r.RunningAttribution.Verdict, Verdict.Clear);
                    Expect(failures, "behavioural definitive still detects on the class axis", r.EvadingClass.Verdict == Verdict.Detected, r.EvadingClass.Verdict, Verdict.Detected);
                }

                // ---- An empty scan produces four answered-but-clean axes, never a null.
                {
                    var r = Run();
                    Expect(failures, "empty scan: Running attribution Clear", r.RunningAttribution.Verdict == Verdict.Clear, r.RunningAttribution.Verdict, Verdict.Clear);
                    Expect(failures, "empty scan: rationale is still written", r.RunningAttribution.Rationale.Length > 0, "(empty)", "a rationale");
                }
            }
            catch (Exception ex)
            {
                failures.Add("SelfTest threw " + ex.GetType().Name + ": " + ex.Message);
            }

            return failures;
        }

        private static Signal Sig(string id, Tier tier, StateAxis state, int attribution, int classScore)
        {
            return new Signal
            {
                Id = id,
                Title = id,
                Detail = "self-test signal",
                Tier = tier,
                State = state,
                Attribution = attribution,
                ClassScore = classScore,
                Source = "selftest"
            };
        }

        private static ScanReport Run(params Signal[] signals)
        {
            var report = new ScanReport();
            foreach (var s in signals) report.Signals.Add(s);
            Score(report);
            return report;
        }

        private static Allowlist TestAllowlist()
        {
            return new Allowlist(new List<AllowlistEntry>
            {
                new AllowlistEntry { ProcessName = "Zoom.exe", ExpectedSigner = "Zoom", ExpectedPathFragment = "", Verified = true, Note = "Meeting controls." },
                new AllowlistEntry { ProcessName = "Slack.exe", ExpectedSigner = "Slack", ExpectedPathFragment = "", Verified = false, Note = "Huddle overlay." },
                new AllowlistEntry { ProcessName = "nvcontainer.exe", ExpectedSigner = "NVIDIA", ExpectedPathFragment = "", Verified = true, Note = "NVIDIA container host." },
                new AllowlistEntry { ProcessName = "obs64.exe", ExpectedSigner = "", ExpectedPathFragment = "", Verified = true, Note = "OBS excludes its own preview." },
                new AllowlistEntry { ProcessName = "ctfmon.exe", ExpectedSigner = "Microsoft", ExpectedPathFragment = @"\Windows\", Verified = true, Note = "Text Services Framework." }
            });
        }

        private static void Expect(List<string> failures, string what, bool ok, object actual, object expected)
        {
            if (!ok)
            {
                failures.Add(what + ": expected " + expected + ", got " + actual + ".");
            }
        }
    }
}

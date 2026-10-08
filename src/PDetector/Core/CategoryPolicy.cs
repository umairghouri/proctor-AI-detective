using System;

namespace PDetector.Core
{
    /// <summary>
    /// Enforces what each vendor CATEGORY is allowed to assert, in exactly one place.
    ///
    /// The app detects a specific class of product: AI assistants that deliberately hide
    /// themselves from screen capture so they can be used during an interview or exam without
    /// the other party seeing them. Mainstream assistants - ChatGPT, Claude, Copilot, Gemini -
    /// are a different thing entirely. They are ordinary productivity software, they make no
    /// attempt to hide, and several hundred million people run them for honest work.
    ///
    /// Folding the two together would be the single worst thing this app could do. "ChatGPT is
    /// installed" scored as evidence of exam cheating would produce an enormous number of false
    /// accusations against people doing nothing wrong. So the policy is absolute and applied
    /// centrally rather than trusted to each scanner:
    ///
    ///     a general-assistant signal scores ZERO on BOTH axes, always.
    ///
    /// It is still recorded and still shown, because an invigilator running a closed-book exam
    /// may legitimately want to know that an AI assistant is open on the machine. But it is
    /// reported as an observation ("ChatGPT is running") and never as a contribution to a
    /// verdict about stealth tooling.
    ///
    /// This does not create a blind spot. The window scanner's capture-excluded signal (C1) is
    /// vendor-blind: if any program - a mainstream assistant included - ever hides a window from
    /// screen capture, C1 fires on the observed behaviour alone, with attribution 0. Behaviour
    /// is judged on behaviour; identity never grants an exemption.
    /// </summary>
    public static class CategoryPolicy
    {
        /// <summary>A tool of the capture-evading interview-assistant class. Scores normally.</summary>
        public const string InterviewCopilot = "interview-copilot";

        /// <summary>A mainstream AI assistant. Always scores zero on both axes.</summary>
        public const string GeneralAssistant = "general-assistant";

        /// <summary>
        /// Stamp every signal with its vendor's category and neutralise the scores of any signal
        /// belonging to a general assistant. Call once per scan, after all scanners have run and
        /// BEFORE <see cref="ScoreEngine.Score"/>.
        /// </summary>
        public static void Apply(ScanReport report, SignatureSet signatures)
        {
            if (report == null || signatures == null) return;

            foreach (Signal s in report.Signals)
            {
                if (s == null) continue;

                // A behavioural signal (hidden window, overlay) carries no vendor key. It is
                // judged purely on what it did, so it is never re-categorised here.
                if (string.IsNullOrEmpty(s.VendorKey)) continue;

                VendorSignature? vendor = signatures.ByKey(s.VendorKey);
                if (vendor == null) continue;

                s.Category = vendor.Category;
                s.VendorName = vendor.Name.Length > 0 ? vendor.Name : vendor.Key;

                if (!vendor.IsGeneralAssistant) continue;

                s.Attribution = 0;
                s.ClassScore = 0;
                s.Tier = Tier.Weak;

                // The whole point of the category is that this is NOT the thing we hunt, so say
                // so where a reader will see it rather than leaving a bare zero to interpret.
                s.Detail = s.Detail +
                    "  [Category: general AI assistant. This is ordinary productivity software " +
                    "that does not hide itself from screen capture, so it scores 0 towards every " +
                    "verdict and cannot on its own make this machine look suspicious. It is " +
                    "listed only so a reader running a closed-book assessment can see that an AI " +
                    "assistant was open. Its presence is not evidence of misconduct.]";
            }
        }

        /// <summary>True when this signal describes a mainstream assistant rather than a stealth tool.</summary>
        public static bool IsGeneralAssistant(Signal s)
        {
            return s != null
                && string.Equals(s.Category, GeneralAssistant, StringComparison.OrdinalIgnoreCase);
        }
    }
}

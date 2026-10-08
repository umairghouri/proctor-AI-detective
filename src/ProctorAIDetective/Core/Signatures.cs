using System;
using System.Collections.Generic;

namespace ProctorAIDetective.Core
{
    /// <summary>
    /// A vendor we can recognise. Deliberately data-driven and loaded from signatures.json:
    /// these products auto-update and rename constantly, and the primary target actively
    /// blanks its own filename, so a compiled-in list would rot into false accusations.
    /// </summary>
    public sealed class VendorSignature
    {
        /// <summary>Stable key, e.g. "parakeet".</summary>
        public string Key = "";
        public string Name = "";

        /// <summary>True for the product this build is primarily about (Parakeet AI).</summary>
        public bool PrimaryTarget;

        /// <summary>
        /// Authenticode signer Organization / Common Name substrings. THE definitive signal:
        /// a user can rename the exe, move it, blank its icon and retitle its window, but
        /// cannot re-sign it with the vendor's private key.
        /// </summary>
        public List<string> SignerContains = new List<string>();

        /// <summary>Known signing-cert thumbprints. Strong hint, but certs roll — never the sole key.</summary>
        public List<string> CertThumbprints = new List<string>();

        /// <summary>VersionInfo CompanyName exact matches.</summary>
        public List<string> CompanyNames = new List<string>();

        /// <summary>VersionInfo LegalCopyright substrings.</summary>
        public List<string> CopyrightContains = new List<string>();

        /// <summary>
        /// Custom URL schemes the installer registers, e.g. "parakeetai". Reading
        /// HKCU/HKLM\Software\Classes\&lt;scheme&gt;\shell\open\command yields the REAL installed
        /// exe path at runtime — strictly better than guessing a filename.
        /// </summary>
        public List<string> UrlSchemes = new List<string>();

        /// <summary>Literal process names. Expected to be empty or useless for stealth products.</summary>
        public List<string> ProcessNames = new List<string>();

        /// <summary>Case-insensitive path fragments, e.g. "\Programs\parakeetai-desktop\".</summary>
        public List<string> PathFragments = new List<string>();

        /// <summary>Window title substrings. Moderate at best: the vendor ships a blank-icon mode.</summary>
        public List<string> WindowTitleContains = new List<string>();

        /// <summary>Hostnames the product talks to. Used for DNS-cache and PID-attributed TCP checks.</summary>
        public List<string> Hostnames = new List<string>();

        /// <summary>Substrings identifying the web app in a browser tab title or URL.</summary>
        public List<string> WebFragments = new List<string>();

        /// <summary>Browser extension ids, when the vendor ships one.</summary>
        public List<string> ExtensionIds = new List<string>();

        /// <summary>
        /// What KIND of product this is. Two values matter:
        ///
        ///   "interview-copilot"  - a tool of the capture-evading class this app exists to find.
        ///                          Its signals feed the class score normally.
        ///   "general-assistant"  - a mainstream AI assistant (ChatGPT, Claude, Copilot, Gemini).
        ///                          Hundreds of millions of people run these for ordinary work.
        ///
        /// A general assistant is NOT a stealth tool: it does not hide from screen capture, it is
        /// not marketed for defeating interviews, and its presence is not evidence of the thing
        /// this app detects. Its signals are therefore forced to Attribution 0 AND ClassScore 0
        /// by <see cref="CategoryPolicy"/>, so they can never move any verdict. They are still
        /// reported, because "ChatGPT is open" is a fact an invigilator may legitimately want
        /// during an exam - but it is reported as a plain observation, never as an accusation.
        ///
        /// If such an app ever DID hide a window from capture, the window scanner's vendor-blind
        /// C1 signal still fires on its own merits. That is the correct outcome.
        /// </summary>
        public string Category = CategoryPolicy.InterviewCopilot;

        /// <summary>"verified" (observed first-hand) or "heuristic" (inferred, unproven).</summary>
        public string Confidence = "heuristic";

        public bool IsGeneralAssistant
        {
            get { return string.Equals(Category, CategoryPolicy.GeneralAssistant, StringComparison.OrdinalIgnoreCase); }
        }

        /// <summary>Where the signature came from, for the audit export.</summary>
        public string Source = "";

        public bool IsVerified
        {
            get { return string.Equals(Confidence, "verified", StringComparison.OrdinalIgnoreCase); }
        }
    }

    /// <summary>
    /// A legitimate process that is expected to hide windows from capture or paint invisible
    /// overlays. Keyed on the TRIPLE (name, signer, path) so the allowlist is a tripwire rather
    /// than a bypass: naming your binary "nvcontainer.exe" without NVIDIA's certificate
    /// escalates instead of suppressing.
    /// </summary>
    public sealed class AllowlistEntry
    {
        /// <summary>Process name including extension, case-insensitive.</summary>
        public string ProcessName = "";

        /// <summary>Required Authenticode signer substring. Empty means "signer not checked".</summary>
        public string ExpectedSigner = "";

        /// <summary>Required image-path substring. Empty means "path not checked".</summary>
        public string ExpectedPathFragment = "";

        /// <summary>
        /// True only when we confirmed first-hand that this process legitimately trips the
        /// signal. Unverified entries down-rank (x0.35) but never hard-suppress.
        /// </summary>
        public bool Verified;

        public string Note = "";
    }

    /// <summary>The whole signature database, loaded from signatures.json next to the exe.</summary>
    public sealed class SignatureSet
    {
        public string Version = "0";
        public string Updated = "";
        public List<VendorSignature> Vendors = new List<VendorSignature>();
        public List<AllowlistEntry> Allowlist = new List<AllowlistEntry>();

        /// <summary>
        /// Codepoints that render as blank. A filename composed entirely of these is the exact
        /// evasion Parakeet AI ships (U+2800 BRAILLE PATTERN BLANK), and is a strong CLASS
        /// signal for any stealth tool — but a weak ATTRIBUTION signal, since anyone can copy it.
        /// </summary>
        public List<int> InvisibleCodepoints = new List<int>();

        public VendorSignature? Primary
        {
            get
            {
                foreach (var v in Vendors) if (v.PrimaryTarget) return v;
                return null;
            }
        }

        public VendorSignature? ByKey(string key)
        {
            foreach (var v in Vendors)
                if (string.Equals(v.Key, key, StringComparison.OrdinalIgnoreCase)) return v;
            return null;
        }
    }

    /// <summary>Shared, read-only state handed to every scanner.</summary>
    public sealed class ScanContext
    {
        public SignatureSet Signatures = new SignatureSet();
        public Allowlist Allowlist = new Allowlist(new List<AllowlistEntry>());

        /// <summary>Whether the process is running elevated. Affects process-path resolution only.</summary>
        public bool Elevated;

        /// <summary>Opt-in: walk browser tab strips via UI Automation. Slower and can hang; off by default.</summary>
        public bool DeepBrowserScan = true;

        /// <summary>Opt-in: report the whole capture-evading class, not just the primary target.</summary>
        public bool ReportClassWide = true;

        /// <summary>Hard ceiling for any single scanner, in milliseconds.</summary>
        public int ScannerTimeoutMs = 8000;

        /// <summary>Set when the user cancels; scanners should check it between items.</summary>
        public System.Threading.CancellationToken Cancel = System.Threading.CancellationToken.None;
    }
}

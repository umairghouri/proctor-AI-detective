using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Reflection;
using System.Text;

namespace ProctorAIDetective.Core
{
    /// <summary>
    /// Loads <see cref="SignatureSet"/> from signatures.json, and carries a compiled-in fallback
    /// for when that file is missing or broken.
    ///
    /// Loading NEVER throws. A detector that refuses to run because somebody put a trailing comma
    /// in a config file is worse than useless: it fails silent on the exact machine the operator
    /// cared about. Every failure path here ends in a working (if reduced) signature set plus a
    /// human-readable sentence in the <c>error</c> out-parameter, which the UI shows verbatim so
    /// the reader knows the scan ran on built-in defaults rather than the shipped database.
    /// </summary>
    public static class SignatureLoader
    {
        /// <summary>Filename looked for in every candidate directory.</summary>
        public const string FileName = "signatures.json";

        /// <summary>Folder under %LOCALAPPDATA% holding the per-user override.</summary>
        public const string UserFolderName = "ProctorAIDetective";

        /// <summary>
        /// Version string of the compiled-in set. Deliberately not a date: it must be obvious in
        /// an exported report that the scan did NOT use the shipped signature database.
        /// </summary>
        public const string EmbeddedVersion = "builtin-1.0";

        /// <summary>Refuse anything larger. signatures.json is ~22 KB; 16 MB is already absurd.</summary>
        private const long MaxFileBytes = 16L * 1024 * 1024;

        /// <summary>Sentinel put in <c>sourcePath</c> when the compiled-in fallback was used.</summary>
        public const string EmbeddedSourcePath = "(built-in fallback)";

        // ------------------------------------------------------------------ loading

        /// <summary>
        /// Loads the signature database. Never throws.
        /// <paramref name="sourcePath"/> receives the file actually used, or
        /// <see cref="EmbeddedSourcePath"/>. <paramref name="error"/> is null on success and a
        /// complete sentence on failure.
        /// </summary>
        public static SignatureSet Load(out string sourcePath, out string? error)
        {
            List<string> ignored;
            return Load(out sourcePath, out error, out ignored);
        }

        /// <summary>
        /// As <see cref="Load(out string, out string?)"/>, but also reports non-fatal problems in
        /// the file that was successfully loaded: a vendor with no key, an allowlist row with no
        /// process name, a codepoint out of Unicode range. These are kept OUT of
        /// <paramref name="error"/> on purpose - <paramref name="error"/> means "we fell back to
        /// built-in defaults", and overloading it with cosmetic warnings would teach the operator
        /// to ignore the one message that matters.
        /// </summary>
        public static SignatureSet Load(out string sourcePath, out string? error, out List<string> warnings)
        {
            warnings = new List<string>();
            var failures = new List<string>();

            List<string> candidates = CandidatePaths();

            for (int i = 0; i < candidates.Count; i++)
            {
                string path = candidates[i];
                try
                {
                    if (!File.Exists(path)) continue;

                    var info = new FileInfo(path);
                    if (info.Length > MaxFileBytes)
                    {
                        failures.Add(Describe(path, "the file is " + info.Length +
                                     " bytes, past the " + MaxFileBytes + "-byte ceiling"));
                        continue;
                    }
                    if (info.Length == 0)
                    {
                        failures.Add(Describe(path, "the file is empty"));
                        continue;
                    }

                    // File.ReadAllText(path) detects a UTF-8/UTF-16 BOM and otherwise assumes
                    // UTF-8, which is what signatures.json is. MiniJson tolerates a stray BOM too.
                    string text = File.ReadAllText(path);

                    var fileWarnings = new List<string>();
                    SignatureSet set = FromJson(text, fileWarnings);

                    if (set.Vendors.Count == 0)
                    {
                        failures.Add(Describe(path, "it parsed but contains no usable vendor entries"));
                        continue;
                    }

                    sourcePath = path;
                    warnings = fileWarnings;

                    // A later candidate succeeded, but an earlier one was present and broken.
                    // That is worth saying out loud: the operator probably edited the wrong copy.
                    error = failures.Count == 0
                        ? null
                        : "Using " + path + ". An earlier signature file could not be read: " +
                          string.Join("; ", failures.ToArray());
                    return set;
                }
                catch (Exception ex)
                {
                    failures.Add(Describe(path, ex.GetType().Name + ": " + ex.Message));
                }
            }

            SignatureSet fallback = Embedded();
            sourcePath = EmbeddedSourcePath;

            if (failures.Count == 0)
            {
                error = FileName + " was not found next to the executable or in %LOCALAPPDATA%\\" +
                        UserFolderName + ". Using the built-in fallback signature set (" +
                        fallback.Version + "), which covers fewer products than the shipped database.";
            }
            else
            {
                error = FileName + " could not be loaded (" + string.Join("; ", failures.ToArray()) +
                        "). Using the built-in fallback signature set (" + fallback.Version +
                        "), which covers fewer products than the shipped database.";
            }
            return fallback;
        }

        /// <summary>
        /// Where signatures.json is looked for, in order:
        /// (1) next to the executable, (2) %LOCALAPPDATA%\ProctorAIDetective\signatures.json.
        /// Never throws; a candidate that cannot be built is simply omitted.
        /// </summary>
        public static List<string> CandidatePaths()
        {
            var paths = new List<string>();

            try
            {
                string baseDir = AppDomain.CurrentDomain.BaseDirectory;
                if (!string.IsNullOrEmpty(baseDir)) AddCandidate(paths, Path.Combine(baseDir, FileName));
            }
            catch { /* best effort */ }

            try
            {
                // Shadow-copied or single-file hosting can put the assembly somewhere other than
                // BaseDirectory. Cheap to check, and it is still "next to the executable".
                string asmPath = Assembly.GetExecutingAssembly().Location;
                if (!string.IsNullOrEmpty(asmPath))
                {
                    string? dir = Path.GetDirectoryName(asmPath);
                    if (!string.IsNullOrEmpty(dir)) AddCandidate(paths, Path.Combine(dir, FileName));
                }
            }
            catch { /* best effort */ }

            try
            {
                string local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
                if (!string.IsNullOrEmpty(local))
                    AddCandidate(paths, Path.Combine(Path.Combine(local, UserFolderName), FileName));
            }
            catch { /* best effort */ }

            return paths;
        }

        private static void AddCandidate(List<string> paths, string path)
        {
            string full;
            try { full = Path.GetFullPath(path); }
            catch { return; }

            for (int i = 0; i < paths.Count; i++)
                if (string.Equals(paths[i], full, StringComparison.OrdinalIgnoreCase)) return;

            paths.Add(full);
        }

        /// <summary>First existing candidate, or null when none is deployed. Never throws.</summary>
        public static string? FindSignatureFile()
        {
            List<string> candidates = CandidatePaths();
            for (int i = 0; i < candidates.Count; i++)
            {
                try { if (File.Exists(candidates[i])) return candidates[i]; }
                catch { /* unreadable candidate: treat as absent */ }
            }
            return null;
        }

        // ------------------------------------------------------------------ mapping

        /// <summary>
        /// Maps a signatures.json document onto <see cref="SignatureSet"/>.
        /// Throws <see cref="JsonParseException"/> on malformed JSON and
        /// <see cref="InvalidDataException"/> when the shape is wrong; <see cref="Load"/> catches
        /// both. Unknown keys - including every "_"-prefixed documentation key in the shipped
        /// file - are ignored in silence.
        /// </summary>
        public static SignatureSet FromJson(string text, List<string>? warnings)
        {
            if (text == null) throw new ArgumentNullException("text");

            JsonValue root = MiniJson.Parse(text);
            if (!root.IsObject)
                throw new InvalidDataException("the top-level JSON value is a " +
                                               root.Kind.ToString().ToLowerInvariant() +
                                               ", but signatures.json must be an object");

            var set = new SignatureSet();
            set.Version = Scalar(root, "version", "0");
            set.Updated = Scalar(root, "updated", "");

            // --- invisibleCodepoints
            JsonValue cps = root.Get("invisibleCodepoints", true);
            foreach (JsonValue cp in cps.Items)
            {
                if (!cp.IsNumber)
                {
                    Warn(warnings, "invisibleCodepoints contains a non-numeric entry; skipped.");
                    continue;
                }
                int value = cp.AsInt(-1);
                if (value < 0 || value > 0x10FFFF)
                {
                    Warn(warnings, "invisibleCodepoints entry " + value + " is outside Unicode; skipped.");
                    continue;
                }
                if (!set.InvisibleCodepoints.Contains(value)) set.InvisibleCodepoints.Add(value);
            }

            // --- vendors
            JsonValue vendors = root.Get("vendors", true);
            if (!vendors.IsArray) Warn(warnings, "there is no \"vendors\" array; no products can be attributed.");

            int vendorIndex = 0;
            foreach (JsonValue v in vendors.Items)
            {
                vendorIndex++;
                if (!v.IsObject)
                {
                    Warn(warnings, "vendors[" + (vendorIndex - 1) + "] is not an object; skipped.");
                    continue;
                }

                var vs = new VendorSignature();
                vs.Key = Scalar(v, "key", "");
                if (vs.Key.Length == 0)
                {
                    Warn(warnings, "vendors[" + (vendorIndex - 1) + "] has no \"key\"; skipped.");
                    continue;
                }

                vs.Name = Scalar(v, "name", vs.Key);
                vs.PrimaryTarget = v.Get("primaryTarget", true).AsBool(false);
                vs.Category = Scalar(v, "category", CategoryPolicy.InterviewCopilot);
                vs.Confidence = Scalar(v, "confidence", "heuristic");
                vs.Source = Scalar(v, "source", "");

                vs.SignerContains = StringList(v, "signerContains");
                vs.CertThumbprints = Thumbprints(v.Get("certThumbprints", true), vs.Key, warnings);
                vs.CompanyNames = StringList(v, "companyNames");
                vs.CopyrightContains = StringList(v, "copyrightContains");
                vs.UrlSchemes = StringList(v, "urlSchemes");
                vs.ProcessNames = StringList(v, "processNames");
                vs.PathFragments = StringList(v, "pathFragments");
                vs.WindowTitleContains = StringList(v, "windowTitleContains");
                vs.Hostnames = StringList(v, "hostnames");
                vs.WebFragments = StringList(v, "webFragments");
                vs.ExtensionIds = StringList(v, "extensionIds");

                if (!vs.Confidence.Equals("verified", StringComparison.OrdinalIgnoreCase) &&
                    !vs.Confidence.Equals("heuristic", StringComparison.OrdinalIgnoreCase))
                {
                    Warn(warnings, "vendor \"" + vs.Key + "\" has confidence \"" + vs.Confidence +
                                   "\"; only \"verified\" counts as first-hand, so it is treated as heuristic.");
                }

                if (set.ByKey(vs.Key) != null)
                {
                    Warn(warnings, "vendor key \"" + vs.Key + "\" appears more than once; only the first is used.");
                    continue;
                }

                set.Vendors.Add(vs);
            }

            int primaries = 0;
            for (int i = 0; i < set.Vendors.Count; i++) if (set.Vendors[i].PrimaryTarget) primaries++;
            if (primaries == 0 && set.Vendors.Count > 0)
                Warn(warnings, "no vendor is marked primaryTarget; the headline verdict has nothing to attribute to.");
            else if (primaries > 1)
                Warn(warnings, primaries + " vendors are marked primaryTarget; only the first is treated as the headline target.");

            // --- allowlist
            JsonValue allow = root.Get("allowlist", true);
            if (!allow.IsArray)
                Warn(warnings, "there is no \"allowlist\" array; every benign overlay will be reported as a finding.");

            int allowIndex = 0;
            foreach (JsonValue a in allow.Items)
            {
                allowIndex++;
                if (!a.IsObject)
                {
                    Warn(warnings, "allowlist[" + (allowIndex - 1) + "] is not an object; skipped.");
                    continue;
                }

                var entry = new AllowlistEntry();

                // NOT trimmed: an allowlisted name could itself be a blank-codepoint masquerade
                // target, and Trim() eats most of the codepoints in invisibleCodepoints.
                entry.ProcessName = RawScalar(a, "processName");
                if (entry.ProcessName.Length == 0)
                {
                    Warn(warnings, "allowlist[" + (allowIndex - 1) + "] has no \"processName\"; skipped.");
                    continue;
                }

                entry.ExpectedSigner = RawScalar(a, "expectedSigner");
                entry.ExpectedPathFragment = RawScalar(a, "expectedPathFragment");
                entry.Verified = a.Get("verified", true).AsBool(false);
                entry.Note = Scalar(a, "note", "");

                if (entry.Verified && entry.ExpectedSigner.Length == 0 && entry.ExpectedPathFragment.Length == 0)
                {
                    Warn(warnings, "allowlist entry \"" + entry.ProcessName +
                                   "\" is verified but pins neither a signer nor a path, so the name alone " +
                                   "suppresses it - anything renamed to that will be hidden.");
                }

                set.Allowlist.Add(entry);
            }

            return set;
        }

        /// <summary>Convenience overload for callers that do not want the warnings.</summary>
        public static SignatureSet FromJson(string text)
        {
            return FromJson(text, null);
        }

        private static void Warn(List<string>? warnings, string message)
        {
            if (warnings != null) warnings.Add(message);
        }

        /// <summary>
        /// A scalar string field, trimmed. Only used for fields that cannot legitimately be made
        /// of invisible whitespace: version, key, name, confidence, source, note.
        /// </summary>
        private static string Scalar(JsonValue obj, string key, string def)
        {
            JsonValue v = obj.Get(key, true);
            if (v.IsMissing || v.IsNull) return def;
            string s = v.AsString(def);
            return s.Trim();
        }

        /// <summary>
        /// A scalar string field, NOT trimmed. For anything that is matched against a real
        /// filename or path, where a leading U+2000-class character is signal rather than noise.
        /// </summary>
        private static string RawScalar(JsonValue obj, string key)
        {
            JsonValue v = obj.Get(key, true);
            if (v.IsMissing || v.IsNull) return "";
            return v.AsString("");
        }

        private static List<string> StringList(JsonValue obj, string key)
        {
            return obj.Get(key, true).AsStringList();
        }

        /// <summary>
        /// Normalises certificate thumbprints to the form X509Certificate2.Thumbprint returns:
        /// uppercase hex, no separators. Users paste these out of certmgr, which inserts spaces.
        /// </summary>
        private static List<string> Thumbprints(JsonValue array, string vendorKey, List<string>? warnings)
        {
            var result = new List<string>();
            foreach (string raw in array.AsStringList())
            {
                var sb = new StringBuilder(raw.Length);
                bool bad = false;
                for (int i = 0; i < raw.Length; i++)
                {
                    char c = raw[i];
                    if (c == ' ' || c == ':' || c == '-' || c == '\t') continue;
                    if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))
                    {
                        sb.Append(char.ToUpperInvariant(c));
                        continue;
                    }
                    bad = true;
                    break;
                }
                if (bad || sb.Length == 0)
                {
                    Warn(warnings, "vendor \"" + vendorKey + "\" has a certThumbprint that is not hexadecimal; skipped.");
                    continue;
                }
                string normalised = sb.ToString();
                if (!result.Contains(normalised)) result.Add(normalised);
            }
            return result;
        }

        // ------------------------------------------------------------------ writing

        /// <summary>
        /// Serialises a signature set back to the signatures.json shape. Used by the diagnostics
        /// export, by the self-test, and as the way a user turns the built-in fallback into a
        /// file they can edit. Output is pure ASCII: U+2800 appears as the escape \u2800.
        /// </summary>
        public static string ToJson(SignatureSet set, bool pretty)
        {
            if (set == null) throw new ArgumentNullException("set");

            var vendors = new List<object?>();
            for (int i = 0; i < set.Vendors.Count; i++)
            {
                VendorSignature v = set.Vendors[i];
                vendors.Add(MiniJson.Obj()
                    .Add("key", v.Key)
                    .Add("name", v.Name)
                    .Add("primaryTarget", v.PrimaryTarget)
                    .Add("category", v.Category)
                    .Add("confidence", v.Confidence)
                    .Add("source", v.Source)
                    .Add("signerContains", v.SignerContains)
                    .Add("certThumbprints", v.CertThumbprints)
                    .Add("companyNames", v.CompanyNames)
                    .Add("copyrightContains", v.CopyrightContains)
                    .Add("urlSchemes", v.UrlSchemes)
                    .Add("processNames", v.ProcessNames)
                    .Add("pathFragments", v.PathFragments)
                    .Add("windowTitleContains", v.WindowTitleContains)
                    .Add("hostnames", v.Hostnames)
                    .Add("webFragments", v.WebFragments)
                    .Add("extensionIds", v.ExtensionIds));
            }

            var allow = new List<object?>();
            for (int i = 0; i < set.Allowlist.Count; i++)
            {
                AllowlistEntry a = set.Allowlist[i];
                allow.Add(MiniJson.Obj()
                    .Add("processName", a.ProcessName)
                    .Add("expectedSigner", a.ExpectedSigner)
                    .Add("expectedPathFragment", a.ExpectedPathFragment)
                    .Add("verified", a.Verified)
                    .Add("note", a.Note));
            }

            JsonObjectBuilder root = MiniJson.Obj()
                .Add("version", set.Version)
                .Add("updated", set.Updated)
                .Add("invisibleCodepoints", set.InvisibleCodepoints)
                .Add("vendors", vendors)
                .Add("allowlist", allow);

            return MiniJson.Write(root, pretty);
        }

        // ------------------------------------------------------------------ fallback

        /// <summary>
        /// The compiled-in fallback. Deliberately a SUBSET of the shipped database, not a copy:
        /// duplicating 100 allowlist rows in source guarantees the two drift apart and the stale
        /// one silently wins. What is here is the verified Parakeet AI signature - which is the
        /// product this build exists to find - two heuristic class-mates, the invisible-codepoint
        /// table, and the allowlist rows most likely to fire during a video interview.
        ///
        /// A fresh instance every call: callers may mutate what they are handed.
        /// </summary>
        public static SignatureSet Embedded()
        {
            var set = new SignatureSet();
            set.Version = EmbeddedVersion;
            set.Updated = "2026-10-07";

            set.InvisibleCodepoints = new List<int>
            {
                0x2800, // BRAILLE PATTERN BLANK - what Parakeet AI's main executable is named
                0x200B, 0x200C, 0x200D, 0xFEFF, 0x00A0, 0x3164, 0x115F, 0x1160,
                0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005, 0x2006,
                0x2007, 0x2008, 0x2009, 0x200A,
                0x202F, 0x205F, 0x3000, 0x180E, 0x0020
            };

            // ---- primary target: verified first-hand on an installed copy of ParakeetAI 3.9.106
            var parakeet = new VendorSignature();
            parakeet.Key = "parakeet";
            parakeet.Name = "Parakeet AI";
            parakeet.PrimaryTarget = true;
            parakeet.Confidence = "verified";
            parakeet.Source = "Built-in fallback. Observed first-hand 2026-10-07 on an installed copy of " +
                              "ParakeetAI 3.9.106 (%LOCALAPPDATA%\\Programs\\parakeetai-desktop). " +
                              "Load signatures.json for the full, maintained database.";
            parakeet.SignerContains = new List<string> { "PARAKEETAI d.o.o.", "O=PARAKEETAI" };
            parakeet.CertThumbprints = new List<string> { "59C214EE88435D2AE141B6222519DD9204892F12" };
            parakeet.CompanyNames = new List<string> { "ParakeetAI" };
            parakeet.CopyrightContains = new List<string> { "ParakeetAI" };
            parakeet.UrlSchemes = new List<string> { "parakeetai" };
            // U+2800 + ".exe". Written as an escape so this source file stays pure ASCII.
            parakeet.ProcessNames = new List<string> { "\u2800.exe", "Uninstall \u2800.exe" };
            parakeet.PathFragments = new List<string>
            {
                "\\Programs\\parakeetai-desktop\\",
                "\\parakeetai-desktop-updater\\",
                "\\AppData\\Roaming\\parakeetai-desktop"
            };
            parakeet.WindowTitleContains = new List<string> { "ParakeetAI", "Parakeet AI" };
            parakeet.Hostnames = new List<string> { "parakeet-ai.com", "www.parakeet-ai.com", "rt.speechmatics.com" };
            parakeet.WebFragments = new List<string> { "parakeet-ai.com", "ParakeetAI" };
            set.Vendors.Add(parakeet);

            // ---- two class-mates, so a fallback scan is not blind to the wider product class.
            var cluely = new VendorSignature();
            cluely.Key = "cluely";
            cluely.Name = "Cluely";
            cluely.Confidence = "heuristic";
            cluely.Source = "Built-in fallback. Installer artifact verified; runtime names inferred from the " +
                            "electron-builder default layout, not observed.";
            cluely.CompanyNames = new List<string> { "Cluely" };
            cluely.CopyrightContains = new List<string> { "Cluely" };
            cluely.UrlSchemes = new List<string> { "cluely" };
            cluely.ProcessNames = new List<string> { "Cluely.exe", "Open-Cluely.exe" };
            cluely.PathFragments = new List<string> { "\\Programs\\cluely\\", "\\Open-Cluely" };
            cluely.WindowTitleContains = new List<string> { "Cluely" };
            cluely.Hostnames = new List<string> { "cluely.com", "api.v2.cluely.com" };
            cluely.WebFragments = new List<string> { "cluely.com" };
            set.Vendors.Add(cluely);

            var interviewCoder = new VendorSignature();
            interviewCoder.Key = "interviewcoder";
            interviewCoder.Name = "Interview Coder";
            interviewCoder.Confidence = "heuristic";
            interviewCoder.Source = "Built-in fallback. electron-builder config from release v1.0.33; " +
                                    "runtime exe inferred from productName.";
            interviewCoder.UrlSchemes = new List<string> { "interviewcoder" };
            interviewCoder.ProcessNames = new List<string> { "Interview Coder.exe" };
            interviewCoder.PathFragments = new List<string> { "\\Programs\\interview-coder", "\\Programs\\Interview Coder" };
            interviewCoder.WindowTitleContains = new List<string> { "Interview Coder" };
            interviewCoder.Hostnames = new List<string> { "interviewcoder.co" };
            interviewCoder.WebFragments = new List<string> { "interviewcoder.co" };
            set.Vendors.Add(interviewCoder);

            // ---- allowlist: the rows most likely to fire during a real video interview.
            // Microsoft-signed shell components are path-pinned to \Windows\, because those names
            // are the obvious masquerade targets and a name-only rule would be a free bypass.
            AddAllow(set, "Zoom.exe", "Zoom", "", true, "Meeting controls / screen-share toolbar. The single most likely benign hit during an interview.");
            AddAllow(set, "CptHost.exe", "Zoom", "", true, "Zoom screen-share control toolbar: topmost, no-activate, excluded from its own capture.");
            AddAllow(set, "ms-teams.exe", "Microsoft", "", true, "Teams share toolbar.");
            AddAllow(set, "Teams.exe", "Microsoft", "", true, "Teams (classic) share toolbar.");
            AddAllow(set, "Slack.exe", "Slack", "", false, "Huddle overlay.");
            AddAllow(set, "Webex.exe", "Cisco", "", false, "Webex share toolbar.");
            AddAllow(set, "Discord.exe", "Discord", "", false, "In-game overlay.");

            AddAllow(set, "msedge.exe", "Microsoft", "", true, "Sets capture protection for DRM video playback.");
            AddAllow(set, "chrome.exe", "Google", "", true, "Sets capture protection for DRM video playback.");

            AddAllow(set, "1Password.exe", "AgileBits", "", false, "Password manager. Process name confirmed; capture-protection use assumed.");
            AddAllow(set, "Bitwarden.exe", "Bitwarden", "", false, "Electron password manager; setContentProtection is one line.");

            AddAllow(set, "NVIDIA Share.exe", "NVIDIA", "", true, "ShadowPlay / GeForce Experience overlay.");
            AddAllow(set, "nvcontainer.exe", "NVIDIA", "", true, "NVIDIA container host.");
            AddAllow(set, "NVDisplay.Container.exe", "NVIDIA", "", true, "NVIDIA display container.");
            AddAllow(set, "GameBar.exe", "Microsoft", "", false, "Xbox Game Bar.");

            // verified=false ON PURPOSE. OBS genuinely excludes its own preview from capture, but
            // we have not confirmed its Authenticode signer first-hand, and a verified row that
            // pins neither signer nor path suppresses on the NAME alone - i.e. anything renamed
            // to obs64.exe would vanish from the report. Down-ranking (x0.35) keeps the evidence
            // visible. Pin a signer here and this can be promoted.
            AddAllow(set, "obs64.exe", "", "", false, "OBS excludes its own preview from capture. Signer not pinned, so this only down-ranks.");
            AddAllow(set, "ShareX.exe", "ShareX", "", true, "Region-select overlay: topmost, layered, click-through.");
            AddAllow(set, "ScreenSketch.exe", "Microsoft", "", true, "Snipping Tool region overlay.");

            AddAllow(set, "PowerToys.exe", "Microsoft", "", true, "FancyZones / ColorPicker / CropAndLock paint topmost overlays.");
            AddAllow(set, "PowerToys.PowerLauncher.exe", "Microsoft", "", true, "PowerToys Run.");

            AddAllow(set, "TextInputHost.exe", "Microsoft", "\\Windows\\", true, "Windows IME / touch keyboard. Path-pinned: an obvious masquerade target.");
            AddAllow(set, "ctfmon.exe", "Microsoft", "\\Windows\\", true, "Text Services Framework; owns CiceroUIWndFrame windows everywhere.");
            AddAllow(set, "ApplicationFrameHost.exe", "Microsoft", "\\Windows\\", true, "UWP frame host; its windows are routinely shell-cloaked.");
            AddAllow(set, "explorer.exe", "Microsoft", "\\Windows\\", true, "Shell.");
            AddAllow(set, "LogonUI.exe", "Microsoft", "\\Windows\\", true, "Secure desktop / Windows Hello UI.");
            AddAllow(set, "consent.exe", "Microsoft", "\\Windows\\", true, "UAC secure desktop.");
            AddAllow(set, "Magnify.exe", "Microsoft", "\\Windows\\", true, "Magnifier.");

            AddAllow(set, "ShellExperienceHost.exe", "Microsoft", "", true, "Shell UI.");
            AddAllow(set, "StartMenuExperienceHost.exe", "Microsoft", "", true, "Start menu.");
            AddAllow(set, "SearchHost.exe", "Microsoft", "", true, "Windows Search UI.");

            return set;
        }

        private static void AddAllow(SignatureSet set, string processName, string signer,
                                     string pathFragment, bool verified, string note)
        {
            var e = new AllowlistEntry();
            e.ProcessName = processName;
            e.ExpectedSigner = signer;
            e.ExpectedPathFragment = pathFragment;
            e.Verified = verified;
            e.Note = note;
            set.Allowlist.Add(e);
        }

        // ------------------------------------------------------------------ helpers

        private static string Describe(string path, string problem)
        {
            return path + " - " + problem;
        }

        /// <summary>
        /// One-line summary for the diagnostics pane, e.g.
        /// "signatures 2026.10.07.1 (8 vendors, 97 allowlist entries) from C:\...\signatures.json".
        /// </summary>
        public static string Summarise(SignatureSet set, string sourcePath)
        {
            if (set == null) return "no signature set";
            return string.Format(CultureInfo.InvariantCulture,
                "signatures {0} ({1} vendor{2}, {3} allowlist entr{4}, {5} invisible codepoints) from {6}",
                set.Version,
                set.Vendors.Count, set.Vendors.Count == 1 ? "" : "s",
                set.Allowlist.Count, set.Allowlist.Count == 1 ? "y" : "ies",
                set.InvisibleCodepoints.Count,
                string.IsNullOrEmpty(sourcePath) ? EmbeddedSourcePath : sourcePath);
        }
    }
}

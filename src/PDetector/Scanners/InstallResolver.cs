using System;
using System.Collections.Generic;
using System.IO;
using Microsoft.Win32;
using PDetector.Core;

namespace PDetector.Scanners
{
    /// <summary>
    /// One custom URL scheme registration that we successfully read back, plus whatever the
    /// registered command line turned out to point at.
    ///
    /// This is the single highest-value installation lookup the app performs. Every other
    /// "is it installed" check has to GUESS a filename or a directory; this one reads the
    /// real, absolute, current path straight out of the registration the product's own
    /// installer wrote. It survives the product being installed to a non-default directory,
    /// and - critically for the primary target - it survives the executable being named
    /// U+2800 BRAILLE PATTERN BLANK, because the scheme name "parakeetai" is plain ASCII
    /// and is chosen by the vendor, not by the user.
    /// </summary>
    public sealed class ResolvedInstall
    {
        /// <summary>VendorSignature.Key this registration belongs to.</summary>
        public string VendorKey { get; set; } = "";

        /// <summary>The scheme as it appears in signatures.json, e.g. "parakeetai" (no "://").</summary>
        public string Scheme { get; set; } = "";

        /// <summary>The raw default value of ...\shell\open\command, verbatim, unexpanded.</summary>
        public string CommandLine { get; set; } = "";

        /// <summary>The executable parsed out of <see cref="CommandLine"/>, environment-expanded. "" when unparseable.</summary>
        public string ExePath { get; set; } = "";

        /// <summary>True when <see cref="ExePath"/> names a file that exists right now.</summary>
        public bool ExeExists { get; set; }

        /// <summary>Full registry path the value was read from, for the audit export.</summary>
        public string Source { get; set; } = "";

        public override string ToString()
        {
            return Scheme + ":// -> " + (ExePath.Length == 0 ? "<unparsed>" : ExePath)
                 + (ExeExists ? " (exists)" : " (missing)") + " [" + Source + "]";
        }
    }

    /// <summary>
    /// Resolves installed products by reading the custom URL-scheme handlers their installers
    /// register under Software\Classes.
    ///
    /// Never throws. Every failure - a missing hive, a denied key, a malformed command string -
    /// produces fewer results, never an exception, because this runs inside a scanner whose
    /// contract forbids throwing.
    /// </summary>
    public static class InstallResolver
    {
        /// <summary>Relative key path template below a Classes root.</summary>
        private const string CommandSubKeyFormat = @"Software\Classes\{0}\shell\open\command";

        /// <summary>
        /// For every URL scheme named by every vendor in <paramref name="sigs"/>, read
        /// HKCU\Software\Classes\&lt;scheme&gt;\shell\open\command and then the HKLM equivalent
        /// (64-bit view, then 32-bit view), and resolve each registration to a concrete exe path.
        ///
        /// Per-user (HKCU) registrations are read first because that is where per-user Electron
        /// installers - the shape every product in this class ships - actually write. The result
        /// is de-duplicated per (vendor, scheme, exe path): when HKCU and HKLM name the same
        /// binary it is reported once, and only a genuinely different target produces a second row.
        /// </summary>
        /// <returns>Possibly empty, never null.</returns>
        public static List<ResolvedInstall> Resolve(SignatureSet sigs)
        {
            List<ResolvedInstall> results = new List<ResolvedInstall>();
            if (sigs == null || sigs.Vendors == null) return results;

            // (vendorKey|scheme|exePath) already emitted, case-insensitive.
            HashSet<string> seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (VendorSignature vendor in sigs.Vendors)
            {
                if (vendor == null || vendor.UrlSchemes == null) continue;

                foreach (string rawScheme in vendor.UrlSchemes)
                {
                    string scheme = NormalizeScheme(rawScheme);
                    if (scheme.Length == 0) continue;

                    TryOne(results, seen, vendor.Key, scheme, RegistryHive.CurrentUser, RegistryView.Default, "HKCU");
                    TryOne(results, seen, vendor.Key, scheme, RegistryHive.LocalMachine, RegistryView.Registry64, "HKLM");
                    // The 32-bit view only differs on 64-bit Windows, and only for the parts of
                    // Software\Classes that are redirected. Reading it is cheap and catches a
                    // product installed by a 32-bit installer that wrote under Wow6432Node.
                    TryOne(results, seen, vendor.Key, scheme, RegistryHive.LocalMachine, RegistryView.Registry32, "HKLM(32-bit view)");
                }
            }

            return results;
        }

        /// <summary>
        /// Read one scheme from one hive/view and append a result if the key exists.
        /// Swallows everything: a denied or absent key is an ordinary outcome here.
        /// </summary>
        private static void TryOne(
            List<ResolvedInstall> results,
            HashSet<string> seen,
            string vendorKey,
            string scheme,
            RegistryHive hive,
            RegistryView view,
            string hiveLabel)
        {
            string subKey = string.Format(System.Globalization.CultureInfo.InvariantCulture, CommandSubKeyFormat, scheme);

            string? command = ReadDefaultValue(hive, view, subKey);
            if (command == null) return;

            command = command.Trim();
            if (command.Length == 0) return;

            string exePath = ParseExePath(command);
            bool exists = FileExists(exePath);

            string key = vendorKey + "|" + scheme + "|" + exePath;
            if (!seen.Add(key)) return;

            ResolvedInstall ri = new ResolvedInstall();
            ri.VendorKey = vendorKey ?? "";
            ri.Scheme = scheme;
            ri.CommandLine = command;
            ri.ExePath = exePath;
            ri.ExeExists = exists;
            ri.Source = hiveLabel + "\\" + subKey;
            results.Add(ri);
        }

        /// <summary>Read a key's default (unnamed) value as a string, or null. Never throws.</summary>
        private static string? ReadDefaultValue(RegistryHive hive, RegistryView view, string subKey)
        {
            try
            {
                using (RegistryKey baseKey = RegistryKey.OpenBaseKey(hive, view))
                {
                    if (baseKey == null) return null;
                    using (RegistryKey? key = baseKey.OpenSubKey(subKey, false))
                    {
                        if (key == null) return null;
                        object? value = key.GetValue(null);
                        string? s = value as string;
                        if (s == null) return null;
                        return s;
                    }
                }
            }
            catch (Exception)
            {
                // Denied, hive unavailable, or the key vanished mid-read. Not an error here.
                return null;
            }
        }

        /// <summary>
        /// Pull the executable out of a shell\open\command value.
        ///
        /// Handles the two forms that occur in the wild:
        ///   "C:\path with spaces\app.exe" "%1"      -> quoted, the overwhelmingly common form
        ///   C:\path\app.exe %1                      -> unquoted
        ///
        /// The unquoted form is genuinely ambiguous (an unquoted path may contain spaces), so it
        /// is resolved by cutting at the first ".exe" rather than at the first space: cutting at
        /// the space would turn "C:\Program Files\x\a.exe" into "C:\Program", which then fails
        /// File.Exists and silently downgrades a real install to a "stale registration".
        ///
        /// Environment variables are expanded, since REG_EXPAND_SZ registrations are legal here.
        /// Public so a test harness can exercise the parser without touching the registry.
        /// Never throws; returns "" when nothing usable is present.
        /// </summary>
        public static string ParseExePath(string? command)
        {
            if (command == null) return "";

            string s = command.Trim();
            if (s.Length == 0) return "";

            string candidate;

            if (s[0] == '"')
            {
                int close = s.IndexOf('"', 1);
                candidate = close > 1 ? s.Substring(1, close - 1) : s.Substring(1);
            }
            else
            {
                int exe = s.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
                if (exe >= 0)
                {
                    candidate = s.Substring(0, exe + 4);
                }
                else
                {
                    int ws = s.IndexOfAny(new[] { ' ', '\t' });
                    candidate = ws > 0 ? s.Substring(0, ws) : s;
                }
            }

            candidate = candidate.Trim().Trim('"').Trim();
            if (candidate.Length == 0) return "";

            // A command whose only token is the placeholder is not a path.
            if (candidate == "%1" || candidate == "%*") return "";

            try
            {
                if (candidate.IndexOf('%') >= 0)
                    candidate = Environment.ExpandEnvironmentVariables(candidate);
            }
            catch (Exception)
            {
                // Leave the unexpanded form; it may still be a literal path.
            }

            return candidate.Trim();
        }

        /// <summary>File.Exists that cannot throw on a malformed or over-long path.</summary>
        private static bool FileExists(string path)
        {
            if (string.IsNullOrEmpty(path)) return false;
            try { return File.Exists(path); }
            catch (Exception) { return false; }
        }

        /// <summary>
        /// Reduce a signature's scheme entry to a bare scheme name usable as a registry key:
        /// strips "://", a trailing ":", surrounding whitespace, and rejects anything containing
        /// a path separator (which would let a malformed signature file walk the registry).
        /// </summary>
        private static string NormalizeScheme(string? raw)
        {
            if (raw == null) return "";

            string s = raw.Trim();
            if (s.Length == 0) return "";

            int sep = s.IndexOf("://", StringComparison.Ordinal);
            if (sep >= 0) s = s.Substring(0, sep);
            if (s.EndsWith(":", StringComparison.Ordinal)) s = s.Substring(0, s.Length - 1);

            s = s.Trim();
            if (s.Length == 0) return "";
            if (s.IndexOf('\\') >= 0 || s.IndexOf('/') >= 0) return "";

            return s;
        }
    }
}

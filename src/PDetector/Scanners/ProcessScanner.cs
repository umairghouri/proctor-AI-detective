using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Text;
using PDetector.Core;
using PDetector.Native;

namespace PDetector.Scanners
{
    /// <summary>
    /// Identifies vendor software from the running process table and from the URL-scheme
    /// registrations their installers leave behind.
    ///
    /// Two deliberate design rules run through everything below.
    ///
    /// 1. ATTRIBUTION IS EARNED BY CRYPTOGRAPHY, NOT BY APPEARANCE. The signals are ordered so
    ///    that the Authenticode signer - the one property a user cannot forge or rename away -
    ///    outranks the version resource, which outranks the install path, which outranks the
    ///    filename. A filename match is the weakest thing in this file precisely because the
    ///    primary target has already defeated filename matching by naming its executable
    ///    U+2800 BRAILLE PATTERN BLANK.
    ///
    /// 2. STATE IS NOT CONFIDENCE. "Installed" and "running right now" are different questions
    ///    with different answers, and the headline the user reads is the running one. Every
    ///    signal this scanner emits declares exactly one of them. The URL-scheme evidence, which
    ///    is the strongest installation evidence available anywhere in the app, is marked
    ///    StateAxis.Installed and therefore cannot move the running verdict off Clear - which is
    ///    the correct and verified behaviour on this machine, where Parakeet AI is installed and
    ///    not running.
    /// </summary>
    public sealed class ProcessScanner : IScanner
    {
        /// <summary>Stable scanner id; also the value written to Signal.Source and ScanReport.Timings.</summary>
        public const string ScannerId = "process";

        public string Id { get { return ScannerId; } }

        public string DisplayName { get { return "Running processes and installed products"; } }

        // ------------------------------------------------------------------ entry point

        /// <summary>
        /// Contract: MUST NOT throw. Every stage below is independently guarded so that a failure
        /// in one of them costs that stage's evidence and nothing else.
        /// </summary>
        public void Scan(ScanContext context, ScanReport report)
        {
            if (report == null) return;

            Stopwatch sw = Stopwatch.StartNew();
            try
            {
                if (context == null)
                {
                    report.Limitations.Add(
                        "The process scanner was invoked without a scan context and did not run. " +
                        "No process or installation evidence was collected.");
                    return;
                }

                SignatureSet sigs = context.Signatures ?? new SignatureSet();

                IReadOnlyList<ProcessInfo> processes = CollectProcesses(context, report);
                RecordCoverage(context, report, processes);

                // Running axis: who is executing right now.
                try
                {
                    EmitProcessSignals(context, report, sigs, processes);
                }
                catch (Exception ex)
                {
                    report.Limitations.Add(
                        "Identifying vendors in the process table failed part-way (" + Describe(ex) +
                        "). Some running processes were not checked against the signature database.");
                }

                // Installed axis (plus one running-axis corroboration): what the registry says is here.
                try
                {
                    EmitInstallSignals(context, report, sigs, processes);
                }
                catch (Exception ex)
                {
                    report.Limitations.Add(
                        "Reading registered URL-scheme handlers failed (" + Describe(ex) +
                        "). Installation evidence from protocol registrations is missing from this report.");
                }
            }
            catch (Exception ex)
            {
                report.Limitations.Add(
                    "The process scanner failed outright (" + Describe(ex) +
                    "). Treat the absence of process and installation evidence in this report as unknown, not clean.");
            }
            finally
            {
                sw.Stop();
                report.Timings[ScannerId] = sw.ElapsedMilliseconds;
            }
        }

        // ------------------------------------------------------------------ collection / coverage

        private static IReadOnlyList<ProcessInfo> CollectProcesses(ScanContext context, ScanReport report)
        {
            try
            {
                // includeCommandLines: ONE machine-wide WMI query, joined by pid. Measured at
                // ~130 ms on top of a warm collection. Never query WMI per process.
                return ProcessInfoCollector.CollectAll(true, context.Cancel);
            }
            catch (Exception ex)
            {
                report.Limitations.Add(
                    "The process table could not be enumerated (" + Describe(ex) +
                    "). No running-process evidence was collected at all.");
                return new List<ProcessInfo>();
            }
        }

        /// <summary>
        /// Fill in the two coverage counters and state the blind spot they describe. A detector
        /// that reports "nothing found" after failing to read 40% of the machine is lying by
        /// omission, so the unresolved count is always carried through to the report.
        /// </summary>
        private static void RecordCoverage(ScanContext context, ScanReport report, IReadOnlyList<ProcessInfo> processes)
        {
            int total = processes.Count;
            int unresolved = 0;
            for (int i = 0; i < total; i++)
            {
                ProcessInfo p = processes[i];
                if (p != null && !p.PathResolved) unresolved++;
            }

            report.ProcessesScanned = total;
            report.ProcessPathsUnresolved = unresolved;

            if (total == 0 || unresolved == 0) return;

            // "Many" = at least a tenth of the machine, and at least a handful in absolute terms.
            bool many = unresolved >= 5 && unresolved * 10 >= total;
            if (!many) return;

            string fraction = unresolved.ToString(CultureInfo.InvariantCulture) + " of "
                            + total.ToString(CultureInfo.InvariantCulture) + " processes ("
                            + ((unresolved * 100) / total).ToString(CultureInfo.InvariantCulture) + "%)";

            if (!context.Elevated)
            {
                report.Limitations.Add(
                    "Could not read the executable path for " + fraction + ", so their signer, company name " +
                    "and install location were never checked. These are processes owned by other users or by " +
                    "the system. Running P-Detector as an administrator resolves substantially more: measured " +
                    "on this class of machine, 259 of 428 paths resolve without elevation against 428 of 430 with it.");
            }
            else
            {
                report.Limitations.Add(
                    "Could not read the executable path for " + fraction + " even while elevated; those processes " +
                    "were not checked against the signature database. Protected-process-light and a few kernel " +
                    "processes refuse the query by design.");
            }
        }

        // ------------------------------------------------------------------ running-axis signals

        /// <summary>
        /// One pass over the process table producing, per (vendor, rule, executable), at most one
        /// signal.
        ///
        /// Grouping by executable rather than by process is deliberate. An Electron product -
        /// which every product in this class is - runs six to ten processes off a single binary.
        /// Emitting the identical "signer matches" finding ten times would both bury the evidence
        /// grid and inflate the noisy-OR aggregate from the multiplicity of one fact, which is
        /// exactly the failure the tier caps exist to prevent. The pid list is preserved in the
        /// detail text, so nothing is lost.
        /// </summary>
        private static void EmitProcessSignals(
            ScanContext context, ScanReport report, SignatureSet sigs, IReadOnlyList<ProcessInfo> processes)
        {
            if (processes.Count == 0) return;

            List<VendorSignature> vendors = SelectVendors(context, sigs);
            List<int> invisible = sigs.InvisibleCodepoints ?? new List<int>();

            Dictionary<string, Group> groups = new Dictionary<string, Group>(StringComparer.Ordinal);
            bool cancelled = false;

            for (int i = 0; i < processes.Count; i++)
            {
                if (context.Cancel.IsCancellationRequested) { cancelled = true; break; }

                ProcessInfo info = processes[i];
                if (info == null) continue;

                try
                {
                    for (int v = 0; v < vendors.Count; v++)
                        MatchVendor(groups, vendors[v], info, sigs);

                    MatchBlankName(groups, info, invisible);
                }
                catch (Exception)
                {
                    // One unreadable process never costs the rest of the table.
                }
            }

            if (cancelled)
                report.Limitations.Add("The scan was cancelled while the process table was being examined; some processes were never checked.");

            foreach (KeyValuePair<string, Group> kv in groups)
                Emit(context, report, kv.Value.Finish());
        }

        /// <summary>
        /// Which vendors this scan reports on.
        ///
        /// ScanContext.ReportClassWide off means the operator asked specifically about the primary
        /// target, so the other vendors are not reported at all. When it is on they are reported,
        /// but always with Attribution 0: attribution answers "is this Parakeet AI", and a Cluely
        /// signature is not evidence about Parakeet AI. Only the class score carries them.
        /// </summary>
        private static List<VendorSignature> SelectVendors(ScanContext context, SignatureSet sigs)
        {
            List<VendorSignature> result = new List<VendorSignature>();
            if (sigs.Vendors == null) return result;

            foreach (VendorSignature v in sigs.Vendors)
            {
                if (v == null) continue;
                if (!v.PrimaryTarget && !context.ReportClassWide) continue;
                result.Add(v);
            }
            return result;
        }

        /// <summary>
        /// Apply A1..A4 to one process for one vendor and record the FIRST rule that fits.
        /// Only the strongest applicable rule is kept: four restatements of one process's identity
        /// are one piece of evidence, not four.
        /// </summary>
        private static void MatchVendor(Dictionary<string, Group> groups, VendorSignature vendor, ProcessInfo info, SignatureSet sigs)
        {
            bool primary = vendor.PrimaryTarget;
            string vendorName = vendor.Name.Length > 0 ? vendor.Name : vendor.Key;
            string displayName = DisplayFileName(info);
            string imageKey = info.PathResolved && info.ImagePath.Length > 0
                ? info.ImagePath
                : "name:" + info.Name;

            // ---- A1: Authenticode signer. The rename-proof signal.
            string signerHit = FirstContained(info.SignerSubject, vendor.SignerContains);
            if (signerHit.Length > 0)
            {
                bool thumbHit = MatchesThumbprint(info.CertThumbprint, vendor.CertThumbprints);

                StringBuilder d = new StringBuilder();
                d.Append("The Authenticode signer subject on this executable is \"").Append(info.SignerSubject)
                 .Append("\", which contains \"").Append(signerHit).Append("\" from the ").Append(vendorName)
                 .Append(" signature. An executable can be renamed, moved, re-iconed and given a blank window title, ")
                 .Append("but it cannot be re-signed without the vendor's private key.");
                if (thumbHit)
                {
                    d.Append(" The signing certificate thumbprint is also an exact match: ")
                     .Append(info.CertThumbprint).Append(".");
                }
                else if (vendor.CertThumbprints != null && vendor.CertThumbprints.Count > 0)
                {
                    d.Append(" The certificate thumbprint (")
                     .Append(info.CertThumbprint.Length > 0 ? info.CertThumbprint : "unreadable")
                     .Append(") is not one of the recorded ones, which is expected after a certificate roll.");
                }
                if (!info.SignatureChainValid)
                {
                    d.Append(" Note: the certificate chain did not validate at scan time, so the signature is ")
                     .Append("present but not currently trusted.");
                }

                Record(groups, vendor.Key + "|A1|" + imageKey, info, primary,
                       "A1.signer",
                       vendorName + ": Authenticode signer matches",
                       Tier.Definitive,
                       thumbHit ? 98 : 95,
                       90,
                       vendor.Key, displayName, d.ToString());
                return;
            }

            // ---- A2: version resource. Independent of the filename, written at build time.
            string companyHit = FirstExact(info.CompanyName, vendor.CompanyNames);
            string copyrightHit = FirstContained(info.LegalCopyright, vendor.CopyrightContains);
            if (companyHit.Length > 0 || copyrightHit.Length > 0)
            {
                StringBuilder d = new StringBuilder();
                if (companyHit.Length > 0)
                {
                    d.Append("The file's version resource declares CompanyName \"").Append(info.CompanyName)
                     .Append("\", an exact match for the ").Append(vendorName).Append(" signature.");
                }
                if (copyrightHit.Length > 0)
                {
                    if (d.Length > 0) d.Append(" ");
                    d.Append("Its LegalCopyright is \"").Append(info.LegalCopyright)
                     .Append("\", which contains \"").Append(copyrightHit).Append("\".");
                }
                d.Append(" The version resource is compiled into the binary and is unaffected by renaming the file.");
                if (info.FileVersion.Length > 0) d.Append(" FileVersion is ").Append(info.FileVersion).Append(".");
                if (info.SignerSubject.Length == 0)
                {
                    d.Append(" No embedded Authenticode signature could be read from this file, so the stronger ")
                     .Append("signer check could not be applied (a file may still be catalog-signed).");
                }

                Record(groups, vendor.Key + "|A2|" + imageKey, info, primary,
                       "A2.versioninfo",
                       vendorName + ": version resource matches",
                       Tier.Definitive, 90, 85,
                       vendor.Key, displayName, d.ToString());
                return;
            }

            // ---- A3: install path.
            string pathHit = info.PathResolved ? FirstContained(info.ImagePath, vendor.PathFragments) : "";
            if (pathHit.Length > 0)
            {
                string d = "The executable is running from \"" + info.ImagePath + "\", which contains the "
                         + vendorName + " install-path fragment \"" + pathHit + "\". The directory name is written "
                         + "by the vendor's installer; it is weaker than the signature because a user can copy a "
                         + "different program into that folder.";

                Record(groups, vendor.Key + "|A3|" + imageKey, info, primary,
                       "A3.path",
                       vendorName + ": running from its install directory",
                       Tier.Strong, 70, 65,
                       vendor.Key, displayName, d);
                return;
            }

            // ---- A3 fallback: the command line, used ONLY when the image path is unreadable.
            // Restricted to that case on purpose. If the path resolved, matching the command line
            // as well would flag any benign program that merely received the path as an argument -
            // a text editor opening a file in that folder, for instance. It is also scored a full
            // tier lower, because a command-line mention is an argument, not an identity.
            if (!info.PathResolved && info.CommandLine.Length > 0)
            {
                string cmdHit = FirstContained(info.CommandLine, vendor.PathFragments);
                if (cmdHit.Length > 0)
                {
                    string d = "This process's executable path could not be read (" +
                               (info.PathFailureReason.Length > 0 ? info.PathFailureReason : "reason unavailable") +
                               "), but its command line contains the " + vendorName + " install-path fragment \"" +
                               cmdHit + "\". Command line: " + Truncate(info.CommandLine, 300) +
                               ". This is an argument, not proof of the program's own identity.";

                    Record(groups, vendor.Key + "|A3c|" + imageKey, info, primary,
                           "A3.cmdline",
                           vendorName + ": install path appears in a process command line",
                           Tier.Moderate, 40, 35,
                           vendor.Key, displayName, d);
                    return;
                }
            }

            // ---- A4: filename. Last, and weakest, because the primary target already defeats it.
            string nameHit = FirstProcessNameMatch(info, vendor.ProcessNames);
            if (nameHit.Length > 0)
            {
                string d = "The process name is \"" + Visible(nameHit) + "\", a literal match for a known "
                         + vendorName + " executable name. A filename is user-controlled and proves very little "
                         + "on its own; it is reported because it corroborates stronger findings.";

                Record(groups, vendor.Key + "|A4|" + imageKey, info, primary,
                       "A4.name",
                       vendorName + ": process name matches",
                       Tier.Moderate, 45, 40,
                       vendor.Key, displayName, d);
            }
        }

        /// <summary>
        /// B1 - the blank-filename heuristic. This is the signal that actually defeats the evasion
        /// the primary target ships: its main executable is named U+2800 BRAILLE PATTERN BLANK,
        /// which Task Manager renders as nothing at all.
        ///
        /// Attribution is deliberately near-zero (10, not 90). Naming a file with an invisible
        /// codepoint is one rename away for anybody; it proves that SOMETHING is hiding its name,
        /// not that the something is Parakeet AI. The class score carries the finding instead.
        /// </summary>
        private static void MatchBlankName(Dictionary<string, Group> groups, ProcessInfo info, List<int> invisibleCodepoints)
        {
            if (invisibleCodepoints.Count == 0) return;

            string basename = BaseNameWithoutExtension(info);
            if (basename.Length == 0) return;
            if (!IsEntirelyInvisible(basename, invisibleCodepoints)) return;

            string display = DisplayFileName(info);
            string imageKey = info.PathResolved && info.ImagePath.Length > 0 ? info.ImagePath : "name:" + info.Name;

            StringBuilder d = new StringBuilder();
            d.Append("The executable's base name is ")
             .Append(basename.Length.ToString(CultureInfo.InvariantCulture))
             .Append(basename.Length == 1 ? " character: " : " characters: ")
             .Append(DescribeCodepoints(basename))
             .Append("; it renders as blank in Task Manager and in any process list. ");
            if (info.PathResolved && info.ImagePath.Length > 0)
                d.Append("Full path: ").Append(Visible(info.ImagePath)).Append(". ");
            d.Append("Every one of those codepoints is on the invisible-codepoint list in the signature database. ")
             .Append("This proves that a running program is concealing its own name. It does NOT identify which ")
             .Append("program: any software can be renamed this way, which is why the attribution score on this ")
             .Append("finding is near zero.");

            Record(groups, "|B1|" + imageKey, info, /*primary:*/ true,
                   "B1.blankname",
                   "Executable name is invisible",
                   Tier.Strong,
                   10,   // attribution: near zero by design
                   45,
                   "", display, d.ToString());
        }

        // ------------------------------------------------------------------ installed-axis signals

        /// <summary>
        /// C1/C2 - resolve each vendor's registered URL scheme to a real executable.
        ///
        /// C1 is marked StateAxis.Installed and ONLY Installed. That is the whole point: on the
        /// machine this was developed against, Parakeet AI is installed, autostart-registered and
        /// not running, and the app has to be able to say exactly that. ScoreEngine selects signals
        /// by state mask, so a C1 signal contributes to InstalledAttribution and contributes
        /// literally nothing to RunningAttribution or RunningClass, which stay Clear.
        ///
        /// C2 is the separate, explicit statement that the resolved binary is live right now, and
        /// it is the only part of this method that touches the running axis.
        /// </summary>
        private static void EmitInstallSignals(
            ScanContext context, ScanReport report, SignatureSet sigs, IReadOnlyList<ProcessInfo> processes)
        {
            List<ResolvedInstall> installs = InstallResolver.Resolve(sigs);
            if (installs.Count == 0) return;

            foreach (ResolvedInstall ri in installs)
            {
                if (context.Cancel.IsCancellationRequested) break;
                if (ri == null) continue;

                VendorSignature? vendor = sigs.ByKey(ri.VendorKey);
                bool primary = vendor != null && vendor.PrimaryTarget;
                if (!primary && !context.ReportClassWide) continue;

                string vendorName = vendor != null && vendor.Name.Length > 0 ? vendor.Name : ri.VendorKey;
                string display = ri.ExePath.Length > 0 ? Visible(SafeFileName(ri.ExePath)) : ri.Scheme + "://";

                // ---------- C1
                Signal c1 = new Signal();
                c1.Source = ScannerId;
                c1.VendorKey = ri.VendorKey;
                c1.State = StateAxis.Installed;
                c1.Subject = display;
                c1.SubjectPath = ri.ExePath;
                c1.Pid = 0;

                StringBuilder d = new StringBuilder();
                d.Append("The custom URL scheme \"").Append(ri.Scheme).Append("://\" is registered on this machine ")
                 .Append("under ").Append(ri.Source).Append(", with the command: ")
                 .Append(Visible(Truncate(ri.CommandLine, 400))).Append(". ");

                ProcessInfo? file = null;
                if (ri.ExeExists)
                {
                    try { file = ProcessInfoCollector.DescribeImageFile(ri.ExePath); }
                    catch (Exception) { file = null; }
                }

                if (ri.ExeExists)
                {
                    c1.Id = "C1.urlscheme";
                    c1.Title = vendorName + ": installed (registered " + ri.Scheme + ":// handler)";
                    c1.Tier = Tier.Definitive;
                    c1.Attribution = primary ? 92 : 0;
                    c1.ClassScore = 85;

                    d.Append("It points at \"").Append(Visible(ri.ExePath)).Append("\", which exists on disk. ")
                     .Append("A URL-scheme handler is written by the product's own installer and the scheme name is ")
                     .Append("chosen by the vendor, so it identifies the product even when the executable itself has ")
                     .Append("been renamed to something unreadable.");

                    if (file != null)
                    {
                        c1.Signer = file.SignerSubject;
                        AppendFileEvidence(d, file, vendor, vendorName);
                    }

                    d.Append(" This is evidence of INSTALLATION only. It says nothing whatever about whether the ")
                     .Append("program is running: the running verdict is decided solely by live-process evidence.");
                }
                else
                {
                    c1.Id = "C1.urlscheme.stale";
                    c1.Title = vendorName + ": stale " + ri.Scheme + ":// handler registration";
                    c1.Tier = Tier.Moderate;
                    c1.Attribution = primary ? 40 : 0;
                    c1.ClassScore = 35;

                    d.Append("It points at \"")
                     .Append(ri.ExePath.Length > 0 ? Visible(ri.ExePath) : "<no executable could be parsed from the command>")
                     .Append("\", which does NOT exist on disk. That is what an uninstall leaves behind, or what a ")
                     .Append("moved installation looks like. It is evidence the product was installed at some point, ")
                     .Append("not that it is installed now, and it is not evidence that anything is running.");
                }

                c1.Detail = d.ToString();
                Emit(context, report, c1);

                // ---------- C2
                if (!ri.ExeExists || ri.ExePath.Length == 0) continue;

                List<int> livePids = new List<int>();
                foreach (ProcessInfo p in processes)
                {
                    if (p == null || !p.PathResolved || p.ImagePath.Length == 0) continue;
                    if (string.Equals(p.ImagePath, ri.ExePath, StringComparison.OrdinalIgnoreCase))
                        livePids.Add(p.Pid);
                }
                if (livePids.Count == 0) continue;

                livePids.Sort();

                Signal c2 = new Signal();
                c2.Id = "C2.urlscheme.running";
                c2.Source = ScannerId;
                c2.VendorKey = ri.VendorKey;
                c2.State = StateAxis.Running;
                c2.Tier = Tier.Definitive;
                c2.Attribution = primary ? 95 : 0;
                c2.ClassScore = 90;
                c2.Title = vendorName + ": its registered executable is running now";
                c2.Subject = display;
                c2.SubjectPath = ri.ExePath;
                c2.Signer = file != null ? file.SignerSubject : "";
                c2.Pid = livePids[0];
                c2.Detail =
                    "The executable named by the registered \"" + ri.Scheme + "://\" handler is executing right now. " +
                    FormatPids(livePids) + ". The match is on the full image path (\"" + Visible(ri.ExePath) +
                    "\"), not on the filename, so it holds regardless of what the file is called. This is the " +
                    "registry registration and the live process table agreeing with each other.";

                Emit(context, report, c2);
            }
        }

        /// <summary>Append what the on-disk file itself says, which either corroborates the registration or contradicts it.</summary>
        private static void AppendFileEvidence(StringBuilder d, ProcessInfo file, VendorSignature? vendor, string vendorName)
        {
            if (file.SignerSubject.Length > 0)
            {
                string hit = vendor != null ? FirstContained(file.SignerSubject, vendor.SignerContains) : "";
                d.Append(" The file's Authenticode signer subject is \"").Append(file.SignerSubject).Append("\"");
                if (hit.Length > 0)
                {
                    d.Append(", which matches the ").Append(vendorName).Append(" signer \"").Append(hit).Append("\"");
                    if (vendor != null && MatchesThumbprint(file.CertThumbprint, vendor.CertThumbprints))
                        d.Append(", and the certificate thumbprint ").Append(file.CertThumbprint).Append(" matches exactly");
                }
                else
                {
                    d.Append(", which does NOT match any recorded ").Append(vendorName)
                     .Append(" signer - the handler may have been re-pointed at a different program");
                }
                d.Append(".");
            }
            else
            {
                d.Append(" The file carries no readable embedded Authenticode signature (it may still be ")
                 .Append("catalog-signed, which this check cannot see).");
            }

            if (file.CompanyName.Length > 0 || file.FileVersion.Length > 0)
            {
                d.Append(" Version resource:");
                if (file.CompanyName.Length > 0) d.Append(" CompanyName \"").Append(Visible(file.CompanyName)).Append("\"");
                if (file.ProductName.Length > 0) d.Append(", ProductName \"").Append(Visible(file.ProductName)).Append("\"");
                if (file.FileVersion.Length > 0) d.Append(", FileVersion ").Append(file.FileVersion);
                d.Append(".");
            }
        }

        // ------------------------------------------------------------------ emit

        /// <summary>Allowlist every signal before it reaches the report, then add it. Never throws.</summary>
        private static void Emit(ScanContext context, ScanReport report, Signal signal)
        {
            if (signal == null) return;
            try
            {
                Allowlist allowlist = context.Allowlist;
                if (allowlist != null) allowlist.Apply(signal);
            }
            catch (Exception)
            {
                // A failed allowlist lookup leaves the signal at its default x1.0 pass-through,
                // which is the conservative direction: nothing is silently hidden.
            }
            report.Signals.Add(signal);
        }

        // ------------------------------------------------------------------ grouping

        /// <summary>
        /// Accumulates every process that produced the same finding about the same executable.
        /// </summary>
        private sealed class Group
        {
            public Signal Signal = new Signal();
            public string Core = "";
            public List<int> Pids = new List<int>();

            public Signal Finish()
            {
                Pids.Sort();
                Signal.Pid = Pids.Count > 0 ? Pids[0] : 0;
                Signal.Detail = Core + " " + FormatPids(Pids) + ".";
                return Signal;
            }
        }

        private static void Record(
            Dictionary<string, Group> groups,
            string key,
            ProcessInfo info,
            bool primary,
            string id,
            string title,
            Tier tier,
            int attribution,
            int classScore,
            string vendorKey,
            string subject,
            string detailCore)
        {
            Group g;
            if (!groups.TryGetValue(key, out g))
            {
                g = new Group();
                g.Core = detailCore;

                Signal s = new Signal();
                s.Id = id;
                s.Title = title;
                s.Tier = tier;
                // Attribution answers "is this the primary target"; for any other vendor it is 0
                // by construction, and the class score carries the finding instead.
                s.Attribution = primary ? attribution : 0;
                s.ClassScore = classScore;
                s.State = StateAxis.Running;
                s.VendorKey = vendorKey;
                s.Subject = subject;
                s.SubjectPath = info.PathResolved ? info.ImagePath : "";
                s.Signer = info.SignerSubject;
                s.Source = ScannerId;

                g.Signal = s;
                groups[key] = g;
            }

            if (!g.Pids.Contains(info.Pid)) g.Pids.Add(info.Pid);
        }

        private static string FormatPids(List<int> pids)
        {
            if (pids.Count == 0) return "No process id was recorded";
            if (pids.Count == 1) return "Observed in process id " + pids[0].ToString(CultureInfo.InvariantCulture);

            StringBuilder sb = new StringBuilder();
            sb.Append("Observed in ").Append(pids.Count.ToString(CultureInfo.InvariantCulture))
              .Append(" processes sharing this executable (pids ");
            int shown = pids.Count < 10 ? pids.Count : 10;
            for (int i = 0; i < shown; i++)
            {
                if (i > 0) sb.Append(", ");
                sb.Append(pids[i].ToString(CultureInfo.InvariantCulture));
            }
            if (shown < pids.Count) sb.Append(", and ").Append((pids.Count - shown).ToString(CultureInfo.InvariantCulture)).Append(" more");
            sb.Append(")");
            return sb.ToString();
        }

        // ------------------------------------------------------------------ invisible-name rendering

        /// <summary>
        /// Codepoints that occupy space but paint nothing, used by <see cref="Visible"/>.
        ///
        /// This is a compiled-in copy rather than a read of SignatureSet.InvisibleCodepoints on
        /// purpose: Visible() is a pure display helper called from scanners and from the UI, in
        /// places that have no signature set to hand, and a rendering function that can silently
        /// start printing nothing because a JSON file was edited is a rendering function that will
        /// eventually hide the evidence. DETECTION reads the signature file; DISPLAY does not.
        /// </summary>
        private static readonly int[] BlankCodepoints =
        {
            0x0020, // SPACE - escaped only when a name is nothing but blanks (see Visible)
            0x00A0, // NO-BREAK SPACE
            0x180E, // MONGOLIAN VOWEL SEPARATOR
            0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005, 0x2006,
            0x2007, 0x2008, 0x2009, 0x200A,
            0x200B, // ZERO WIDTH SPACE
            0x200C, // ZERO WIDTH NON-JOINER
            0x200D, // ZERO WIDTH JOINER
            0x202F, // NARROW NO-BREAK SPACE
            0x205F, // MEDIUM MATHEMATICAL SPACE
            0x2060, // WORD JOINER
            0x2800, // BRAILLE PATTERN BLANK  <- what the primary target is actually named
            0x3000, // IDEOGRAPHIC SPACE
            0x115F, // HANGUL CHOSEONG FILLER
            0x1160, // HANGUL JUNGSEONG FILLER
            0x3164, // HANGUL FILLER
            0xFEFF  // ZERO WIDTH NO-BREAK SPACE / BOM
        };

        private static readonly HashSet<int> BlankSet = BuildBlankSet();

        private static HashSet<int> BuildBlankSet()
        {
            HashSet<int> set = new HashSet<int>();
            for (int i = 0; i < BlankCodepoints.Length; i++) set.Add(BlankCodepoints[i]);
            return set;
        }

        /// <summary>
        /// Render a string so that characters which paint nothing become visible, e.g.
        /// "⠀.exe" becomes "⟨U+2800⟩.exe".
        ///
        /// Exported for every other scanner and for the UI, because a blank name printed blank is
        /// the one thing this application must never do. The whole product exists because a
        /// filename that renders as nothing walked straight past Task Manager; reproducing that
        /// bug in our own evidence grid would be the single worst defect available to us.
        ///
        /// An ordinary space is left alone so that "Interview Coder.exe" stays readable - UNLESS
        /// the entire string is blank characters, in which case the spaces are escaped too and the
        /// caller still gets something to look at. Never throws.
        /// </summary>
        public static string Visible(string? name)
        {
            if (string.IsNullOrEmpty(name)) return "";

            string s = name!;

            bool allBlank = true;
            for (int i = 0; i < s.Length; i++)
            {
                if (!BlankSet.Contains(s[i])) { allBlank = false; break; }
            }

            bool anyToEscape = false;
            for (int i = 0; i < s.Length; i++)
            {
                char c = s[i];
                if (c == ' ' && !allBlank) continue;
                if (BlankSet.Contains(c) || char.IsControl(c)) { anyToEscape = true; break; }
            }
            if (!anyToEscape) return s;

            StringBuilder sb = new StringBuilder(s.Length + 16);
            for (int i = 0; i < s.Length; i++)
            {
                char c = s[i];
                if (c == ' ' && !allBlank) { sb.Append(c); continue; }

                if (BlankSet.Contains(c) || char.IsControl(c))
                {
                    sb.Append('⟨').Append("U+")
                      .Append(((int)c).ToString("X4", CultureInfo.InvariantCulture))
                      .Append('⟩');
                }
                else
                {
                    sb.Append(c);
                }
            }
            return sb.ToString();
        }

        /// <summary>"1 character: U+2800 BRAILLE PATTERN BLANK" style enumeration, for the detail text.</summary>
        private static string DescribeCodepoints(string s)
        {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < s.Length; i++)
            {
                if (i > 0) sb.Append(", ");
                int cp = s[i];
                sb.Append("U+").Append(cp.ToString("X4", CultureInfo.InvariantCulture));
                string label = CodepointName(cp);
                if (label.Length > 0) sb.Append(' ').Append(label);
            }
            return sb.ToString();
        }

        private static string CodepointName(int cp)
        {
            switch (cp)
            {
                case 0x0020: return "SPACE";
                case 0x00A0: return "NO-BREAK SPACE";
                case 0x180E: return "MONGOLIAN VOWEL SEPARATOR";
                case 0x2000: return "EN QUAD";
                case 0x2001: return "EM QUAD";
                case 0x2002: return "EN SPACE";
                case 0x2003: return "EM SPACE";
                case 0x2004: return "THREE-PER-EM SPACE";
                case 0x2005: return "FOUR-PER-EM SPACE";
                case 0x2006: return "SIX-PER-EM SPACE";
                case 0x2007: return "FIGURE SPACE";
                case 0x2008: return "PUNCTUATION SPACE";
                case 0x2009: return "THIN SPACE";
                case 0x200A: return "HAIR SPACE";
                case 0x200B: return "ZERO WIDTH SPACE";
                case 0x200C: return "ZERO WIDTH NON-JOINER";
                case 0x200D: return "ZERO WIDTH JOINER";
                case 0x202F: return "NARROW NO-BREAK SPACE";
                case 0x205F: return "MEDIUM MATHEMATICAL SPACE";
                case 0x2060: return "WORD JOINER";
                case 0x2800: return "BRAILLE PATTERN BLANK";
                case 0x3000: return "IDEOGRAPHIC SPACE";
                case 0x115F: return "HANGUL CHOSEONG FILLER";
                case 0x1160: return "HANGUL JUNGSEONG FILLER";
                case 0x3164: return "HANGUL FILLER";
                case 0xFEFF: return "ZERO WIDTH NO-BREAK SPACE";
                default: return "";
            }
        }

        /// <summary>
        /// True when every character of <paramref name="s"/> is on the signature file's
        /// invisible-codepoint list. The DETECTION side reads the data file, not the compiled-in
        /// display list, so a new evasion codepoint can be added without a rebuild.
        /// </summary>
        private static bool IsEntirelyInvisible(string s, List<int> invisible)
        {
            if (s.Length == 0) return false;
            for (int i = 0; i < s.Length; i++)
            {
                int cp = s[i];
                bool found = false;
                for (int j = 0; j < invisible.Count; j++)
                {
                    if (invisible[j] == cp) { found = true; break; }
                }
                if (!found) return false;
            }
            return true;
        }

        // ------------------------------------------------------------------ small helpers

        /// <summary>Base name with the extension removed; prefers the resolved path over the OS process name.</summary>
        private static string BaseNameWithoutExtension(ProcessInfo info)
        {
            if (info.PathResolved && info.ImagePath.Length > 0)
            {
                try
                {
                    string n = Path.GetFileNameWithoutExtension(info.ImagePath);
                    if (!string.IsNullOrEmpty(n)) return n;
                }
                catch (Exception) { }
            }
            return info.Name;
        }

        /// <summary>Filename as it should appear in the UI: with extension where known, always rendered visibly.</summary>
        private static string DisplayFileName(ProcessInfo info)
        {
            if (info.PathResolved && info.ImagePath.Length > 0)
            {
                string f = SafeFileName(info.ImagePath);
                if (f.Length > 0) return Visible(f);
            }
            return Visible(info.Name);
        }

        private static string SafeFileName(string path)
        {
            try
            {
                string f = Path.GetFileName(path);
                return f ?? "";
            }
            catch (Exception) { return ""; }
        }

        /// <summary>First needle contained in <paramref name="haystack"/>, case-insensitively, or "".</summary>
        private static string FirstContained(string? haystack, List<string>? needles)
        {
            if (haystack == null || haystack.Length == 0 || needles == null) return "";
            for (int i = 0; i < needles.Count; i++)
            {
                string n = needles[i];
                // An empty needle is contained in everything; a malformed signature file must not
                // be able to match every process on the machine.
                if (string.IsNullOrEmpty(n)) continue;
                if (haystack.IndexOf(n, StringComparison.OrdinalIgnoreCase) >= 0) return n;
            }
            return "";
        }

        /// <summary>First candidate exactly equal to <paramref name="value"/> (trimmed, case-insensitive), or "".</summary>
        private static string FirstExact(string? value, List<string>? candidates)
        {
            if (value == null || candidates == null) return "";
            string v = value.Trim();
            if (v.Length == 0) return "";
            for (int i = 0; i < candidates.Count; i++)
            {
                string c = candidates[i];
                if (string.IsNullOrEmpty(c)) continue;
                if (string.Equals(v, c.Trim(), StringComparison.OrdinalIgnoreCase)) return c;
            }
            return "";
        }

        /// <summary>
        /// Exact process-name match, comparing both with and without ".exe" because the OS reports
        /// "chrome" while signatures.json records "chrome.exe".
        /// </summary>
        private static string FirstProcessNameMatch(ProcessInfo info, List<string>? names)
        {
            if (names == null || names.Count == 0) return "";

            string withExt = info.PathResolved && info.ImagePath.Length > 0 ? SafeFileName(info.ImagePath) : "";
            string bare = info.Name;

            for (int i = 0; i < names.Count; i++)
            {
                string n = names[i];
                if (string.IsNullOrEmpty(n)) continue;

                if (withExt.Length > 0 && string.Equals(withExt, n, StringComparison.OrdinalIgnoreCase)) return n;
                if (bare.Length > 0 && string.Equals(bare, n, StringComparison.OrdinalIgnoreCase)) return n;

                string stripped = n.Length > 4 && n.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
                    ? n.Substring(0, n.Length - 4)
                    : n;
                if (bare.Length > 0 && string.Equals(bare, stripped, StringComparison.OrdinalIgnoreCase)) return n;
            }
            return "";
        }

        /// <summary>Thumbprint comparison tolerant of the spaces certmgr inserts when you copy one out.</summary>
        private static bool MatchesThumbprint(string? observed, List<string>? expected)
        {
            if (observed == null || expected == null) return false;
            string o = StripNonHex(observed);
            if (o.Length == 0) return false;
            for (int i = 0; i < expected.Count; i++)
            {
                string e = expected[i];
                if (string.IsNullOrEmpty(e)) continue;
                if (string.Equals(o, StripNonHex(e), StringComparison.OrdinalIgnoreCase)) return true;
            }
            return false;
        }

        private static string StripNonHex(string s)
        {
            StringBuilder sb = new StringBuilder(s.Length);
            for (int i = 0; i < s.Length; i++)
            {
                char c = s[i];
                if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) sb.Append(c);
            }
            return sb.ToString();
        }

        private static string Truncate(string s, int max)
        {
            if (s.Length <= max) return s;
            return s.Substring(0, max) + "... (truncated)";
        }

        private static string Describe(Exception ex)
        {
            return ex.GetType().Name + ": " + ex.Message;
        }
    }
}

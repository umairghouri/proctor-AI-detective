using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Windows.Forms;
using ProctorAIDetective.Core;
using ProctorAIDetective.Ui;

namespace ProctorAIDetective
{
    internal static class Program
    {
        private const string AppName = "Proctor AI Detective";

        [STAThread]
        private static int Main(string[] args)
        {
            // Parse before touching WinForms: the headless modes must not create a message loop.
            var cli = CommandLine.Parse(args);

            if (cli.ShowHelp)
            {
                WriteConsole(CommandLine.HelpText(), false);
                return 0;
            }

            if (cli.SelfTest) return RunSelfTest();
            if (cli.Headless) return RunHeadless(cli);

            return RunGui();
        }

        // ------------------------------------------------------------------ GUI

        private static int RunGui()
        {
            // Last-resort handlers so a bug surfaces as a readable dialog rather than the
            // raw .NET crash box. A tool that makes claims about people should fail legibly.
            Application.ThreadException += (s, e) => ShowCrash(e.Exception, false);
            AppDomain.CurrentDomain.UnhandledException += (s, e) => ShowCrash(e.ExceptionObject as Exception, true);
            Application.SetUnhandledExceptionMode(UnhandledExceptionMode.CatchException);

            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            // Note: Application.SetHighDpiMode does not exist on .NET Framework 4.8.
            // DPI awareness is declared in app.manifest (PerMonitorV2) instead.

            try
            {
                Application.Run(new MainForm());
                return 0;
            }
            catch (Exception ex)
            {
                ShowCrash(ex, true);
                return 1;
            }
        }

        private static void ShowCrash(Exception? ex, bool fatal)
        {
            string detail = ex == null ? "Unknown error." : ex.ToString();
            string head = fatal
                ? AppName + " hit an unrecoverable error and has to close."
                : AppName + " hit an error. The scan may be incomplete.";

            try
            {
                MessageBox.Show(
                    head + Environment.NewLine + Environment.NewLine +
                    detail + Environment.NewLine + Environment.NewLine +
                    "Nothing was changed on this machine - " + AppName + " only reads.",
                    AppName + " - error",
                    MessageBoxButtons.OK,
                    fatal ? MessageBoxIcon.Error : MessageBoxIcon.Warning);
            }
            catch
            {
                // If even the dialog fails there is nothing useful left to do.
            }

            if (fatal) Environment.Exit(1);
        }

        // ------------------------------------------------------------------ --selftest

        private static int RunSelfTest()
        {
            var sb = new StringBuilder();
            int failures = 0;

            sb.AppendLine(AppName + " self-test");
            sb.AppendLine(new string('=', 60));
            sb.AppendLine();

            failures += RunSuite(sb, "MiniJson", SafeSuite(MiniJson.SelfTest));
            failures += RunSuite(sb, "ScoreEngine", SafeSuite(ScoreEngine.SelfTest));

            // Loading the real signature file is part of the self-test: a malformed
            // signatures.json silently falling back to the built-in set is exactly the kind
            // of quiet degradation that makes a detector wrong without looking wrong.
            sb.AppendLine("Signatures");
            sb.AppendLine(new string('-', 60));
            try
            {
                string source;
                string? error;
                List<string> warnings;
                var set = SignatureLoader.Load(out source, out error, out warnings);

                sb.AppendLine("  source   : " + (string.IsNullOrEmpty(source) ? "(built-in fallback)" : source));
                sb.AppendLine("  version  : " + set.Version);
                sb.AppendLine("  vendors  : " + set.Vendors.Count);
                sb.AppendLine("  allowlist: " + set.Allowlist.Count);

                if (!string.IsNullOrEmpty(error))
                {
                    sb.AppendLine("  FAIL     : " + error);
                    failures++;
                }
                foreach (var w in warnings) sb.AppendLine("  warning  : " + w);

                if (set.Primary == null)
                {
                    sb.AppendLine("  FAIL     : no vendor is marked primaryTarget");
                    failures++;
                }
            }
            catch (Exception ex)
            {
                sb.AppendLine("  FAIL     : " + ex.Message);
                failures++;
            }
            sb.AppendLine();

            sb.AppendLine(new string('=', 60));
            sb.AppendLine(failures == 0 ? "PASS - all self-tests green." : "FAIL - " + failures + " problem(s).");

            WriteConsole(sb.ToString(), failures != 0);
            return failures == 0 ? 0 : 1;
        }

        private static Func<List<string>> SafeSuite(Func<List<string>> suite)
        {
            return () =>
            {
                try { return suite() ?? new List<string>(); }
                catch (Exception ex) { return new List<string> { "suite threw: " + ex.Message }; }
            };
        }

        private static int RunSuite(StringBuilder sb, string name, Func<List<string>> suite)
        {
            var failures = suite();
            sb.AppendLine(name);
            sb.AppendLine(new string('-', 60));
            if (failures.Count == 0)
            {
                sb.AppendLine("  PASS");
            }
            else
            {
                foreach (var f in failures) sb.AppendLine("  FAIL: " + f);
            }
            sb.AppendLine();
            return failures.Count;
        }

        // ------------------------------------------------------------------ --scan / --json

        private static int RunHeadless(CommandLine cli)
        {
            try
            {
                var notes = new List<string>();
                string signatureSource;
                var ctx = ScanRunner.CreateContext(notes, out signatureSource);
                ctx.DeepBrowserScan = !cli.NoBrowser;
                ctx.ReportClassWide = !cli.PrimaryOnly;

                var runner = new ScanRunner();
                if (cli.Verbose)
                {
                    runner.Progress += (msg, pct) =>
                        Console.Error.WriteLine("[" + pct.ToString(CultureInfo.InvariantCulture).PadLeft(3) + "%] " + msg);
                }

                var report = runner.Run(ctx);

                string body = cli.AsText ? ReportExporter.ToText(report) : ReportExporter.ToJson(report);

                if (string.IsNullOrEmpty(cli.OutputPath))
                {
                    WriteConsole(body, false);
                }
                else
                {
                    string full = Path.GetFullPath(cli.OutputPath!);
                    string? dir = Path.GetDirectoryName(full);
                    if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir)) Directory.CreateDirectory(dir!);
                    // BOM for the text report only: it carries U+2800 and other invisible
                    // codepoints, and without one Notepad mis-decodes them. JSON must NOT have
                    // a BOM - RFC 8259 forbids it and strict parsers (python json, jq) reject
                    // it outright. The JSON writer escapes non-ASCII as \uXXXX anyway, so the
                    // file is pure ASCII and needs no BOM to survive.
                    File.WriteAllText(full, body, new UTF8Encoding(cli.AsText));
                    Console.Error.WriteLine("Report written to " + full);
                }

                // Exit code carries the headline verdict so a proctoring script can branch on it
                // without parsing JSON:  0 = clear, 2 = suspicious, 3 = detected (running).
                switch (ReportExporter.VerdictOf(report.RunningAttribution))
                {
                    case Verdict.Detected: return 3;
                    case Verdict.Suspicious: return 2;
                    default:
                        // Fall back to the class axis: "some tool of this kind is running" still
                        // deserves a non-zero code even when we cannot attribute it to Parakeet.
                        if (ReportExporter.VerdictOf(report.RunningClass) == Verdict.Detected) return 3;
                        if (ReportExporter.VerdictOf(report.RunningClass) == Verdict.Suspicious) return 2;
                        return 0;
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine(AppName + ": scan failed: " + ex.Message);
                return 1;
            }
        }

        // ------------------------------------------------------------------ console plumbing

        [DllImport("kernel32.dll")]
        private static extern bool AttachConsole(int dwProcessId);
        [DllImport("kernel32.dll")]
        private static extern bool AllocConsole();
        [DllImport("kernel32.dll")]
        private static extern bool FreeConsole();
        [DllImport("kernel32.dll")]
        private static extern IntPtr GetConsoleWindow();

        private const int AttachParentProcess = -1;

        /// <summary>
        /// This is a WinExe, so it has no console of its own. Attach to the parent console when
        /// launched from one; otherwise fall back to a message box so a double-clicked
        /// "ProctorAIDetective.exe --selftest" is not silently invisible.
        /// </summary>
        private static void WriteConsole(string text, bool isError)
        {
            bool attached = false;
            bool hadConsole = GetConsoleWindow() != IntPtr.Zero;

            if (!hadConsole) attached = AttachConsole(AttachParentProcess);

            if (hadConsole || attached)
            {
                try
                {
                    // The report contains U+2800 and similar; without this they become '?'.
                    try { Console.OutputEncoding = Encoding.UTF8; } catch { /* redirected */ }

                    var w = isError ? Console.Error : Console.Out;
                    w.WriteLine(text);
                    w.Flush();
                }
                catch
                {
                    // Redirected or closed handle - nothing useful to do.
                }
                finally
                {
                    if (attached) FreeConsole();
                }
                return;
            }

            try
            {
                MessageBox.Show(text, AppName, MessageBoxButtons.OK,
                    isError ? MessageBoxIcon.Warning : MessageBoxIcon.Information);
            }
            catch
            {
            }
        }

        // ------------------------------------------------------------------ argument parsing

        private sealed class CommandLine
        {
            public bool Headless;
            public bool AsText;
            public bool SelfTest;
            public bool ShowHelp;
            public bool Verbose;
            public bool NoBrowser;
            public bool PrimaryOnly;
            public string? OutputPath;

            public static CommandLine Parse(string[] args)
            {
                var c = new CommandLine();
                if (args == null) return c;

                for (int i = 0; i < args.Length; i++)
                {
                    string a = args[i] ?? "";
                    string key = a.TrimStart('-', '/').ToLowerInvariant();

                    switch (key)
                    {
                        case "scan":
                            c.Headless = true;
                            break;
                        case "json":
                            c.Headless = true;
                            // --json may be bare (write to stdout) or take a path.
                            if (i + 1 < args.Length && !IsSwitch(args[i + 1]))
                            {
                                c.OutputPath = args[i + 1];
                                i++;
                            }
                            break;
                        case "text":
                        case "txt":
                            c.Headless = true;
                            c.AsText = true;
                            if (i + 1 < args.Length && !IsSwitch(args[i + 1]))
                            {
                                c.OutputPath = args[i + 1];
                                i++;
                            }
                            break;
                        case "out":
                        case "o":
                            if (i + 1 < args.Length) { c.OutputPath = args[i + 1]; i++; }
                            c.Headless = true;
                            break;
                        case "selftest":
                        case "self-test":
                            c.SelfTest = true;
                            break;
                        case "nobrowser":
                        case "no-browser":
                            c.NoBrowser = true;
                            break;
                        case "primaryonly":
                        case "primary-only":
                            c.PrimaryOnly = true;
                            break;
                        case "v":
                        case "verbose":
                            c.Verbose = true;
                            break;
                        case "h":
                        case "?":
                        case "help":
                            c.ShowHelp = true;
                            break;
                        default:
                            // An unrecognised bare token is treated as the output path when we
                            // are already headless; otherwise it is a usage error.
                            if (c.Headless && string.IsNullOrEmpty(c.OutputPath) && !IsSwitch(a))
                                c.OutputPath = a;
                            else if (!string.IsNullOrEmpty(a))
                                c.ShowHelp = true;
                            break;
                    }
                }
                return c;
            }

            private static bool IsSwitch(string s)
            {
                return !string.IsNullOrEmpty(s) && (s[0] == '-' || s[0] == '/');
            }

            public static string HelpText()
            {
                var sb = new StringBuilder();
                sb.AppendLine(AppName + " " + ScanRunner.AppVersion());
                sb.AppendLine("Detects whether Parakeet AI - or another screen-capture-evading AI");
                sb.AppendLine("assistant - is running on this Windows machine.");
                sb.AppendLine();
                sb.AppendLine("USAGE");
                sb.AppendLine("  ProctorAIDetective.exe                      Open the window (normal use).");
                sb.AppendLine("  ProctorAIDetective.exe --scan               Run one scan, print JSON to stdout.");
                sb.AppendLine("  ProctorAIDetective.exe --json <path>        Run one scan, write JSON to a file.");
                sb.AppendLine("  ProctorAIDetective.exe --text <path>        Same, but the human-readable report.");
                sb.AppendLine("  ProctorAIDetective.exe --selftest           Run built-in checks and exit.");
                sb.AppendLine();
                sb.AppendLine("OPTIONS");
                sb.AppendLine("  --no-browser     Skip UI Automation browser-tab reading (faster).");
                sb.AppendLine("  --primary-only   Report only Parakeet AI, not the wider tool class.");
                sb.AppendLine("  -v, --verbose    Print scan progress to stderr.");
                sb.AppendLine();
                sb.AppendLine("EXIT CODES (headless)");
                sb.AppendLine("  0  clear        3  detected (running)");
                sb.AppendLine("  2  suspicious   1  the scan itself failed");
                sb.AppendLine();
                sb.AppendLine("This tool only reads. It changes nothing on the machine, and it needs");
                sb.AppendLine("no administrator rights; running elevated only resolves more process");
                sb.AppendLine("paths.  A clear result is NOT proof that no assistance was used.");
                return sb.ToString();
            }
        }
    }
}

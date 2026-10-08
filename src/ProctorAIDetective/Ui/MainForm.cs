using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Globalization;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

using ProctorAIDetective.Core;

namespace ProctorAIDetective.Ui
{
    /// <summary>
    /// The whole user interface, written by hand rather than as a .Designer.cs + .resx pair.
    ///
    /// A designer file would be the larger half of this app by line count, unreviewable in a
    /// diff, and prone to drifting out of step with the code that actually drives it. For a tool
    /// whose output is used to form an opinion about a person, every pixel that states a verdict
    /// should be reviewable in the same file as the logic that chose it.
    ///
    /// The central design rule: THREE SEPARATE SENTENCES, NOT ONE NUMBER.
    ///   "Running now"                 - is Parakeet AI executing at this moment?
    ///   "Installed"                   - is it present on this machine?
    ///   "Hiding from screen capture"  - is anything evading capture, whatever it is?
    /// Collapsing those into a single score would turn the common and entirely innocent state
    /// "installed and set to auto-start, but not running" into a headline accusation. The scan
    /// that produced this file found exactly that state on the development machine, and the UI
    /// has to be able to say it plainly.
    /// </summary>
    public sealed class MainForm : Form
    {
        // ---------------------------------------------------------------- palette
        //
        // Suspicious is AMBER, never red. Amber asks a question; red announces a finding, and a
        // Suspicious verdict is by definition not a finding.

        private static readonly Color InkPrimary = Color.FromArgb(28, 30, 34);
        private static readonly Color InkSecondary = Color.FromArgb(96, 101, 110);
        private static readonly Color InkMuted = Color.FromArgb(138, 144, 154);
        private static readonly Color Surface = Color.FromArgb(250, 250, 251);
        private static readonly Color CardBack = Color.FromArgb(255, 255, 255);
        private static readonly Color CardLine = Color.FromArgb(222, 225, 230);
        private static readonly Color NoticeBack = Color.FromArgb(245, 246, 248);

        private static readonly Color ClearChip = Color.FromArgb(94, 143, 112);
        private static readonly Color ClearInk = Color.FromArgb(46, 100, 69);
        private static readonly Color SuspiciousChip = Color.FromArgb(201, 154, 46);
        private static readonly Color SuspiciousInk = Color.FromArgb(132, 97, 16);
        private static readonly Color DetectedChip = Color.FromArgb(192, 57, 43);
        private static readonly Color DetectedInk = Color.FromArgb(158, 42, 31);
        private static readonly Color UnscannedChip = Color.FromArgb(205, 208, 213);

        private static readonly Color RowSuppressed = Color.FromArgb(150, 155, 163);
        private static readonly Color RowDownRanked = Color.FromArgb(110, 116, 126);
        private static readonly Color RowMasquerade = Color.FromArgb(158, 42, 31);

        // ---------------------------------------------------------------- evidence columns

        private const int ColSignal = 0;
        private const int ColConfidence = 1;
        private const int ColObserved = 2;
        private const int ColProcess = 3;
        private const int ColPid = 4;
        private const int ColSigner = 5;
        private const int ColScore = 6;
        private const int ColAllowlist = 7;

        // ---------------------------------------------------------------- state

        private ScanReport? _report;
        private CancellationTokenSource? _cts;
        private bool _scanning;

        private readonly ColumnSorter _sorter = new ColumnSorter();
        private readonly ToolTip _tips = new ToolTip();

        // ---------------------------------------------------------------- controls

        private readonly TableLayoutPanel _root = new TableLayoutPanel();

        private readonly Label _title = new Label();
        private readonly Label _subtitle = new Label();
        private readonly Label _elevationLabel = new Label();
        private readonly LinkLabel _elevationLink = new LinkLabel();
        private readonly Button _scanButton = new Button();
        private readonly CheckBox _deepBrowser = new CheckBox();
        private readonly CheckBox _classWide = new CheckBox();

        private readonly Label _disclaimer = new Label();

        private readonly TableLayoutPanel _verdictGrid = new TableLayoutPanel();
        private readonly VerdictRow _vRunning = new VerdictRow();
        private readonly VerdictRow _vInstalled = new VerdictRow();
        private readonly VerdictRow _vHiding = new VerdictRow();
        private readonly Label _situation = new Label();
        private readonly Label _suspiciousNote = new Label();
        private readonly Label _behaviouralNote = new Label();
        private readonly Label _assistantsNote = new Label();

        private readonly SplitContainer _split = new SplitContainer();
        private readonly Label _evidenceHeading = new Label();
        private readonly CheckBox _showSuppressed = new CheckBox();
        private readonly ListView _list = new ListView();
        private readonly Label _detailHeading = new Label();
        private readonly TextBox _detail = new TextBox();

        private readonly Button _limToggle = new Button();
        private readonly Panel _limBody = new Panel();
        private readonly Label _limCounts = new Label();
        private readonly TextBox _limText = new TextBox();

        private readonly Button _exportJson = new Button();
        private readonly Button _exportText = new Button();
        private readonly Button _copy = new Button();
        private readonly Label _status = new Label();
        private readonly ProgressBar _progress = new ProgressBar();

        // ================================================================== construction

        public MainForm()
        {
            SuspendLayout();
            BuildWindow();
            BuildHeader();
            BuildDisclaimer();
            BuildVerdicts();
            BuildEvidence();
            BuildLimitations();
            BuildFooter();
            ResumeLayout(false);
            PerformLayout();

            ApplyElevationIndicator();
            RenderReport();   // paints the empty, "nothing has been scanned yet" state
        }

        private void BuildWindow()
        {
            Text = "Proctor AI Detective";
            Font = new Font("Segoe UI", 9F, FontStyle.Regular, GraphicsUnit.Point);
            AutoScaleDimensions = new SizeF(7F, 15F);
            AutoScaleMode = AutoScaleMode.Font;
            BackColor = Surface;
            ForeColor = InkPrimary;
            MinimumSize = new Size(900, 650);
            ClientSize = new Size(1120, 760);
            StartPosition = FormStartPosition.CenterScreen;
            KeyPreview = true;
            DoubleBuffered = true;

            _root.Dock = DockStyle.Fill;
            _root.ColumnCount = 1;
            _root.RowCount = 6;
            _root.Padding = new Padding(16, 12, 16, 12);
            _root.BackColor = Surface;
            _root.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100F));
            _root.RowStyles.Add(new RowStyle(SizeType.AutoSize));   // header
            _root.RowStyles.Add(new RowStyle(SizeType.AutoSize));   // disclaimer
            _root.RowStyles.Add(new RowStyle(SizeType.AutoSize));   // verdicts
            _root.RowStyles.Add(new RowStyle(SizeType.Percent, 100F)); // evidence
            _root.RowStyles.Add(new RowStyle(SizeType.AutoSize));   // limitations
            _root.RowStyles.Add(new RowStyle(SizeType.AutoSize));   // footer
            Controls.Add(_root);
        }

        // ---------------------------------------------------------------- header

        private void BuildHeader()
        {
            var header = new TableLayoutPanel();
            header.Dock = DockStyle.Fill;
            header.AutoSize = true;
            header.AutoSizeMode = AutoSizeMode.GrowAndShrink;
            header.ColumnCount = 2;
            header.RowCount = 3;
            header.Margin = new Padding(0, 0, 0, 8);
            header.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100F));
            header.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            header.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            header.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            header.RowStyles.Add(new RowStyle(SizeType.AutoSize));

            _title.Text = "Proctor AI Detective";
            _title.Font = new Font("Segoe UI Semibold", 16F, FontStyle.Bold, GraphicsUnit.Point);
            _title.AutoSize = true;
            _title.Margin = new Padding(0, 0, 0, 0);
            _title.ForeColor = InkPrimary;

            _subtitle.Text = "Is Parakeet AI running on this machine right now?";
            _subtitle.AutoSize = true;
            _subtitle.ForeColor = InkSecondary;
            _subtitle.Margin = new Padding(0, 0, 0, 8);

            // Elevation indicator, top right. Deliberately phrased as optional enrichment.
            var elevation = new FlowLayoutPanel();
            elevation.AutoSize = true;
            elevation.AutoSizeMode = AutoSizeMode.GrowAndShrink;
            elevation.FlowDirection = FlowDirection.TopDown;
            elevation.WrapContents = false;
            elevation.Anchor = AnchorStyles.Top | AnchorStyles.Right;
            elevation.Margin = new Padding(16, 2, 0, 0);

            _elevationLabel.AutoSize = true;
            _elevationLabel.Font = new Font("Segoe UI Semibold", 9F, FontStyle.Bold, GraphicsUnit.Point);
            _elevationLabel.Margin = new Padding(0, 0, 0, 2);
            _elevationLabel.TextAlign = ContentAlignment.MiddleRight;

            _elevationLink.Text = "Restart as administrator";
            _elevationLink.AutoSize = true;
            _elevationLink.Margin = new Padding(0);
            _elevationLink.LinkBehavior = LinkBehavior.HoverUnderline;
            _elevationLink.LinkColor = Color.FromArgb(38, 94, 168);
            _elevationLink.ActiveLinkColor = Color.FromArgb(24, 70, 130);
            _elevationLink.TabStop = true;
            _elevationLink.LinkClicked += OnRestartElevated;

            _tips.SetToolTip(_elevationLink,
                "Optional. Administrator rights only ENRICH the report: they let the tool read the "
                + "image path of more processes (measured here: 428 of 430 elevated, 259 of 430 "
                + "not).\r\n\r\nThe decisive signal - whether a window is excluded from screen "
                + "capture - is read across processes with no elevation at all, so a scan without "
                + "administrator rights is still a real scan.");

            elevation.Controls.Add(_elevationLabel);
            elevation.Controls.Add(_elevationLink);

            // Controls row.
            var actions = new FlowLayoutPanel();
            actions.AutoSize = true;
            actions.AutoSizeMode = AutoSizeMode.GrowAndShrink;
            actions.FlowDirection = FlowDirection.LeftToRight;
            actions.WrapContents = true;
            actions.Margin = new Padding(0, 4, 0, 0);
            actions.Dock = DockStyle.Fill;

            StylePrimaryButton(_scanButton, "&Scan now");
            _scanButton.Margin = new Padding(0, 0, 16, 0);
            _scanButton.Click += OnScanClicked;
            _tips.SetToolTip(_scanButton, "Run every check once (F5). Nothing is scanned until you ask.");

            _deepBrowser.Text = "&Deep browser scan";
            _deepBrowser.AutoSize = true;
            _deepBrowser.Checked = true;
            _deepBrowser.Margin = new Padding(0, 6, 16, 0);
            _deepBrowser.ForeColor = InkPrimary;
            _tips.SetToolTip(_deepBrowser,
                "Walk browser tab strips with UI Automation, so a vendor page sitting in a "
                + "BACKGROUND tab is found and not just the tab you are looking at.\r\n"
                + "Slower (measured 130-250 ms per browser window) and it can stall on a busy "
                + "renderer, so it is reported as a blind spot when it cannot read a tab strip.");

            _classWide.Text = "Report the whole tool &class";
            _classWide.AutoSize = true;
            _classWide.Checked = true;
            _classWide.Margin = new Padding(0, 6, 0, 0);
            _classWide.ForeColor = InkPrimary;
            _tips.SetToolTip(_classWide,
                "Report every known capture-evading AI assistant, not only Parakeet AI.\r\n"
                + "Findings about other vendors never carry attribution to Parakeet AI: they "
                + "score on the class axis only.");

            actions.Controls.Add(_scanButton);
            actions.Controls.Add(_deepBrowser);
            actions.Controls.Add(_classWide);

            header.Controls.Add(_title, 0, 0);
            header.Controls.Add(_subtitle, 0, 1);
            header.Controls.Add(elevation, 1, 0);
            header.SetRowSpan(elevation, 2);
            header.Controls.Add(actions, 0, 2);
            header.SetColumnSpan(actions, 2);

            _root.Controls.Add(header, 0, 0);
        }

        // ---------------------------------------------------------------- disclaimer

        private void BuildDisclaimer()
        {
            // ALWAYS visible, above the verdict, in body text. Never behind a link, never in
            // fine print: the limits of the evidence travel with the evidence.
            TableLayoutPanel card = Card(NoticeBack, CardLine, new Padding(12, 10, 12, 10));

            var heading = new Label();
            heading.Text = "What this tool can and cannot tell you";
            heading.Font = new Font("Segoe UI Semibold", 9F, FontStyle.Bold, GraphicsUnit.Point);
            heading.AutoSize = true;
            heading.Dock = DockStyle.Top;
            heading.ForeColor = InkPrimary;
            heading.Margin = new Padding(0, 0, 0, 4);

            _disclaimer.Text = ReportExporter.Disclaimer;
            Wrap(_disclaimer);
            _disclaimer.Anchor = AnchorStyles.Top | AnchorStyles.Left;
            _disclaimer.ForeColor = InkSecondary;
            _disclaimer.Margin = new Padding(0);
            _disclaimer.UseMnemonic = false;

            AddCardRow(card, heading);
            AddCardRow(card, _disclaimer);

            _root.Controls.Add(card, 0, 1);
        }

        // ---------------------------------------------------------------- verdicts

        private void BuildVerdicts()
        {
            TableLayoutPanel card = Card(CardBack, CardLine, new Padding(14, 12, 14, 12));

            _verdictGrid.Dock = DockStyle.Top;
            _verdictGrid.AutoSize = true;
            _verdictGrid.AutoSizeMode = AutoSizeMode.GrowAndShrink;
            _verdictGrid.ColumnCount = 3;
            _verdictGrid.RowCount = 6;
            _verdictGrid.Margin = new Padding(0);
            _verdictGrid.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 8F));    // colour chip
            _verdictGrid.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 230F));  // caption
            _verdictGrid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100F));   // value + why
            for (int i = 0; i < 6; i++) _verdictGrid.RowStyles.Add(new RowStyle(SizeType.AutoSize));

            AddVerdictRow(_vRunning, 0, "Running now:", 16F, true);
            AddVerdictRow(_vInstalled, 2, "Installed:", 11F, false);
            AddVerdictRow(_vHiding, 4, "Hiding from screen capture:", 11F, false);

            Wrap(_situation);
            _situation.Anchor = AnchorStyles.Top | AnchorStyles.Left;
            _situation.ForeColor = InkPrimary;
            _situation.Font = new Font("Segoe UI", 9.75F, FontStyle.Regular, GraphicsUnit.Point);
            _situation.Margin = new Padding(0, 10, 0, 0);
            _situation.UseMnemonic = false;
            _situation.Visible = false;

            Wrap(_suspiciousNote);
            _suspiciousNote.Anchor = AnchorStyles.Top | AnchorStyles.Left;
            _suspiciousNote.ForeColor = SuspiciousInk;
            _suspiciousNote.Font = new Font("Segoe UI Semibold", 9F, FontStyle.Bold, GraphicsUnit.Point);
            _suspiciousNote.Margin = new Padding(0, 8, 0, 0);
            _suspiciousNote.Text = ReportExporter.SuspiciousNote;
            _suspiciousNote.UseMnemonic = false;
            _suspiciousNote.Visible = false;

            Wrap(_behaviouralNote);
            _behaviouralNote.Anchor = AnchorStyles.Top | AnchorStyles.Left;
            _behaviouralNote.ForeColor = InkSecondary;
            _behaviouralNote.Margin = new Padding(0, 8, 0, 0);
            _behaviouralNote.Text = ReportExporter.BehaviouralCaveat;
            _behaviouralNote.UseMnemonic = false;
            _behaviouralNote.Visible = false;

            Wrap(_assistantsNote);
            _assistantsNote.ForeColor = InkSecondary;
            _assistantsNote.Margin = new Padding(0, 8, 0, 0);
            _assistantsNote.UseMnemonic = false;
            _assistantsNote.Visible = false;

            AddCardRow(card, _verdictGrid);
            AddCardRow(card, _situation);
            AddCardRow(card, _suspiciousNote);
            AddCardRow(card, _behaviouralNote);
            AddCardRow(card, _assistantsNote);

            _root.Controls.Add(card, 0, 2);
        }

        private void AddVerdictRow(VerdictRow row, int topRow, string caption, float size, bool headline)
        {
            row.Chip.Dock = DockStyle.Fill;
            row.Chip.BackColor = UnscannedChip;
            row.Chip.Margin = new Padding(0, headline ? 4 : 3, 12, 2);
            row.Chip.MinimumSize = new Size(6, 16);

            row.Caption.Text = caption;
            row.Caption.AutoSize = true;
            row.Caption.Anchor = AnchorStyles.Left;
            row.Caption.ForeColor = InkSecondary;
            row.Caption.Font = new Font("Segoe UI", 10F, FontStyle.Regular, GraphicsUnit.Point);
            row.Caption.Margin = new Padding(0, 4, 8, 2);
            row.Caption.UseMnemonic = false;

            row.Value.Text = "not scanned yet";
            row.Value.AutoSize = true;
            row.Value.Anchor = AnchorStyles.Left;
            row.Value.ForeColor = InkMuted;
            row.Value.Font = new Font("Segoe UI Semibold", size, FontStyle.Bold, GraphicsUnit.Point);
            row.Value.Margin = new Padding(0, 2, 0, 2);
            row.Value.UseMnemonic = false;

            row.Why.Text = "";
            Wrap(row.Why);
            row.Why.Anchor = AnchorStyles.Top | AnchorStyles.Left;
            row.Why.ForeColor = InkSecondary;
            row.Why.Font = new Font("Segoe UI", 8.75F, FontStyle.Regular, GraphicsUnit.Point);
            row.Why.Margin = new Padding(0, 0, 0, headline ? 10 : 8);
            row.Why.UseMnemonic = false;

            _verdictGrid.Controls.Add(row.Chip, 0, topRow);
            _verdictGrid.SetRowSpan(row.Chip, 2);
            _verdictGrid.Controls.Add(row.Caption, 1, topRow);
            _verdictGrid.Controls.Add(row.Value, 2, topRow);
            _verdictGrid.Controls.Add(row.Why, 1, topRow + 1);
            _verdictGrid.SetColumnSpan(row.Why, 2);
        }

        // ---------------------------------------------------------------- evidence

        private void BuildEvidence()
        {
            _split.Dock = DockStyle.Fill;
            _split.Orientation = Orientation.Horizontal;
            _split.SplitterWidth = 8;
            _split.Panel1MinSize = 160;
            _split.Panel2MinSize = 96;
            _split.BackColor = Surface;
            _split.Margin = new Padding(0, 0, 0, 8);
            _split.TabStop = false;

            // ---- top: the grid
            var top = new TableLayoutPanel();
            top.Dock = DockStyle.Fill;
            top.ColumnCount = 2;
            top.RowCount = 2;
            top.Margin = new Padding(0);
            top.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100F));
            top.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            top.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            top.RowStyles.Add(new RowStyle(SizeType.Percent, 100F));

            _evidenceHeading.Text = "Evidence";
            _evidenceHeading.AutoSize = true;
            _evidenceHeading.Anchor = AnchorStyles.Left | AnchorStyles.Bottom;
            _evidenceHeading.Font = new Font("Segoe UI Semibold", 10F, FontStyle.Bold, GraphicsUnit.Point);
            _evidenceHeading.ForeColor = InkPrimary;
            _evidenceHeading.Margin = new Padding(0, 0, 0, 6);
            _evidenceHeading.UseMnemonic = false;

            _showSuppressed.Text = "Show &suppressed";
            _showSuppressed.AutoSize = true;
            _showSuppressed.Checked = true;   // ON by default: the allowlist must be auditable
            _showSuppressed.Anchor = AnchorStyles.Right | AnchorStyles.Bottom;
            _showSuppressed.Margin = new Padding(8, 0, 0, 6);
            _showSuppressed.ForeColor = InkSecondary;
            _showSuppressed.CheckedChanged += delegate { PopulateEvidence(); };
            _tips.SetToolTip(_showSuppressed,
                "Signals the allowlist zeroed are shown greyed out, not hidden.\r\n"
                + "An allowlist that silently deletes evidence is an invisible policy, and an "
                + "invisible policy cannot be challenged by the person it is applied to.");

            _list.Dock = DockStyle.Fill;
            _list.View = View.Details;
            _list.FullRowSelect = true;
            _list.MultiSelect = false;
            _list.HideSelection = false;
            _list.GridLines = false;
            _list.UseCompatibleStateImageBehavior = false;
            _list.BorderStyle = BorderStyle.FixedSingle;
            _list.BackColor = CardBack;
            _list.Margin = new Padding(0);
            _list.ListViewItemSorter = _sorter;
            _list.ColumnClick += OnColumnClick;
            _list.SelectedIndexChanged += delegate { ShowSelectedDetail(); };
            _list.Resize += delegate { LayoutColumns(); };

            _list.Columns.Add("Signal", 170, HorizontalAlignment.Left);
            _list.Columns.Add("Confidence", 85, HorizontalAlignment.Left);
            _list.Columns.Add("What was observed", 280, HorizontalAlignment.Left);
            _list.Columns.Add("Process", 150, HorizontalAlignment.Left);
            _list.Columns.Add("PID", 55, HorizontalAlignment.Right);
            _list.Columns.Add("Signer", 180, HorizontalAlignment.Left);
            _list.Columns.Add("Score", 120, HorizontalAlignment.Left);
            _list.Columns.Add("Allowlist", 110, HorizontalAlignment.Left);

            top.Controls.Add(_evidenceHeading, 0, 0);
            top.Controls.Add(_showSuppressed, 1, 0);
            top.Controls.Add(_list, 0, 1);
            top.SetColumnSpan(_list, 2);

            // ---- bottom: the full detail of the selected row
            var bottom = new TableLayoutPanel();
            bottom.Dock = DockStyle.Fill;
            bottom.ColumnCount = 1;
            bottom.RowCount = 2;
            bottom.Margin = new Padding(0);
            bottom.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100F));
            bottom.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            bottom.RowStyles.Add(new RowStyle(SizeType.Percent, 100F));

            _detailHeading.Text = "Selected evidence";
            _detailHeading.AutoSize = true;
            _detailHeading.Font = new Font("Segoe UI Semibold", 10F, FontStyle.Bold, GraphicsUnit.Point);
            _detailHeading.ForeColor = InkPrimary;
            _detailHeading.Margin = new Padding(0, 0, 0, 6);
            _detailHeading.UseMnemonic = false;

            _detail.Dock = DockStyle.Fill;
            _detail.Multiline = true;
            _detail.ReadOnly = true;
            _detail.ScrollBars = ScrollBars.Vertical;
            _detail.WordWrap = true;
            _detail.BorderStyle = BorderStyle.FixedSingle;
            _detail.BackColor = CardBack;
            _detail.ForeColor = InkPrimary;
            _detail.Font = new Font("Consolas", 9F, FontStyle.Regular, GraphicsUnit.Point);
            _detail.Margin = new Padding(0);
            _detail.Text = "Select a row above to see everything that was observed, including the "
                         + "full image path and the Authenticode signer.";

            bottom.Controls.Add(_detailHeading, 0, 0);
            bottom.Controls.Add(_detail, 0, 1);

            _split.Panel1.Controls.Add(top);
            _split.Panel2.Controls.Add(bottom);

            _root.Controls.Add(_split, 0, 3);
        }

        // ---------------------------------------------------------------- limitations

        private void BuildLimitations()
        {
            TableLayoutPanel card = Card(CardBack, CardLine, new Padding(12, 8, 12, 10));

            _limToggle.Text = "> Scan limitations and blind spots";
            _limToggle.AutoSize = true;
            _limToggle.Anchor = AnchorStyles.Left;
            _limToggle.FlatStyle = FlatStyle.Flat;
            _limToggle.FlatAppearance.BorderSize = 0;
            _limToggle.FlatAppearance.MouseOverBackColor = NoticeBack;
            _limToggle.BackColor = CardBack;
            _limToggle.ForeColor = InkPrimary;
            _limToggle.Font = new Font("Segoe UI Semibold", 9.5F, FontStyle.Bold, GraphicsUnit.Point);
            _limToggle.TextAlign = ContentAlignment.MiddleLeft;
            _limToggle.Padding = new Padding(0);
            _limToggle.Margin = new Padding(0, 0, 0, 4);
            _limToggle.UseVisualStyleBackColor = false;
            _limToggle.Click += delegate { SetLimitationsExpanded(!_limBody.Visible); };
            _tips.SetToolTip(_limToggle,
                "What this scan could not see. Blind spots belong next to the verdict, not "
                + "buried in an export.");

            _limBody.Dock = DockStyle.Top;
            _limBody.Height = 150;
            _limBody.Margin = new Padding(0);
            _limBody.BackColor = CardBack;

            _limCounts.Dock = DockStyle.Top;
            _limCounts.Height = 22;
            _limCounts.ForeColor = InkSecondary;
            _limCounts.TextAlign = ContentAlignment.MiddleLeft;
            _limCounts.UseMnemonic = false;
            _limCounts.Text = "";

            _limText.Dock = DockStyle.Fill;
            _limText.Multiline = true;
            _limText.ReadOnly = true;
            _limText.ScrollBars = ScrollBars.Vertical;
            _limText.WordWrap = true;
            _limText.BorderStyle = BorderStyle.FixedSingle;
            _limText.BackColor = NoticeBack;
            _limText.ForeColor = InkPrimary;

            _limBody.Controls.Add(_limText);
            _limBody.Controls.Add(_limCounts);

            AddCardRow(card, _limToggle);
            AddCardRow(card, _limBody);

            _root.Controls.Add(card, 0, 4);

            SetLimitationsExpanded(false);
        }

        private void SetLimitationsExpanded(bool expanded)
        {
            _limBody.Visible = expanded;
            UpdateLimitationsCaption();
        }

        private void UpdateLimitationsCaption()
        {
            int count = _report != null ? _report.Limitations.Count : 0;
            string arrow = _limBody.Visible ? "v" : ">";
            string suffix = count == 1 ? " (1 note)" : " (" + count.ToString(CultureInfo.InvariantCulture) + " notes)";
            _limToggle.Text = arrow + " Scan limitations and blind spots" + suffix;
        }

        // ---------------------------------------------------------------- footer

        private void BuildFooter()
        {
            var footer = new TableLayoutPanel();
            footer.Dock = DockStyle.Fill;
            footer.AutoSize = true;
            footer.AutoSizeMode = AutoSizeMode.GrowAndShrink;
            footer.ColumnCount = 3;
            footer.RowCount = 1;
            footer.Margin = new Padding(0, 8, 0, 0);
            footer.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            footer.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100F));
            footer.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            footer.RowStyles.Add(new RowStyle(SizeType.AutoSize));

            var buttons = new FlowLayoutPanel();
            buttons.AutoSize = true;
            buttons.AutoSizeMode = AutoSizeMode.GrowAndShrink;
            buttons.FlowDirection = FlowDirection.LeftToRight;
            buttons.WrapContents = false;
            buttons.Margin = new Padding(0);

            StyleSecondaryButton(_exportJson, "Export &JSON...");
            _exportJson.Click += delegate { Export(true); };
            _tips.SetToolTip(_exportJson,
                "Machine-readable export: every signal including the ones the allowlist "
                + "suppressed, every limitation, every timing, and all four axis rationales.");

            StyleSecondaryButton(_exportText, "Export &text...");
            _exportText.Click += delegate { Export(false); };
            _tips.SetToolTip(_exportText, "The same content laid out to be read, printed or pasted into a ticket.");

            StyleSecondaryButton(_copy, "&Copy report");
            _copy.Click += delegate { CopyToClipboard(); };
            _tips.SetToolTip(_copy, "Copy the full text report to the clipboard (Ctrl+Shift+C).");

            buttons.Controls.Add(_exportJson);
            buttons.Controls.Add(_exportText);
            buttons.Controls.Add(_copy);

            _status.AutoSize = true;
            _status.Anchor = AnchorStyles.Left;
            _status.ForeColor = InkSecondary;
            _status.Margin = new Padding(16, 0, 16, 0);
            _status.UseMnemonic = false;
            _status.Text = "Ready. Nothing is scanned until you ask.";

            _progress.Style = ProgressBarStyle.Marquee;
            _progress.MarqueeAnimationSpeed = 30;
            _progress.Size = new Size(190, 10);
            _progress.Anchor = AnchorStyles.Right;
            _progress.Margin = new Padding(0, 8, 0, 8);
            _progress.Visible = false;

            footer.Controls.Add(buttons, 0, 0);
            footer.Controls.Add(_status, 1, 0);
            footer.Controls.Add(_progress, 2, 0);

            _root.Controls.Add(footer, 0, 5);

            AcceptButton = _scanButton;

            // Tab order: the primary action first, then the options, then the evidence, then export.
            _scanButton.TabIndex = 0;
            _deepBrowser.TabIndex = 1;
            _classWide.TabIndex = 2;
            _elevationLink.TabIndex = 3;
            _showSuppressed.TabIndex = 4;
            _list.TabIndex = 5;
            _detail.TabIndex = 6;
            _limToggle.TabIndex = 7;
            _limText.TabIndex = 8;
            _exportJson.TabIndex = 9;
            _exportText.TabIndex = 10;
            _copy.TabIndex = 11;
        }

        // ================================================================== lifecycle

        protected override void OnShown(EventArgs e)
        {
            base.OnShown(e);
            ApplyWrapWidths();   // the first reliable moment: _root now has its real width
            try
            {
                int h = _split.Height;
                int ceiling = h - _split.Panel2MinSize - _split.SplitterWidth;
                int want = h - 180;
                if (want > ceiling) want = ceiling;
                if (want < _split.Panel1MinSize) want = _split.Panel1MinSize;
                if (want > 0 && want < h) _split.SplitterDistance = want;
            }
            catch (Exception) { /* a splitter that will not move is cosmetic, not fatal */ }

            LayoutColumns();
            _scanButton.Focus();
        }

        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            try
            {
                CancellationTokenSource? cts = _cts;
                if (cts != null) cts.Cancel();
            }
            catch (Exception) { }
            base.OnFormClosing(e);
        }

        protected override bool ProcessCmdKey(ref Message msg, Keys keyData)
        {
            if (keyData == Keys.F5)
            {
                OnScanClicked(this, EventArgs.Empty);
                return true;
            }
            if (keyData == (Keys.Control | Keys.Shift | Keys.C))
            {
                CopyToClipboard();
                return true;
            }
            return base.ProcessCmdKey(ref msg, keyData);
        }

        // ================================================================== scanning

        private async void OnScanClicked(object? sender, EventArgs e)
        {
            if (_scanning)
            {
                try
                {
                    CancellationTokenSource? cts = _cts;
                    if (cts != null) cts.Cancel();
                    _status.Text = "Cancelling...";
                }
                catch (Exception) { }
                return;
            }

            _scanning = true;
            SetScanningUi(true);

            ScanReport? produced = null;
            string? failure = null;

            try
            {
                var notes = new List<string>();
                ScanContext context = ScanRunner.CreateContext(notes);
                context.DeepBrowserScan = _deepBrowser.Checked;
                context.ReportClassWide = _classWide.Checked;

                var cts = new CancellationTokenSource();
                _cts = cts;
                context.Cancel = cts.Token;

                var runner = new ScanRunner();
                runner.PreflightNotes.AddRange(notes);
                runner.Progress += OnProgress;

                try
                {
                    produced = await runner.RunAsync(context);
                }
                finally
                {
                    runner.Progress -= OnProgress;
                }
            }
            catch (Exception ex)
            {
                failure = ex.GetType().Name + ": " + ex.Message;
            }
            finally
            {
                try
                {
                    CancellationTokenSource? cts = _cts;
                    _cts = null;
                    if (cts != null) cts.Dispose();
                }
                catch (Exception) { }

                _scanning = false;
                SetScanningUi(false);
            }

            if (failure != null)
            {
                _status.Text = "The scan could not be completed.";
                MessageBox.Show(this,
                    "The scan could not be completed." + Environment.NewLine + Environment.NewLine
                    + failure + Environment.NewLine + Environment.NewLine
                    + "Nothing was concluded. Do not read this as a clean result.",
                    "Proctor AI Detective", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            _report = produced;
            RenderReport();

            if (produced != null)
            {
                long ms = 0;
                try { ms = (long)(produced.FinishedUtc - produced.StartedUtc).TotalMilliseconds; }
                catch (Exception) { }
                _status.Text = "Scan finished in " + ms.ToString(CultureInfo.InvariantCulture) + " ms - "
                             + produced.Signals.Count.ToString(CultureInfo.InvariantCulture)
                             + (produced.Signals.Count == 1 ? " signal, " : " signals, ")
                             + produced.Limitations.Count.ToString(CultureInfo.InvariantCulture)
                             + (produced.Limitations.Count == 1 ? " limitation." : " limitations.");
            }
        }

        /// <summary>Raised on the scan thread. Marshals to the UI thread and never throws.</summary>
        private void OnProgress(string message, int percent)
        {
            try
            {
                if (IsDisposed || !IsHandleCreated) return;
                BeginInvoke((Action)delegate
                {
                    try
                    {
                        _status.Text = message + "  (" + percent.ToString(CultureInfo.InvariantCulture) + "%)";
                    }
                    catch (Exception) { }
                });
            }
            catch (Exception) { /* handle died between the check and the post */ }
        }

        private void SetScanningUi(bool scanning)
        {
            _progress.Visible = scanning;
            _progress.MarqueeAnimationSpeed = scanning ? 30 : 0;
            _scanButton.Text = scanning ? "&Cancel scan" : "&Scan now";
            _deepBrowser.Enabled = !scanning;
            _classWide.Enabled = !scanning;
            _exportJson.Enabled = !scanning;
            _exportText.Enabled = !scanning;
            _copy.Enabled = !scanning;
            if (scanning) _status.Text = "Starting...";
            UseWaitCursor = false;   // the window stays responsive; a wait cursor would lie
        }

        // ================================================================== rendering

        private void RenderReport()
        {
            ScanReport? r = _report;

            RenderVerdict(_vRunning, r == null ? null : r.RunningAttribution, RunningWhy(r));
            RenderVerdict(_vInstalled, r == null ? null : r.InstalledAttribution,
                          r == null ? "" : r.InstalledAttribution.Rationale);
            RenderVerdict(_vHiding, r == null ? null : r.EvadingClass,
                          r == null ? "" : r.EvadingClass.Rationale);

            string situation = ReportExporter.SituationLine(r);
            _situation.Text = situation;
            _situation.Visible = situation.Length > 0;

            bool anySuspicious = r != null &&
                (ReportExporter.IsSuspicious(r.RunningAttribution)
                 || ReportExporter.IsSuspicious(r.InstalledAttribution)
                 || ReportExporter.IsSuspicious(r.EvadingClass)
                 || ReportExporter.IsSuspicious(r.RunningClass));
            _suspiciousNote.Visible = anySuspicious;

            _behaviouralNote.Visible = ReportExporter.HasBehaviouralSignal(r);

            string assistants = ReportExporter.AssistantsLine(r);
            _assistantsNote.Text = assistants;
            _assistantsNote.Visible = assistants.Length > 0;

            PopulateEvidence();
            PopulateLimitations();

            // Rationale text has just changed and some labels became visible for the first
            // time; re-measure so the new prose wraps to the window instead of clipping.
            ForceRewrap();
        }

        /// <summary>
        /// The "Running now" line answers the attribution question. When the CLASS axis says
        /// something more than the attribution axis does, that is appended rather than merged:
        /// "a tool of this kind is running" and "Parakeet AI is running" are different claims and
        /// must not be allowed to borrow each other's confidence.
        /// </summary>
        private static string RunningWhy(ScanReport? r)
        {
            if (r == null) return "";
            string why = r.RunningAttribution.Rationale ?? "";

            if (r.RunningClass.Verdict != Verdict.Clear
                && r.RunningClass.Score > r.RunningAttribution.Score)
            {
                if (why.Length > 0) why += "  ";
                why += "Separately, on the question \"is any capture-evading AI assistant running\": "
                     + ReportExporter.VerdictWord(r.RunningClass.Verdict).ToUpperInvariant()
                     + " (" + r.RunningClass.Score.ToString(CultureInfo.InvariantCulture) + "/100). "
                     + (r.RunningClass.Rationale ?? "");
            }
            return why;
        }

        private static void RenderVerdict(VerdictRow row, AxisResult? axis, string why)
        {
            if (axis == null)
            {
                row.Value.Text = "not scanned yet";
                row.Value.ForeColor = InkMuted;
                row.Chip.BackColor = UnscannedChip;
                row.Why.Text = "";
                row.Why.Visible = false;
                return;
            }

            row.Value.Text = ReportExporter.VerdictWord(axis.Verdict).ToUpperInvariant()
                           + "   " + axis.Score.ToString(CultureInfo.InvariantCulture) + "/100";

            switch (axis.Verdict)
            {
                case Verdict.Detected:
                    row.Value.ForeColor = DetectedInk;
                    row.Chip.BackColor = DetectedChip;
                    break;
                case Verdict.Suspicious:
                    row.Value.ForeColor = SuspiciousInk;
                    row.Chip.BackColor = SuspiciousChip;
                    break;
                default:
                    row.Value.ForeColor = ClearInk;
                    row.Chip.BackColor = ClearChip;
                    break;
            }

            row.Why.Text = why ?? "";
            row.Why.Visible = row.Why.Text.Length > 0;
        }

        private void PopulateEvidence()
        {
            _list.BeginUpdate();
            try
            {
                _list.Items.Clear();

                ScanReport? r = _report;
                int shown = 0;
                int hidden = 0;

                if (r != null)
                {
                    foreach (Signal s in r.Signals)
                    {
                        if (s == null) continue;
                        if (s.IsSuppressed && !_showSuppressed.Checked) { hidden++; continue; }

                        var item = new ListViewItem(ReportExporter.Visible(s.Title));
                        item.SubItems.Add(ReportExporter.TierWord(s.Tier));
                        item.SubItems.Add(OneLine(s.Detail));
                        item.SubItems.Add(ProcessCell(s));
                        item.SubItems.Add(s.Pid > 0 ? s.Pid.ToString(CultureInfo.InvariantCulture) : "");
                        item.SubItems.Add(SignerCell(s.Signer));
                        item.SubItems.Add(ScoreCell(s));
                        item.SubItems.Add(AllowlistCell(s));
                        item.Tag = s;
                        item.UseItemStyleForSubItems = true;

                        if (s.IsSuppressed) item.ForeColor = RowSuppressed;
                        else if (s.Allowlist == AllowlistOutcome.DownRanked) item.ForeColor = RowDownRanked;
                        else if (s.Allowlist == AllowlistOutcome.Masquerade) item.ForeColor = RowMasquerade;

                        _list.Items.Add(item);
                        shown++;
                    }
                }

                _evidenceHeading.Text = r == null
                    ? "Evidence"
                    : "Evidence - " + shown.ToString(CultureInfo.InvariantCulture)
                      + (shown == 1 ? " signal" : " signals")
                      + (hidden > 0
                         ? "  (" + hidden.ToString(CultureInfo.InvariantCulture) + " suppressed and hidden)"
                         : "");
            }
            finally
            {
                _list.EndUpdate();
            }

            LayoutColumns();
            ShowSelectedDetail();
        }

        private void PopulateLimitations()
        {
            ScanReport? r = _report;

            if (r == null)
            {
                _limCounts.Text = "";
                _limText.Text = "";
                UpdateLimitationsCaption();
                return;
            }

            _limCounts.Text = string.Format(CultureInfo.InvariantCulture,
                "Windows scanned {0}   |   capture-affinity queries failed {1}   |   "
                + "processes scanned {2}   |   process paths unresolved {3}",
                r.WindowsScanned, r.WindowsQueryFailed, r.ProcessesScanned, r.ProcessPathsUnresolved);

            var sb = new StringBuilder();
            if (r.WindowsQueryFailed > 0)
            {
                sb.Append("- ")
                  .Append(r.WindowsQueryFailed.ToString(CultureInfo.InvariantCulture))
                  .Append(" window(s) could not be asked whether they are excluded from screen ")
                  .Append("capture. Those are recorded as UNKNOWN, not as \"not hidden\".")
                  .Append(Environment.NewLine);
            }
            if (r.ProcessPathsUnresolved > 0)
            {
                sb.Append("- ")
                  .Append(r.ProcessPathsUnresolved.ToString(CultureInfo.InvariantCulture))
                  .Append(" process(es) would not give up their image path, so they could not be ")
                  .Append("identified or authenticated.")
                  .Append(r.Elevated ? "" : " Running as administrator resolves most of these.")
                  .Append(Environment.NewLine);
            }

            foreach (string l in r.Limitations)
            {
                if (string.IsNullOrEmpty(l)) continue;
                sb.Append("- ").Append(l).Append(Environment.NewLine);
            }

            if (sb.Length == 0)
            {
                sb.Append("No limitations were recorded for this scan.")
                  .Append(Environment.NewLine)
                  .Append(Environment.NewLine)
                  .Append("That means every check ran to completion. It does NOT mean the machine ")
                  .Append("is clean: read the notice at the top of this window for what no scan on ")
                  .Append("this device can see.");
            }

            _limText.Text = sb.ToString();
            UpdateLimitationsCaption();
        }

        private void ShowSelectedDetail()
        {
            if (_list.SelectedItems.Count == 0)
            {
                _detail.Text = _list.Items.Count == 0
                    ? "No evidence to show."
                    : "Select a row above to see everything that was observed, including the full "
                      + "image path and the Authenticode signer.";
                return;
            }

            Signal? s = _list.SelectedItems[0].Tag as Signal;
            if (s == null) { _detail.Text = ""; return; }

            string nl = Environment.NewLine;
            var sb = new StringBuilder(1024);

            sb.Append(ReportExporter.Visible(s.Title)).Append(nl);
            sb.Append("signal id       ").Append(ReportExporter.Visible(s.Id)).Append(nl);
            sb.Append("confidence      ").Append(ReportExporter.TierWord(s.Tier)).Append(nl);
            sb.Append("proves          ").Append(ReportExporter.StateWords(s.State)).Append(nl);
            sb.Append("found by        ").Append(ReportExporter.Visible(s.Source)).Append(" scanner").Append(nl);
            sb.Append("attributed to   ")
              .Append(s.VendorKey.Length > 0 ? ReportExporter.Visible(s.VendorKey)
                                             : "(no vendor - this is a behaviour, not an identity)").Append(nl);
            sb.Append("subject         ")
              .Append(s.Subject.Length > 0 ? ReportExporter.Visible(s.Subject) : "(none)").Append(nl);
            sb.Append("process id      ")
              .Append(s.Pid > 0 ? s.Pid.ToString(CultureInfo.InvariantCulture) : "(not applicable)").Append(nl);
            sb.Append("image path      ")
              .Append(s.SubjectPath.Length > 0 ? ReportExporter.Visible(s.SubjectPath)
                                               : "(not resolved)").Append(nl);
            sb.Append("signed by       ")
              .Append(s.Signer.Length > 0 ? ReportExporter.Visible(s.Signer)
                                          : "(no embedded signature was read - this is NOT the same as unsigned: "
                                            + "catalog-signed Windows binaries read as empty here)").Append(nl);
            sb.Append("score           attribution ")
              .Append(s.Attribution.ToString(CultureInfo.InvariantCulture))
              .Append(", class ").Append(s.ClassScore.ToString(CultureInfo.InvariantCulture))
              .Append("  ->  effective ").Append(s.EffectiveAttribution.ToString(CultureInfo.InvariantCulture))
              .Append(" / ").Append(s.EffectiveClass.ToString(CultureInfo.InvariantCulture)).Append(nl);
            sb.Append("allowlist       ").Append(ReportExporter.AllowlistWord(s.Allowlist))
              .Append("  (x").Append(s.Multiplier.ToString("0.00", CultureInfo.InvariantCulture)).Append(')').Append(nl);
            if (s.AllowlistReason.Length > 0)
                sb.Append("allowlist why   ").Append(ReportExporter.Visible(s.AllowlistReason)).Append(nl);

            if (s.IsSuppressed)
            {
                sb.Append(nl)
                  .Append("*** The allowlist zeroed this signal. It did not contribute to any verdict. ")
                  .Append("It is shown here so the allowlist can be audited and argued with. ***").Append(nl);
            }
            else if (s.Allowlist == AllowlistOutcome.Masquerade)
            {
                sb.Append(nl)
                  .Append("*** This process wears an allowlisted NAME but carries the wrong signature ")
                  .Append("or sits in the wrong folder, so its score was ESCALATED rather than ")
                  .Append("suppressed. ***").Append(nl);
            }

            sb.Append(nl).Append("What was observed").Append(nl);
            sb.Append(new string('-', 60)).Append(nl);
            sb.Append(ReportExporter.Visible(s.Detail)).Append(nl);

            if (s.Attribution == 0 && s.ClassScore > 0)
            {
                sb.Append(nl)
                  .Append("Note: this signal carries NO attribution. It says a tool of this kind is ")
                  .Append("present or running; it does not say which tool.").Append(nl);
            }

            _detail.Text = sb.ToString();
            _detail.SelectionStart = 0;
            _detail.SelectionLength = 0;
        }

        // ---------------------------------------------------------------- cell formatting

        private static string OneLine(string? text)
        {
            string s = ReportExporter.Visible(text);
            s = s.Replace("\r\n", " ").Replace('\r', ' ').Replace('\n', ' ').Replace('\t', ' ');
            while (s.IndexOf("  ", StringComparison.Ordinal) >= 0) s = s.Replace("  ", " ");
            return s.Trim();
        }

        private static string ProcessCell(Signal s)
        {
            if (s.Subject.Length > 0) return ReportExporter.Visible(s.Subject);
            if (s.SubjectPath.Length > 0)
            {
                try { return ReportExporter.Visible(Path.GetFileName(s.SubjectPath)); }
                catch (Exception) { return ReportExporter.Visible(s.SubjectPath); }
            }
            return "";
        }

        /// <summary>
        /// Shows the certificate's common name rather than the whole distinguished name, which is
        /// 90 characters wide and unreadable in a grid cell. The full subject is always in the
        /// detail box below, so nothing is lost.
        /// </summary>
        private static string SignerCell(string? signer)
        {
            if (string.IsNullOrEmpty(signer)) return "";
            string s = signer!;

            int cn = s.IndexOf("CN=", StringComparison.OrdinalIgnoreCase);
            if (cn >= 0)
            {
                int start = cn + 3;
                int end = s.IndexOf(',', start);
                if (end < 0) end = s.Length;
                string name = s.Substring(start, end - start).Trim();
                if (name.Length > 0) return ReportExporter.Visible(name);
            }
            return ReportExporter.Visible(s);
        }

        private static string ScoreCell(Signal s)
        {
            string core = s.EffectiveAttribution.ToString(CultureInfo.InvariantCulture)
                        + " / " + s.EffectiveClass.ToString(CultureInfo.InvariantCulture);
            if (Math.Abs(s.Multiplier - 1.0) < 0.0005) return core;

            return core + "  (was " + s.Attribution.ToString(CultureInfo.InvariantCulture)
                 + " / " + s.ClassScore.ToString(CultureInfo.InvariantCulture)
                 + ", x" + s.Multiplier.ToString("0.00", CultureInfo.InvariantCulture) + ")";
        }

        private static string AllowlistCell(Signal s)
        {
            return ReportExporter.AllowlistWord(s.Allowlist);
        }

        private void LayoutColumns()
        {
            try
            {
                if (_list.Columns.Count < 8) return;

                int available = _list.ClientSize.Width;
                if (available <= 0) return;

                int fixedWidth = _list.Columns[ColSignal].Width
                               + _list.Columns[ColConfidence].Width
                               + _list.Columns[ColProcess].Width
                               + _list.Columns[ColPid].Width
                               + _list.Columns[ColSigner].Width
                               + _list.Columns[ColScore].Width
                               + _list.Columns[ColAllowlist].Width;

                int observed = available - fixedWidth - 4;
                if (observed < 160) observed = 160;
                if (_list.Columns[ColObserved].Width != observed)
                    _list.Columns[ColObserved].Width = observed;
            }
            catch (Exception) { }
        }

        private void OnColumnClick(object? sender, ColumnClickEventArgs e)
        {
            try
            {
                if (_sorter.Column == e.Column) _sorter.Descending = !_sorter.Descending;
                else { _sorter.Column = e.Column; _sorter.Descending = false; }
                _list.Sort();
            }
            catch (Exception) { }
        }

        // ================================================================== actions

        private void OnRestartElevated(object? sender, LinkLabelLinkClickedEventArgs e)
        {
            try
            {
                var psi = new ProcessStartInfo();
                psi.FileName = Application.ExecutablePath;
                psi.UseShellExecute = true;
                psi.Verb = "runas";
                try { psi.WorkingDirectory = Path.GetDirectoryName(Application.ExecutablePath) ?? ""; }
                catch (Exception) { }

                Process.Start(psi);
                Application.Exit();
            }
            catch (System.ComponentModel.Win32Exception)
            {
                // Code 1223 is the user clicking No on the UAC prompt. Nothing has gone wrong.
                MessageBox.Show(this,
                    "Windows did not grant administrator rights, so the app is still running "
                    + "without them." + Environment.NewLine + Environment.NewLine
                    + "This is not a problem for the main check: whether a window is excluded "
                    + "from screen capture is readable across processes without elevation. "
                    + "Administrator rights only let the tool resolve the image path of more "
                    + "processes.",
                    "Proctor AI Detective", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show(this,
                    "Could not restart with administrator rights: " + ex.Message,
                    "Proctor AI Detective", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }

        private void ApplyElevationIndicator()
        {
            bool elevated = ScanRunner.IsElevated();
            _elevationLabel.Text = elevated ? "Elevated" : "Not elevated";
            _elevationLabel.ForeColor = elevated ? ClearInk : InkSecondary;
            _elevationLink.Visible = !elevated;
        }

        private void Export(bool json)
        {
            ScanReport? r = _report;
            if (r == null)
            {
                MessageBox.Show(this, "There is no scan to export yet. Run a scan first.",
                    "Proctor AI Detective", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            string suggested;
            try
            {
                suggested = "proctor-ai-detective-" + Sanitise(r.MachineName) + "-"
                          + DateTime.Now.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture)
                          + (json ? ".json" : ".txt");
            }
            catch (Exception)
            {
                suggested = json ? "proctor-ai-detective-report.json" : "proctor-ai-detective-report.txt";
            }

            using (var dialog = new SaveFileDialog())
            {
                dialog.Title = json ? "Export the scan report as JSON" : "Export the scan report as text";
                dialog.Filter = json
                    ? "JSON report (*.json)|*.json|All files (*.*)|*.*"
                    : "Text report (*.txt)|*.txt|All files (*.*)|*.*";
                dialog.FileName = suggested;
                dialog.OverwritePrompt = true;
                dialog.AddExtension = true;
                dialog.DefaultExt = json ? "json" : "txt";

                if (dialog.ShowDialog(this) != DialogResult.OK) return;

                try
                {
                    string content = json ? ReportExporter.ToJson(r) : ReportExporter.ToText(r);

                    // JSON is pure ASCII by construction, so no BOM. The text report gets one so
                    // Notepad does not have to guess.
                    var encoding = new UTF8Encoding(!json);
                    File.WriteAllText(dialog.FileName, content, encoding);

                    _status.Text = "Exported to " + dialog.FileName;
                }
                catch (Exception ex)
                {
                    MessageBox.Show(this,
                        "Could not write the export:" + Environment.NewLine + Environment.NewLine
                        + ex.GetType().Name + ": " + ex.Message,
                        "Proctor AI Detective", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                }
            }
        }

        private void CopyToClipboard()
        {
            ScanReport? r = _report;
            if (r == null)
            {
                MessageBox.Show(this, "There is no scan to copy yet. Run a scan first.",
                    "Proctor AI Detective", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            try
            {
                Clipboard.SetText(ReportExporter.ToText(r));
                _status.Text = "The full text report was copied to the clipboard.";
            }
            catch (Exception ex)
            {
                // Another process holding the clipboard open throws ExternalException. Routine.
                MessageBox.Show(this,
                    "Could not copy to the clipboard (" + ex.GetType().Name
                    + "). Another program may be holding it open. Try the text export instead.",
                    "Proctor AI Detective", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
        }

        private static string Sanitise(string? name)
        {
            if (string.IsNullOrEmpty(name)) return "machine";
            var sb = new StringBuilder(name!.Length);
            foreach (char c in name!)
            {
                if (char.IsLetterOrDigit(c) || c == '-' || c == '_') sb.Append(c);
            }
            return sb.Length > 0 ? sb.ToString() : "machine";
        }

        // ================================================================== small helpers

        /// <summary>
        /// A bordered container whose height follows its contents. A TableLayoutPanel rather than
        /// a Panel because only the former propagates a width constraint into an AutoSize label,
        /// which is what lets the disclaimer wrap and still report the right height.
        /// </summary>
        // ---------------------------------------------------------------- text wrapping
        //
        // A WinForms Label with AutoSize=true and no MaximumSize grows to the width of its
        // longest line instead of wrapping, so long prose runs off the right edge of the window.
        // The fix is to pin MaximumSize.Width to the width actually available and let AutoSize
        // compute the height. That width changes whenever the window is resized, so every
        // multi-line label registers here and gets re-measured on layout.

        private readonly List<Label> _wrapLabels = new List<Label>();
        private bool _applyingWrap;

        /// <summary>Register a label whose text should wrap to the available width.</summary>
        private Label Wrap(Label label)
        {
            // AutoSize is deliberately OFF. The usual "AutoSize + MaximumSize" recipe does not
            // survive this layout: MaximumSize clamps the control's SIZE after the fact, but the
            // text has already been laid out against the much wider size the TableLayoutPanel
            // proposed, so every line wraps too late and is then clipped at the control edge.
            // Measuring the text ourselves and setting an explicit size is deterministic.
            label.AutoSize = false;
            label.Dock = DockStyle.None;
            label.Anchor = AnchorStyles.Top | AnchorStyles.Left;
            _wrapLabels.Add(label);
            return label;
        }

        private void ApplyWrapWidths()
        {
            // Setting MaximumSize triggers a re-layout, which would call us again.
            if (_applyingWrap) return;
            _applyingWrap = true;
            try
            {
                foreach (Label label in _wrapLabels)
                {
                    if (label.Parent == null) continue;

                    int available = AvailableWidth(label);

                    // Below this the text becomes unreadable shards; let it clip instead.
                    if (available < 200) available = 200;

                    // Measure with the SAME engine the label paints with. WordBreak is what
                    // actually wraps; TextBoxControl makes the measurement account for the
                    // trailing line the way the renderer does.
                    Size needed = TextRenderer.MeasureText(
                        label.Text ?? string.Empty,
                        label.Font,
                        new Size(available, int.MaxValue),
                        TextFormatFlags.WordBreak | TextFormatFlags.TextBoxControl);

                    // +2 absorbs the rounding difference between measuring and painting, which
                    // otherwise shaves the descenders off the final line.
                    var size = new Size(available, needed.Height + 2);
                    if (label.Size != size) label.Size = size;

                    if (Environment.GetEnvironmentVariable("PROCTOR_UIDIAG") == "1")
                    {
                        try
                        {
                            File.AppendAllText(
                                Path.Combine(Path.GetTempPath(), "proctor-uidiag.txt"),
                                string.Format(
                                    "root={0} parent={1} parentClient={2} avail={3} set={4} actual={5} autosize={6} dock={7} text={8}\r\n",
                                    _root.ClientSize.Width,
                                    label.Parent.GetType().Name,
                                    label.Parent.ClientSize.Width,
                                    available, size, label.Size, label.AutoSize, label.Dock,
                                    (label.Text ?? "").Substring(0, Math.Min(28, (label.Text ?? "").Length))));
                        }
                        catch { }
                    }
                }
            }
            finally
            {
                _applyingWrap = false;
            }
        }

        /// <summary>
        /// Width a wrapping label may use, measured DOWN from _root rather than up from the
        /// label's own parent.
        ///
        /// The cards between _root and the label are AutoSize, so their width is a function of
        /// their content - which is what we are trying to compute. Reading it would be circular,
        /// and in practice settles on a far narrower column than the window actually offers.
        /// _root is docked Fill on the form, so its width is authoritative; subtract the chrome
        /// between it and the label and we get the real answer in one pass.
        /// </summary>
        private int AvailableWidth(Label label)
        {
            // Measured from the FORM, not from _root.
            //
            // _root is a TableLayoutPanel and will not shrink below the minimum width its
            // content demands - the evidence ListView's eight columns push that to ~1600px.
            // Docking it Fill does not change that, so _root.ClientSize.Width reports 1600
            // inside an 1120px window, and any label sized from it overflows the window and
            // gets clipped. The form's own client width is the only honest ceiling.
            int width = ClientSize.Width - _root.Padding.Horizontal;

            for (Control? c = label.Parent; c != null && c != _root; c = c.Parent)
                width -= c.Padding.Horizontal + c.Margin.Horizontal;

            width -= label.Margin.Horizontal;

            // Gutter. Label measures its wrap points with a little slack, cards paint a 1px
            // border, and a vertical scrollbar can appear at narrow sizes; without this the last
            // word on a line sits flush against the card edge or clips outright.
            width -= 72;

            // Columns to the left of the label inside a TableLayoutPanel are not available to it.
            var table = label.Parent as TableLayoutPanel;
            if (table != null)
            {
                try
                {
                    TableLayoutPanelCellPosition cell = table.GetCellPosition(label);
                    int[] columns = table.GetColumnWidths();
                    for (int i = 0; i < cell.Column && i < columns.Length; i++)
                        width -= columns[i];
                }
                catch
                {
                    // GetCellPosition throws for a control the table does not own; the
                    // unadjusted width is still a reasonable answer.
                }
            }

            return width;
        }

        /// <summary>
        /// Re-measure every wrapping label against the current width, whether or not the
        /// available width changed. Needed after the text itself changes, since a label that
        /// was empty (or held shorter prose) has no useful cached layout.
        /// </summary>
        private void ForceRewrap()
        {
            ApplyWrapWidths();
        }

        protected override void OnResize(EventArgs e)
        {
            base.OnResize(e);
            ApplyWrapWidths();
        }

        private static TableLayoutPanel Card(Color back, Color border, Padding pad)
        {
            var card = new TableLayoutPanel();
            card.Dock = DockStyle.Fill;
            card.AutoSize = true;
            card.AutoSizeMode = AutoSizeMode.GrowAndShrink;
            card.ColumnCount = 1;
            card.RowCount = 0;
            card.Padding = pad;
            card.Margin = new Padding(0, 0, 0, 8);
            card.BackColor = back;
            card.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100F));
            card.Paint += delegate (object? s, PaintEventArgs e)
            {
                var c = s as Control;
                if (c == null) return;
                using (var pen = new Pen(border))
                    e.Graphics.DrawRectangle(pen, 0, 0, c.Width - 1, c.Height - 1);
            };
            return card;
        }

        private static void AddCardRow(TableLayoutPanel card, Control child)
        {
            int row = card.RowCount;
            card.RowCount = row + 1;
            card.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            card.Controls.Add(child, 0, row);
        }

        private static void StylePrimaryButton(Button b, string text)
        {
            b.Text = text;
            b.AutoSize = false;
            b.Size = new Size(132, 32);
            b.FlatStyle = FlatStyle.Flat;
            b.FlatAppearance.BorderSize = 0;
            b.BackColor = Color.FromArgb(38, 94, 168);
            b.ForeColor = Color.White;
            b.Font = new Font("Segoe UI Semibold", 9.5F, FontStyle.Bold, GraphicsUnit.Point);
            b.UseVisualStyleBackColor = false;
            b.Cursor = Cursors.Hand;
            b.FlatAppearance.MouseOverBackColor = Color.FromArgb(30, 80, 146);
            b.FlatAppearance.MouseDownBackColor = Color.FromArgb(24, 66, 122);
        }

        private static void StyleSecondaryButton(Button b, string text)
        {
            b.Text = text;
            b.AutoSize = false;
            b.Size = new Size(124, 30);
            b.FlatStyle = FlatStyle.Flat;
            b.FlatAppearance.BorderSize = 1;
            b.FlatAppearance.BorderColor = CardLine;
            b.BackColor = CardBack;
            b.ForeColor = InkPrimary;
            b.UseVisualStyleBackColor = false;
            b.Margin = new Padding(0, 0, 8, 0);
            b.Cursor = Cursors.Hand;
            b.FlatAppearance.MouseOverBackColor = NoticeBack;
        }

        // ================================================================== nested types

        private sealed class VerdictRow
        {
            public readonly Panel Chip = new Panel();
            public readonly Label Caption = new Label();
            public readonly Label Value = new Label();
            public readonly Label Why = new Label();
        }

        /// <summary>
        /// Column sorter that reads the underlying <see cref="Signal"/> from the row tag wherever
        /// it can, so Confidence sorts Weak-&gt;Definitive rather than alphabetically (which would
        /// put Definitive between Weak and Strong and quietly mislead a reviewer skimming the
        /// grid), and PID and Score sort numerically.
        /// </summary>
        private sealed class ColumnSorter : IComparer
        {
            public int Column;
            public bool Descending;

            public int Compare(object? x, object? y)
            {
                var a = x as ListViewItem;
                var b = y as ListViewItem;
                if (a == null || b == null) return 0;

                int result = CompareCore(a, b);
                return Descending ? -result : result;
            }

            private int CompareCore(ListViewItem a, ListViewItem b)
            {
                var sa = a.Tag as Signal;
                var sb = b.Tag as Signal;

                if (sa != null && sb != null)
                {
                    switch (Column)
                    {
                        case ColConfidence:
                            return ((int)sa.Tier).CompareTo((int)sb.Tier);
                        case ColPid:
                            return sa.Pid.CompareTo(sb.Pid);
                        case ColScore:
                            int va = Math.Max(sa.EffectiveAttribution, sa.EffectiveClass);
                            int vb = Math.Max(sb.EffectiveAttribution, sb.EffectiveClass);
                            return va.CompareTo(vb);
                        case ColAllowlist:
                            return ((int)sa.Allowlist).CompareTo((int)sb.Allowlist);
                    }
                }

                return string.Compare(Cell(a, Column), Cell(b, Column),
                                      StringComparison.CurrentCultureIgnoreCase);
            }

            private static string Cell(ListViewItem item, int column)
            {
                if (column < 0 || column >= item.SubItems.Count) return "";
                return item.SubItems[column].Text ?? "";
            }
        }
    }
}

using System;
using System.Drawing;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using CrashLens.Core;

namespace CrashLens
{
    sealed class MainForm : Form
    {
        readonly ComboBox cboDays = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 90 };
        readonly Button btnRun = new Button { Text = "분석", AutoSize = true };
        readonly Button btnSave = new Button { Text = "리포트 저장", AutoSize = true, Enabled = false };
        readonly Button btnCopy = new Button { Text = "리포트 복사", AutoSize = true, Enabled = false };
        readonly Label lblStatus = new Label { AutoSize = true, Padding = new Padding(8, 7, 0, 0) };
        readonly ListView list = new ListView { Dock = DockStyle.Fill, View = View.Details, FullRowSelect = true, HideSelection = false, MultiSelect = false };
        readonly TabControl tabs = new TabControl { Dock = DockStyle.Fill };
        readonly TextBox txtOverall = MakeText();
        readonly TextBox txtDetail = MakeText();
        readonly TextBox txtApps = MakeText();
        readonly TextBox txtChanges = MakeText();

        Snapshot snapshot;
        AnalysisResult result;

        public MainForm()
        {
            Text = "CrashLens — Windows 크래시·비정상 종료 분석기";
            Font = new Font("Malgun Gothic", 9f);
            AutoScaleMode = AutoScaleMode.Dpi;
            ClientSize = new Size(1180, 760);
            MinimumSize = new Size(820, 520);
            StartPosition = FormStartPosition.CenterScreen;

            cboDays.Items.AddRange(new object[] { "30일", "90일", "180일", "365일" });
            cboDays.SelectedIndex = 1;

            var top = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, Padding = new Padding(6), WrapContents = false };
            top.Controls.Add(new Label { Text = "분석 기간", AutoSize = true, Padding = new Padding(0, 7, 0, 0) });
            top.Controls.Add(cboDays);
            top.Controls.Add(btnRun);
            top.Controls.Add(btnSave);
            top.Controls.Add(btnCopy);
            top.Controls.Add(lblStatus);

            list.Columns.Add("기록 시각", 140);
            list.Columns.Add("유형", 170);
            list.Columns.Add("코드", 300);
            list.Columns.Add("지목된 모듈", 240);
            list.Columns.Add("추정", 280);

            AddTab("종합 진단", txtOverall);
            AddTab("선택 항목 상세", txtDetail);
            AddTab("프로그램 오류", txtApps);
            AddTab("변경·종료 이력", txtChanges);

            var split = new SplitContainer { Dock = DockStyle.Fill, Orientation = Orientation.Horizontal };
            split.Panel1.Controls.Add(list);
            split.Panel2.Controls.Add(tabs);
            Controls.Add(split);
            Controls.Add(top);

            Shown += (s, e) => { split.SplitterDistance = Math.Max(120, split.Height / 3); RunAnalysis(); };
            btnRun.Click += (s, e) => RunAnalysis();
            btnSave.Click += (s, e) => SaveReport();
            btnCopy.Click += (s, e) => { if (result != null) { Clipboard.SetText(Report.Full(snapshot, result)); lblStatus.Text = "리포트를 클립보드에 복사했습니다."; } };
            list.SelectedIndexChanged += (s, e) =>
            {
                if (list.SelectedItems.Count == 0) return;
                txtDetail.Text = Report.Detail((Incident)list.SelectedItems[0].Tag);
                tabs.SelectedIndex = 1;
            };
        }

        static TextBox MakeText()
        {
            return new TextBox
            {
                Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Both, WordWrap = true, Dock = DockStyle.Fill,
                BackColor = SystemColors.Window, Font = new Font("Malgun Gothic", 9.5f)
            };
        }

        void AddTab(string title, Control c)
        {
            var page = new TabPage(title) { Padding = new Padding(4) };
            page.Controls.Add(c);
            tabs.TabPages.Add(page);
        }

        int SelectedDays()
        {
            switch (cboDays.SelectedIndex) { case 0: return 30; case 2: return 180; case 3: return 365; default: return 90; }
        }

        async void RunAnalysis()
        {
            if (!btnRun.Enabled) return;
            btnRun.Enabled = btnSave.Enabled = btnCopy.Enabled = false;
            list.Items.Clear();
            txtDetail.Text = "목록에서 항목을 선택하면 상세 내용이 표시됩니다.";
            int days = SelectedDays();
            try
            {
                Snapshot snap = null;
                AnalysisResult res = null;
                await Task.Run(() =>
                {
                    snap = Collector.Collect(days, msg => BeginInvoke((Action)(() => lblStatus.Text = msg)));
                    res = Analyzer.Analyze(snap);
                });
                snapshot = snap; result = res;
                Show(snap, res);
                lblStatus.Text = "완료 — 사건 " + res.Incidents.Count + "건, 이벤트 " + snap.Events.Count + "개 분석" + (snap.IsAdmin ? "" : "  (관리자 권한 아님: 덤프 목록 제외)");
                btnSave.Enabled = btnCopy.Enabled = true;
            }
            catch (Exception ex)
            {
                lblStatus.Text = "분석 실패";
                txtOverall.Text = "분석 중 오류가 발생했습니다.\r\n\r\n" + ex;
            }
            finally { btnRun.Enabled = true; }
        }

        void Show(Snapshot s, AnalysisResult r)
        {
            list.BeginUpdate();
            foreach (var inc in r.Incidents)
            {
                var item = new ListViewItem(new[]
                {
                    inc.Time.ToString("yyyy-MM-dd HH:mm"), Report.KindLabel(inc.Kind), Report.CodeName(inc), Report.ModuleText(inc), Report.ShortCause(inc)
                }) { Tag = inc };
                if (inc.Kind == IncidentKind.BlueScreen) item.ForeColor = Color.FromArgb(170, 30, 30);
                else if (inc.Kind == IncidentKind.LiveKernelEvent) item.ForeColor = SystemColors.GrayText;
                list.Items.Add(item);
            }
            list.EndUpdate();
            txtOverall.Text = Crlf(Report.Overall(s, r));
            txtApps.Text = Crlf(Report.Apps(r));
            txtChanges.Text = Crlf(Report.Changes(r));
            tabs.SelectedIndex = 0;
        }

        static string Crlf(string t) { return t.Replace("\r\n", "\n").Replace("\n", "\r\n"); }

        void SaveReport()
        {
            if (result == null) return;
            using (var dlg = new SaveFileDialog
            {
                Filter = "텍스트 파일 (*.txt)|*.txt",
                FileName = "CrashLens_" + Environment.MachineName + "_" + DateTime.Now.ToString("yyyyMMdd_HHmm") + ".txt"
            })
            {
                if (dlg.ShowDialog(this) != DialogResult.OK) return;
                File.WriteAllText(dlg.FileName, Crlf(Report.Full(snapshot, result)), new UTF8Encoding(true));
                lblStatus.Text = "저장했습니다: " + dlg.FileName;
            }
        }
    }
}

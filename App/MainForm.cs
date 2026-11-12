using System;
using System.Drawing;
using System.Globalization;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using CrashLens.Core;

namespace CrashLens
{
    sealed class MainForm : Form
    {
        readonly Label lblPeriod = new Label { AutoSize = true, Padding = new Padding(0, 7, 0, 0) };
        readonly ComboBox cboDays = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 100 };
        readonly Button btnRun = new Button { AutoSize = true };
        readonly Button btnSave = new Button { AutoSize = true, Enabled = false };
        readonly Button btnCopy = new Button { AutoSize = true, Enabled = false };
        readonly ComboBox cboLang = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 110, Margin = new Padding(16, 3, 3, 3) };
        readonly Label lblStatus = new Label { AutoSize = true, Padding = new Padding(8, 7, 0, 0) };
        readonly ListView list = new ListView { Dock = DockStyle.Fill, View = View.Details, FullRowSelect = true, HideSelection = false, MultiSelect = false };
        readonly TabControl tabs = new TabControl { Dock = DockStyle.Fill };
        readonly TextBox txtOverall = MakeText();
        readonly TextBox txtDetail = MakeText();
        readonly TextBox txtApps = MakeText();
        readonly TextBox txtChanges = MakeText();

        static readonly int[] DayChoices = { 30, 90, 180, 365 };
        Snapshot snapshot;
        AnalysisResult result;
        Incident selected;

        public MainForm()
        {
            // 기본 언어는 Windows 표시 언어를 따른다(한국어/베트남어, 그 외는 영어). 화면에서 바꿀 수 있다.
            L.Current = L.FromCulture(CultureInfo.CurrentUICulture.Name);

            Font = new Font("Segoe UI", 9f);
            AutoScaleMode = AutoScaleMode.Dpi;
            ClientSize = new Size(1180, 760);
            MinimumSize = new Size(860, 520);
            StartPosition = FormStartPosition.CenterScreen;
            try { Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath); } catch { }

            cboLang.Items.AddRange(new object[] { "한국어", "English", "Tiếng Việt" });
            cboLang.SelectedIndex = (int)L.Current;

            var top = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, Padding = new Padding(6), WrapContents = false };
            top.Controls.AddRange(new Control[] { lblPeriod, cboDays, btnRun, btnSave, btnCopy, cboLang, lblStatus });

            for (int i = 0; i < 5; i++) list.Columns.Add("");
            int[] widths = { 140, 190, 300, 240, 290 };
            for (int i = 0; i < 5; i++) list.Columns[i].Width = widths[i];

            foreach (var t in new[] { txtOverall, txtDetail, txtApps, txtChanges })
            {
                var page = new TabPage { Padding = new Padding(4) };
                page.Controls.Add(t);
                tabs.TabPages.Add(page);
            }

            var split = new SplitContainer { Dock = DockStyle.Fill, Orientation = Orientation.Horizontal };
            split.Panel1.Controls.Add(list);
            split.Panel2.Controls.Add(tabs);
            Controls.Add(split);
            Controls.Add(top);

            ApplyLanguage();
            cboDays.SelectedIndex = 1;

            Shown += (s, e) => { split.SplitterDistance = Math.Max(120, split.Height / 3); RunAnalysis(); };
            btnRun.Click += (s, e) => RunAnalysis();
            btnSave.Click += (s, e) => SaveReport();
            btnCopy.Click += (s, e) =>
            {
                if (result == null) return;
                Clipboard.SetText(Crlf(Report.Full(snapshot, result)));
                lblStatus.Text = L.T("리포트를 클립보드에 복사했습니다.", "Report copied to the clipboard.", "Đã sao chép báo cáo vào clipboard.");
            };
            cboLang.SelectedIndexChanged += (s, e) =>
            {
                L.Current = (Lang)cboLang.SelectedIndex;
                ApplyLanguage();
                // 진단 문장은 분석 시점에 만들어지므로, 이미 수집한 자료로 다시 분석해 언어를 바꾼다(재수집 없음).
                if (snapshot != null && btnRun.Enabled) { result = Analyzer.Analyze(snapshot); ShowResult(); }
            };
            list.SelectedIndexChanged += (s, e) =>
            {
                if (list.SelectedItems.Count == 0) return;
                selected = (Incident)list.SelectedItems[0].Tag;
                txtDetail.Text = Crlf(Report.Detail(selected));
                tabs.SelectedIndex = 1;
            };
        }

        static TextBox MakeText()
        {
            return new TextBox
            {
                Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Both, WordWrap = true, Dock = DockStyle.Fill,
                BackColor = SystemColors.Window, Font = new Font("Segoe UI", 9.75f)
            };
        }

        void ApplyLanguage()
        {
            Text = "CrashLens — " + L.T("Windows 크래시·비정상 종료 분석기", "Windows crash and abnormal shutdown analyzer", "Trình phân tích sự cố và tắt máy bất thường của Windows");
            lblPeriod.Text = L.T("분석 기간", "Period", "Khoảng thời gian");
            btnRun.Text = L.T("분석", "Analyze", "Phân tích");
            btnSave.Text = L.T("리포트 저장", "Save report", "Lưu báo cáo");
            btnCopy.Text = L.T("리포트 복사", "Copy report", "Sao chép báo cáo");

            int sel = cboDays.SelectedIndex;
            cboDays.Items.Clear();
            foreach (var d in DayChoices) cboDays.Items.Add(L.F("{0}일", "{0} days", "{0} ngày", d));
            if (sel >= 0) cboDays.SelectedIndex = sel;

            string[] cols =
            {
                L.T("기록 시각", "Logged at", "Thời điểm ghi"),
                L.T("유형", "Type", "Loại"),
                L.T("코드", "Code", "Mã"),
                L.T("지목된 모듈", "Named module", "Mô-đun được nêu"),
                L.T("추정", "Likely area", "Phỏng đoán")
            };
            for (int i = 0; i < cols.Length; i++) list.Columns[i].Text = cols[i];

            string[] tabNames =
            {
                L.T("종합 진단", "Diagnosis", "Chẩn đoán tổng hợp"),
                L.T("선택 항목 상세", "Selected incident", "Chi tiết mục đã chọn"),
                L.T("프로그램 오류", "Program failures", "Lỗi chương trình"),
                L.T("변경·종료 이력", "Changes & shutdowns", "Thay đổi & tắt máy")
            };
            for (int i = 0; i < tabNames.Length; i++) tabs.TabPages[i].Text = tabNames[i];
        }

        string SelectHint()
        {
            return L.T("목록에서 항목을 선택하면 상세 내용이 표시됩니다.", "Select an item in the list to see its details.", "Chọn một mục trong danh sách để xem chi tiết.");
        }

        async void RunAnalysis()
        {
            if (!btnRun.Enabled) return;
            btnRun.Enabled = btnSave.Enabled = btnCopy.Enabled = false;
            list.Items.Clear();
            selected = null;
            txtDetail.Text = SelectHint();
            int days = DayChoices[Math.Max(0, cboDays.SelectedIndex)];
            try
            {
                Snapshot snap = null;
                await Task.Run(() => { snap = Collector.Collect(days, msg => BeginInvoke((Action)(() => lblStatus.Text = msg))); });
                snapshot = snap;
                result = Analyzer.Analyze(snap);
                ShowResult();
                btnSave.Enabled = btnCopy.Enabled = true;
            }
            catch (Exception ex)
            {
                lblStatus.Text = L.T("분석 실패", "Analysis failed", "Phân tích thất bại");
                txtOverall.Text = L.T("분석 중 오류가 발생했습니다.", "An error occurred during analysis.", "Đã xảy ra lỗi khi phân tích.") + "\r\n\r\n" + ex;
            }
            finally { btnRun.Enabled = true; }
        }

        void ShowResult()
        {
            var s = snapshot; var r = result;
            list.BeginUpdate();
            list.Items.Clear();
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
            txtDetail.Text = SelectHint();
            selected = null;
            tabs.SelectedIndex = 0;
            lblStatus.Text = L.F("완료 — 사건 {0}건, 이벤트 {1}개 분석", "Done — {0} incident(s), {1} events analyzed", "Xong — {0} sự cố, đã phân tích {1} sự kiện", r.Incidents.Count, s.Events.Count) +
                (s.IsAdmin ? "" : "  " + L.T("(관리자 권한 아님: 덤프 목록 제외)", "(not administrator: dump list excluded)", "(không có quyền quản trị: bỏ qua danh sách dump)"));
        }

        static string Crlf(string t) { return t.Replace("\r\n", "\n").Replace("\n", "\r\n"); }

        void SaveReport()
        {
            if (result == null) return;
            using (var dlg = new SaveFileDialog
            {
                Filter = L.T("텍스트 파일", "Text file", "Tệp văn bản") + " (*.txt)|*.txt",
                FileName = "CrashLens_" + Environment.MachineName + "_" + DateTime.Now.ToString("yyyyMMdd_HHmm") + ".txt"
            })
            {
                if (dlg.ShowDialog(this) != DialogResult.OK) return;
                File.WriteAllText(dlg.FileName, Crlf(Report.Full(snapshot, result)), new UTF8Encoding(true));
                lblStatus.Text = L.T("저장했습니다: ", "Saved: ", "Đã lưu: ") + dlg.FileName;
            }
        }
    }
}

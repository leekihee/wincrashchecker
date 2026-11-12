using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.RegularExpressions;

namespace CrashLens.Core
{
    /// <summary>수집된 이벤트를 "사건" 단위로 묶고 원인을 추론한다. Windows API에 의존하지 않는 순수 로직.</summary>
    public static class Analyzer
    {
        public const string PBug = "Microsoft-Windows-WER-SystemErrorReporting";
        public const string PKp = "Microsoft-Windows-Kernel-Power";
        public const string PWhea = "Microsoft-Windows-WHEA-Logger";
        public const string PWer = "Windows Error Reporting";

        static readonly Regex RxBug = new Regex(
            @"0x([0-9a-fA-F]{8})\s*\(\s*0x([0-9a-fA-F]+)\s*,\s*0x([0-9a-fA-F]+)\s*,\s*0x([0-9a-fA-F]+)\s*,\s*0x([0-9a-fA-F]+)\s*\)",
            RegexOptions.Compiled);
        static readonly Regex RxDump = new Regex(@"[A-Za-z]:\\[^\r\n\t""<>|?*]*?\.dmp", RegexOptions.Compiled | RegexOptions.IgnoreCase);

        static readonly TimeSpan Before = TimeSpan.FromSeconds(60);
        static readonly TimeSpan After = TimeSpan.FromMinutes(6);

        public static AnalysisResult Analyze(Snapshot s)
        {
            var r = new AnalysisResult();
            var evs = s.Events.OrderBy(e => e.Time).ToList();

            BuildIncidents(evs, r);
            foreach (var inc in r.Incidents) Resolve(inc, s);
            PropagateBuckets(r.Incidents);
            r.Incidents.Sort((a, b) => b.Time.CompareTo(a.Time));

            r.WheaCorrected = evs.Count(e => e.Provider == PWhea && e.Id != 1);
            BuildApps(evs, r);
            BuildChanges(evs, r);
            Findings.Build(s, r);
            return r;
        }

        // ---------- 이벤트 판별 ----------

        static bool IsKp41(RawEvent e) { return e.Provider == PKp && e.Id == 41; }
        static bool IsBug(RawEvent e) { return e.Provider == PBug && RxBug.IsMatch(e.Text); }
        static bool Is6008(RawEvent e) { return e.Provider == "EventLog" && e.Id == 6008; }
        static bool IsWhea(RawEvent e) { return e.Provider == PWhea; }

        public static string WerEventName(RawEvent e)
        {
            if (e.Provider != PWer) return "";
            var p = e.Prop(2);
            if (p == "BlueScreen" || p == "LiveKernelEvent") return p;
            if (e.Text.IndexOf("LiveKernelEvent", StringComparison.Ordinal) >= 0) return "LiveKernelEvent";
            if (e.Text.IndexOf("BlueScreen", StringComparison.Ordinal) >= 0) return "BlueScreen";
            return "";
        }

        static string WerBucket(RawEvent e)
        {
            if (e.Props.Count > 5) return e.Prop(0).Trim();
            var m = Regex.Match(e.Message, @"Fault bucket\s*(.*?),\s*type");
            return m.Success ? m.Groups[1].Value.Trim() : "";
        }

        static string WerP1(RawEvent e)
        {
            if (e.Props.Count > 5) return e.Prop(5).Trim();
            var m = Regex.Match(e.Message, @"P1:\s*(\S+)");
            return m.Success ? m.Groups[1].Value : "";
        }

        public static ulong ParseNum(string s)
        {
            if (string.IsNullOrWhiteSpace(s)) return 0;
            s = s.Trim();
            ulong v;
            if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                return ulong.TryParse(s.Substring(2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out v) ? v : 0;
            return ulong.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out v) ? v : 0;
        }

        static uint ParseHex(string s)
        {
            uint v;
            return uint.TryParse((s ?? "").Trim(), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out v) ? v : 0;
        }

        // ---------- 사건 묶기 ----------
        // 비정상 종료 후 재부팅하면 몇 초~몇 분 사이에 Kernel-Power 41, 버그체크 기록, WHEA, WER 보고가 연달아 찍힌다.
        // Kernel-Power 41을 기준점으로 삼고, 나머지는 시간상 가장 가까운 기준점에 붙인다.

        static void BuildIncidents(List<RawEvent> evs, AnalysisResult r)
        {
            foreach (var e in evs.Where(IsKp41)) r.Incidents.Add(NewIncident(e));
            foreach (var e in evs.Where(IsBug)) Attach(r, e, true);
            foreach (var e in evs.Where(Is6008)) Attach(r, e, true);
            foreach (var e in evs.Where(x => x.Provider == PBug && !IsBug(x))) Attach(r, e, false);
            foreach (var e in evs.Where(x => IsWhea(x) && x.Id == 1)) Attach(r, e, true);
            foreach (var e in evs.Where(x => WerEventName(x) != "")) Attach(r, e, true);
        }

        static Incident NewIncident(RawEvent e)
        {
            var inc = new Incident { Time = e.Time };
            inc.Events.Add(e);
            return inc;
        }

        static void Attach(AnalysisResult r, RawEvent e, bool createIfOrphan)
        {
            Incident best = null;
            double bestDist = double.MaxValue;
            foreach (var inc in r.Incidents)
            {
                var d = e.Time - inc.Time;
                if (d < -Before || d > After) continue;
                var dist = Math.Abs(d.TotalSeconds);
                if (dist < bestDist) { bestDist = dist; best = inc; }
            }
            if (best != null) best.Events.Add(e);
            else if (createIfOrphan) r.Incidents.Add(NewIncident(e));
        }

        static void Resolve(Incident inc, Snapshot s)
        {
            var kp = inc.Events.FirstOrDefault(IsKp41);
            var bug = inc.Events.FirstOrDefault(IsBug);
            var wers = inc.Events.Where(e => WerEventName(e) != "").ToList();
            var blue = wers.Where(e => WerEventName(e) == "BlueScreen").OrderByDescending(e => WerBucket(e).Length).FirstOrDefault();
            var lives = wers.Where(e => WerEventName(e) == "LiveKernelEvent").OrderByDescending(e => WerBucket(e).Length).ToList();
            bool whea = inc.Events.Any(IsWhea);
            inc.MinidumpFailed = inc.Events.Any(e => e.Provider == PBug && !IsBug(e));

            string dumpFromBug = "";
            if (bug != null)
            {
                var m = RxBug.Match(bug.Text);
                inc.Code = ParseHex(m.Groups[1].Value);
                for (int i = 0; i < 4; i++) inc.P[i] = ParseNum("0x" + m.Groups[i + 2].Value);
                var dm = RxDump.Match(bug.Text);
                if (dm.Success) dumpFromBug = dm.Value;
            }
            else if (kp != null && ParseNum(kp.Prop(0)) != 0)
            {
                inc.Code = (uint)ParseNum(kp.Prop(0));
                for (int i = 0; i < 4; i++) inc.P[i] = ParseNum(kp.Prop(i + 1));
            }
            else if (blue != null)
            {
                inc.Code = ParseHex(WerP1(blue));
            }

            if (blue != null) inc.Bucket = WerBucket(blue);
            uint liveCode = lives.Count > 0 ? ParseHex(WerP1(lives[0])) : 0;
            string liveBucket = lives.Count > 0 ? WerBucket(lives[0]) : "";
            bool crashLog = liveBucket.IndexOf("CRASHLOG", StringComparison.OrdinalIgnoreCase) >= 0;

            if (inc.Code != 0)
            {
                inc.Kind = IncidentKind.BlueScreen;
                // 버그체크 자체가 0x124가 아닌데 재부팅 직후 WHEA/LiveKernelEvent 124가 따라붙으면 원인이 아니라 부산물이다.
                inc.WheaByproduct = inc.Code != 0x124 && (whea || liveCode == 0x124);
            }
            else if (kp != null)
            {
                inc.Kind = ParseNum(kp.Prop(6)) != 0 ? IncidentKind.ForcedPowerOff : IncidentKind.PowerLoss;
                inc.FirmwareResetRecord = whea || crashLog;
            }
            else if (inc.Events.Any(Is6008))
            {
                inc.Kind = IncidentKind.UnexpectedShutdown;
                inc.FirmwareResetRecord = whea || crashLog;
            }
            else if (lives.Count > 0)
            {
                inc.Kind = IncidentKind.LiveKernelEvent;
                inc.Code = liveCode;
                inc.Bucket = liveBucket;
            }
            else
            {
                inc.Kind = IncidentKind.HardwareError;
            }

            // 덤프 파일: WER 첨부 목록의 미니덤프를 우선하고, MEMORY.DMP는 다음 크래시가 덮어쓰므로 시각이 맞을 때만 인정한다.
            string mini = "";
            foreach (var e in wers.Where(x => WerEventName(x) == "BlueScreen"))
            {
                foreach (Match m in RxDump.Matches(e.Text))
                    if (m.Value.IndexOf("Minidump", StringComparison.OrdinalIgnoreCase) >= 0) mini = TrimDevicePrefix(m.Value);
            }
            if (inc.Kind == IncidentKind.LiveKernelEvent)
            {
                foreach (var e in lives)
                    foreach (Match m in RxDump.Matches(e.Text))
                        if (m.Value.IndexOf("LiveKernelReports", StringComparison.OrdinalIgnoreCase) >= 0) mini = TrimDevicePrefix(m.Value);
            }
            if (mini != "" && (s.Dumps.Count == 0 || HasDump(s, mini))) inc.DumpPath = mini;
            else if (dumpFromBug != "")
            {
                var f = s.Dumps.FirstOrDefault(d => d.Path.Equals(dumpFromBug, StringComparison.OrdinalIgnoreCase));
                if (f != null && Math.Abs((f.Time - inc.Time).TotalMinutes) <= 10) inc.DumpPath = f.Path;
            }

            SetModule(inc);
        }

        static string TrimDevicePrefix(string p)
        {
            int i = p.LastIndexOf(":\\", StringComparison.Ordinal);
            return i >= 1 ? p.Substring(i - 1) : p;
        }

        static bool HasDump(Snapshot s, string path)
        {
            return s.Dumps.Any(d => d.Path.Equals(path, StringComparison.OrdinalIgnoreCase));
        }

        static void SetModule(Incident inc)
        {
            string mod, fn;
            Knowledge.ParseBucket(inc.Bucket, out mod, out fn);
            inc.Module = mod; inc.Function = fn;
            inc.Category = Knowledge.Categorize(mod);
            if (inc.Category == "" && inc.Kind == IncidentKind.BlueScreen && (inc.Code == 0x124 || inc.Code == 0x9C || inc.Code == 0x101))
                inc.Category = "hardware";
            if (inc.Category == "" && (inc.Code == 0x116 || inc.Code == 0x119 || inc.Code == 0x117 || inc.Code == 0x141 || inc.Code == 0x193))
                inc.Category = "gpu";
            if (inc.Category == "" && (inc.Code == 0x7A || inc.Code == 0x7B || inc.Code == 0x154 || inc.Code == 0xF4))
                inc.Category = "storage";
            inc.Signature = MakeSignature(inc);
        }

        /// <summary>같은 크래시인지 판별하는 키. 커널 모듈은 64KB 단위로 배치되므로 부팅마다 주소가 달라도 하위 16비트는 같다.</summary>
        static string MakeSignature(Incident inc)
        {
            if (inc.Kind != IncidentKind.BlueScreen && inc.Kind != IncidentKind.LiveKernelEvent) return inc.Kind.ToString();
            BugcheckInfo info;
            if (inc.Kind == IncidentKind.BlueScreen && Knowledge.Bugchecks.TryGetValue(inc.Code, out info) && info.IpParam > 0 && inc.P[info.IpParam - 1] != 0)
                return inc.CodeText + ":ip" + (inc.P[info.IpParam - 1] & 0xFFFF).ToString("x4");
            if (inc.Module != "") return inc.CodeText + ":" + inc.Module.ToLowerInvariant() + "!" + inc.Function;
            return inc.CodeText;
        }

        /// <summary>버킷 이름은 WER 보고가 성공한 사건에만 남는다. 시그니처가 같은 다른 사건에도 같은 버킷을 적용한다.</summary>
        static void PropagateBuckets(List<Incident> incidents)
        {
            foreach (var g in incidents.Where(i => i.Kind == IncidentKind.BlueScreen && i.Signature.Contains(":ip")).GroupBy(i => i.Signature))
            {
                var src = g.FirstOrDefault(i => i.Bucket != "");
                if (src == null) continue;
                foreach (var inc in g.Where(i => i.Bucket == ""))
                {
                    inc.Bucket = src.Bucket; inc.BucketInferred = true;
                    inc.Module = src.Module; inc.Function = src.Function; inc.Category = src.Category;
                }
            }
        }

        // ---------- 앱 크래시 ----------

        static void BuildApps(List<RawEvent> evs, AnalysisResult r)
        {
            var map = new Dictionary<string, AppCrashGroup>(StringComparer.OrdinalIgnoreCase);
            foreach (var e in evs)
            {
                string app = "", module = "", code = "";
                bool hang = false;
                if (e.Provider == "Application Error" && e.Id == 1000) { app = e.Prop(0); module = e.Prop(3); code = e.Prop(6); }
                else if (e.Provider == "Application Hang" && e.Id == 1002) { app = e.Prop(0); hang = true; }
                else if (e.Provider == ".NET Runtime" && e.Id == 1026)
                {
                    var m = Regex.Match(e.Text, @"Application:\s*(\S+)");
                    if (m.Success) app = m.Groups[1].Value;
                    m = Regex.Match(e.Text, @"Exception Info:\s*([A-Za-z0-9_\.`]+)");
                    if (m.Success) code = m.Groups[1].Value;
                    module = L.T(".NET 미처리 예외", ".NET unhandled exception", "Ngoại lệ .NET không được xử lý");
                }
                else continue;
                app = app.Trim();
                if (app == "") continue;

                AppCrashGroup g;
                if (!map.TryGetValue(app, out g)) { g = new AppCrashGroup { App = app }; map[app] = g; }
                if (hang) g.Hangs++; else g.Crashes++;
                if (e.Time > g.Last) g.Last = e.Time;
                if (module.Trim() != "") g.Modules.Add(module.Trim());
                if (code.Trim() != "") g.Codes.Add(code.Trim());
            }
            r.Apps = map.Values.OrderByDescending(g => g.Crashes + g.Hangs).ThenByDescending(g => g.Last).ToList();
        }

        // ---------- 변경 이력 / 정상 종료 이력 ----------

        static void BuildChanges(List<RawEvent> evs, AnalysisResult r)
        {
            foreach (var e in evs)
            {
                if (e.Provider == "Microsoft-Windows-WindowsUpdateClient" && e.Id == 19)
                    r.Changes.Add(new ChangeItem { Time = e.Time, Kind = L.T("Windows 업데이트", "Windows update", "Cập nhật Windows"), Text = FirstNonEmpty(e.Prop(0), FirstLine(e.Message)) });
                else if (e.Provider == "Microsoft-Windows-UserPnp" && e.Id == 20001)
                    r.Changes.Add(new ChangeItem { Time = e.Time, Kind = L.T("드라이버 설치", "Driver install", "Cài trình điều khiển"), Text = FirstLine(e.Message) != "" ? FirstLine(e.Message) : string.Join(" | ", e.Props.Take(4)) });
                else if (e.Provider == "MsiInstaller" && e.Id == 11707)
                    r.Changes.Add(new ChangeItem { Time = e.Time, Kind = L.T("프로그램 설치", "Program install", "Cài chương trình"), Text = FirstNonEmpty(e.Prop(0), FirstLine(e.Message)) });
                else if (e.Provider == "User32" && e.Id == 1074)
                    r.Shutdowns.Add(new ChangeItem
                    {
                        Time = e.Time,
                        Kind = FirstNonEmpty(e.Prop(4), L.T("종료", "Shutdown", "Tắt máy")),
                        Text = L.F("{0} / 사유: {1} / 사용자: {2}", "{0} / reason: {1} / user: {2}", "{0} / lý do: {1} / người dùng: {2}", e.Prop(0), FirstNonEmpty(e.Prop(2), "-"), FirstNonEmpty(e.Prop(6), "-"))
                    });
            }
            r.Changes.Sort((a, b) => b.Time.CompareTo(a.Time));
            r.Shutdowns.Sort((a, b) => b.Time.CompareTo(a.Time));
        }

        static string FirstLine(string s)
        {
            if (string.IsNullOrEmpty(s)) return "";
            var line = s.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries).FirstOrDefault() ?? "";
            return line.Length > 220 ? line.Substring(0, 220) + "…" : line;
        }

        static string FirstNonEmpty(string a, string b) { return string.IsNullOrWhiteSpace(a) ? b : a.Trim(); }
    }
}

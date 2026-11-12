using System;
using System.Linq;
using System.Text;

namespace CrashLens.Core
{
    /// <summary>화면과 저장용 리포트에 쓰는 텍스트를 만든다.</summary>
    public static class Report
    {
        public static string KindLabel(IncidentKind k)
        {
            switch (k)
            {
                case IncidentKind.BlueScreen: return "블루스크린";
                case IncidentKind.PowerLoss: return "갑작스러운 꺼짐/리셋";
                case IncidentKind.ForcedPowerOff: return "전원 버튼 강제 종료";
                case IncidentKind.UnexpectedShutdown: return "예기치 않은 종료";
                case IncidentKind.LiveKernelEvent: return "커널 오류 보고(복구됨)";
                default: return "하드웨어 오류";
            }
        }

        public static string CodeName(Incident inc)
        {
            if (inc.Code == 0) return "";
            BugcheckInfo info;
            if (inc.Kind == IncidentKind.BlueScreen && Knowledge.Bugchecks.TryGetValue(inc.Code, out info)) return inc.CodeText + " " + info.Name;
            string live;
            if (inc.Kind == IncidentKind.LiveKernelEvent && Knowledge.LiveCodes.TryGetValue(inc.Code, out live)) return inc.CodeText + " " + live;
            return inc.CodeText;
        }

        public static string ModuleText(Incident inc)
        {
            if (inc.Module == "") return "";
            return inc.Module + (inc.Function != "" ? "!" + inc.Function : "");
        }

        public static string ShortCause(Incident inc)
        {
            switch (inc.Kind)
            {
                case IncidentKind.BlueScreen:
                    if (inc.Category != "") return Knowledge.CategoryLabel(inc.Category) + " 쪽" + (inc.BucketInferred ? " (같은 크래시에서 추정)" : "");
                    return inc.DumpPath != "" ? "덤프 분석 필요" : "모듈 정보 없음";
                case IncidentKind.PowerLoss:
                case IncidentKind.UnexpectedShutdown:
                    return inc.FirmwareResetRecord ? "전원/하드웨어 리셋 (펌웨어 기록 있음)" : "전원 차단 또는 완전 멈춤";
                case IncidentKind.ForcedPowerOff: return "직전에 시스템 멈춤 추정";
                case IncidentKind.LiveKernelEvent: return inc.Category != "" ? Knowledge.CategoryLabel(inc.Category) + " 쪽" : "";
                default: return "하드웨어가 오류 보고";
            }
        }

        public static string Overall(Snapshot s, AnalysisResult r)
        {
            var sb = new StringBuilder();
            sb.AppendLine("■ 시스템");
            sb.AppendLine("  분석 시각: " + s.CollectedAt.ToString("yyyy-MM-dd HH:mm") + "   분석 기간: 최근 " + s.Days + "일");
            if (s.Model != "") sb.AppendLine("  모델: " + s.Model);
            if (s.Os != "") sb.AppendLine("  OS: " + s.Os);
            if (s.Cpu != "") sb.AppendLine("  CPU: " + s.Cpu + (s.Memory != "" ? "   메모리: " + s.Memory : ""));
            if (s.Bios != "") sb.AppendLine("  BIOS: " + s.Bios);
            sb.AppendLine();

            sb.AppendLine("■ 요약");
            sb.AppendLine("  블루스크린 " + r.Incidents.Count(i => i.Kind == IncidentKind.BlueScreen) + "회" +
                          " / 코드 없는 꺼짐·리셋 " + r.Incidents.Count(i => i.Kind == IncidentKind.PowerLoss || i.Kind == IncidentKind.UnexpectedShutdown) + "회" +
                          " / 강제 종료 " + r.Incidents.Count(i => i.Kind == IncidentKind.ForcedPowerOff) + "회" +
                          " / 커널 오류 보고 " + r.Incidents.Count(i => i.Kind == IncidentKind.LiveKernelEvent) + "회" +
                          " / 프로그램 오류 " + r.Apps.Sum(a => a.Crashes + a.Hangs) + "건");
            sb.AppendLine();

            sb.AppendLine("■ 진단");
            int n = 1;
            foreach (var f in r.Findings)
            {
                string tag = f.Severity == Severity.High ? "[중요]" : f.Severity == Severity.Medium ? "[주의]" : "[참고]";
                sb.AppendLine(n++ + ". " + tag + " " + f.Title);
                foreach (var line in f.Body.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None)) sb.AppendLine("   " + line);
                sb.AppendLine();
            }
            foreach (var w in s.Warnings) sb.AppendLine("※ 수집 경고: " + w);
            sb.AppendLine("이 진단은 이벤트 로그 패턴에 근거한 추정입니다. 확정하려면 덤프 분석이나 장치를 하나씩 빼 보는 비교가 필요합니다.");
            return sb.ToString();
        }

        public static string Detail(Incident inc)
        {
            var sb = new StringBuilder();
            sb.AppendLine("■ " + KindLabel(inc.Kind) + "  " + inc.Time.ToString("yyyy-MM-dd HH:mm:ss") + "  (재부팅 후 기록된 시각)");
            if (inc.Code != 0) sb.AppendLine("코드: " + CodeName(inc));
            BugcheckInfo info;
            if (inc.Kind == IncidentKind.BlueScreen && Knowledge.Bugchecks.TryGetValue(inc.Code, out info))
            {
                sb.AppendLine("의미: " + info.Meaning);
                sb.AppendLine("흔한 원인: " + info.Causes);
            }
            if (inc.Kind == IncidentKind.BlueScreen)
                sb.AppendLine("파라미터: " + string.Join(", ", inc.P.Select(p => "0x" + p.ToString("x"))));
            if (inc.Bucket != "") sb.AppendLine("Windows 분류(버킷): " + inc.Bucket + (inc.BucketInferred ? "  ← 같은 위치에서 난 다른 크래시의 분류를 적용" : ""));
            if (inc.Module != "") sb.AppendLine("지목된 모듈: " + ModuleText(inc) + "  [" + Knowledge.CategoryLabel(inc.Category) + "]");
            if (inc.Category != "") { sb.AppendLine(); sb.AppendLine(Knowledge.CategoryAdvice(inc.Category)); }
            if (inc.WheaByproduct) { sb.AppendLine(); sb.AppendLine("함께 찍힌 Hardware error(WHEA / LiveKernelEvent 124)는 재부팅 직후 펌웨어가 보고한 부산물입니다."); }
            if (inc.FirmwareResetRecord) { sb.AppendLine(); sb.AppendLine("펌웨어가 비정상 리셋을 기록했습니다(WHEA). 전원/하드웨어 수준의 리셋 가능성이 높습니다."); }
            if (inc.MinidumpFailed) sb.AppendLine("이 크래시는 미니덤프 변환에 실패했습니다(덤프가 불완전할 수 있음).");

            sb.AppendLine();
            if (inc.DumpPath != "")
            {
                sb.AppendLine("■ 덤프 파일: " + inc.DumpPath);
                sb.AppendLine("WinDbg가 설치돼 있으면 관리자 PowerShell에서 아래 한 줄로 분석 결과를 파일로 받을 수 있습니다.");
                sb.AppendLine("  windbgx -z \"" + inc.DumpPath + "\" -c \".logopen C:\\Users\\Public\\crash_analyze.txt; !analyze -v; r; kv 40; .logclose\"");
                sb.AppendLine("결과의 STACK_TEXT(호출 스택)에서 Windows 기본 모듈이 아닌 드라이버 이름을 찾으세요.");
            }
            else if (inc.Kind == IncidentKind.BlueScreen)
            {
                sb.AppendLine("■ 이 크래시의 덤프 파일은 남아 있지 않습니다(또는 권한 부족으로 확인하지 못했습니다).");
            }

            sb.AppendLine();
            sb.AppendLine("■ 관련 이벤트 (" + inc.Events.Count + "건)");
            foreach (var e in inc.Events.OrderBy(x => x.Time))
            {
                var msg = (e.Message ?? "").Replace("\r", " ").Replace("\n", " ").Trim();
                if (msg.Length > 260) msg = msg.Substring(0, 260) + "…";
                sb.AppendLine("  " + e.Time.ToString("HH:mm:ss") + "  " + e.Provider + " #" + e.Id + (msg != "" ? "  " + msg : ""));
            }
            return sb.ToString();
        }

        public static string Apps(AnalysisResult r)
        {
            var sb = new StringBuilder();
            sb.AppendLine("■ 프로그램 오류 (크래시 / 응답 없음)");
            if (r.Apps.Count == 0) sb.AppendLine("  기록 없음");
            foreach (var a in r.Apps.Take(40))
            {
                sb.AppendLine("  " + a.App + "  — 크래시 " + a.Crashes + ", 응답 없음 " + a.Hangs + ", 마지막 " + a.Last.ToString("MM-dd HH:mm"));
                if (a.Modules.Count > 0) sb.AppendLine("      모듈: " + string.Join(", ", a.Modules.Take(6)));
                if (a.Codes.Count > 0) sb.AppendLine("      예외: " + string.Join(", ", a.Codes.Take(6)));
            }
            return sb.ToString();
        }

        public static string Changes(AnalysisResult r)
        {
            var sb = new StringBuilder();
            sb.AppendLine("■ 변경 이력 (Windows 업데이트 / 드라이버 설치 / 프로그램 설치)");
            if (r.Changes.Count == 0) sb.AppendLine("  기록 없음");
            foreach (var c in r.Changes.Take(80)) sb.AppendLine("  " + c.Time.ToString("yyyy-MM-dd HH:mm") + "  [" + c.Kind + "] " + c.Text);
            sb.AppendLine();
            sb.AppendLine("■ 정상 종료·재시작 이력 (누가 종료시켰는지)");
            if (r.Shutdowns.Count == 0) sb.AppendLine("  기록 없음");
            foreach (var c in r.Shutdowns.Take(40)) sb.AppendLine("  " + c.Time.ToString("yyyy-MM-dd HH:mm") + "  [" + c.Kind + "] " + c.Text);
            return sb.ToString();
        }

        public static string Full(Snapshot s, AnalysisResult r)
        {
            var sb = new StringBuilder();
            sb.AppendLine("CrashLens 분석 리포트");
            sb.AppendLine(new string('=', 60));
            sb.AppendLine(Overall(s, r));
            sb.AppendLine(new string('=', 60));
            sb.AppendLine("■ 사건 목록");
            foreach (var inc in r.Incidents)
                sb.AppendLine("  " + inc.Time.ToString("yyyy-MM-dd HH:mm") + "  " + KindLabel(inc.Kind) + "  " + CodeName(inc) + "  " + ModuleText(inc) + "  → " + ShortCause(inc));
            sb.AppendLine();
            sb.AppendLine(Apps(r));
            sb.AppendLine(Changes(r));
            sb.AppendLine(new string('=', 60));
            sb.AppendLine("■ 사건별 상세");
            foreach (var inc in r.Incidents) { sb.AppendLine(); sb.AppendLine(Detail(inc)); }
            return sb.ToString();
        }
    }
}

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace CrashLens.Core
{
    /// <summary>사건 목록 전체를 보고 패턴을 찾아 진단 문장을 만든다.</summary>
    public static class Findings
    {
        public static void Build(Snapshot s, AnalysisResult r)
        {
            var f = r.Findings;
            var blues = r.Incidents.Where(i => i.Kind == IncidentKind.BlueScreen).OrderBy(i => i.Time).ToList();

            if (r.Incidents.Count == 0)
                f.Add(New(Severity.Info, "기간 내 비정상 종료 기록이 없습니다",
                    "최근 " + s.Days + "일 동안 블루스크린이나 갑작스러운 꺼짐이 이벤트 로그에 없습니다. 더 오래된 문제라면 기간을 늘려 다시 분석하세요."));

            // 1) 같은 블루스크린 반복 / 단발
            int singles = 0;
            foreach (var g in blues.GroupBy(i => i.Signature).OrderByDescending(g => g.Count()))
            {
                var list = g.ToList();
                var first = list[0];
                if (list.Count >= 2) f.Add(Repeated(s, r, list));
                else if (singles++ < 5) f.Add(Single(first));
            }

            // 2) 서로 다른 메모리 계열 블루스크린이 섞여 있음
            var memSigs = blues.Where(i => IsMemoryLike(i.Code)).Select(i => i.Signature).Distinct().Count();
            var codes = blues.Select(i => i.Code).Distinct().Count();
            if (codes >= 3 && memSigs >= 3)
                f.Add(New(Severity.High, "서로 다른 종류의 블루스크린이 섞여 발생합니다 (" + codes + "종)",
                    "매번 다른 위치에서 메모리 손상 계열 오류가 나는 것은 특정 드라이버보다 메모리(RAM)나 CPU 불안정에서 흔한 패턴입니다.\r\n" +
                    "- Windows 메모리 진단(mdsched) 또는 MemTest86으로 메모리를 검사하세요.\r\n" +
                    "- BIOS에서 XMP/오버클럭을 끄고 기본값으로 며칠 써 보세요.\r\n" +
                    "- 메모리가 여러 장이면 한 장씩 꽂아 비교하세요."));

            // 3) 재부팅 직후의 Hardware error는 부산물
            int byp = blues.Count(i => i.WheaByproduct);
            if (byp > 0)
                f.Add(New(Severity.Info, "'Hardware error' 기록 " + byp + "건은 원인이 아니라 부산물입니다",
                    "블루스크린으로 재부팅한 직후 몇 초 안에 찍힌 WHEA / LiveKernelEvent 124 기록입니다. 펌웨어가 '직전에 비정상 리셋이 있었다'고 보고한 것이므로, 이것만으로 하드웨어 고장이라고 판단하지 마세요."));

            // 4) 덤프 없이 꺼짐
            var power = r.Incidents.Where(i => i.Kind == IncidentKind.PowerLoss || i.Kind == IncidentKind.UnexpectedShutdown).ToList();
            if (power.Count > 0)
            {
                int fw = power.Count(i => i.FirmwareResetRecord);
                f.Add(New(power.Count >= 2 ? Severity.High : Severity.Medium,
                    "오류 코드 없이 갑자기 꺼지거나 리셋됨: " + power.Count + "회",
                    "블루스크린 기록조차 남기지 못하고 전원이 끊기거나 리셋된 경우입니다. Windows가 덤프를 쓸 틈이 없었으므로 소프트웨어보다 전원·하드웨어 쪽을 먼저 봅니다.\r\n" +
                    "- 정전, 전원 케이블/멀티탭 접촉, 파워서플라이 노후\r\n" +
                    "- 과열로 인한 보호 차단 (CPU/GPU 온도 확인)\r\n" +
                    "- 시스템이 완전히 멈춰 리셋 버튼이나 워치독으로 재시작된 경우\r\n" +
                    (fw > 0 ? "- 이 중 " + fw + "회는 펌웨어가 비정상 리셋을 직접 기록했습니다(WHEA). 하드웨어/전원 가능성이 더 높습니다.\r\n" : "") +
                    "발생 시각: " + Times(power)));
            }
            var forced = r.Incidents.Where(i => i.Kind == IncidentKind.ForcedPowerOff).ToList();
            if (forced.Count > 0)
                f.Add(New(Severity.Medium, "전원 버튼으로 강제 종료: " + forced.Count + "회",
                    "전원 버튼을 길게 눌러 끈 기록입니다. 대개 그 직전에 화면이 멈췄다는 뜻입니다. 멈춤이 반복되면 그래픽 드라이버, 저장장치, 과열을 확인하세요.\r\n발생 시각: " + Times(forced)));

            // 5) LiveKernelEvent (죽지는 않았지만 커널이 남긴 오류)
            foreach (var g in r.Incidents.Where(i => i.Kind == IncidentKind.LiveKernelEvent).GroupBy(i => i.Code).OrderByDescending(g => g.Count()))
            {
                var any = g.First();
                string label;
                if (!Knowledge.LiveCodes.TryGetValue(g.Key, out label)) label = "커널 오류 보고";
                f.Add(New(g.Count() >= 3 ? Severity.Medium : Severity.Info,
                    "시스템은 유지됐지만 커널 오류 보고 " + g.Count() + "회: 0x" + g.Key.ToString("X") + " " + label,
                    (any.Bucket != "" ? "분류: " + any.Bucket + "\r\n" : "") +
                    (any.Category != "" ? Knowledge.CategoryAdvice(any.Category) + "\r\n" : "") +
                    "발생 시각: " + Times(g.ToList())));
            }

            // 6) 하드웨어 오류
            var hw = r.Incidents.Count(i => i.Kind == IncidentKind.HardwareError);
            if (hw > 0 || r.WheaCorrected > 0)
                f.Add(New(Severity.Medium, "하드웨어 오류 기록(WHEA): 단독 " + hw + "건, 정정된 오류 " + r.WheaCorrected + "건",
                    "크래시와 무관하게 하드웨어가 오류를 보고했습니다. 정정된 오류가 계속 쌓이면 해당 부품(CPU, 메모리, PCIe 장치, SSD)의 초기 불량 신호일 수 있습니다. 이벤트 뷰어의 WHEA-Logger 항목에서 오류 출처를 확인하세요."));

            // 7) 앱 크래시
            foreach (var a in r.Apps.Where(a => a.Crashes + a.Hangs >= 3).Take(4))
                f.Add(New(Severity.Info, "프로그램 반복 오류: " + a.App + " (크래시 " + a.Crashes + ", 응답 없음 " + a.Hangs + ")",
                    "같은 프로그램만 반복해서 죽으면 그 프로그램(또는 표시된 모듈)의 문제입니다. Windows 전체 다운의 원인은 아닙니다.\r\n" +
                    (a.Modules.Count > 0 ? "오류 모듈: " + string.Join(", ", a.Modules.Take(6)) + "\r\n" : "") +
                    (a.Codes.Count > 0 ? "예외: " + string.Join(", ", a.Codes.Take(6)) : "")));
            int avApps = r.Apps.Count(a => a.Codes.Contains("c0000005"));
            if (avApps >= 6)
                f.Add(New(Severity.Medium, "서로 다른 프로그램 " + avApps + "개가 메모리 접근 오류(c0000005)로 종료",
                    "여러 프로그램이 제각각 같은 유형으로 죽는 것은 개별 프로그램 버그보다 메모리(RAM) 불안정에서 흔한 패턴입니다. 메모리 진단을 권합니다."));

            // 8) 수집 환경
            if (s.CrashDumpEnabled == 0)
                f.Add(New(Severity.Medium, "메모리 덤프가 꺼져 있습니다",
                    "블루스크린이 나도 분석할 덤프 파일이 남지 않습니다. sysdm.cpl → 고급 → 시작 및 복구에서 '자동 메모리 덤프' 또는 '작은 메모리 덤프'로 바꾸세요."));
            int mf = blues.Count(i => i.MinidumpFailed);
            if (mf > 0)
                f.Add(New(Severity.Info, "덤프 변환 실패: " + mf + "회",
                    "크래시 후 미니덤프를 만들지 못했다는 기록이 있습니다. 덤프가 불완전하게 저장됐을 수 있습니다. 시스템 드라이브 여유 공간과 페이지 파일 설정(시스템 관리 크기)을 확인하세요."));
            if (!s.IsAdmin)
                f.Add(New(Severity.Info, "관리자 권한 없이 실행했습니다",
                    "이벤트 로그 분석은 정상이지만 덤프 파일 목록(C:\\Windows\\Minidump 등)은 읽지 못했을 수 있습니다. 덤프 경로까지 보려면 관리자 권한으로 실행하세요."));

            r.Findings = f.OrderBy(x => (int)x.Severity).ToList();
        }

        static Finding Repeated(Snapshot s, AnalysisResult r, List<Incident> list)
        {
            var first = list[0];
            var last = list[list.Count - 1];
            var sb = new StringBuilder();
            sb.AppendLine("기간: " + first.Time.ToString("yyyy-MM-dd") + " ~ " + last.Time.ToString("yyyy-MM-dd") + "  (" + Times(list) + ")");
            sb.AppendLine("매번 같은 코드 위치에서 죽었습니다. 무작위 하드웨어 고장이 아니라 특정 드라이버/소프트웨어 결함에서 나오는 패턴입니다.");
            BugcheckInfo info;
            if (Knowledge.Bugchecks.TryGetValue(first.Code, out info)) sb.AppendLine("의미: " + info.Meaning);

            var src = list.FirstOrDefault(i => i.Module != "") ?? first;
            if (src.Module != "")
            {
                sb.AppendLine("지목된 모듈: " + src.Module + (src.Function != "" ? "!" + src.Function : "") + "  [" + Knowledge.CategoryLabel(src.Category) + "]");
                sb.AppendLine(Knowledge.CategoryAdvice(src.Category));
                if (src.Category == "network" && s.NetDrivers.Count > 0)
                {
                    sb.AppendLine("이 PC의 서드파티 네트워크 드라이버 (용의자 목록):");
                    foreach (var d in s.NetDrivers.Take(12))
                        sb.AppendLine("  - " + d.Device + "  [" + d.Provider + " " + d.Version + (d.Date != "" ? ", " + d.Date : "") + "]");
                }
            }
            else
            {
                sb.AppendLine("지목된 모듈 정보가 없습니다(WER 보고가 남지 않음). 덤프를 WinDbg로 분석해야 합니다.");
            }

            // 재부팅 직후 재발
            for (int i = 1; i < list.Count; i++)
            {
                var gap = list[i].Time - list[i - 1].Time;
                if (gap.TotalMinutes <= 15)
                {
                    sb.AppendLine("재부팅 후 " + Math.Max(1, (int)Math.Round(gap.TotalMinutes)) + "분 만에 다시 발생한 적이 있습니다(" + list[i].Time.ToString("MM-dd HH:mm") + "). 부팅 직후 자동으로 시작·연결되는 장치나 프로그램과 관련될 수 있습니다.");
                    break;
                }
            }

            // 언제부터 시작됐는가 + 그 직전 변경 사항
            var windowStart = s.CollectedAt.AddDays(-s.Days);
            if ((first.Time - windowStart).TotalDays >= 14)
                sb.AppendLine(first.Time.ToString("yyyy-MM-dd") + " 이전에는 이 크래시가 없었습니다. 그 무렵 바뀐 것(새 장치, 드라이버, 업데이트, 프로그램)이 가장 강한 단서입니다.");
            var near = r.Changes.Where(c => c.Time <= first.Time && (first.Time - c.Time).TotalDays <= 7).OrderByDescending(c => c.Time).Take(8).ToList();
            if (near.Count > 0)
            {
                sb.AppendLine("첫 발생 직전 7일간의 변경 기록:");
                foreach (var c in near) sb.AppendLine("  - " + c.Time.ToString("MM-dd HH:mm") + " [" + c.Kind + "] " + c.Text);
            }

            // 마지막 발생 이후 조용한 기간
            var quiet = (s.CollectedAt - last.Time).TotalDays;
            if (list.Count >= 3)
            {
                double avgGap = (last.Time - first.Time).TotalDays / (list.Count - 1);
                if (quiet >= Math.Max(5, avgGap * 2.5))
                    sb.AppendLine("평균 " + avgGap.ToString("0.#") + "일 간격으로 나던 크래시가 최근 " + ((int)quiet) + "일간 없습니다. 그 사이 달라진 사용 환경(뺀 장치, 바꾼 연결 방식, 제거한 프로그램)이 원인일 가능성이 높습니다.");
            }

            if (list.Any(i => i.DumpPath != ""))
                sb.AppendLine("덤프 파일이 남아 있습니다. 목록에서 해당 항목을 선택하면 WinDbg 분석 명령이 표시됩니다.");

            string name = info != null ? " " + info.Name : "";
            string where = src.Module != "" ? " — " + src.Module + (src.Function != "" ? "!" + src.Function : "") : "";
            return New(Severity.High, "같은 블루스크린 " + list.Count + "회 반복: " + first.CodeText + name + where, sb.ToString().TrimEnd());
        }

        static Finding Single(Incident inc)
        {
            var sb = new StringBuilder();
            BugcheckInfo info;
            Knowledge.Bugchecks.TryGetValue(inc.Code, out info);
            sb.AppendLine("발생: " + inc.Time.ToString("yyyy-MM-dd HH:mm") + " (1회)");
            if (info != null) { sb.AppendLine("의미: " + info.Meaning); sb.AppendLine("흔한 원인: " + info.Causes); }
            if (inc.Module != "") sb.AppendLine("지목된 모듈: " + inc.Module + (inc.Function != "" ? "!" + inc.Function : "") + "  [" + Knowledge.CategoryLabel(inc.Category) + "]");
            if (inc.Category != "") sb.AppendLine(Knowledge.CategoryAdvice(inc.Category));
            sb.AppendLine("한 번뿐이면 원인을 단정하기 어렵습니다. 재발하는지, 같은 코드인지 지켜보세요.");
            return New(Severity.Medium, "블루스크린 1회: " + inc.CodeText + (info != null ? " " + info.Name : ""), sb.ToString().TrimEnd());
        }

        static bool IsMemoryLike(uint code)
        {
            BugcheckInfo info;
            return Knowledge.Bugchecks.TryGetValue(code, out info) && info.MemoryLike;
        }

        static string Times(List<Incident> list)
        {
            var parts = list.OrderBy(i => i.Time).Select(i => i.Time.ToString("MM-dd HH:mm")).ToList();
            if (parts.Count > 10) return string.Join(", ", parts.Take(10)) + " 외 " + (parts.Count - 10) + "건";
            return string.Join(", ", parts);
        }

        static Finding New(Severity sev, string title, string body)
        {
            return new Finding { Severity = sev, Title = title, Body = body };
        }
    }
}

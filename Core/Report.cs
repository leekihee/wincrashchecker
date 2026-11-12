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
                case IncidentKind.BlueScreen: return L.T("블루스크린", "Blue screen", "Màn hình xanh");
                case IncidentKind.PowerLoss: return L.T("갑작스러운 꺼짐/리셋", "Sudden power-off / reset", "Tắt / reset đột ngột");
                case IncidentKind.ForcedPowerOff: return L.T("전원 버튼 강제 종료", "Forced off (power button)", "Tắt cưỡng bức (nút nguồn)");
                case IncidentKind.UnexpectedShutdown: return L.T("예기치 않은 종료", "Unexpected shutdown", "Tắt máy bất ngờ");
                case IncidentKind.LiveKernelEvent: return L.T("커널 오류 보고(복구됨)", "Kernel error report (recovered)", "Báo cáo lỗi nhân (đã khôi phục)");
                default: return L.T("하드웨어 오류", "Hardware error", "Lỗi phần cứng");
            }
        }

        public static string CodeName(Incident inc)
        {
            if (inc.Code == 0) return "";
            BugcheckInfo info;
            if (inc.Kind == IncidentKind.BlueScreen && Knowledge.Bugchecks.TryGetValue(inc.Code, out info)) return inc.CodeText + " " + info.Name;
            Tx live;
            if (inc.Kind == IncidentKind.LiveKernelEvent && Knowledge.LiveCodes.TryGetValue(inc.Code, out live)) return inc.CodeText + " " + live;
            return inc.CodeText;
        }

        public static string ModuleText(Incident inc)
        {
            if (inc.Module == "") return "";
            return inc.Module + (inc.Function != "" ? "!" + inc.Function : "");
        }

        static string Side(string cat)
        {
            return L.F("{0} 쪽", "{0} side", "Phía {0}", Knowledge.CategoryLabel(cat));
        }

        public static string ShortCause(Incident inc)
        {
            switch (inc.Kind)
            {
                case IncidentKind.BlueScreen:
                    if (inc.Category != "") return Side(inc.Category) + (inc.BucketInferred ? L.T(" (같은 크래시에서 추정)", " (inferred from the same crash)", " (suy ra từ cùng lỗi)") : "");
                    return inc.DumpPath != "" ? L.T("덤프 분석 필요", "Dump analysis needed", "Cần phân tích dump") : L.T("모듈 정보 없음", "No module information", "Không có thông tin mô-đun");
                case IncidentKind.PowerLoss:
                case IncidentKind.UnexpectedShutdown:
                    return inc.FirmwareResetRecord
                        ? L.T("전원/하드웨어 리셋 (펌웨어 기록 있음)", "Power/hardware reset (recorded by firmware)", "Reset nguồn/phần cứng (firmware có ghi nhận)")
                        : L.T("전원 차단 또는 완전 멈춤", "Power cut or complete freeze", "Mất điện hoặc treo hoàn toàn");
                case IncidentKind.ForcedPowerOff: return L.T("직전에 시스템 멈춤 추정", "System probably froze just before", "Có lẽ hệ thống bị treo ngay trước đó");
                case IncidentKind.LiveKernelEvent: return inc.Category != "" ? Side(inc.Category) : "";
                default: return L.T("하드웨어가 오류 보고", "Hardware reported an error", "Phần cứng báo lỗi");
            }
        }

        public static string Overall(Snapshot s, AnalysisResult r)
        {
            var sb = new StringBuilder();
            sb.AppendLine("■ " + L.T("시스템", "System", "Hệ thống"));
            sb.AppendLine("  " + L.F("분석 시각: {0}   분석 기간: 최근 {1}일", "Analyzed: {0}   Period: last {1} days", "Thời điểm phân tích: {0}   Khoảng thời gian: {1} ngày gần đây", s.CollectedAt.ToString("yyyy-MM-dd HH:mm"), s.Days));
            if (s.Model != "") sb.AppendLine("  " + L.T("모델: ", "Model: ", "Model: ") + s.Model);
            if (s.Os != "") sb.AppendLine("  OS: " + s.Os);
            if (s.Cpu != "") sb.AppendLine("  CPU: " + s.Cpu + (s.Memory != "" ? "   " + L.T("메모리: ", "Memory: ", "Bộ nhớ: ") + s.Memory : ""));
            if (s.Bios != "") sb.AppendLine("  BIOS: " + s.Bios);
            sb.AppendLine();

            sb.AppendLine("■ " + L.T("요약", "Summary", "Tóm tắt"));
            sb.AppendLine("  " + L.F("블루스크린 {0}회 / 코드 없는 꺼짐·리셋 {1}회 / 강제 종료 {2}회 / 커널 오류 보고 {3}회 / 프로그램 오류 {4}건",
                "Blue screens {0} / power-offs or resets with no code {1} / forced power-offs {2} / kernel error reports {3} / program failures {4}",
                "Màn hình xanh {0} / tắt hoặc reset không mã lỗi {1} / tắt cưỡng bức {2} / báo cáo lỗi nhân {3} / lỗi chương trình {4}",
                r.Incidents.Count(i => i.Kind == IncidentKind.BlueScreen),
                r.Incidents.Count(i => i.Kind == IncidentKind.PowerLoss || i.Kind == IncidentKind.UnexpectedShutdown),
                r.Incidents.Count(i => i.Kind == IncidentKind.ForcedPowerOff),
                r.Incidents.Count(i => i.Kind == IncidentKind.LiveKernelEvent),
                r.Apps.Sum(a => a.Crashes + a.Hangs)));
            sb.AppendLine();

            sb.AppendLine("■ " + L.T("진단", "Diagnosis", "Chẩn đoán"));
            int n = 1;
            foreach (var f in r.Findings)
            {
                string tag = f.Severity == Severity.High ? L.T("[중요]", "[Important]", "[Quan trọng]")
                           : f.Severity == Severity.Medium ? L.T("[주의]", "[Caution]", "[Lưu ý]")
                           : L.T("[참고]", "[Note]", "[Tham khảo]");
                sb.AppendLine(n++ + ". " + tag + " " + f.Title);
                foreach (var line in f.Body.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None)) sb.AppendLine("   " + line);
                sb.AppendLine();
            }
            foreach (var w in s.Warnings) sb.AppendLine("※ " + w);
            sb.AppendLine(L.T("이 진단은 이벤트 로그 패턴에 근거한 추정입니다. 확정하려면 덤프 분석이나 장치를 하나씩 빼 보는 비교가 필요합니다.",
                              "This diagnosis is an inference from event log patterns. Confirming it takes dump analysis or removing devices one at a time and comparing.",
                              "Chẩn đoán này là suy luận từ các mẫu trong nhật ký sự kiện. Để xác nhận cần phân tích dump hoặc tháo từng thiết bị để so sánh."));
            return sb.ToString();
        }

        public static string Detail(Incident inc)
        {
            var sb = new StringBuilder();
            sb.AppendLine("■ " + KindLabel(inc.Kind) + "  " + inc.Time.ToString("yyyy-MM-dd HH:mm:ss") + "  " + L.T("(재부팅 후 기록된 시각)", "(time logged after reboot)", "(thời điểm ghi sau khi khởi động lại)"));
            if (inc.Code != 0) sb.AppendLine(L.T("코드: ", "Code: ", "Mã: ") + CodeName(inc));
            BugcheckInfo info;
            if (inc.Kind == IncidentKind.BlueScreen && Knowledge.Bugchecks.TryGetValue(inc.Code, out info))
            {
                sb.AppendLine(L.T("의미: ", "Meaning: ", "Ý nghĩa: ") + info.Meaning);
                sb.AppendLine(L.T("흔한 원인: ", "Common causes: ", "Nguyên nhân thường gặp: ") + info.Causes);
            }
            if (inc.Kind == IncidentKind.BlueScreen)
                sb.AppendLine(L.T("파라미터: ", "Parameters: ", "Tham số: ") + string.Join(", ", inc.P.Select(p => "0x" + p.ToString("x"))));
            if (inc.Bucket != "")
                sb.AppendLine(L.T("Windows 분류(버킷): ", "Windows bucket: ", "Phân loại của Windows (bucket): ") + inc.Bucket +
                    (inc.BucketInferred ? "  ← " + L.T("같은 위치에서 난 다른 크래시의 분류를 적용", "taken from another crash at the same location", "lấy từ một lần sập khác tại cùng vị trí") : ""));
            if (inc.Module != "") sb.AppendLine(L.T("지목된 모듈: ", "Named module: ", "Mô-đun được nêu: ") + ModuleText(inc) + "  [" + Knowledge.CategoryLabel(inc.Category) + "]");
            if (inc.Category != "") { sb.AppendLine(); sb.AppendLine(Knowledge.CategoryAdvice(inc.Category)); }
            if (inc.WheaByproduct)
            {
                sb.AppendLine();
                sb.AppendLine(L.T("함께 찍힌 Hardware error(WHEA / LiveKernelEvent 124)는 재부팅 직후 펌웨어가 보고한 부산물입니다.",
                                  "The Hardware error logged alongside (WHEA / LiveKernelEvent 124) is a by-product reported by the firmware right after reboot.",
                                  "Hardware error ghi kèm (WHEA / LiveKernelEvent 124) là hệ quả do firmware báo ngay sau khi khởi động lại."));
            }
            if (inc.FirmwareResetRecord)
            {
                sb.AppendLine();
                sb.AppendLine(L.T("펌웨어가 비정상 리셋을 기록했습니다(WHEA). 전원/하드웨어 수준의 리셋 가능성이 높습니다.",
                                  "The firmware recorded an abnormal reset (WHEA). A power- or hardware-level reset is likely.",
                                  "Firmware đã ghi nhận reset bất thường (WHEA). Nhiều khả năng là reset ở mức nguồn/phần cứng."));
            }
            if (inc.MinidumpFailed)
                sb.AppendLine(L.T("이 크래시는 미니덤프 변환에 실패했습니다(덤프가 불완전할 수 있음).",
                                  "Minidump conversion failed for this crash (the dump may be incomplete).",
                                  "Lần sập này không chuyển đổi được minidump (dump có thể không đầy đủ)."));

            sb.AppendLine();
            if (inc.DumpPath != "")
            {
                sb.AppendLine("■ " + L.T("덤프 파일: ", "Dump file: ", "Tệp dump: ") + inc.DumpPath);
                sb.AppendLine(L.T("WinDbg가 설치돼 있으면 관리자 PowerShell에서 아래 한 줄로 분석 결과를 파일로 받을 수 있습니다.",
                                  "With WinDbg installed, this one line in an administrator PowerShell writes the analysis to a file.",
                                  "Nếu đã cài WinDbg, một dòng lệnh sau trong PowerShell quyền quản trị sẽ ghi kết quả phân tích ra tệp."));
                sb.AppendLine("  windbgx -z \"" + inc.DumpPath + "\" -c \".logopen C:\\Users\\Public\\crash_analyze.txt; !analyze -v; r; kv 40; .logclose\"");
                sb.AppendLine(L.T("결과의 STACK_TEXT(호출 스택)에서 Windows 기본 모듈이 아닌 드라이버 이름을 찾으세요.",
                                  "In the result, look in STACK_TEXT (the call stack) for a driver name that is not a Windows component.",
                                  "Trong kết quả, hãy tìm ở STACK_TEXT (ngăn xếp lời gọi) tên trình điều khiển không phải thành phần của Windows."));
            }
            else if (inc.Kind == IncidentKind.BlueScreen)
            {
                sb.AppendLine("■ " + L.T("이 크래시의 덤프 파일은 남아 있지 않습니다(또는 권한 부족으로 확인하지 못했습니다).",
                                         "No dump file remains for this crash (or it could not be checked without administrator rights).",
                                         "Không còn tệp dump cho lần sập này (hoặc không kiểm tra được do thiếu quyền quản trị)."));
            }

            sb.AppendLine();
            sb.AppendLine("■ " + L.F("관련 이벤트 ({0}건)", "Related events ({0})", "Sự kiện liên quan ({0})", inc.Events.Count));
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
            sb.AppendLine("■ " + L.T("프로그램 오류 (크래시 / 응답 없음)", "Program failures (crashes / hangs)", "Lỗi chương trình (sập / treo)"));
            if (r.Apps.Count == 0) sb.AppendLine("  " + None());
            foreach (var a in r.Apps.Take(40))
            {
                sb.AppendLine("  " + a.App + "  — " + L.F("크래시 {0}, 응답 없음 {1}, 마지막 {2}", "crashes {0}, hangs {1}, last {2}", "sập {0}, treo {1}, lần cuối {2}", a.Crashes, a.Hangs, a.Last.ToString("MM-dd HH:mm")));
                if (a.Modules.Count > 0) sb.AppendLine("      " + L.T("모듈: ", "Module: ", "Mô-đun: ") + string.Join(", ", a.Modules.Take(6)));
                if (a.Codes.Count > 0) sb.AppendLine("      " + L.T("예외: ", "Exception: ", "Ngoại lệ: ") + string.Join(", ", a.Codes.Take(6)));
            }
            return sb.ToString();
        }

        public static string Changes(AnalysisResult r)
        {
            var sb = new StringBuilder();
            sb.AppendLine("■ " + L.T("변경 이력 (Windows 업데이트 / 드라이버 설치 / 프로그램 설치)", "Change history (Windows updates / driver installs / program installs)", "Lịch sử thay đổi (cập nhật Windows / cài trình điều khiển / cài chương trình)"));
            if (r.Changes.Count == 0) sb.AppendLine("  " + None());
            foreach (var c in r.Changes.Take(80)) sb.AppendLine("  " + c.Time.ToString("yyyy-MM-dd HH:mm") + "  [" + c.Kind + "] " + c.Text);
            sb.AppendLine();
            sb.AppendLine("■ " + L.T("정상 종료·재시작 이력 (누가 종료시켰는지)", "Normal shutdown / restart history (who initiated it)", "Lịch sử tắt / khởi động lại bình thường (ai thực hiện)"));
            if (r.Shutdowns.Count == 0) sb.AppendLine("  " + None());
            foreach (var c in r.Shutdowns.Take(40)) sb.AppendLine("  " + c.Time.ToString("yyyy-MM-dd HH:mm") + "  [" + c.Kind + "] " + c.Text);
            return sb.ToString();
        }

        static string None() { return L.T("기록 없음", "No records", "Không có bản ghi"); }

        public static string Full(Snapshot s, AnalysisResult r)
        {
            var sb = new StringBuilder();
            sb.AppendLine(L.T("CrashLens 분석 리포트", "CrashLens analysis report", "Báo cáo phân tích CrashLens"));
            sb.AppendLine(new string('=', 60));
            sb.AppendLine(Overall(s, r));
            sb.AppendLine(new string('=', 60));
            sb.AppendLine("■ " + L.T("사건 목록", "Incident list", "Danh sách sự cố"));
            foreach (var inc in r.Incidents)
                sb.AppendLine("  " + inc.Time.ToString("yyyy-MM-dd HH:mm") + "  " + KindLabel(inc.Kind) + "  " + CodeName(inc) + "  " + ModuleText(inc) + "  → " + ShortCause(inc));
            sb.AppendLine();
            sb.AppendLine(Apps(r));
            sb.AppendLine(Changes(r));
            sb.AppendLine(new string('=', 60));
            sb.AppendLine("■ " + L.T("사건별 상세", "Incident details", "Chi tiết từng sự cố"));
            foreach (var inc in r.Incidents) { sb.AppendLine(); sb.AppendLine(Detail(inc)); }
            return sb.ToString();
        }
    }
}

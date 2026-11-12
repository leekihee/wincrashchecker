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
                f.Add(New(Severity.Info,
                    L.T("기간 내 비정상 종료 기록이 없습니다", "No abnormal shutdowns in this period", "Không có lần tắt bất thường nào trong khoảng thời gian này"),
                    L.F("최근 {0}일 동안 블루스크린이나 갑작스러운 꺼짐이 이벤트 로그에 없습니다. 더 오래된 문제라면 기간을 늘려 다시 분석하세요.",
                        "The event log shows no blue screens or sudden power-offs in the last {0} days. For an older problem, widen the period and analyze again.",
                        "Nhật ký sự kiện không ghi nhận màn hình xanh hay tắt đột ngột nào trong {0} ngày qua. Nếu sự cố xảy ra lâu hơn, hãy tăng khoảng thời gian rồi phân tích lại.", s.Days)));

            // 1) 같은 블루스크린 반복 / 단발
            int singles = 0;
            foreach (var g in blues.GroupBy(i => i.Signature).OrderByDescending(g => g.Count()))
            {
                var list = g.ToList();
                if (list.Count >= 2) f.Add(Repeated(s, r, list));
                else if (singles++ < 5) f.Add(Single(list[0]));
            }

            // 2) 서로 다른 메모리 계열 블루스크린이 섞여 있음
            var memSigs = blues.Where(i => IsMemoryLike(i.Code)).Select(i => i.Signature).Distinct().Count();
            var codes = blues.Select(i => i.Code).Distinct().Count();
            if (codes >= 3 && memSigs >= 3)
                f.Add(New(Severity.High,
                    L.F("서로 다른 종류의 블루스크린이 섞여 발생합니다 ({0}종)", "Different kinds of blue screens are mixed ({0} kinds)", "Nhiều loại màn hình xanh khác nhau xen kẽ ({0} loại)", codes),
                    L.T("매번 다른 위치에서 메모리 손상 계열 오류가 나는 것은 특정 드라이버보다 메모리(RAM)나 CPU 불안정에서 흔한 패턴입니다.\r\n" +
                        "- Windows 메모리 진단(mdsched) 또는 MemTest86으로 메모리를 검사하세요.\r\n" +
                        "- BIOS에서 XMP/오버클럭을 끄고 기본값으로 며칠 써 보세요.\r\n" +
                        "- 메모리가 여러 장이면 한 장씩 꽂아 비교하세요.",
                        "Memory-corruption errors at a different location each time are more typical of unstable RAM or CPU than of one specific driver.\r\n" +
                        "- Test the memory with Windows Memory Diagnostic (mdsched) or MemTest86.\r\n" +
                        "- Turn off XMP/overclocking in the BIOS and run on defaults for a few days.\r\n" +
                        "- With several memory modules, test them one at a time.",
                        "Lỗi hỏng bộ nhớ xảy ra ở vị trí khác nhau mỗi lần thường do RAM hoặc CPU không ổn định hơn là do một trình điều khiển cụ thể.\r\n" +
                        "- Kiểm tra RAM bằng Windows Memory Diagnostic (mdsched) hoặc MemTest86.\r\n" +
                        "- Tắt XMP/ép xung trong BIOS và chạy mặc định vài ngày.\r\n" +
                        "- Nếu có nhiều thanh RAM, hãy thử từng thanh một.")));

            // 3) 재부팅 직후의 Hardware error는 부산물
            int byp = blues.Count(i => i.WheaByproduct);
            if (byp > 0)
                f.Add(New(Severity.Info,
                    L.F("'Hardware error' 기록 {0}건은 원인이 아니라 부산물입니다", "{0} 'Hardware error' records are by-products, not the cause", "{0} bản ghi 'Hardware error' là hệ quả, không phải nguyên nhân", byp),
                    L.T("블루스크린으로 재부팅한 직후 몇 초 안에 찍힌 WHEA / LiveKernelEvent 124 기록입니다. 펌웨어가 '직전에 비정상 리셋이 있었다'고 보고한 것이므로, 이것만으로 하드웨어 고장이라고 판단하지 마세요.",
                        "These are WHEA / LiveKernelEvent 124 records logged within seconds of rebooting after a blue screen. The firmware is reporting that an abnormal reset just happened, so do not conclude a hardware fault from them alone.",
                        "Đây là các bản ghi WHEA / LiveKernelEvent 124 được ghi chỉ vài giây sau khi khởi động lại do màn hình xanh. Firmware chỉ báo rằng vừa có một lần reset bất thường, nên đừng chỉ dựa vào đó để kết luận phần cứng hỏng.")));

            // 4) 덤프 없이 꺼짐
            var power = r.Incidents.Where(i => i.Kind == IncidentKind.PowerLoss || i.Kind == IncidentKind.UnexpectedShutdown).ToList();
            if (power.Count > 0)
            {
                int fw = power.Count(i => i.FirmwareResetRecord);
                f.Add(New(power.Count >= 2 ? Severity.High : Severity.Medium,
                    L.F("오류 코드 없이 갑자기 꺼지거나 리셋됨: {0}회", "Sudden power-off or reset with no error code: {0} time(s)", "Tắt hoặc reset đột ngột không có mã lỗi: {0} lần", power.Count),
                    L.T("블루스크린 기록조차 남기지 못하고 전원이 끊기거나 리셋된 경우입니다. Windows가 덤프를 쓸 틈이 없었으므로 소프트웨어보다 전원·하드웨어 쪽을 먼저 봅니다.\r\n" +
                        "- 정전, 전원 케이블/멀티탭 접촉, 파워서플라이 노후\r\n" +
                        "- 과열로 인한 보호 차단 (CPU/GPU 온도 확인)\r\n" +
                        "- 시스템이 완전히 멈춰 리셋 버튼이나 워치독으로 재시작된 경우\r\n",
                        "The PC lost power or reset without even recording a blue screen. Windows had no chance to write a dump, so look at power and hardware before software.\r\n" +
                        "- Power outage, loose power cable or power strip, aging power supply\r\n" +
                        "- Thermal protection shutdown (check CPU/GPU temperatures)\r\n" +
                        "- A complete freeze followed by the reset button or a watchdog restart\r\n",
                        "Máy mất điện hoặc reset mà không kịp ghi cả màn hình xanh. Windows không có thời gian ghi dump, nên hãy xem nguồn điện và phần cứng trước phần mềm.\r\n" +
                        "- Mất điện, dây nguồn/ổ cắm lỏng, bộ nguồn xuống cấp\r\n" +
                        "- Tự ngắt bảo vệ do quá nhiệt (kiểm tra nhiệt độ CPU/GPU)\r\n" +
                        "- Máy treo hoàn toàn rồi bị bấm nút reset hoặc watchdog khởi động lại\r\n") +
                    (fw > 0 ? L.F("- 이 중 {0}회는 펌웨어가 비정상 리셋을 직접 기록했습니다(WHEA). 하드웨어/전원 가능성이 더 높습니다.\r\n",
                                  "- In {0} of these the firmware itself recorded an abnormal reset (WHEA), which makes hardware/power more likely.\r\n",
                                  "- Trong đó {0} lần firmware tự ghi nhận reset bất thường (WHEA), nên khả năng do phần cứng/nguồn cao hơn.\r\n", fw) : "") +
                    L.T("발생 시각: ", "Occurred: ", "Thời điểm: ") + Times(power)));
            }
            var forced = r.Incidents.Where(i => i.Kind == IncidentKind.ForcedPowerOff).ToList();
            if (forced.Count > 0)
                f.Add(New(Severity.Medium,
                    L.F("전원 버튼으로 강제 종료: {0}회", "Forced power-off with the power button: {0} time(s)", "Tắt cưỡng bức bằng nút nguồn: {0} lần", forced.Count),
                    L.T("전원 버튼을 길게 눌러 끈 기록입니다. 대개 그 직전에 화면이 멈췄다는 뜻입니다. 멈춤이 반복되면 그래픽 드라이버, 저장장치, 과열을 확인하세요.",
                        "The power button was held down to turn the PC off, which usually means the screen had frozen just before. If freezes repeat, check the graphics driver, storage and overheating.",
                        "Nút nguồn đã bị giữ để tắt máy, thường nghĩa là màn hình bị treo ngay trước đó. Nếu treo lặp lại, hãy kiểm tra trình điều khiển đồ họa, ổ lưu trữ và tình trạng quá nhiệt.") +
                    "\r\n" + L.T("발생 시각: ", "Occurred: ", "Thời điểm: ") + Times(forced)));

            // 5) LiveKernelEvent (죽지는 않았지만 커널이 남긴 오류)
            foreach (var g in r.Incidents.Where(i => i.Kind == IncidentKind.LiveKernelEvent).GroupBy(i => i.Code).OrderByDescending(g => g.Count()))
            {
                var any = g.First();
                Tx tx;
                string label = Knowledge.LiveCodes.TryGetValue(g.Key, out tx) ? tx.ToString() : L.T("커널 오류 보고", "Kernel error report", "Báo cáo lỗi nhân");
                f.Add(New(g.Count() >= 3 ? Severity.Medium : Severity.Info,
                    L.F("시스템은 유지됐지만 커널 오류 보고 {0}회: 0x{1} {2}", "System stayed up, but {0} kernel error report(s): 0x{1} {2}", "Hệ thống vẫn chạy nhưng có {0} báo cáo lỗi nhân: 0x{1} {2}", g.Count(), g.Key.ToString("X"), label),
                    (any.Bucket != "" ? L.T("분류: ", "Bucket: ", "Phân loại: ") + any.Bucket + "\r\n" : "") +
                    (any.Category != "" ? Knowledge.CategoryAdvice(any.Category) + "\r\n" : "") +
                    L.T("발생 시각: ", "Occurred: ", "Thời điểm: ") + Times(g.ToList())));
            }

            // 6) 하드웨어 오류
            var hw = r.Incidents.Count(i => i.Kind == IncidentKind.HardwareError);
            if (hw > 0 || r.WheaCorrected > 0)
                f.Add(New(Severity.Medium,
                    L.F("하드웨어 오류 기록(WHEA): 단독 {0}건, 정정된 오류 {1}건", "Hardware error records (WHEA): {0} standalone, {1} corrected", "Bản ghi lỗi phần cứng (WHEA): {0} độc lập, {1} đã được sửa", hw, r.WheaCorrected),
                    L.T("크래시와 무관하게 하드웨어가 오류를 보고했습니다. 정정된 오류가 계속 쌓이면 해당 부품(CPU, 메모리, PCIe 장치, SSD)의 초기 불량 신호일 수 있습니다. 이벤트 뷰어의 WHEA-Logger 항목에서 오류 출처를 확인하세요.",
                        "Hardware reported errors independently of any crash. If corrected errors keep accumulating, they can be an early sign of a failing part (CPU, RAM, PCIe device, SSD). Check the error source under WHEA-Logger in Event Viewer.",
                        "Phần cứng báo lỗi không liên quan đến lần sập nào. Nếu lỗi đã sửa cứ tăng dần, đó có thể là dấu hiệu sớm của linh kiện sắp hỏng (CPU, RAM, thiết bị PCIe, SSD). Hãy xem nguồn lỗi trong mục WHEA-Logger của Event Viewer.")));

            // 7) 앱 크래시
            foreach (var a in r.Apps.Where(a => a.Crashes + a.Hangs >= 3).Take(4))
                f.Add(New(Severity.Info,
                    L.F("프로그램 반복 오류: {0} (크래시 {1}, 응답 없음 {2})", "Repeated program failures: {0} (crashes {1}, hangs {2})", "Chương trình lỗi lặp lại: {0} (sập {1}, treo {2})", a.App, a.Crashes, a.Hangs),
                    L.T("같은 프로그램만 반복해서 죽으면 그 프로그램(또는 표시된 모듈)의 문제입니다. Windows 전체 다운의 원인은 아닙니다.",
                        "When only the same program keeps failing, the problem is in that program (or the module shown). It is not the cause of whole-system crashes.",
                        "Khi chỉ một chương trình lỗi lặp lại thì vấn đề nằm ở chương trình đó (hoặc mô-đun được nêu). Đó không phải nguyên nhân làm sập cả Windows.") + "\r\n" +
                    (a.Modules.Count > 0 ? L.T("오류 모듈: ", "Faulting module: ", "Mô-đun lỗi: ") + string.Join(", ", a.Modules.Take(6)) + "\r\n" : "") +
                    (a.Codes.Count > 0 ? L.T("예외: ", "Exception: ", "Ngoại lệ: ") + string.Join(", ", a.Codes.Take(6)) : "")));
            int avApps = r.Apps.Count(a => a.Codes.Contains("c0000005"));
            if (avApps >= 6)
                f.Add(New(Severity.Medium,
                    L.F("서로 다른 프로그램 {0}개가 메모리 접근 오류(c0000005)로 종료", "{0} different programs ended with an access violation (c0000005)", "{0} chương trình khác nhau kết thúc do lỗi truy cập bộ nhớ (c0000005)", avApps),
                    L.T("여러 프로그램이 제각각 같은 유형으로 죽는 것은 개별 프로그램 버그보다 메모리(RAM) 불안정에서 흔한 패턴입니다. 메모리 진단을 권합니다.",
                        "Many unrelated programs failing the same way is more typical of unstable RAM than of individual program bugs. Run a memory diagnostic.",
                        "Nhiều chương trình không liên quan cùng lỗi theo một kiểu thường do RAM không ổn định hơn là lỗi riêng từng chương trình. Nên chạy chẩn đoán bộ nhớ.")));

            // 8) 수집 환경
            if (s.CrashDumpEnabled == 0)
                f.Add(New(Severity.Medium,
                    L.T("메모리 덤프가 꺼져 있습니다", "Memory dumps are turned off", "Tính năng ghi dump bộ nhớ đang tắt"),
                    L.T("블루스크린이 나도 분석할 덤프 파일이 남지 않습니다. sysdm.cpl → 고급 → 시작 및 복구에서 '자동 메모리 덤프' 또는 '작은 메모리 덤프'로 바꾸세요.",
                        "A blue screen will leave no dump file to analyze. In sysdm.cpl → Advanced → Startup and Recovery, choose 'Automatic memory dump' or 'Small memory dump'.",
                        "Khi có màn hình xanh sẽ không có tệp dump để phân tích. Trong sysdm.cpl → Advanced → Startup and Recovery, hãy chọn 'Automatic memory dump' hoặc 'Small memory dump'.")));
            int mf = blues.Count(i => i.MinidumpFailed);
            if (mf > 0)
                f.Add(New(Severity.Info,
                    L.F("덤프 변환 실패: {0}회", "Dump conversion failed: {0} time(s)", "Chuyển đổi dump thất bại: {0} lần", mf),
                    L.T("크래시 후 미니덤프를 만들지 못했다는 기록이 있습니다. 덤프가 불완전하게 저장됐을 수 있습니다. 시스템 드라이브 여유 공간과 페이지 파일 설정(시스템 관리 크기)을 확인하세요.",
                        "Windows logged that it could not produce a minidump after the crash, so the dump may be incomplete. Check free space on the system drive and the page file setting (system managed size).",
                        "Windows ghi nhận không tạo được minidump sau khi sập, nên tệp dump có thể không đầy đủ. Hãy kiểm tra dung lượng trống của ổ hệ thống và thiết lập tệp phân trang (để hệ thống quản lý).")));
            if (!s.IsAdmin)
                f.Add(New(Severity.Info,
                    L.T("관리자 권한 없이 실행했습니다", "Running without administrator rights", "Đang chạy không có quyền quản trị"),
                    L.T("이벤트 로그 분석은 정상이지만 덤프 파일 목록(C:\\Windows\\Minidump 등)은 읽지 못했을 수 있습니다. 덤프 경로까지 보려면 관리자 권한으로 실행하세요.",
                        "Event log analysis works, but the dump file list (C:\\Windows\\Minidump and others) may not have been readable. Run as administrator to see dump paths.",
                        "Phân tích nhật ký sự kiện vẫn hoạt động, nhưng có thể không đọc được danh sách tệp dump (C:\\Windows\\Minidump...). Hãy chạy với quyền quản trị để xem đường dẫn dump.")));

            r.Findings = f.OrderBy(x => (int)x.Severity).ToList();
        }

        static Finding Repeated(Snapshot s, AnalysisResult r, List<Incident> list)
        {
            var first = list[0];
            var last = list[list.Count - 1];
            var sb = new StringBuilder();
            sb.AppendLine(L.T("기간: ", "Period: ", "Khoảng thời gian: ") + first.Time.ToString("yyyy-MM-dd") + " ~ " + last.Time.ToString("yyyy-MM-dd") + "  (" + Times(list) + ")");
            sb.AppendLine(L.T("매번 같은 코드 위치에서 죽었습니다. 무작위 하드웨어 고장이 아니라 특정 드라이버/소프트웨어 결함에서 나오는 패턴입니다.",
                              "It crashed at the same code location every time. That is the pattern of a specific driver/software defect, not of random hardware failure.",
                              "Lần nào cũng sập tại cùng một vị trí mã. Đây là kiểu lỗi của một trình điều khiển/phần mềm cụ thể, không phải hỏng phần cứng ngẫu nhiên."));
            BugcheckInfo info;
            if (Knowledge.Bugchecks.TryGetValue(first.Code, out info)) sb.AppendLine(L.T("의미: ", "Meaning: ", "Ý nghĩa: ") + info.Meaning);

            var src = list.FirstOrDefault(i => i.Module != "") ?? first;
            if (src.Module != "")
            {
                sb.AppendLine(L.T("지목된 모듈: ", "Named module: ", "Mô-đun được nêu: ") + src.Module + (src.Function != "" ? "!" + src.Function : "") + "  [" + Knowledge.CategoryLabel(src.Category) + "]");
                sb.AppendLine(Knowledge.CategoryAdvice(src.Category));
                if (src.Category == "network" && s.NetDrivers.Count > 0)
                {
                    sb.AppendLine(L.T("이 PC의 서드파티 네트워크 드라이버 (용의자 목록):", "Third-party network drivers on this PC (suspect list):", "Trình điều khiển mạng bên thứ ba trên máy này (danh sách nghi vấn):"));
                    foreach (var d in s.NetDrivers.Take(12))
                        sb.AppendLine("  - " + d.Device + "  [" + d.Provider + " " + d.Version + (d.Date != "" ? ", " + d.Date : "") + "]");
                }
            }
            else
            {
                sb.AppendLine(L.T("지목된 모듈 정보가 없습니다(WER 보고가 남지 않음). 덤프를 WinDbg로 분석해야 합니다.",
                                  "No module was named (no WER report was kept). The dump needs to be analyzed in WinDbg.",
                                  "Không có mô-đun nào được nêu (không còn báo cáo WER). Cần phân tích tệp dump bằng WinDbg."));
            }

            // 재부팅 직후 재발
            for (int i = 1; i < list.Count; i++)
            {
                var gap = list[i].Time - list[i - 1].Time;
                if (gap.TotalMinutes <= 15)
                {
                    sb.AppendLine(L.F("재부팅 후 {0}분 만에 다시 발생한 적이 있습니다({1}). 부팅 직후 자동으로 시작·연결되는 장치나 프로그램과 관련될 수 있습니다.",
                                      "It once recurred {0} minute(s) after rebooting ({1}). It may be tied to a device or program that starts or connects right after boot.",
                                      "Đã có lần tái diễn chỉ {0} phút sau khi khởi động lại ({1}). Có thể liên quan đến thiết bị hoặc chương trình tự khởi động/kết nối ngay sau khi bật máy.",
                                      Math.Max(1, (int)Math.Round(gap.TotalMinutes)), list[i].Time.ToString("MM-dd HH:mm")));
                    break;
                }
            }

            // 언제부터 시작됐는가 + 그 직전 변경 사항
            var windowStart = s.CollectedAt.AddDays(-s.Days);
            if ((first.Time - windowStart).TotalDays >= 14)
                sb.AppendLine(L.F("{0} 이전에는 이 크래시가 없었습니다. 그 무렵 바뀐 것(새 장치, 드라이버, 업데이트, 프로그램)이 가장 강한 단서입니다.",
                                  "This crash did not occur before {0}. Whatever changed around then (new device, driver, update, program) is the strongest lead.",
                                  "Trước {0} không có lỗi này. Những gì thay đổi quanh thời điểm đó (thiết bị mới, trình điều khiển, bản cập nhật, chương trình) là manh mối mạnh nhất.",
                                  first.Time.ToString("yyyy-MM-dd")));
            var near = r.Changes.Where(c => c.Time <= first.Time && (first.Time - c.Time).TotalDays <= 7).OrderByDescending(c => c.Time).Take(8).ToList();
            if (near.Count > 0)
            {
                sb.AppendLine(L.T("첫 발생 직전 7일간의 변경 기록:", "Changes in the 7 days before the first occurrence:", "Các thay đổi trong 7 ngày trước lần đầu xảy ra:"));
                foreach (var c in near) sb.AppendLine("  - " + c.Time.ToString("MM-dd HH:mm") + " [" + c.Kind + "] " + c.Text);
            }

            // 마지막 발생 이후 조용한 기간
            var quiet = (s.CollectedAt - last.Time).TotalDays;
            if (list.Count >= 3)
            {
                double avgGap = (last.Time - first.Time).TotalDays / (list.Count - 1);
                if (quiet >= Math.Max(5, avgGap * 2.5))
                    sb.AppendLine(L.F("평균 {0}일 간격으로 나던 크래시가 최근 {1}일간 없습니다. 그 사이 달라진 사용 환경(뺀 장치, 바꾼 연결 방식, 제거한 프로그램)이 원인일 가능성이 높습니다.",
                                      "The crash used to occur about every {0} day(s) but has not occurred for the last {1} days. Whatever changed in how the PC is used since then (a device removed, a different connection, a program uninstalled) is likely the cause.",
                                      "Lỗi từng xảy ra khoảng {0} ngày một lần nhưng {1} ngày gần đây không còn. Điều gì đã thay đổi trong cách dùng máy từ đó (rút thiết bị, đổi cách kết nối, gỡ chương trình) nhiều khả năng là nguyên nhân.",
                                      avgGap.ToString("0.#"), (int)quiet));
            }

            if (list.Any(i => i.DumpPath != ""))
                sb.AppendLine(L.T("덤프 파일이 남아 있습니다. 목록에서 해당 항목을 선택하면 WinDbg 분석 명령이 표시됩니다.",
                                  "Dump files are available. Select the item in the list to see the WinDbg analysis command.",
                                  "Còn tệp dump. Chọn mục tương ứng trong danh sách để xem lệnh phân tích WinDbg."));

            string name = info != null ? " " + info.Name : "";
            string where = src.Module != "" ? " — " + src.Module + (src.Function != "" ? "!" + src.Function : "") : "";
            return New(Severity.High,
                L.F("같은 블루스크린 {0}회 반복: ", "Same blue screen repeated {0} times: ", "Cùng một lỗi màn hình xanh lặp lại {0} lần: ", list.Count) + first.CodeText + name + where,
                sb.ToString().TrimEnd());
        }

        static Finding Single(Incident inc)
        {
            var sb = new StringBuilder();
            BugcheckInfo info;
            Knowledge.Bugchecks.TryGetValue(inc.Code, out info);
            sb.AppendLine(L.T("발생: ", "Occurred: ", "Thời điểm: ") + inc.Time.ToString("yyyy-MM-dd HH:mm") + L.T(" (1회)", " (once)", " (1 lần)"));
            if (info != null)
            {
                sb.AppendLine(L.T("의미: ", "Meaning: ", "Ý nghĩa: ") + info.Meaning);
                sb.AppendLine(L.T("흔한 원인: ", "Common causes: ", "Nguyên nhân thường gặp: ") + info.Causes);
            }
            if (inc.Module != "") sb.AppendLine(L.T("지목된 모듈: ", "Named module: ", "Mô-đun được nêu: ") + inc.Module + (inc.Function != "" ? "!" + inc.Function : "") + "  [" + Knowledge.CategoryLabel(inc.Category) + "]");
            if (inc.Category != "") sb.AppendLine(Knowledge.CategoryAdvice(inc.Category));
            sb.AppendLine(L.T("한 번뿐이면 원인을 단정하기 어렵습니다. 재발하는지, 같은 코드인지 지켜보세요.",
                              "A single occurrence is not enough to name a cause. Watch whether it recurs and whether the code is the same.",
                              "Chỉ một lần thì chưa đủ để kết luận nguyên nhân. Hãy theo dõi xem có tái diễn không và mã lỗi có giống không."));
            return New(Severity.Medium,
                L.T("블루스크린 1회: ", "Blue screen, once: ", "Màn hình xanh 1 lần: ") + inc.CodeText + (info != null ? " " + info.Name : ""),
                sb.ToString().TrimEnd());
        }

        static bool IsMemoryLike(uint code)
        {
            BugcheckInfo info;
            return Knowledge.Bugchecks.TryGetValue(code, out info) && info.MemoryLike;
        }

        static string Times(List<Incident> list)
        {
            var parts = list.OrderBy(i => i.Time).Select(i => i.Time.ToString("MM-dd HH:mm")).ToList();
            if (parts.Count > 10) return string.Join(", ", parts.Take(10)) + L.F(" 외 {0}건", " and {0} more", " và {0} lần khác", parts.Count - 10);
            return string.Join(", ", parts);
        }

        static Finding New(Severity sev, string title, string body)
        {
            return new Finding { Severity = sev, Title = title, Body = body };
        }
    }
}

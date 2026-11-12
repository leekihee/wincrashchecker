using System;
using System.Collections.Generic;
using System.Linq;
using CrashLens.Core;

// 실제 현장 PC에서 수집된 기록(2026-10~11, tcpip 0xD1 반복 크래시)을 재현한 회귀 테스트.
static class Program
{
    static int fails;
    static void Check(bool ok, string what) { Console.WriteLine((ok ? "  ok   " : "  FAIL ") + what); if (!ok) fails++; }
    static DateTime T(string s) { return DateTime.Parse("2026-" + s); }

    static RawEvent Kp(string t, uint code) =>
        new RawEvent { Time = T(t), Log = "System", Provider = Analyzer.PKp, Id = 41, Props = new List<string> { code.ToString(), "0", "0", "0", "0", "false", "0" } };
    static RawEvent Bug(string t, string p1, string p4) =>
        new RawEvent { Time = T(t), Log = "System", Provider = Analyzer.PBug, Id = 1001,
            Message = "The computer has rebooted from a bugcheck.  The bugcheck was: 0x000000d1 (0x" + p1 + ", 0x0000000000000002, 0x0000000000000000, 0x" + p4 + "). A dump was saved in: C:\\WINDOWS\\MEMORY.DMP. Report Id: 0." };
    static RawEvent NoMini(string t) =>
        new RawEvent { Time = T(t), Log = "System", Provider = Analyzer.PBug, Id = 1005, Message = "Unable to produce a minidump file from the full dump file." };
    static RawEvent Whea(string t) =>
        new RawEvent { Time = T(t), Log = "System", Provider = Analyzer.PWhea, Id = 1, Message = "A fatal hardware error has occurred." };
    static RawEvent Wer(string t, string name, string bucket, string p1, string files = "") =>
        new RawEvent { Time = T(t), Log = "Application", Provider = Analyzer.PWer, Id = 1001,
            Props = new List<string> { bucket, "0", name, "Not available", "0", p1, "a", "a", "a", "a", "", "", "", "", "", files } };

    const string Lkd = "LKD_0x124_7_GenuineIntel_CRASHLOG.PMC.5H_2018E3E146FE1E77D5853702728A431E_IMAGE_GenuineIntel.sys";

    static void Main()
    {
        var s = new Snapshot { CollectedAt = T("11-12 09:00"), Days = 90, IsAdmin = true, CrashDumpEnabled = 7 };
        var ev = s.Events;

        // (KP41 시각, 버그체크 시각, P1, P4, 미니덤프 실패 여부)
        var crashes = new[] {
            ("10-21 07:52:05", "10-21 07:52:18", "ffffd70df1407150", "fffff80064a3864a", true),
            ("10-23 13:00:26", "10-23 13:00:36", "ffff938a7575b2f0", "fffff8011a5a864a", false),
            ("10-23 13:05:05", "10-23 13:05:14", "ffffc784eddaef80", "fffff803505c864a", true),
            ("10-26 19:42:19", "10-26 19:42:27", "ffffc186788b2220", "fffff8004409864a", true),
            ("10-28 11:25:18", "10-28 11:25:25", "ffff928326f06730", "fffff80321f3864a", false),
            ("10-28 11:29:39", "10-28 11:29:47", "ffff870954202950", "fffff8051f8e864a", true),
            ("10-30 06:40:53", "10-30 06:41:01", "ffffb806a1106fc0", "fffff80253e5864a", true),
            ("11-04 08:06:40", "11-04 08:06:49", "ffff920852886e10", "fffff8013273864a", true),
        };
        foreach (var c in crashes)
        {
            ev.Add(Kp(c.Item1, 0xD1));
            ev.Add(Bug(c.Item2, c.Item3, c.Item4));
            if (c.Item5) ev.Add(NoMini(c.Item2));
            ev.Add(Whea(T(c.Item2).AddSeconds(2).ToString("MM-dd HH:mm:ss")));
            ev.Add(Wer(T(c.Item2).AddSeconds(25).ToString("MM-dd HH:mm:ss"), "LiveKernelEvent", "", "124"));
            ev.Add(Wer(T(c.Item2).AddSeconds(50).ToString("MM-dd HH:mm:ss"), "LiveKernelEvent", Lkd, "124"));
        }
        // WER BlueScreen 보고는 두 번만 남았다
        ev.Add(Wer("10-23 13:00:59", "BlueScreen", "", "d1", "\\\\?\\C:\\WINDOWS\\Minidump\\102326-14062-01.dmp\n\\\\?\\C:\\WINDOWS\\MEMORY.DMP"));
        ev.Add(Wer("10-23 13:01:38", "BlueScreen", "AV_tcpip!INET_UNALIGNED_ADDR_EQUAL", "d1", "\\\\?\\C:\\WINDOWS\\Minidump\\102326-14062-01.dmp"));
        ev.Add(Wer("10-28 11:25:52", "BlueScreen", "", "d1", "\\\\?\\C:\\WINDOWS\\Minidump\\102826-12500-01.dmp"));
        ev.Add(Wer("10-28 11:26:19", "BlueScreen", "AV_tcpip!INET_UNALIGNED_ADDR_EQUAL", "d1", "\\\\?\\C:\\WINDOWS\\Minidump\\102826-12500-01.dmp"));
        // 11-09: 0x1A, 버그체크 기록 없음
        ev.Add(Kp("11-09 11:09:16", 0x1A));
        ev.Add(Whea("11-09 11:09:26"));
        ev.Add(Wer("11-09 11:10:04", "LiveKernelEvent", Lkd, "124"));
        // 09-28: 코드 없는 꺼짐
        ev.Add(Kp("09-28 09:16:35", 0));
        // 앱 크래시, 변경 이력, 정상 종료
        ev.Add(new RawEvent { Time = T("10-30 06:41:10"), Log = "Application", Provider = "Application Error", Id = 1000,
            Props = new List<string> { "DAX3API.exe", "3.30705.750.0", "66d95cf8", "DAX3API.exe", "3.30705.750.0", "66d95cf8", "c0000005", "1546ac" } });
        ev.Add(new RawEvent { Time = T("10-20 18:00:00"), Log = "System", Provider = "Microsoft-Windows-UserPnp", Id = 20001,
            Message = "Driver Management concluded the process to install driver axusbeth.inf for Device Instance ID USB\\VID_0B95&PID_1790." });
        ev.Add(new RawEvent { Time = T("11-01 02:00:00"), Log = "System", Provider = "User32", Id = 1074,
            Props = new List<string> { "TrustedInstaller.exe", "PC", "운영 체제: 업그레이드(계획됨)", "0x80020003", "다시 시작", "", "NT AUTHORITY\\SYSTEM" } });

        s.Dumps.Add(new DumpFile { Path = "C:\\Windows\\Minidump\\102326-14062-01.dmp", Time = T("10-23 13:00:36"), Size = 1133308 });
        s.Dumps.Add(new DumpFile { Path = "C:\\Windows\\Minidump\\102826-12500-01.dmp", Time = T("10-28 11:25:25"), Size = 1224788 });
        s.Dumps.Add(new DumpFile { Path = "C:\\Windows\\MEMORY.DMP", Time = T("11-04 08:06:47"), Size = 4811848556 });
        s.NetDrivers.Add(new DriverInfo { Device = "ASIX USB to Gigabit Ethernet Family Adapter", Provider = "ASIX", Version = "4.22.1.0", Date = "2026-01-05" });
        s.NetDrivers.Add(new DriverInfo { Device = "Tailscale Tunnel", Provider = "WireGuard LLC", Version = "0.14.0.0" });

        var r = Analyzer.Analyze(s);
        var blue = r.Incidents.Where(i => i.Kind == IncidentKind.BlueScreen).ToList();
        var d1 = blue.Where(i => i.Code == 0xD1).ToList();

        Console.WriteLine("[사건 묶기]");
        Check(r.Incidents.Count == 10, "사건 10건 (실제 " + r.Incidents.Count + ")");
        Check(d1.Count == 8, "0xD1 블루스크린 8건 (실제 " + d1.Count + ")");
        Check(d1.Select(i => i.Signature).Distinct().Count() == 1 && d1[0].Signature == "0xD1:ip864a", "8건 모두 같은 시그니처 0xD1:ip864a");
        Check(blue.Count(i => i.Code == 0x1A) == 1, "0x1A 1건 (Kernel-Power 41에서만 코드 확인)");
        Check(r.Incidents.Count(i => i.Kind == IncidentKind.PowerLoss) == 1, "코드 없는 꺼짐 1건");
        Check(r.Incidents.Count(i => i.Kind == IncidentKind.LiveKernelEvent || i.Kind == IncidentKind.HardwareError) == 0, "LiveKernelEvent 124가 별도 사건으로 분리되지 않음");
        Check(d1.All(i => i.Events.Count(e => e.Provider == Analyzer.PKp) == 1), "4분 간격 연속 크래시(10-23, 10-28)가 서로 섞이지 않음");

        Console.WriteLine("[원인 추론]");
        Check(d1.All(i => i.Module == "tcpip" && i.Function == "INET_UNALIGNED_ADDR_EQUAL"), "8건 모두 tcpip!INET_UNALIGNED_ADDR_EQUAL (2건 직접, 6건 전파)");
        Check(d1.Count(i => i.BucketInferred) == 6, "버킷 전파 6건");
        Check(d1.All(i => i.Category == "network"), "분류: 네트워크 스택");
        Check(blue.All(i => i.WheaByproduct), "Hardware error를 부산물로 판정");
        Check(d1.Count(i => i.MinidumpFailed) == 6, "미니덤프 실패 6건");

        Console.WriteLine("[덤프 연결]");
        Check(d1.Single(i => i.Time == T("10-28 11:25:18")).DumpPath.EndsWith("102826-12500-01.dmp"), "10-28 크래시 → 미니덤프");
        Check(d1.Single(i => i.Time == T("11-04 08:06:40")).DumpPath.EndsWith("MEMORY.DMP"), "11-04 크래시 → MEMORY.DMP");
        Check(d1.Single(i => i.Time == T("10-30 06:40:53")).DumpPath == "", "10-30 크래시 → 덤프 없음(MEMORY.DMP는 덮어써짐)");

        Console.WriteLine("[진단 문장]");
        var top = r.Findings.First();
        Check(top.Severity == Severity.High && top.Title.Contains("8회 반복") && top.Title.Contains("tcpip"), "최상위 진단: " + top.Title);
        Check(top.Body.Contains("ASIX"), "용의자 목록에 ASIX 어댑터");
        Check(top.Body.Contains("분 만에 다시 발생"), "재부팅 직후 재발 감지");
        Check(top.Body.Contains("10-21 이전에는"), "시작 시점 감지");
        Check(top.Body.Contains("axusbeth.inf"), "첫 발생 직전 드라이버 설치 기록 연결");
        Check(top.Body.Contains("일간 없습니다"), "최근 조용한 기간 감지");
        Check(r.Findings.Any(f => f.Title.Contains("부산물")), "부산물 안내");
        Check(!r.Findings.Any(f => f.Title.Contains("서로 다른 종류")), "하드웨어 불안정 오탐 없음");
        Check(r.Apps.Count == 1 && r.Apps[0].App == "DAX3API.exe", "앱 크래시 집계");
        Check(r.Shutdowns.Count == 1 && r.Shutdowns[0].Text.Contains("TrustedInstaller"), "정상 종료 이력");

        Console.WriteLine("[버킷 파싱]");
        string m, f2;
        Knowledge.ParseBucket("LKD_0x141_IMAGE_nvlddmkm.sys", out m, out f2); Check(m == "nvlddmkm" && Knowledge.Categorize(m) == "gpu", "LKD_0x141_IMAGE_nvlddmkm.sys → gpu");
        Knowledge.ParseBucket("0x1a_41792_nt!MiDeleteVa", out m, out f2); Check(m == "nt" && f2 == "MiDeleteVa", "0x1a_41792_nt!MiDeleteVa → nt");
        Knowledge.ParseBucket("AV_R_INVALID_AxUsbEth!unknown_function", out m, out f2); Check(m == "AxUsbEth" && f2 == "" && Knowledge.Categorize(m) == "thirdparty", "AxUsbEth → 서드파티");
        Knowledge.ParseBucket(Lkd, out m, out f2); Check(Knowledge.Categorize(m) == "hardware", "GenuineIntel → 하드웨어");

        // 서로 다른 메모리 계열 크래시 → 하드웨어 의심
        var s2 = new Snapshot { CollectedAt = T("11-12 09:00"), Days = 30, IsAdmin = true };
        s2.Events.Add(Kp("11-01 10:00:00", 0x1A)); s2.Events.Add(Kp("11-03 10:00:00", 0x50)); s2.Events.Add(Kp("11-05 10:00:00", 0x139));
        var r2 = Analyzer.Analyze(s2);
        Check(r2.Findings.Any(f => f.Title.Contains("서로 다른 종류")), "서로 다른 메모리 계열 3종 → 메모리/하드웨어 의심");

        Console.WriteLine();
        Console.WriteLine(Report.Overall(s, r));
        Console.WriteLine(Report.Detail(d1.Single(i => i.Time == T("10-28 11:25:18"))));
        Console.WriteLine(fails == 0 ? "ALL PASSED" : fails + " FAILED");
        Environment.Exit(fails == 0 ? 0 : 1);
    }
}

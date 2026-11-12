using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Management;
using System.Security.Principal;
using CrashLens.Core;
using Microsoft.Win32;

namespace CrashLens
{
    /// <summary>이 PC의 이벤트 로그, 덤프 파일 목록, 드라이버 정보를 읽어 Snapshot으로 만든다. 읽기 전용이며 시스템을 변경하지 않는다.</summary>
    static class Collector
    {
        public static Snapshot Collect(int days, Action<string> progress)
        {
            var s = new Snapshot { Days = days, CollectedAt = DateTime.Now, IsAdmin = IsAdmin() };
            long ms = (long)days * 24 * 3600 * 1000;
            string time = "TimeCreated[timediff(@SystemTime) <= " + ms + "]";

            progress(L.T("시스템 로그 읽는 중…", "Reading the System log…", "Đang đọc nhật ký System…"));
            ReadLog(s, "System",
                "*[System[" + time + " and (" +
                "Provider[@Name='" + Analyzer.PBug + "']" +
                " or (Provider[@Name='" + Analyzer.PKp + "'] and EventID=41)" +
                " or (Provider[@Name='EventLog'] and EventID=6008)" +
                " or (Provider[@Name='User32'] and EventID=1074)" +
                " or Provider[@Name='" + Analyzer.PWhea + "']" +
                " or (Provider[@Name='Microsoft-Windows-UserPnp'] and EventID=20001)" +
                " or (Provider[@Name='Microsoft-Windows-WindowsUpdateClient'] and EventID=19)" +
                ")]]", null);

            progress(L.T("응용 프로그램 로그 읽는 중…", "Reading the Application log…", "Đang đọc nhật ký Application…"));
            ReadLog(s, "Application",
                "*[System[" + time + " and (" +
                "(Provider[@Name='" + Analyzer.PWer + "'] and EventID=1001)" +
                " or (Provider[@Name='Application Error'] and EventID=1000)" +
                " or (Provider[@Name='Application Hang'] and EventID=1002)" +
                " or (Provider[@Name='.NET Runtime'] and EventID=1026)" +
                " or (Provider[@Name='MsiInstaller'] and EventID=11707)" +
                ")]]",
                // WER 1001은 앱 크래시 보고가 대부분이라 커널 관련 보고만 남긴다(앱 크래시는 Application Error로 집계).
                e => e.Provider != Analyzer.PWer || Analyzer.WerEventName(e) != "");

            progress(L.T("덤프 파일 확인 중…", "Checking dump files…", "Đang kiểm tra tệp dump…"));
            ReadDumps(s);

            progress(L.T("시스템 정보 읽는 중…", "Reading system information…", "Đang đọc thông tin hệ thống…"));
            ReadSystemInfo(s);
            return s;
        }

        static bool IsAdmin()
        {
            try { using (var id = WindowsIdentity.GetCurrent()) return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator); }
            catch { return false; }
        }

        static void ReadLog(Snapshot s, string log, string xpath, Func<RawEvent, bool> keep)
        {
            try
            {
                var q = new EventLogQuery(log, PathType.LogName, xpath) { ReverseDirection = true };
                using (var reader = new EventLogReader(q))
                {
                    EventRecord rec;
                    int n = 0;
                    while ((rec = reader.ReadEvent()) != null && n < 20000)
                    {
                        using (rec)
                        {
                            var e = new RawEvent
                            {
                                Time = rec.TimeCreated ?? DateTime.MinValue,
                                Log = log,
                                Provider = rec.ProviderName ?? "",
                                Id = rec.Id
                            };
                            try
                            {
                                foreach (var p in rec.Properties)
                                {
                                    var v = p.Value;
                                    if (v is byte[]) e.Props.Add("");
                                    else e.Props.Add(Convert.ToString(v, CultureInfo.InvariantCulture) ?? "");
                                }
                            }
                            catch { }
                            if (keep != null && !keep(e)) continue;
                            try
                            {
                                var msg = rec.FormatDescription() ?? "";
                                e.Message = msg.Length > 4000 ? msg.Substring(0, 4000) : msg;
                            }
                            catch { }
                            s.Events.Add(e);
                            n++;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                s.Warnings.Add(L.F("{0} 로그를 읽지 못했습니다: {1}", "Could not read the {0} log: {1}", "Không đọc được nhật ký {0}: {1}", log, ex.Message));
            }
        }

        static void ReadDumps(Snapshot s)
        {
            string win = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            AddDump(s, Path.Combine(win, "MEMORY.DMP"));
            AddDumpDir(s, Path.Combine(win, "Minidump"), SearchOption.TopDirectoryOnly);
            AddDumpDir(s, Path.Combine(win, "LiveKernelReports"), SearchOption.AllDirectories);

            try
            {
                using (var k = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\CrashControl"))
                {
                    var v = k == null ? null : k.GetValue("CrashDumpEnabled");
                    if (v != null) s.CrashDumpEnabled = Convert.ToInt32(v);
                }
            }
            catch { }
        }

        static void AddDumpDir(Snapshot s, string dir, SearchOption opt)
        {
            try
            {
                if (!Directory.Exists(dir)) return;
                foreach (var f in Directory.GetFiles(dir, "*.dmp", opt)) AddDump(s, f);
            }
            catch (UnauthorizedAccessException) { /* 관리자 권한이 아니면 정상. 진단에서 안내한다. */ }
            catch (Exception ex) { s.Warnings.Add(dir + ": " + ex.Message); }
        }

        static void AddDump(Snapshot s, string path)
        {
            try
            {
                var fi = new FileInfo(path);
                if (fi.Exists) s.Dumps.Add(new DumpFile { Path = fi.FullName, Time = fi.LastWriteTime, Size = fi.Length });
            }
            catch { }
        }

        static void ReadSystemInfo(Snapshot s)
        {
            s.Os = Wmi("SELECT Caption, Version FROM Win32_OperatingSystem", o => o["Caption"] + " (" + o["Version"] + ")");
            s.Cpu = Wmi("SELECT Name FROM Win32_Processor", o => Convert.ToString(o["Name"]).Trim());
            s.Bios = Wmi("SELECT Manufacturer, SMBIOSBIOSVersion, ReleaseDate FROM Win32_BIOS",
                o => o["Manufacturer"] + " " + o["SMBIOSBIOSVersion"] + " (" + CimDate(o["ReleaseDate"]) + ")");
            s.Model = Wmi("SELECT Manufacturer, Model, TotalPhysicalMemory FROM Win32_ComputerSystem", o =>
            {
                try { s.Memory = Math.Round(Convert.ToDouble(o["TotalPhysicalMemory"]) / (1024.0 * 1024 * 1024)) + " GB"; } catch { }
                return o["Manufacturer"] + " " + o["Model"];
            });

            // 서드파티 네트워크 드라이버: 네트워크 스택 크래시의 용의자 목록으로 쓴다.
            try
            {
                using (var q = new ManagementObjectSearcher("SELECT DeviceName, DriverProviderName, DriverVersion, DriverDate, InfName FROM Win32_PnPSignedDriver WHERE DeviceClass='NET'"))
                using (var col = q.Get())
                {
                    foreach (ManagementObject o in col)
                    {
                        string provider = Convert.ToString(o["DriverProviderName"]) ?? "";
                        string name = Convert.ToString(o["DeviceName"]) ?? "";
                        if (name == "" || provider.IndexOf("Microsoft", StringComparison.OrdinalIgnoreCase) >= 0) continue;
                        if (s.NetDrivers.Any(d => d.Device == name)) continue;
                        s.NetDrivers.Add(new DriverInfo
                        {
                            Device = name, Provider = provider,
                            Version = Convert.ToString(o["DriverVersion"]) ?? "",
                            Date = CimDate(o["DriverDate"]),
                            Inf = Convert.ToString(o["InfName"]) ?? ""
                        });
                    }
                }
            }
            catch (Exception ex) { s.Warnings.Add(L.T("네트워크 드라이버 목록을 읽지 못했습니다: ", "Could not read the network driver list: ", "Không đọc được danh sách trình điều khiển mạng: ") + ex.Message); }
        }

        static string Wmi(string query, Func<ManagementObject, string> pick)
        {
            try
            {
                using (var q = new ManagementObjectSearcher(query))
                using (var col = q.Get())
                    foreach (ManagementObject o in col) return (pick(o) ?? "").Trim();
            }
            catch { }
            return "";
        }

        static string CimDate(object v)
        {
            try
            {
                var str = Convert.ToString(v);
                return string.IsNullOrEmpty(str) ? "" : ManagementDateTimeConverter.ToDateTime(str).ToString("yyyy-MM-dd");
            }
            catch { return ""; }
        }
    }
}

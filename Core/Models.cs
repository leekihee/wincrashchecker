using System;
using System.Collections.Generic;

namespace CrashLens.Core
{
    /// <summary>이벤트 로그에서 읽은 원본 레코드. 수집기(Windows 전용)와 분석기(순수 로직)를 분리하기 위한 중간 형식.</summary>
    public sealed class RawEvent
    {
        public DateTime Time;
        public string Log = "";
        public string Provider = "";
        public int Id;
        public string Message = "";
        public List<string> Props = new List<string>();

        public string Text { get { return Message + "\n" + string.Join("\n", Props); } }
        public string Prop(int i) { return i >= 0 && i < Props.Count ? (Props[i] ?? "") : ""; }
    }

    public sealed class DumpFile
    {
        public string Path = "";
        public DateTime Time;
        public long Size;
    }

    public sealed class DriverInfo
    {
        public string Device = "";
        public string Provider = "";
        public string Version = "";
        public string Date = "";
        public string Inf = "";
    }

    public sealed class Snapshot
    {
        public DateTime CollectedAt = DateTime.Now;
        public int Days = 90;
        public bool IsAdmin;
        public string Os = "", Cpu = "", Bios = "", Model = "", Memory = "";
        /// <summary>CrashControl\CrashDumpEnabled 값. -1 = 알 수 없음, 0 = 덤프 꺼짐.</summary>
        public int CrashDumpEnabled = -1;
        public List<RawEvent> Events = new List<RawEvent>();
        public List<DumpFile> Dumps = new List<DumpFile>();
        public List<DriverInfo> NetDrivers = new List<DriverInfo>();
        public List<string> Warnings = new List<string>();
    }

    public enum IncidentKind { BlueScreen, PowerLoss, ForcedPowerOff, UnexpectedShutdown, LiveKernelEvent, HardwareError }

    public sealed class Incident
    {
        public DateTime Time;
        public IncidentKind Kind;
        public uint Code;
        public ulong[] P = new ulong[4];
        public string Bucket = "";
        public bool BucketInferred;
        public string Module = "";
        public string Function = "";
        public string Category = "";
        public string DumpPath = "";
        /// <summary>블루스크린 재부팅 직후 펌웨어가 보고한 WHEA/LiveKernelEvent 124 기록이 함께 있음(원인이 아니라 부산물).</summary>
        public bool WheaByproduct;
        public bool FirmwareResetRecord;
        public bool MinidumpFailed;
        public string Signature = "";
        public List<RawEvent> Events = new List<RawEvent>();

        public string CodeText { get { return Code == 0 ? "" : "0x" + Code.ToString("X"); } }
    }

    public enum Severity { High, Medium, Info }

    public sealed class Finding
    {
        public Severity Severity;
        public string Title = "";
        public string Body = "";
    }

    public sealed class AppCrashGroup
    {
        public string App = "";
        public int Crashes;
        public int Hangs;
        public DateTime Last;
        public SortedSet<string> Modules = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
        public SortedSet<string> Codes = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
    }

    public sealed class ChangeItem
    {
        public DateTime Time;
        public string Kind = "";
        public string Text = "";
    }

    public sealed class AnalysisResult
    {
        public List<Incident> Incidents = new List<Incident>();
        public List<Finding> Findings = new List<Finding>();
        public List<AppCrashGroup> Apps = new List<AppCrashGroup>();
        public List<ChangeItem> Changes = new List<ChangeItem>();
        public List<ChangeItem> Shutdowns = new List<ChangeItem>();
        public int WheaCorrected;
    }
}

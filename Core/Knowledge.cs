using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace CrashLens.Core
{
    public sealed class BugcheckInfo
    {
        public string Name;
        public string Meaning;
        public string Causes;
        /// <summary>크래시 난 코드 주소가 들어 있는 파라미터 번호(1~4). 0이면 없음.</summary>
        public int IpParam;
        /// <summary>메모리 손상 계열: 여러 종류가 섞여 나오면 RAM/하드웨어 의심.</summary>
        public bool MemoryLike;
        public BugcheckInfo(string name, string meaning, string causes, int ipParam = 0, bool memoryLike = false)
        { Name = name; Meaning = meaning; Causes = causes; IpParam = ipParam; MemoryLike = memoryLike; }
    }

    public static class Knowledge
    {
        public static readonly Dictionary<uint, BugcheckInfo> Bugchecks = new Dictionary<uint, BugcheckInfo>
        {
            { 0x0A, new BugcheckInfo("IRQL_NOT_LESS_OR_EQUAL", "커널 코드가 높은 인터럽트 수준에서 잘못된 메모리에 접근했습니다.", "드라이버 버그, 불량 메모리", 4, true) },
            { 0x19, new BugcheckInfo("BAD_POOL_HEADER", "커널 메모리 풀의 관리 정보가 손상됐습니다.", "드라이버의 메모리 덮어쓰기, 불량 메모리", 0, true) },
            { 0x1A, new BugcheckInfo("MEMORY_MANAGEMENT", "메모리 관리자가 내부 구조 손상을 감지했습니다.", "불량 메모리, 드라이버의 메모리 손상, 디스크(페이지 파일) 오류", 0, true) },
            { 0x1E, new BugcheckInfo("KMODE_EXCEPTION_NOT_HANDLED", "커널 모드에서 처리되지 않은 예외가 발생했습니다.", "드라이버 버그, 불량 메모리", 2, true) },
            { 0x3B, new BugcheckInfo("SYSTEM_SERVICE_EXCEPTION", "시스템 호출 처리 중 예외가 발생했습니다.", "드라이버 버그(그래픽·보안 프로그램 포함), 불량 메모리", 2, true) },
            { 0x4E, new BugcheckInfo("PFN_LIST_CORRUPT", "물리 메모리 페이지 목록이 손상됐습니다.", "불량 메모리, 드라이버의 메모리 손상", 0, true) },
            { 0x50, new BugcheckInfo("PAGE_FAULT_IN_NONPAGED_AREA", "존재하지 않는 커널 메모리를 참조했습니다.", "드라이버 버그, 불량 메모리, 보안 프로그램", 3, true) },
            { 0x7A, new BugcheckInfo("KERNEL_DATA_INPAGE_ERROR", "디스크에서 커널 데이터를 읽어 오지 못했습니다.", "SSD/HDD 불량, 케이블, 저장장치 드라이버") },
            { 0x7B, new BugcheckInfo("INACCESSIBLE_BOOT_DEVICE", "부팅 디스크에 접근하지 못했습니다.", "저장장치 드라이버/컨트롤러 모드 변경, 디스크 불량") },
            { 0x7E, new BugcheckInfo("SYSTEM_THREAD_EXCEPTION_NOT_HANDLED", "시스템 스레드에서 처리되지 않은 예외가 발생했습니다.", "드라이버 버그", 2, true) },
            { 0x7F, new BugcheckInfo("UNEXPECTED_KERNEL_MODE_TRAP", "CPU가 커널이 처리할 수 없는 트랩을 발생시켰습니다.", "불량 메모리/CPU, 오버클럭, 드라이버의 스택 손상", 0, true) },
            { 0x9C, new BugcheckInfo("MACHINE_CHECK_EXCEPTION", "CPU가 하드웨어 오류를 보고했습니다.", "CPU/메모리/메인보드 불량, 과열, 오버클럭") },
            { 0x9F, new BugcheckInfo("DRIVER_POWER_STATE_FAILURE", "드라이버가 절전 전환 요청을 제때 처리하지 못했습니다.", "절전/깨어나기 중 장치 드라이버 문제(USB, 네트워크, 그래픽)") },
            { 0xC2, new BugcheckInfo("BAD_POOL_CALLER", "드라이버가 커널 메모리 풀을 잘못 사용했습니다.", "드라이버 버그", 0, true) },
            { 0xC4, new BugcheckInfo("DRIVER_VERIFIER_DETECTED_VIOLATION", "Driver Verifier가 드라이버 위반을 잡았습니다.", "지목된 드라이버의 버그") },
            { 0xC5, new BugcheckInfo("DRIVER_CORRUPTED_EXPOOL", "드라이버가 커널 메모리 풀을 손상시켰습니다.", "드라이버 버그", 0, true) },
            { 0xD1, new BugcheckInfo("DRIVER_IRQL_NOT_LESS_OR_EQUAL", "드라이버가 높은 인터럽트 수준에서 잘못된 메모리 주소를 읽거나 썼습니다.", "드라이버 버그(해제된 메모리 사용 등). 지목된 모듈이 Windows 기본 모듈이면 그 위아래의 서드파티 드라이버를 의심", 4) },
            { 0xE2, new BugcheckInfo("MANUALLY_INITIATED_CRASH", "사용자가 직접 크래시를 발생시켰습니다.", "키보드 크래시 단축키 또는 디버깅 도구") },
            { 0xEF, new BugcheckInfo("CRITICAL_PROCESS_DIED", "Windows 필수 프로세스가 종료됐습니다.", "시스템 파일 손상, 디스크 오류, 드라이버/보안 프로그램") },
            { 0xF4, new BugcheckInfo("CRITICAL_OBJECT_TERMINATION", "필수 프로세스나 스레드가 예기치 않게 종료됐습니다.", "디스크 오류, 시스템 파일 손상") },
            { 0x101, new BugcheckInfo("CLOCK_WATCHDOG_TIMEOUT", "CPU 코어 하나가 응답하지 않았습니다.", "CPU 불안정(전압, 오버클럭), BIOS, 드라이버") },
            { 0x109, new BugcheckInfo("CRITICAL_STRUCTURE_CORRUPTION", "커널의 보호된 코드나 데이터가 변조됐습니다.", "드라이버의 커널 변조, 불량 메모리", 0, true) },
            { 0x116, new BugcheckInfo("VIDEO_TDR_FAILURE", "그래픽 드라이버가 응답하지 않아 복구에 실패했습니다.", "그래픽 드라이버, GPU 과열/불량, 전원 부족") },
            { 0x119, new BugcheckInfo("VIDEO_SCHEDULER_INTERNAL_ERROR", "그래픽 스케줄러에서 치명적 오류가 발생했습니다.", "그래픽 드라이버, GPU 불량") },
            { 0x124, new BugcheckInfo("WHEA_UNCORRECTABLE_ERROR", "하드웨어가 복구 불가능한 오류를 보고했습니다.", "CPU/메모리/메인보드/전원 불량, 과열, 오버클럭") },
            { 0x133, new BugcheckInfo("DPC_WATCHDOG_VIOLATION", "드라이버가 인터럽트 처리에서 너무 오래 머물렀습니다.", "저장장치/네트워크/그래픽 드라이버, SSD 펌웨어") },
            { 0x139, new BugcheckInfo("KERNEL_SECURITY_CHECK_FAILURE", "커널이 핵심 자료구조 손상을 감지했습니다.", "드라이버 버그, 불량 메모리", 0, true) },
            { 0x13A, new BugcheckInfo("KERNEL_MODE_HEAP_CORRUPTION", "커널 힙이 손상됐습니다.", "드라이버 버그, 불량 메모리", 0, true) },
            { 0x154, new BugcheckInfo("UNEXPECTED_STORE_EXCEPTION", "메모리 압축 저장소에서 예외가 발생했습니다.", "SSD/HDD 불량, 불량 메모리, 보안 프로그램") },
            { 0x1CA, new BugcheckInfo("SYNTHETIC_WATCHDOG_TIMEOUT", "시스템 전체가 일정 시간 응답하지 않았습니다.", "하드웨어 멈춤, 가상화 환경 문제, 드라이버") },
        };

        /// <summary>LiveKernelEvent(시스템은 죽지 않았지만 Windows가 남긴 커널 오류 보고) 코드.</summary>
        public static readonly Dictionary<uint, string> LiveCodes = new Dictionary<uint, string>
        {
            { 0x117, "그래픽 드라이버 응답 지연(복구됨)" },
            { 0x141, "그래픽 엔진 응답 지연(복구됨)" },
            { 0x193, "그래픽 커널 내부 오류 보고" },
            { 0x144, "USB 3 컨트롤러/장치 오류" },
            { 0x124, "하드웨어 오류 보고(WHEA)" },
            { 0x15F, "절전(모던 스탠바이) 중 응답 지연" },
            { 0x1A1, "화면/입력 처리(win32k) 응답 지연" },
        };

        static readonly Dictionary<string, string> ModuleCategory = BuildCategories();

        static Dictionary<string, string> BuildCategories()
        {
            var d = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            Action<string, string> add = (cat, names) => { foreach (var n in names.Split(' ')) d[n] = cat; };
            add("network", "tcpip ndis netio afd fwpkclnt wfplwfs tdx http nwifi wdiwifi msquic nsiproxy pacer");
            add("gpu", "nvlddmkm igdkmd64 igdkmdn64 igdkmdnd64 amdkmdag atikmdag atikmpag dxgkrnl dxgmms1 dxgmms2 watchdog");
            add("storage", "storport stornvme storahci iastora iastorac iastorvd iastoravc ntfs disk volmgr volmgrx volsnap fltmgr partmgr classpnp nvmedisk fvevol");
            add("usb", "usbxhci usbhub3 ucx01000 usbccgp usbport usbhub usbehci");
            add("kernel", "nt ntoskrnl ntkrnlmp hal win32k win32kbase win32kfull ci clfs wdf01000 acpi pci");
            add("hardware", "genuineintel authenticamd hardware memory_corruption");
            add("audio", "portcls hdaudbus hdaudio acxhdaudio ks");
            return d;
        }

        static readonly HashSet<string> GpuVendor = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            { "nvlddmkm", "igdkmd64", "igdkmdn64", "igdkmdnd64", "amdkmdag", "atikmdag", "atikmpag" };

        /// <summary>모듈 이름을 분류한다. 알려진 Windows 기본 모듈이 아니면 "thirdparty".</summary>
        public static string Categorize(string module)
        {
            if (string.IsNullOrEmpty(module)) return "";
            string cat;
            return ModuleCategory.TryGetValue(module, out cat) ? cat : "thirdparty";
        }

        public static bool IsWindowsModule(string module)
        {
            if (string.IsNullOrEmpty(module)) return false;
            return ModuleCategory.ContainsKey(module) && !GpuVendor.Contains(module) && Categorize(module) != "hardware";
        }

        public static string CategoryLabel(string cat)
        {
            switch (cat)
            {
                case "network": return "네트워크 스택";
                case "gpu": return "그래픽";
                case "storage": return "저장장치/파일 시스템";
                case "usb": return "USB";
                case "kernel": return "Windows 커널";
                case "hardware": return "하드웨어";
                case "audio": return "오디오";
                case "thirdparty": return "서드파티 드라이버";
                default: return "";
            }
        }

        public static string CategoryAdvice(string cat)
        {
            switch (cat)
            {
                case "network":
                    return "Windows 네트워크 스택은 대개 피해자입니다. 실제 원인은 네트워크 어댑터 드라이버(특히 USB 이더넷), VPN/터널 드라이버, 가상화 네트워크 필터, 보안 프로그램인 경우가 많습니다. 어댑터를 바꿔 쓰거나 하나씩 꺼 보며 재발 여부를 비교하세요.";
                case "gpu":
                    return "그래픽 드라이버를 제조사 최신(또는 한 단계 이전) 버전으로 깨끗이 재설치하고, GPU 온도와 전원 공급을 확인하세요. 딥러닝 추론처럼 GPU 부하가 큰 작업 중이었는지도 확인하세요.";
                case "storage":
                    return "SSD/HDD 상태(SMART), 저장장치 드라이버(Intel RST 등), SSD 펌웨어를 확인하세요. 'chkdsk /scan'과 제조사 진단 도구를 권합니다.";
                case "usb":
                    return "USB 장치/허브/케이블 문제일 수 있습니다. 카메라·조명 컨트롤러·동글 등 연결 장치를 하나씩 분리해 비교하고, 메인보드 칩셋/USB 드라이버를 갱신하세요.";
                case "kernel":
                    return "Windows 커널 자체가 지목되면 원인이 특정되지 않은 것입니다. 다른 드라이버가 메모리를 손상시켰거나 메모리(RAM)가 불량일 수 있습니다. 덤프를 WinDbg로 열어 스택을 확인하고, 메모리 진단(mdsched)을 돌려 보세요.";
                case "hardware":
                    return "하드웨어 오류입니다. BIOS 업데이트, BIOS 기본값(XMP·오버클럭 해제), 온도, 전원 공급 장치를 확인하세요.";
                case "audio":
                    return "오디오 드라이버를 PC 제조사 버전으로 갱신하세요.";
                case "thirdparty":
                    return "이 드라이버가 직접 지목됐습니다. 해당 제품의 드라이버를 갱신하거나 이전 버전으로 되돌리고, 안 쓰는 제품이면 제거하세요.";
                default: return "";
            }
        }

        static readonly Regex RxModFunc = new Regex(@"([A-Za-z0-9_\.\-]+)!([A-Za-z0-9_:<>~\+]+)", RegexOptions.Compiled);
        static readonly Regex RxImage = new Regex(@"IMAGE_([A-Za-z0-9_\-\.]+?)(?:\.(?:sys|dll|exe))?$", RegexOptions.Compiled | RegexOptions.IgnoreCase);

        /// <summary>WER 버킷 문자열(예: AV_tcpip!INET_UNALIGNED_ADDR_EQUAL)에서 모듈과 함수를 뽑는다.</summary>
        public static void ParseBucket(string bucket, out string module, out string function)
        {
            module = ""; function = "";
            if (string.IsNullOrEmpty(bucket)) return;
            var m = RxModFunc.Match(bucket);
            if (m.Success)
            {
                module = m.Groups[1].Value;
                int us = module.LastIndexOf('_');
                // "AV_tcpip", "0x1a_41792_nt" 처럼 앞에 붙은 접두어 제거
                if (us >= 0 && us < module.Length - 1) module = module.Substring(us + 1);
                function = m.Groups[2].Value;
                if (function.Equals("unknown_function", StringComparison.OrdinalIgnoreCase)) function = "";
            }
            else
            {
                m = RxImage.Match(bucket);
                if (m.Success) module = m.Groups[1].Value;
                else if (bucket.IndexOf("MEMORY_CORRUPTION", StringComparison.OrdinalIgnoreCase) >= 0) module = "memory_corruption";
            }
            if (module.EndsWith(".sys", StringComparison.OrdinalIgnoreCase)) module = module.Substring(0, module.Length - 4);
        }
    }
}

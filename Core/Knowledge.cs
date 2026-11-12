using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace CrashLens.Core
{
    public sealed class BugcheckInfo
    {
        public string Name;
        public Tx Meaning;
        public Tx Causes;
        /// <summary>크래시 난 코드 주소가 들어 있는 파라미터 번호(1~4). 0이면 없음.</summary>
        public int IpParam;
        /// <summary>메모리 손상 계열: 여러 종류가 섞여 나오면 RAM/하드웨어 의심.</summary>
        public bool MemoryLike;
        public BugcheckInfo(string name, Tx meaning, Tx causes, int ipParam = 0, bool memoryLike = false)
        { Name = name; Meaning = meaning; Causes = causes; IpParam = ipParam; MemoryLike = memoryLike; }
    }

    public static class Knowledge
    {
        static Tx X(string ko, string en, string vi) { return new Tx(ko, en, vi); }

        static readonly Tx DriverOrRam = X("드라이버 버그, 불량 메모리", "Driver bug, faulty RAM", "Lỗi trình điều khiển, RAM hỏng");
        static readonly Tx DriverBug = X("드라이버 버그", "Driver bug", "Lỗi trình điều khiển");

        public static readonly Dictionary<uint, BugcheckInfo> Bugchecks = new Dictionary<uint, BugcheckInfo>
        {
            { 0x0A, new BugcheckInfo("IRQL_NOT_LESS_OR_EQUAL",
                X("커널 코드가 높은 인터럽트 수준에서 잘못된 메모리에 접근했습니다.", "Kernel code accessed invalid memory at a high interrupt level.", "Mã nhân truy cập bộ nhớ không hợp lệ ở mức ngắt cao."),
                DriverOrRam, 4, true) },
            { 0x19, new BugcheckInfo("BAD_POOL_HEADER",
                X("커널 메모리 풀의 관리 정보가 손상됐습니다.", "The kernel memory pool bookkeeping was corrupted.", "Thông tin quản lý vùng nhớ của nhân bị hỏng."),
                X("드라이버의 메모리 덮어쓰기, 불량 메모리", "A driver overwriting memory, faulty RAM", "Trình điều khiển ghi đè bộ nhớ, RAM hỏng"), 0, true) },
            { 0x1A, new BugcheckInfo("MEMORY_MANAGEMENT",
                X("메모리 관리자가 내부 구조 손상을 감지했습니다.", "The memory manager detected corrupted internal structures.", "Trình quản lý bộ nhớ phát hiện cấu trúc nội bộ bị hỏng."),
                X("불량 메모리, 드라이버의 메모리 손상, 디스크(페이지 파일) 오류", "Faulty RAM, memory corruption by a driver, disk (page file) errors", "RAM hỏng, trình điều khiển làm hỏng bộ nhớ, lỗi đĩa (tệp phân trang)"), 0, true) },
            { 0x1E, new BugcheckInfo("KMODE_EXCEPTION_NOT_HANDLED",
                X("커널 모드에서 처리되지 않은 예외가 발생했습니다.", "An unhandled exception occurred in kernel mode.", "Xảy ra ngoại lệ không được xử lý trong chế độ nhân."),
                DriverOrRam, 2, true) },
            { 0x3B, new BugcheckInfo("SYSTEM_SERVICE_EXCEPTION",
                X("시스템 호출 처리 중 예외가 발생했습니다.", "An exception occurred while handling a system call.", "Xảy ra ngoại lệ khi xử lý lời gọi hệ thống."),
                X("드라이버 버그(그래픽·보안 프로그램 포함), 불량 메모리", "Driver bug (including graphics and security software), faulty RAM", "Lỗi trình điều khiển (kể cả đồ họa, phần mềm bảo mật), RAM hỏng"), 2, true) },
            { 0x4E, new BugcheckInfo("PFN_LIST_CORRUPT",
                X("물리 메모리 페이지 목록이 손상됐습니다.", "The physical memory page list was corrupted.", "Danh sách trang bộ nhớ vật lý bị hỏng."),
                X("불량 메모리, 드라이버의 메모리 손상", "Faulty RAM, memory corruption by a driver", "RAM hỏng, trình điều khiển làm hỏng bộ nhớ"), 0, true) },
            { 0x50, new BugcheckInfo("PAGE_FAULT_IN_NONPAGED_AREA",
                X("존재하지 않는 커널 메모리를 참조했습니다.", "Kernel memory that does not exist was referenced.", "Tham chiếu tới vùng nhớ nhân không tồn tại."),
                X("드라이버 버그, 불량 메모리, 보안 프로그램", "Driver bug, faulty RAM, security software", "Lỗi trình điều khiển, RAM hỏng, phần mềm bảo mật"), 3, true) },
            { 0x7A, new BugcheckInfo("KERNEL_DATA_INPAGE_ERROR",
                X("디스크에서 커널 데이터를 읽어 오지 못했습니다.", "Kernel data could not be read from disk.", "Không đọc được dữ liệu nhân từ đĩa."),
                X("SSD/HDD 불량, 케이블, 저장장치 드라이버", "Failing SSD/HDD, cabling, storage driver", "SSD/HDD hỏng, cáp, trình điều khiển lưu trữ")) },
            { 0x7B, new BugcheckInfo("INACCESSIBLE_BOOT_DEVICE",
                X("부팅 디스크에 접근하지 못했습니다.", "The boot disk could not be accessed.", "Không truy cập được đĩa khởi động."),
                X("저장장치 드라이버/컨트롤러 모드 변경, 디스크 불량", "Storage driver or controller mode change, failing disk", "Thay đổi trình điều khiển/chế độ bộ điều khiển lưu trữ, đĩa hỏng")) },
            { 0x7E, new BugcheckInfo("SYSTEM_THREAD_EXCEPTION_NOT_HANDLED",
                X("시스템 스레드에서 처리되지 않은 예외가 발생했습니다.", "An unhandled exception occurred in a system thread.", "Xảy ra ngoại lệ không được xử lý trong luồng hệ thống."),
                DriverBug, 2, true) },
            { 0x7F, new BugcheckInfo("UNEXPECTED_KERNEL_MODE_TRAP",
                X("CPU가 커널이 처리할 수 없는 트랩을 발생시켰습니다.", "The CPU raised a trap the kernel could not handle.", "CPU phát sinh bẫy mà nhân không xử lý được."),
                X("불량 메모리/CPU, 오버클럭, 드라이버의 스택 손상", "Faulty RAM/CPU, overclocking, stack corruption by a driver", "RAM/CPU hỏng, ép xung, trình điều khiển làm hỏng ngăn xếp"), 0, true) },
            { 0x9C, new BugcheckInfo("MACHINE_CHECK_EXCEPTION",
                X("CPU가 하드웨어 오류를 보고했습니다.", "The CPU reported a hardware error.", "CPU báo lỗi phần cứng."),
                X("CPU/메모리/메인보드 불량, 과열, 오버클럭", "Faulty CPU/RAM/motherboard, overheating, overclocking", "CPU/RAM/bo mạch chủ hỏng, quá nhiệt, ép xung")) },
            { 0x9F, new BugcheckInfo("DRIVER_POWER_STATE_FAILURE",
                X("드라이버가 절전 전환 요청을 제때 처리하지 못했습니다.", "A driver did not complete a power state transition in time.", "Trình điều khiển không hoàn tất chuyển trạng thái nguồn kịp thời."),
                X("절전/깨어나기 중 장치 드라이버 문제(USB, 네트워크, 그래픽)", "Device driver trouble during sleep/wake (USB, network, graphics)", "Lỗi trình điều khiển thiết bị khi ngủ/thức (USB, mạng, đồ họa)")) },
            { 0xC2, new BugcheckInfo("BAD_POOL_CALLER",
                X("드라이버가 커널 메모리 풀을 잘못 사용했습니다.", "A driver misused the kernel memory pool.", "Trình điều khiển dùng sai vùng nhớ của nhân."),
                DriverBug, 0, true) },
            { 0xC4, new BugcheckInfo("DRIVER_VERIFIER_DETECTED_VIOLATION",
                X("Driver Verifier가 드라이버 위반을 잡았습니다.", "Driver Verifier caught a driver violation.", "Driver Verifier phát hiện trình điều khiển vi phạm."),
                X("지목된 드라이버의 버그", "A bug in the named driver", "Lỗi trong trình điều khiển được nêu tên")) },
            { 0xC5, new BugcheckInfo("DRIVER_CORRUPTED_EXPOOL",
                X("드라이버가 커널 메모리 풀을 손상시켰습니다.", "A driver corrupted the kernel memory pool.", "Trình điều khiển làm hỏng vùng nhớ của nhân."),
                DriverBug, 0, true) },
            { 0xD1, new BugcheckInfo("DRIVER_IRQL_NOT_LESS_OR_EQUAL",
                X("드라이버가 높은 인터럽트 수준에서 잘못된 메모리 주소를 읽거나 썼습니다.", "A driver read or wrote an invalid memory address at a high interrupt level.", "Trình điều khiển đọc hoặc ghi địa chỉ bộ nhớ không hợp lệ ở mức ngắt cao."),
                X("드라이버 버그(해제된 메모리 사용 등). 지목된 모듈이 Windows 기본 모듈이면 그 위아래의 서드파티 드라이버를 의심",
                  "Driver bug (such as using freed memory). If the named module is a Windows component, suspect the third-party drivers above or below it",
                  "Lỗi trình điều khiển (ví dụ dùng bộ nhớ đã giải phóng). Nếu mô-đun được nêu là thành phần Windows, hãy nghi ngờ trình điều khiển bên thứ ba nằm trên hoặc dưới nó"), 4) },
            { 0xE2, new BugcheckInfo("MANUALLY_INITIATED_CRASH",
                X("사용자가 직접 크래시를 발생시켰습니다.", "The crash was triggered manually.", "Sự cố được kích hoạt thủ công."),
                X("키보드 크래시 단축키 또는 디버깅 도구", "Keyboard crash shortcut or a debugging tool", "Phím tắt gây sự cố hoặc công cụ gỡ lỗi")) },
            { 0xEF, new BugcheckInfo("CRITICAL_PROCESS_DIED",
                X("Windows 필수 프로세스가 종료됐습니다.", "A critical Windows process terminated.", "Một tiến trình thiết yếu của Windows đã kết thúc."),
                X("시스템 파일 손상, 디스크 오류, 드라이버/보안 프로그램", "Corrupted system files, disk errors, drivers or security software", "Tệp hệ thống hỏng, lỗi đĩa, trình điều khiển hoặc phần mềm bảo mật")) },
            { 0xF4, new BugcheckInfo("CRITICAL_OBJECT_TERMINATION",
                X("필수 프로세스나 스레드가 예기치 않게 종료됐습니다.", "A critical process or thread ended unexpectedly.", "Một tiến trình hoặc luồng thiết yếu kết thúc bất ngờ."),
                X("디스크 오류, 시스템 파일 손상", "Disk errors, corrupted system files", "Lỗi đĩa, tệp hệ thống hỏng")) },
            { 0x101, new BugcheckInfo("CLOCK_WATCHDOG_TIMEOUT",
                X("CPU 코어 하나가 응답하지 않았습니다.", "A CPU core stopped responding.", "Một lõi CPU ngừng phản hồi."),
                X("CPU 불안정(전압, 오버클럭), BIOS, 드라이버", "CPU instability (voltage, overclocking), BIOS, drivers", "CPU không ổn định (điện áp, ép xung), BIOS, trình điều khiển")) },
            { 0x109, new BugcheckInfo("CRITICAL_STRUCTURE_CORRUPTION",
                X("커널의 보호된 코드나 데이터가 변조됐습니다.", "Protected kernel code or data was modified.", "Mã hoặc dữ liệu được bảo vệ của nhân bị thay đổi."),
                X("드라이버의 커널 변조, 불량 메모리", "A driver modifying the kernel, faulty RAM", "Trình điều khiển sửa đổi nhân, RAM hỏng"), 0, true) },
            { 0x116, new BugcheckInfo("VIDEO_TDR_FAILURE",
                X("그래픽 드라이버가 응답하지 않아 복구에 실패했습니다.", "The graphics driver stopped responding and recovery failed.", "Trình điều khiển đồ họa ngừng phản hồi và khôi phục thất bại."),
                X("그래픽 드라이버, GPU 과열/불량, 전원 부족", "Graphics driver, GPU overheating or fault, insufficient power", "Trình điều khiển đồ họa, GPU quá nhiệt/hỏng, thiếu nguồn")) },
            { 0x119, new BugcheckInfo("VIDEO_SCHEDULER_INTERNAL_ERROR",
                X("그래픽 스케줄러에서 치명적 오류가 발생했습니다.", "The graphics scheduler hit a fatal error.", "Bộ lập lịch đồ họa gặp lỗi nghiêm trọng."),
                X("그래픽 드라이버, GPU 불량", "Graphics driver, faulty GPU", "Trình điều khiển đồ họa, GPU hỏng")) },
            { 0x124, new BugcheckInfo("WHEA_UNCORRECTABLE_ERROR",
                X("하드웨어가 복구 불가능한 오류를 보고했습니다.", "Hardware reported an uncorrectable error.", "Phần cứng báo lỗi không thể khắc phục."),
                X("CPU/메모리/메인보드/전원 불량, 과열, 오버클럭", "Faulty CPU/RAM/motherboard/power supply, overheating, overclocking", "CPU/RAM/bo mạch chủ/nguồn hỏng, quá nhiệt, ép xung")) },
            { 0x133, new BugcheckInfo("DPC_WATCHDOG_VIOLATION",
                X("드라이버가 인터럽트 처리에서 너무 오래 머물렀습니다.", "A driver spent too long handling an interrupt.", "Trình điều khiển xử lý ngắt quá lâu."),
                X("저장장치/네트워크/그래픽 드라이버, SSD 펌웨어", "Storage/network/graphics driver, SSD firmware", "Trình điều khiển lưu trữ/mạng/đồ họa, firmware SSD")) },
            { 0x139, new BugcheckInfo("KERNEL_SECURITY_CHECK_FAILURE",
                X("커널이 핵심 자료구조 손상을 감지했습니다.", "The kernel detected corruption of a critical data structure.", "Nhân phát hiện cấu trúc dữ liệu quan trọng bị hỏng."),
                DriverOrRam, 0, true) },
            { 0x13A, new BugcheckInfo("KERNEL_MODE_HEAP_CORRUPTION",
                X("커널 힙이 손상됐습니다.", "The kernel heap was corrupted.", "Heap của nhân bị hỏng."),
                DriverOrRam, 0, true) },
            { 0x154, new BugcheckInfo("UNEXPECTED_STORE_EXCEPTION",
                X("메모리 압축 저장소에서 예외가 발생했습니다.", "An exception occurred in the memory compression store.", "Xảy ra ngoại lệ trong kho nén bộ nhớ."),
                X("SSD/HDD 불량, 불량 메모리, 보안 프로그램", "Failing SSD/HDD, faulty RAM, security software", "SSD/HDD hỏng, RAM hỏng, phần mềm bảo mật")) },
            { 0x1CA, new BugcheckInfo("SYNTHETIC_WATCHDOG_TIMEOUT",
                X("시스템 전체가 일정 시간 응답하지 않았습니다.", "The whole system stopped responding for a period.", "Toàn bộ hệ thống ngừng phản hồi trong một khoảng thời gian."),
                X("하드웨어 멈춤, 가상화 환경 문제, 드라이버", "Hardware hang, virtualization issues, drivers", "Phần cứng treo, sự cố ảo hóa, trình điều khiển")) },
        };

        /// <summary>LiveKernelEvent(시스템은 죽지 않았지만 Windows가 남긴 커널 오류 보고) 코드.</summary>
        public static readonly Dictionary<uint, Tx> LiveCodes = new Dictionary<uint, Tx>
        {
            { 0x117, X("그래픽 드라이버 응답 지연(복구됨)", "Graphics driver timeout (recovered)", "Trình điều khiển đồ họa phản hồi chậm (đã khôi phục)") },
            { 0x141, X("그래픽 엔진 응답 지연(복구됨)", "Graphics engine timeout (recovered)", "Bộ máy đồ họa phản hồi chậm (đã khôi phục)") },
            { 0x193, X("그래픽 커널 내부 오류 보고", "Graphics kernel internal error report", "Báo cáo lỗi nội bộ của nhân đồ họa") },
            { 0x144, X("USB 3 컨트롤러/장치 오류", "USB 3 controller or device error", "Lỗi bộ điều khiển hoặc thiết bị USB 3") },
            { 0x124, X("하드웨어 오류 보고(WHEA)", "Hardware error report (WHEA)", "Báo cáo lỗi phần cứng (WHEA)") },
            { 0x15F, X("절전(모던 스탠바이) 중 응답 지연", "Timeout during modern standby", "Phản hồi chậm khi ở chế độ chờ hiện đại") },
            { 0x1A1, X("화면/입력 처리(win32k) 응답 지연", "Display/input (win32k) timeout", "Xử lý hiển thị/nhập liệu (win32k) phản hồi chậm") },
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

        /// <summary>모듈 이름을 분류한다. 알려진 Windows 기본 모듈이 아니면 "thirdparty".</summary>
        public static string Categorize(string module)
        {
            if (string.IsNullOrEmpty(module)) return "";
            string cat;
            return ModuleCategory.TryGetValue(module, out cat) ? cat : "thirdparty";
        }

        public static string CategoryLabel(string cat)
        {
            switch (cat)
            {
                case "network": return L.T("네트워크 스택", "Network stack", "Ngăn xếp mạng");
                case "gpu": return L.T("그래픽", "Graphics", "Đồ họa");
                case "storage": return L.T("저장장치/파일 시스템", "Storage / file system", "Lưu trữ / hệ thống tệp");
                case "usb": return "USB";
                case "kernel": return L.T("Windows 커널", "Windows kernel", "Nhân Windows");
                case "hardware": return L.T("하드웨어", "Hardware", "Phần cứng");
                case "audio": return L.T("오디오", "Audio", "Âm thanh");
                case "thirdparty": return L.T("서드파티 드라이버", "Third-party driver", "Trình điều khiển bên thứ ba");
                default: return "";
            }
        }

        public static string CategoryAdvice(string cat)
        {
            switch (cat)
            {
                case "network":
                    return L.T(
                        "Windows 네트워크 스택은 대개 피해자입니다. 실제 원인은 네트워크 어댑터 드라이버(특히 USB 이더넷), VPN/터널 드라이버, 가상화 네트워크 필터, 보안 프로그램인 경우가 많습니다. 어댑터를 바꿔 쓰거나 하나씩 꺼 보며 재발 여부를 비교하세요.",
                        "The Windows network stack is usually the victim. The real cause is often a network adapter driver (USB Ethernet in particular), a VPN/tunnel driver, a virtualization network filter, or security software. Switch adapters or disable them one at a time and compare whether the crash returns.",
                        "Ngăn xếp mạng của Windows thường chỉ là nạn nhân. Nguyên nhân thật sự hay nằm ở trình điều khiển card mạng (nhất là USB Ethernet), trình điều khiển VPN/đường hầm, bộ lọc mạng ảo hóa hoặc phần mềm bảo mật. Hãy đổi card mạng hoặc tắt từng cái một rồi so sánh xem lỗi có tái diễn không.");
                case "gpu":
                    return L.T(
                        "그래픽 드라이버를 제조사 최신(또는 한 단계 이전) 버전으로 깨끗이 재설치하고, GPU 온도와 전원 공급을 확인하세요. 딥러닝 추론처럼 GPU 부하가 큰 작업 중이었는지도 확인하세요.",
                        "Clean-install the graphics driver using the vendor's latest (or previous) version, and check GPU temperature and power delivery. Also check whether a GPU-heavy job such as deep-learning inference was running.",
                        "Cài sạch lại trình điều khiển đồ họa bằng bản mới nhất (hoặc bản trước đó) của hãng, kiểm tra nhiệt độ GPU và nguồn cấp. Cũng kiểm tra xem lúc đó có đang chạy tác vụ nặng GPU như suy luận deep learning hay không.");
                case "storage":
                    return L.T(
                        "SSD/HDD 상태(SMART), 저장장치 드라이버(Intel RST 등), SSD 펌웨어를 확인하세요. 'chkdsk /scan'과 제조사 진단 도구를 권합니다.",
                        "Check SSD/HDD health (SMART), the storage driver (Intel RST and similar), and SSD firmware. Run 'chkdsk /scan' and the vendor's diagnostic tool.",
                        "Kiểm tra tình trạng SSD/HDD (SMART), trình điều khiển lưu trữ (Intel RST...), firmware SSD. Nên chạy 'chkdsk /scan' và công cụ chẩn đoán của hãng.");
                case "usb":
                    return L.T(
                        "USB 장치/허브/케이블 문제일 수 있습니다. 카메라·조명 컨트롤러·동글 등 연결 장치를 하나씩 분리해 비교하고, 메인보드 칩셋/USB 드라이버를 갱신하세요.",
                        "A USB device, hub or cable may be at fault. Unplug connected devices (cameras, light controllers, dongles) one at a time to compare, and update the motherboard chipset/USB drivers.",
                        "Có thể do thiết bị, hub hoặc cáp USB. Hãy rút từng thiết bị (camera, bộ điều khiển đèn, dongle) để so sánh, và cập nhật trình điều khiển chipset/USB của bo mạch chủ.");
                case "kernel":
                    return L.T(
                        "Windows 커널 자체가 지목되면 원인이 특정되지 않은 것입니다. 다른 드라이버가 메모리를 손상시켰거나 메모리(RAM)가 불량일 수 있습니다. 덤프를 WinDbg로 열어 스택을 확인하고, 메모리 진단(mdsched)을 돌려 보세요.",
                        "When the Windows kernel itself is named, the cause has not been pinned down. Another driver may have corrupted memory, or the RAM may be faulty. Open the dump in WinDbg to inspect the stack, and run the memory diagnostic (mdsched).",
                        "Khi chính nhân Windows bị nêu tên thì nguyên nhân chưa được xác định. Có thể trình điều khiển khác làm hỏng bộ nhớ hoặc RAM bị lỗi. Hãy mở tệp dump bằng WinDbg để xem ngăn xếp và chạy chẩn đoán bộ nhớ (mdsched).");
                case "hardware":
                    return L.T(
                        "하드웨어 오류입니다. BIOS 업데이트, BIOS 기본값(XMP·오버클럭 해제), 온도, 전원 공급 장치를 확인하세요.",
                        "This is a hardware error. Check for a BIOS update, load BIOS defaults (XMP and overclocking off), and check temperatures and the power supply.",
                        "Đây là lỗi phần cứng. Hãy kiểm tra bản cập nhật BIOS, đặt BIOS về mặc định (tắt XMP và ép xung), kiểm tra nhiệt độ và bộ nguồn.");
                case "audio":
                    return L.T("오디오 드라이버를 PC 제조사 버전으로 갱신하세요.", "Update the audio driver to the PC maker's version.", "Cập nhật trình điều khiển âm thanh theo bản của hãng máy.");
                case "thirdparty":
                    return L.T(
                        "이 드라이버가 직접 지목됐습니다. 해당 제품의 드라이버를 갱신하거나 이전 버전으로 되돌리고, 안 쓰는 제품이면 제거하세요.",
                        "This driver was named directly. Update it or roll it back to an earlier version, and uninstall the product if you do not use it.",
                        "Trình điều khiển này bị nêu tên trực tiếp. Hãy cập nhật hoặc quay về phiên bản trước, và gỡ bỏ nếu không dùng sản phẩm đó.");
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

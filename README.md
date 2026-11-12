# CrashLens

Windows 블루스크린·비정상 종료 기록을 읽어 원인을 추정하는 무설치 분석기.
A portable tool that reads Windows blue screen and abnormal shutdown records and infers the likely cause.
Công cụ không cần cài đặt, đọc các bản ghi màn hình xanh và tắt máy bất thường của Windows để suy đoán nguyên nhân.

## 한국어

- 실행: `dist/CrashLens.exe` 하나만 복사해 실행 (Windows 10/11 기본 포함 .NET Framework 4.8 사용)
- 언어: Windows 표시 언어에 따라 한국어/베트남어/영어가 자동 선택되고, 화면 위쪽에서 바꿀 수 있음
- 덤프 파일 경로까지 보려면 관리자 권한으로 실행
- 읽기 전용: 이벤트 로그, 덤프 파일 목록, 드라이버 정보를 읽기만 하고 시스템을 바꾸지 않음

## English

- Run: copy `dist/CrashLens.exe` and run it (uses .NET Framework 4.8, included in Windows 10/11)
- Language: Korean, Vietnamese or English is chosen from the Windows display language and can be changed at the top of the window
- Run as administrator to also see dump file paths
- Read-only: it reads event logs, the dump file list and driver information, and changes nothing

## Tiếng Việt

- Chạy: chỉ cần sao chép `dist/CrashLens.exe` và chạy (dùng .NET Framework 4.8 có sẵn trong Windows 10/11)
- Ngôn ngữ: tự chọn tiếng Hàn, tiếng Việt hoặc tiếng Anh theo ngôn ngữ hiển thị của Windows, có thể đổi ở phía trên cửa sổ
- Chạy với quyền quản trị để xem cả đường dẫn tệp dump
- Chỉ đọc: chỉ đọc nhật ký sự kiện, danh sách tệp dump và thông tin trình điều khiển, không thay đổi hệ thống

## 구조 / Layout

| 폴더 | 내용 |
|---|---|
| `Core/` | 분석 로직 (Windows API 비의존). `Analyzer` 사건 묶기, `Findings` 패턴 진단, `Knowledge` 버그체크·모듈 지식, `Report` 출력, `L` 3개 국어 선택 |
| `App/` | WinForms 화면과 수집기(`Collector`: 이벤트 로그, WMI, 레지스트리), 아이콘 |
| `Tests/` | 실제 현장 기록을 재현한 회귀 테스트 (3개 국어 번역 누락 검사 포함) |
| `dist/` | 빌드된 실행 파일 |

## 빌드 / Build

```bash
dotnet build App/CrashLens.csproj -c Release
```

```bash
dotnet run --project Tests
```

문구를 추가할 때는 `L.T("한국어", "English", "Tiếng Việt")` 형태로 세 언어를 함께 적는다.
진단 규칙은 `Core/Knowledge.cs`(코드·모듈 표)와 `Core/Findings.cs`(패턴 규칙)에 있다.

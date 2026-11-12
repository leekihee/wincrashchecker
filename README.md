# CrashLens

Windows 블루스크린·비정상 종료 기록을 읽어 원인을 추정하는 무설치 분석기.

- 실행: `CrashLens.exe` 하나만 복사해 실행 (Windows 10/11 기본 포함 .NET Framework 4.8 사용)
- 덤프 파일 경로까지 보려면 관리자 권한으로 실행
- 읽기 전용: 이벤트 로그, 덤프 파일 목록, 드라이버 정보를 읽기만 하고 시스템을 바꾸지 않음

## 구조

| 폴더 | 내용 |
|---|---|
| `Core/` | 분석 로직 (Windows API 비의존). `Analyzer` 사건 묶기, `Findings` 패턴 진단, `Knowledge` 버그체크·모듈 지식, `Report` 출력 |
| `App/` | WinForms 화면과 수집기(`Collector`: 이벤트 로그, WMI, 레지스트리) |
| `Tests/` | 실제 현장 기록을 재현한 회귀 테스트 |

## 빌드

```bash
dotnet build App/CrashLens.csproj -c Release
```

```bash
dotnet run --project Tests
```

진단 규칙을 추가하려면 `Core/Knowledge.cs`(코드·모듈 표)와 `Core/Findings.cs`(패턴 규칙)를 고친다.

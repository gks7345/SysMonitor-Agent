# SysMonitor Agent

> Windows 시스템 모니터링 Agent — 수집한 데이터를 중앙 서버로 전송합니다.

## 개요

SysMonitor Agent는 Windows PC에 설치되어 시스템/프로세스/타겟 프로그램 지표를 1초 주기로 수집하고, gRPC를 통해 중앙 집계 서버로 전송하는 모니터링 도구입니다.

기존 [SysMonitor](https://github.com/gks7345/SysMonitor)의 수집 엔진을 재활용하여, HTTP 기반 단독 동작에서 gRPC 기반 다중 Agent 구조로 확장한 프로젝트입니다.

## 현재 진행 상태

| 단계 | 내용 | 상태 |
|------|------|------|
| Phase 1 | gRPC 뼈대 (Agent ↔ Server 연결, 실시간/배치 채널) | ✅ 완료 |
| Phase 2 | 인증 + 설정 파일 (`agent.ini`, api_key, 장비 식별) | ✅ 완료 |
| Phase 3 | 실제 수집 데이터 전송 | 🔧 proto 구조만 선반영, 수집기 연결 예정 |
| Phase 4 | 연결 끊김 처리 (재연결, 로컬 버퍼, 갭 전송) | 예정 |
| Phase 9 | 로컬 폴백 모드 (`send_to_server = false`) | 예정 |

지금 Agent는 서버에 연결해 **더미 스냅샷**(sys / proc / target)을 1초마다 보내고, 서버와 연결이 끊기거나 거부되면 원인을 로그로 남기고 종료합니다. 아래 설명 중 "(Phase N 예정)"으로 표시된 부분은 아직 구현되지 않은 목표 설계입니다.

## 아키텍처

```
SysMonitor Agent (Windows PC)
  │
  ├── 수집기 (C++)                                    (Phase 3에서 연결 예정)
  │     SystemCollector   PDH: CPU · 메모리 · 디스크 · 네트워크
  │     ProcessCollector  PDH 와일드카드 · ETW 네트워크 병합
  │     TargetCollector   PDH Process V2 · 자식 프로세스 · ETW 통신
  │
  ├── 실시간 채널 (gRPC Client Streaming)
  │     1초마다 sys / proc(전체 프로세스 목록) / target 스냅샷 전송
  │     스냅샷 1건 = 메시지 1개
  │
  ├── 배치 채널 (gRPC Client Streaming)
  │     재연결 후 끊겼던 동안의 갭 데이터 전송 전용       (Phase 4 예정)
  │
  └── 로컬 DuckDB (단기 버퍼)                          (Phase 4 예정)
        연결 끊김 시 임시 저장 (최대 24시간)
        재연결 시 갭 전송 후 삭제
```

## 기술 스택

| 분류 | 기술 |
|------|------|
| 언어 | C++17 |
| 빌드 | CMake + FetchContent (의존성 자동 빌드) |
| 수집 | PDH, ETW, Win32 API |
| 통신 | gRPC (Protobuf) |
| 설정 | inih (ini 파서) |
| 버퍼 | DuckDB |
| 로깅 | spdlog |

## 기존 SysMonitor와의 차이

| 항목 | SysMonitor (기존) | SysMonitor Agent (확장) |
|------|-------------------|------------------------|
| 목적 | 단일 PC 모니터링 | 다중 PC 모니터링 |
| 통신 | HTTP REST | gRPC 스트리밍 |
| UI | 로컬 React Web UI | 없음 (중앙 서버 UI 사용) |
| 저장 | 로컬 DuckDB (영구) | 로컬 DuckDB (단기 버퍼) |
| 배포 | SysMonitor.exe | SysMonitorAgent.exe |

## 채널 설계

### 왜 채널을 2개로 나눴나

재연결 후 보내는 갭 데이터는 몇 시간 분량일 수 있습니다. 같은 채널에 넣으면 갭을 보내는 동안 실시간 데이터가 밀립니다. gRPC의 HTTP/2 멀티플렉싱으로 채널을 분리해 서로 영향 없이 동작합니다.

```
실시간 채널  1초마다        sys / proc(전체 목록) / target 스냅샷
배치 채널    재연결 시에만   끊겼던 동안 로컬 버퍼에 쌓인 갭 데이터
```

- 실시간 채널은 프로세스 **전체 목록**을 보냅니다. 상위 N개와 정렬 기준(CPU/메모리/디스크/네트워크)은 **UI에서 사용자가 정하므로** Agent가 미리 자르지 않습니다.
- 60초마다 따로 보내는 배치는 없습니다. 실시간 채널이 이미 전체 데이터를 보내기 때문입니다.

### 메시지 구조

메시지 1개에 스냅샷 1건을 담고, 종류는 `oneof`로 구분합니다. 실시간/갭 구분은 어느 채널로 왔는지로 합니다.

```protobuf
message AgentData {
  string agent_id = 1;
  reserved 2, 3, 4;                 // 이전 버전 필드 — 번호 재사용 금지
  oneof body {
    SysSnapshot    sys    = 10;     // CPU · 메모리 · 디스크 · 네트워크
    ProcSnapshot   proc   = 11;     // 전체 프로세스 목록
    TargetSnapshot target = 12;     // 타겟 프로그램 + 자식 프로세스 + 네트워크 연결
  }
}
```

- 모든 `string` 필드는 UTF-8이어야 합니다. 수집기는 Windows W API로 읽어 UTF-8로 변환합니다 (Phase 3 예정).
- `proto/sysmonitor.proto`는 SysMonitor-Server와 **같은 내용**이어야 합니다. 구조를 바꾸면 파일 안의 `PROTOCOL_VERSION_CURRENT`를 올립니다. 버전이 다르면 서버가 연결 시점에 거부합니다.

## 연결과 인증

```
1. 서버 연결 확인 (최대 5초)
2. Hello RPC   — 인증 + 프로토콜 버전 + 장비 확인
3. 실시간 / 배치 스트림 열기
```

모든 요청에 gRPC metadata로 세 가지 값을 싣습니다.

| metadata | 값 | 용도 |
|---|---|---|
| `agent_id` | `agent.ini`의 `id` | 이 Agent가 누구인지 (자리/역할) |
| `api_key` | `agent.ini`의 `api_key` | 서버에 등록된 키와 대조 |
| `instance_id` | Windows `MachineGuid` | 어느 장비인지 |

- 서버는 요청마다 인증하고, 메시지마다 `agent_id`가 인증된 값과 같은지 확인합니다.
- **같은 `agent_id`로 다른 장비가 이미 접속 중이면 거부됩니다.** 설치 폴더를 복사하고 `id`를 바꾸지 않은 경우 두 PC의 데이터가 섞이는 것을 막기 위해서입니다. 같은 장비의 재접속은 허용됩니다.
- 거부되면 원인(키 오류, 프로토콜 불일치, 같은 ID 사용 중 등)을 로그로 남기고 종료합니다.

## 연결 끊김 처리 (Phase 4 예정)

```
연결 끊김 감지
  gRPC keepalive ping으로 감지
  지수 백오프로 자동 재연결 (1초 → 2초 → 4초 ...), 각 단계에 ±20~30% 랜덤 지터 적용
    (서버 재시작 시 모든 Agent가 동시에 재연결·갭 전송을 시도하는 thundering herd 방지)

끊김 동안
  수집 계속 진행
  로컬 DuckDB 버퍼에 임시 저장 (스냅샷마다 수집한 장비 정보 함께 기록)

재연결 시
  서버에 마지막 수신 timestamp 요청
  로컬 DuckDB에서 갭 데이터 조회
  배치 채널로 갭 전송 후 로컬 데이터 삭제
  실시간 스트리밍 재개
```

- 로컬 DuckDB는 메인 수집 루프 스레드에서만 접근합니다. 네트워크 스레드는 갭 데이터가 필요할 때 커맨드 큐에 요청을 적재하고 `std::future`로 결과를 전달받습니다. 기존 SysMonitor의 `TargetCollector` 등록/해제 패턴과 같은 방식으로, 메인 루프의 쓰기와 재연결 시 읽기가 동시에 발생하는 것을 막습니다.
- 갭 데이터가 정말 이 자리(`agent_id`)의 것인지는 **서버가 장비 연결 이력으로 판정**합니다. 설치 폴더를 복사할 때 다른 PC의 버퍼가 함께 따라와도 서버 기록이 오염되지 않게 하기 위해서입니다.

## 설정

실행 위치(현재 작업 디렉터리)의 `agent.ini`에서 읽습니다. 컴파일타임 상수가 아니므로 PC마다 다시 빌드하지 않고 같은 exe를 배포할 수 있습니다. `agent.ini.example`을 복사해 사용합니다.

```ini
[server]
url = 192.168.0.100:50051     ; 서버 주소 (0.0.0.0 같은 대기 주소가 아닌 실제 주소)
send_to_server = true

[agent]
id = PC-01                    ; 서버 agents.ini에 등록된 ID
api_key =                     ; 서버 agents.ini의 같은 ID에 등록한 키와 같은 값
local_buffer_hours = 24
```

- **`api_key`는 예제에서 일부러 비워 두었습니다.** 원하는 문자열을 정해 Agent와 서버 양쪽에 같은 값으로 넣으면 됩니다. 비워 둔 채 실행하면 서버가 연결을 거부합니다.
- **파일이 없으면** 기본값(`send_to_server = false`)으로 동작합니다. 로컬 폴백 모드(Phase 9)가 구현되기 전까지는 바로 종료합니다.
- **틀린 줄이나 값**(`=` 누락, `true/false`가 아닌 값, 같은 키 중복 등)이 있으면 그 설정만 기본값을 쓰고 줄 번호와 함께 경고합니다. 실제로 적용된 값은 시작할 때 항상 로그로 남습니다.
- 단, `send_to_server = true`인데 `url`을 읽을 수 없으면(없음/빈 값/중복) **기본 주소로 대신 연결하지 않고 종료**합니다.

## 빌드 및 실행

의존성(gRPC, Protobuf, DuckDB, spdlog, inih)은 CMake FetchContent가 소스로 받아 함께 빌드합니다. 별도 설치가 필요 없지만, 처음 빌드할 때 gRPC 빌드에 시간이 오래 걸립니다.

```powershell
# Visual Studio 2022 개발자 환경에서
cmake -B out/build/x64-Debug
cmake --build out/build/x64-Debug

# 실행 — agent.ini가 있는 폴더에서 실행
cd out/build/x64-Debug/src
.\SysMonitorAgent.exe
```

Visual Studio에서는 폴더 열기(`File > Open > Folder`)로 CMake 프로젝트를 바로 열 수 있습니다.

## 플랫폼 지원

| OS | 지원 여부 |
|----|----------|
| Windows 11 | ✅ |
| Linux | 추후 개발 예정 (/proc 기반) |
| macOS | 미정 |

> Windows 전용인 이유: PDH, ETW API가 Windows 전용입니다. Docker 컨테이너 안에서는 호스트 OS의 실제 지표를 수집할 수 없어 네이티브 설치 방식을 채택했습니다.

## 관련 프로젝트

- [SysMonitor](https://github.com/gks7345/SysMonitor) — 단일 PC 모니터링 (기반 프로젝트)
- [SysMonitor-Server](링크) — 중앙 집계 서버 + 통합 Web UI

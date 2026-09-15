# SysMonitor Agent

> Windows 시스템 모니터링 Agent — 수집한 데이터를 중앙 서버로 전송합니다.

## 개요

SysMonitor Agent는 Windows PC에 설치되어 시스템/프로세스/타겟 프로그램 지표를 1초 주기로 수집하고, gRPC를 통해 중앙 집계 서버로 전송하는 모니터링 도구입니다.

기존 [SysMonitor](https://github.com/gks7345/SysMonitor)의 수집 엔진을 재활용하여, HTTP 기반 단독 동작에서 gRPC 기반 다중 Agent 구조로 확장한 프로젝트입니다.

## 아키텍처

```
SysMonitor Agent (Windows PC)
  │
  ├── 수집기 (C++)
  │     SystemCollector   PDH: CPU · 메모리 · 디스크 · 네트워크
  │     ProcessCollector  PDH 와일드카드 · ETW 네트워크 병합
  │     TargetCollector   PDH Process V2 · 자식 프로세스 · ETW 통신
  │
  ├── 실시간 채널 (gRPC Client Streaming)
  │     1초마다 소량 데이터 전송
  │     sys / proc / target 실시간 수치
  │
  ├── 배치 채널 (gRPC Client Streaming)
  │     60초마다 대량 데이터 전송
  │     sys / proc / target 상세 스냅샷
  │
  └── 로컬 DuckDB (단기 버퍼)
        연결 끊김 시 임시 저장 (최대 24시간)
        재연결 시 갭 채우기 후 삭제
```

## 기술 스택

| 분류 | 기술 |
|------|------|
| 언어 | C++17 |
| 빌드 | CMake |
| 수집 | PDH, ETW, Win32 API |
| 통신 | gRPC (Protobuf) |
| 버퍼 | DuckDB |
| 로깅 | spdlog |

## 기존 SysMonitor와의 차이

| 항목 | SysMonitor (기존) | SysMonitor Agent (확장) |
|------|-------------------|------------------------|
| 목적 | 단일 PC 모니터링 | 다중 PC 모니터링 |
| 통신 | HTTP REST | gRPC 스트리밍 |
| UI | 로컬 React Web UI | 없음 (중앙 서버 UI 사용) |
| 저장 | 로컬 DuckDB (영구) | 로컬 DuckDB (단기 버퍼) |
| 배포 | SysMonitor.exe | SysMonitor-Agent.exe |

## 채널 설계

### 왜 채널을 2개로 나눴나

실시간 데이터(1초, 소량)와 배치 데이터(60초, 수 MB)를 같은 채널에 넣으면 배치 전송 중 실시간 데이터가 지연됩니다. gRPC의 HTTP/2 멀티플렉싱으로 채널을 분리해 서로 영향 없이 동작합니다.

```
실시간 채널  1초마다  수 KB   sys/proc/target 현재 수치
배치 채널    60초마다 수 MB   sys/proc/target 상세 스냅샷
```

### 타입 구분

```protobuf
message AgentData {
  enum Type {
    SYS_REALTIME    = 0;
    PROC_REALTIME   = 1;
    TARGET_REALTIME = 2;
    SYS_BATCH       = 3;
    PROC_BATCH      = 4;
    TARGET_BATCH    = 5;
  }
  string agent_id = 1;
  Type   type     = 2;
  bytes  payload  = 3;
}
```

## 연결 끊김 처리

```
연결 끊김 감지
  gRPC keepalive ping → 즉시 감지
  지수 백오프로 자동 재연결 (1초 → 2초 → 4초 ...), 각 단계에 ±20~30% 랜덤 지터 적용
    (서버 재시작 시 모든 Agent가 동시에 재연결·갭 전송을 시도하는 thundering herd 방지)

끊김 동안
  수집 계속 진행
  로컬 DuckDB 버퍼에 임시 저장

재연결 시
  서버에 마지막 수신 timestamp 요청
  로컬 DuckDB에서 갭 데이터 조회
  배치 채널로 갭 전송 후 로컬 데이터 삭제
  실시간 스트리밍 재개
```

로컬 DuckDB는 메인 수집 루프 스레드에서만 접근합니다. 네트워크 스레드는 갭 데이터가 필요할 때 커맨드 큐에 요청을 적재하고 `std::future`로 결과를 전달받습니다 — 기존 SysMonitor의 `TargetCollector` 등록/해제 패턴과 동일한 방식으로, 메인 루프의 1초 주기 쓰기와 재연결 시 읽기가 동시에 발생하는 것을 방지합니다.

## 설정

exe와 같은 경로의 `agent.json`에서 런타임에 로드합니다 (컴파일타임 상수 아님 — PC마다 재빌드 없이 배포 가능).

```json
// agent.json
{
  "server_url": "192.168.0.100:50051",
  "agent_id": "PC-01",
  "api_key": "발급받은 API Key",
  "send_to_server": true,
  "local_buffer_hours": 24
}
```

- `send_to_server: false` 설정 시 로컬 Web UI 모드로 전환됩니다 (기존 SysMonitor 동작).
- `api_key`는 gRPC 요청 시 metadata에 실려 서버로 전달되며, 서버가 등록된 `(agent_id, api_key)` 조합과 대조해 인증합니다. (인증 없이 `agent_id` 문자열만으로 신뢰하면 다른 프로세스가 동일 ID로 접속해도 구분할 수 없기 때문입니다.)
- `agent.json`이 없으면 기본값(`send_to_server=false`)으로 폴백합니다.

## 빌드 및 실행

```bash
# 의존성
# - gRPC / Protobuf
# - DuckDB
# - spdlog

cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build

# 실행
./build/SysMonitor-Agent.exe
```

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

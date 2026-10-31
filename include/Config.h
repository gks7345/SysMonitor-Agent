// SysMonitor.h 또는 별도 Config.h
#pragma once
#include <chrono>

namespace Config {
    // RingBuffer 용량 (초 단위 = 보관 시간)
    constexpr size_t PROC_BUFFER_CAPACITY = 600;  // 120초
    constexpr size_t SYS_BUFFER_CAPACITY = 600;  // 120초
    constexpr size_t TARGET_BUFFER_CAPACITY = 600; // 120초

    // 로컬 버퍼(GapBuffer)에서 보관 시간이 지난 행을 지우는 주기 (tick 단위 = 초)
    constexpr int BUFFER_EXPIRE_INTERVAL_TICKS = 60;
    // 틱 사이 대기 중 송신 스레드의 버퍼 작업을 처리하러 깨어나는 간격
    constexpr std::chrono::milliseconds BUFFER_TASK_POLL{ 20 };

    // 프로세스 상위 N개
    constexpr int DEFAULT_TOP_N = 10;

    // 수집 주기
    constexpr int SLOW_COLLECT_INTERVAL = 2;      // 2초마다 collectSlow
    constexpr int MIDDLE_COLLECT_INTERVAL = 1;  // 수집 주기 (초)

    // 중앙 집계 서버용 — agent.ini 폴백 기본값
    // ※ agent.ini의 값이 항상 우선한다. 아래 값은 agent.ini가 없거나 파싱에 실패했을 때, 또는 해당 키가
    //   빠져 있을 때만 쓰인다 (AgentConfig::load()의 Get*() 기본값 인자, AgentConfig 멤버 초기값).
    //   운영 중 설정을 바꾸려면 여기가 아니라 agent.ini를 수정할 것.
    static constexpr bool SEND_TO_SERVER = false;       // 중앙 서버 전송 여부 (기획노트 §7: ini가 없으면 false, 로컬 UI 모드)
    static constexpr const char* SERVER_URL = "localhost:50051";    // 서버 주소 (gRPC target, host:port)
    static constexpr const char* AGENT_ID = "PC-01";    // Agent 식별자
    static constexpr int LOCAL_BUFFER_HOURS = 24;       // 연결 끊김 시 로컬 버퍼 보관 시간 (시간)
}
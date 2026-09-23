#pragma once

#include <optional>
#include <string>

#include "Config.h"

// Phase 2: exe와 같은 경로의 agent.ini에서 런타임 설정을 로드한다.
// agent.ini의 값이 항상 우선하고, 파일이나 키가 없을 때만 Config.h의 폴백 기본값을 쓴다
// (기획노트 §7: "파일이 없으면 기본값으로 폴백 (send_to_server=false, 로컬 UI 모드)").
// 기본값은 Config.h 한 곳에만 정의한다 — 아래 멤버 초기값과 load()의 Get*() 기본값 인자 모두 Config::를 참조한다.
struct AgentConfig {
    bool sendToServer = Config::SEND_TO_SERVER;
    std::string serverUrl = Config::SERVER_URL;
    std::string agentId = Config::AGENT_ID;
    std::string apiKey;                          // 기본값 없음 (빈 문자열 = 키 없음)
    int localBufferHours = Config::LOCAL_BUFFER_HOURS;

    // iniPath가 없으면 실행 파일과 같은 경로의 "agent.ini"를 사용한다.
    // - 파일 없음: 폴백 설정(send_to_server=false)을 반환
    // - 문법 오류 줄: 그 줄만 무시하고 해당 설정은 기본값, 나머지는 파일 값 사용 (경고 로그)
    // - send_to_server=true인데 [server] url을 읽지 못함: std::nullopt (localhost로 대신 붙지 않도록 기동 중단)
    static std::optional<AgentConfig> load(const std::string& iniPath = "agent.ini");
};

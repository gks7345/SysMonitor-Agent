#include <chrono>
#include <optional>
#include <string>
#include <thread>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <spdlog/spdlog.h>

#include "Config.h"
#include "AgentConfig.h"
#include "grpc/GrpcClient.h"

namespace {

std::string wideToUtf8(const wchar_t* w) {
    int len = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
    if (len <= 1) {
        return "";
    }
    std::string out(static_cast<size_t>(len - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w, -1, out.data(), len, nullptr, nullptr);
    return out;
}

// gRPC metadata 값은 출력 가능한 ASCII(0x20~0x7E)만 허용한다 — 그 밖의 바이트(예: 한글 컴퓨터 이름)는 %XX로 바꾼다.
std::string toMetadataSafe(const std::string& s) {
    static const char* hex = "0123456789ABCDEF";
    std::string out;
    for (unsigned char c : s) {
        if (c >= 0x20 && c <= 0x7E && c != '%') {
            out += static_cast<char>(c);
        } else {
            out += '%';
            out += hex[c >> 4];
            out += hex[c & 0x0F];
        }
    }
    return out;
}

// 설치(PC) 단위 고유값 — 같은 agent_id를 쓰는 다른 PC(설치 폴더를 복사하고 id를 안 바꾼 경우)를 서버가 구분하는 데 쓴다.
// Windows가 설치 시 만드는 MachineGuid를 쓰고, 읽지 못하면 컴퓨터 이름으로 대체한다.
// 한계: 디스크 이미지로 복제한 PC/VM은 MachineGuid가 같을 수 있어 구분하지 못한다 (지금과 같은 동작으로 남음).
// 설치 폴더 안의 파일에 UUID를 저장하는 방식은 쓰지 않는다 — 폴더 복사와 함께 복사되어 목적을 잃는다.
std::string readInstanceId() {
    wchar_t guid[64] = {};
    DWORD size = sizeof(guid);
    if (RegGetValueW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Cryptography", L"MachineGuid", RRF_RT_REG_SZ, nullptr, guid, &size) == ERROR_SUCCESS && guid[0] != L'\0') {
        return toMetadataSafe(wideToUtf8(guid));
    }

    wchar_t name[MAX_COMPUTERNAME_LENGTH + 1] = {};
    DWORD nameLen = MAX_COMPUTERNAME_LENGTH + 1;
    if (GetComputerNameW(name, &nameLen)) {
        spdlog::warn("[SysMonitorAgent] MachineGuid not readable — using computer name as instance_id");
        return "host:" + toMetadataSafe(wideToUtf8(name));
    }

    // 공용 값("unknown" 등)을 쓰면 실패한 PC들이 서로 같은 PC로 취급되므로, 비워서 서버가 원인과 함께 거부하게 한다.
    spdlog::error("[SysMonitorAgent] could not determine instance_id (MachineGuid and computer name both unavailable)");
    return "";
}

// Phase 4(재연결) 전까지는 Ok가 아니면 전부 종료한다. Phase 4에서는 Disconnected case만
// 백오프 재연결로 바꾸면 된다. default를 두지 않아, enum 값이 추가되면 여기도 함께 검토하게 한다.
// 구체적인 원인(gRPC 상태 코드/메시지)은 GrpcClient가 이미 로그로 남긴다.
bool shouldContinue(ClientResult result, const char* stage) {
    switch (result) {
    case ClientResult::Ok:
        return true;
    case ClientResult::Disconnected:
        spdlog::error("[SysMonitorAgent] {}: disconnected from server, exiting (reconnect is Phase 4)", stage);
        return false;
    case ClientResult::Unauthenticated:
        spdlog::error("[SysMonitorAgent] {}: rejected by server — check agent_id/api_key in agent.ini, exiting", stage);
        return false;
    case ClientResult::Fatal:
        // proto 불일치, 같은 agent_id를 쓰는 다른 PC(ALREADY_EXISTS) 등 — 서버가 보낸 사유는 바로 앞 GrpcClient 로그에 있다.
        spdlog::error("[SysMonitorAgent] {}: rejected by server or unexpected error (see the reason logged above; e.g. proto mismatch, agent_id already used by another machine), exiting", stage);
        return false;
    }
    return false;
}

} // namespace

// Phase 2 체크포인트: agent.ini에서 agent_id/api_key를 읽어 gRPC metadata로 전송하고,
// 서버가 잘못된 api_key를 가진 연결을 거부하는지 확인한다.
int main() {
    // 소스는 UTF-8(/utf-8)로 컴파일되지만 Windows 콘솔 기본 코드페이지는 CP949라
    // 로그의 한글이 깨져 보인다. 콘솔 출력 코드페이지를 UTF-8로 맞춰 해결한다.
    SetConsoleOutputCP(CP_UTF8);

    std::optional<AgentConfig> config = AgentConfig::load("agent.ini");
    if (!config) {
        return 1;   // 원인은 AgentConfig::load()가 이미 로그로 남김
    }
    if (!config->sendToServer) {
        spdlog::warn("[SysMonitorAgent] send_to_server=false (agent.ini 없음 또는 비활성화) — Phase 9 로컬 폴백 모드 전까지는 종료한다");
        return 0;
    }

    const std::string instanceId = readInstanceId();
    spdlog::info("[SysMonitorAgent] starting, agent_id={}, instance_id={}", config->agentId, instanceId);

    GrpcClient client(config->serverUrl, config->agentId, config->apiKey, instanceId);
    if (!shouldContinue(client.connect(), "connect")) {
        return 1;
    }

    int tick = 0;
    while (true) {
        if (!shouldContinue(client.sendRealtimeDummy(), "realtime")) {
            return 1;
        }

        // 주기적 배치 전송은 새 설계(기획노트 §2)에 없다 — 배치 채널이 살아 있는지 확인하는 Phase 1/2 스캐폴딩이며,
        // Phase 4-4에서 "재연결 시 갭 전송"으로 교체된다.
        if (tick % Config::FLUSH_INTERVAL_TICKS == 0) {
            if (!shouldContinue(client.sendBatchDummy(), "batch")) {
                return 1;
            }
        }

        ++tick;
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

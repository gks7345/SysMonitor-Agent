#include <chrono>
#include <optional>
#include <string>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <shellapi.h>
#pragma comment(lib, "shell32.lib")

#include <spdlog/spdlog.h>

#include "Config.h"
#include "AgentConfig.h"
#include "collectors/SystemCollector.h"
#include "collectors/ProcessCollector.h"
#include "collectors/TargetCollector.h"
#include "grpc/GrpcClient.h"
#include "util/ProcessList.h"
#include "util/StrUtil.h"

namespace {

using StrUtil::wideToUtf8;

// 개발용 타겟 등록: `SysMonitorAgent.exe --target <이름> [--target <이름> ...]`
// 정식 등록 경로는 통합 Web UI → 서버 → 역방향 명령(기획노트 §4, Phase 7)이라 agent.ini에는 두지 않는다 —
// Phase 3 체크포인트(타겟 수치 수신 확인)를 위한 임시 경로이며 Phase 7에서 제거한다.
// main()의 argv는 ANSI(CP949)라 한글 이름이 깨지므로 wide 명령줄을 직접 읽어 UTF-8로 바꾼다 (Phase 3-0).
// 이름 정규화(".exe" 제거, 대소문자 무시 중복 판정)는 TargetCollector::registerTarget()이 한 곳에서 한다 —
// Phase 7 역방향 명령으로 들어오는 이름도 같은 규칙을 거치도록 여기서는 손대지 않는다.
// 모르는 인자·값 없는 --target은 오타가 조용히 무시되지 않도록 기동을 중단시킨다 (nullopt).
std::optional<std::vector<std::string>> parseTargetArgs() {
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (!argv) {
        spdlog::error("[SysMonitorAgent] could not read command line (error {})", GetLastError());
        return std::nullopt;
    }

    std::vector<std::string> names;
    bool ok = true;
    for (int i = 1; i < argc; ++i) {
        const std::string arg = wideToUtf8(argv[i]);
        if (arg != "--target") {
            spdlog::error("[SysMonitorAgent] unknown argument '{}' (usage: SysMonitorAgent.exe [--target <name>]...)", arg);
            ok = false;
            break;
        }
        if (i + 1 >= argc || argv[i + 1][0] == L'\0') {
            spdlog::error("[SysMonitorAgent] --target needs a process name (e.g. --target notepad)");
            ok = false;
            break;
        }
        names.push_back(wideToUtf8(argv[++i]));
    }
    LocalFree(argv);

    if (!ok) {
        return std::nullopt;
    }
    return names;
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

// Phase 3: 실제 수집기(sys / proc 전체 / target)의 스냅샷을 1초마다 실시간 채널로 보낸다.
// 수집 순서·주기는 원본 SysMonitor의 메인 루프와 같다. 로컬 DuckDB(DataStore)는 끊김 동안의 버퍼 역할로
// Phase 4-3에서 붙인다 (기획노트 §3) — 그 전까지 연결이 끊기면 종료한다.
int main() {
    // 소스는 UTF-8(/utf-8)로 컴파일되지만 Windows 콘솔 기본 코드페이지는 CP949라
    // 로그의 한글이 깨져 보인다. 콘솔 출력 코드페이지를 UTF-8로 맞춰 해결한다.
    SetConsoleOutputCP(CP_UTF8);

    std::optional<std::vector<std::string>> targetNames = parseTargetArgs();
    if (!targetNames) {
        return 1;   // 원인은 parseTargetArgs()가 이미 로그로 남김
    }

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

    // 인증·프로토콜 버전 오류는 수집기(ETW 세션 등)를 띄우기 전에 빨리 드러나도록 연결을 먼저 한다.
    GrpcClient client(config->serverUrl, config->agentId, config->apiKey, instanceId);
    if (!shouldContinue(client.connect(), "connect")) {
        return 1;
    }

    // ETW 세션은 ProcessCollector가 소유하고 TargetCollector가 공유한다 (프로세스별 네트워크 사용량 — 관리자 권한 필요,
    // 없으면 경고만 남고 네트워크 값이 0으로 나간다). SystemCollector 생성자는 PDH 기준점을 잡느라 1초 대기한다.
    SystemCollector sysCollector;
    ProcessCollector procCollector;
    TargetCollector targetCollector(procCollector.getEtwNet());

    // 여기는 메인 루프 스레드이므로 registerTarget()을 직접 불러도 된다 (다른 스레드는 requestRegister() 경유).
    for (const auto& name : *targetNames) {
        targetCollector.registerTarget(name);
    }

    int tick = 0;
    while (true) {
        const auto loopStart = std::chrono::steady_clock::now();

        // 다른 스레드가 큐에 넣은 타겟 등록/해제 요청을 이 스레드에서 반영한다 (Phase 7 역방향 명령이 쓸 경로)
        targetCollector.applyPending();

        // 1초 주기 수집
        sysCollector.collectMiddle();

        // 프로세스 목록은 틱당 1번 떠서 proc 목록과 타겟 수집이 함께 쓴다 (같은 시점의 목록, 스냅샷 1번).
        // 못 받은 틱은 빈 목록으로 취급하지 않는다: proc 목록은 보내지 않고, 타겟은 직전 상태를 유지한다.
        const std::optional<ProcessList> procs = takeProcessList();
        if (!procs) {
            spdlog::warn("[SysMonitorAgent] process snapshot failed (error {}) — proc list is not sent and target start/exit detection is skipped this tick", GetLastError());
        }
        procCollector.collectProc(procs);
        targetCollector.collect(procs);
        if (tick % Config::SLOW_COLLECT_INTERVAL == 0) {
            sysCollector.collectSlow();   // 2초 주기 (디스크)
        }

        // 원본은 여기서 종료된 타겟의 마지막 세션 요약을 로컬 DuckDB(SessionReport)로 계산해 넣었다.
        // 로컬 DB는 Phase 4-3에서 붙으므로, 그 전까지 종료된 타겟은 요약 없이 NEVER_SEEN으로 보고된다.
        targetCollector.clearPendingDeactivated();

        if (!shouldContinue(client.sendRealtime(sysCollector.makeSnapshot(), procCollector.makeSnapshot(), targetCollector.getSnapshot()), "realtime")) {
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

        // 수집·전송에 쓴 시간을 빼고 남은 시간만 기다려 1초 주기를 유지한다. 그 사이 타겟 등록/해제 요청이 들어오면
        // 즉시 깨어나 반영한 뒤 deadline까지 다시 기다린다 (원본 SysMonitor와 같은 방식).
        const auto deadline = loopStart + std::chrono::seconds(1);
        while (std::chrono::steady_clock::now() < deadline) {
            if (targetCollector.waitForPendingUntil(deadline)) {
                targetCollector.applyPending();
            }
        }
    }
}

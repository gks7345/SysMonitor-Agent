#include <algorithm>
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
#include "datastore/GapBuffer.h"
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

// PC 하나에 Agent 하나만 돌게 한다. 같은 PC의 두 프로세스는 instance_id가 같아 서버가 둘 다 받아들이고
// (한 자리에 데이터가 두 벌 들어가고 재개 지점도 나눠 쓴다), 두 번째는 버퍼 파일을 열지 못한 채 계속 돈다.
// 설치 폴더가 달라도 막도록 PC 전체에서 보이는 이름(Global\)을 쓴다 (관리자 권한 없이 만들 수 있다).
// 핸들은 일부러 닫지 않는다 — 프로세스가 어떻게 끝나든 OS가 닫으므로, 잠금 파일처럼 죽은 프로세스의 잠금이 남지 않는다.
// 이미 있으면 ERROR_ALREADY_EXISTS, 다른 권한으로 실행된 Agent가 만들었으면 ERROR_ACCESS_DENIED로 실패한다 — 둘 다 "이미 실행 중"이다.
bool acquireSingleInstance() {
    HANDLE mutex = CreateMutexW(nullptr, FALSE, L"Global\\SysMonitorAgent");
    const DWORD error = GetLastError();
    if (mutex && error != ERROR_ALREADY_EXISTS) {
        return true;
    }
    if (mutex) {
        CloseHandle(mutex);
    }
    if (error == ERROR_ALREADY_EXISTS || error == ERROR_ACCESS_DENIED) {
        spdlog::error("[SysMonitorAgent] another SysMonitorAgent is already running on this PC — exiting (only one Agent per PC)");
    } else {
        spdlog::error("[SysMonitorAgent] could not check for another running Agent (CreateMutex error {}) — exiting", error);
    }
    return false;
}

// 전송 결과로 계속할지 정한다. Disconnected는 GrpcClient가 스스로 백오프 재연결하고 그동안 틱을 로컬 버퍼에 모으므로
// 계속한다. 인증 거부·프로토콜 불일치 등은 재시도해도 소용없어 종료한다 (fail-closed).
// default를 두지 않아, enum 값이 추가되면 여기도 함께 검토하게 한다.
// 구체적인 원인(gRPC 상태 코드/메시지)은 GrpcClient가 이미 로그로 남긴다.
bool shouldContinue(ClientResult result, const char* stage) {
    switch (result) {
    case ClientResult::Ok:
        return true;
    case ClientResult::Disconnected:
        spdlog::warn("[SysMonitorAgent] {}: server not reachable — collecting into the local buffer and retrying in the background", stage);
        return true;
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

// 실제 수집기(sys / proc 전체 / target)의 스냅샷을 1초마다 GrpcClient에 넘긴다. 수집 순서·주기는 원본 SysMonitor의
// 메인 루프와 같다. 전송·재연결·갭 전송은 GrpcClient의 스레드가 하고, 끊긴 동안의 틱은 로컬 버퍼(GapBuffer)에 쌓인다.
// 로컬 버퍼는 이 스레드에서만 다룬다 — 송신 스레드가 요청한 버퍼 작업은 틱 사이 대기 시간에 runBufferTasks()로 실행한다.
int main() {
    // 소스는 UTF-8(/utf-8)로 컴파일되지만 Windows 콘솔 기본 코드페이지는 CP949라
    // 로그의 한글이 깨져 보인다. 콘솔 출력 코드페이지를 UTF-8로 맞춰 해결한다.
    SetConsoleOutputCP(CP_UTF8);

    // 버퍼를 열거나 서버에 연결하기 전에 막는다.
    if (!acquireSingleInstance()) {
        return 1;
    }

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

    // 끊긴 동안의 스냅샷을 보관한다. 설치 폴더 기준 상대 경로라 폴더째 복사되면 함께 따라간다 — 그래서 행마다 수집 장비를 기록하고
    // 출처는 서버가 판정한다.
    GapBuffer buffer("reports/buffer/gap_buffer.db", config->localBufferHours);

    // 인증·프로토콜 버전 오류는 수집기(ETW 세션 등)를 띄우기 전에 빨리 드러나도록 첫 연결 결과를 먼저 본다.
    // 서버에 닿지 않는 것(Disconnected)은 계속한다 — 수집을 시작하고 백그라운드에서 다시 연결한다.
    GrpcClient client(config->serverUrl, config->agentId, config->apiKey, instanceId);
    if (!shouldContinue(client.start(), "connect")) {
        return 1;
    }

    // ETW 세션은 ProcessCollector가 소유하고 TargetCollector가 공유한다 (프로세스별 네트워크 사용량 — 관리자 권한 필요,
    // 없으면 경고만 남고 네트워크 값이 0으로 나간다). SystemCollector 생성자는 PDH 기준점을 잡느라 1초 대기한다.
    SystemCollector sysCollector;
    ProcessCollector procCollector;
    TargetCollector targetCollector(procCollector.getEtwNet());

    // 프로세스 시작 이벤트는 ETW 세션이 열려야 온다 (관리자 권한 필요). 없어도 수집은 그대로 하고, 무엇이 달라지는지만 한 번 알린다.
    if (!procCollector.getEtwNet().processEventsEnabled()) {
        spdlog::warn("[SysMonitorAgent] process start events are unavailable (the Agent is not running as administrator, or the ETW session could not be opened). "
            "Collection continues from the per-second process list: a process started by a launcher that exits within a second can be missing from a target's children. "
            "Run the Agent as administrator to close that gap. (A parent PID reused within a second cannot be told apart either way)");
    }

    // 여기는 메인 루프 스레드이므로 registerTarget()을 직접 불러도 된다 (다른 스레드는 requestRegister() 경유).
    for (const auto& name : *targetNames) {
        targetCollector.registerTarget(name);
    }

    int tick = 0;
    bool processListWarned = false;   // 프로세스 목록 실패를 이미 알렸는가
    while (true) {
        const auto loopStart = std::chrono::steady_clock::now();
        // 이번 틱의 시각 — sys / proc / target 스냅샷이 모두 이 값을 싣는다. 수집기마다 따로 정하면 한 틱의 스냅샷이
        // 서로 다른 시각을 갖게 되어, 받는 쪽이 같은 틱끼리 묶거나 "어디까지 받았는가"를 시각 하나로 가를 수 없다.
        const auto tickTime = std::chrono::system_clock::now();

        // 다른 스레드가 큐에 넣은 타겟 등록/해제 요청을 이 스레드에서 반영한다 (Phase 7 역방향 명령이 쓸 경로)
        targetCollector.applyPending();

        // 1초 주기 수집
        sysCollector.collectMiddle();

        // 프로세스 목록은 틱당 1번 떠서 proc 목록과 타겟 수집이 함께 쓴다 (같은 시점의 목록, 스냅샷 1번).
        // 못 받은 틱은 빈 목록으로 취급하지 않는다: proc 목록은 보내지 않고, 타겟은 직전 상태를 유지한다.
        // 같은 실패가 매 틱 쌓이지 않게 실패가 시작될 때 1번만 알리고, 다시 받으면 그 사실도 1번 알린다.
        const std::optional<ProcessList> procs = takeProcessList();
        if (!procs && !processListWarned) {
            processListWarned = true;
            spdlog::warn("[SysMonitorAgent] process snapshot failed (error {}) — proc list is not sent and target start/exit detection is skipped until it succeeds again", GetLastError());
        }
        else if (procs && processListWarned) {
            processListWarned = false;
            spdlog::info("[SysMonitorAgent] process snapshot succeeds again");
        }
        procCollector.collectProc(procs);
        targetCollector.collect(procs, tickTime);
        if (tick % Config::SLOW_COLLECT_INTERVAL == 0) {
            sysCollector.collectSlow();   // 2초 주기 (디스크)
        }

        // 원본은 여기서 종료된 타겟의 마지막 세션 요약을 로컬 DuckDB(SessionReport)로 계산해 넣었다.
        // 로컬 버퍼는 전송 메시지를 그대로 보관할 뿐 지표를 조회할 수 없어 요약을 계산하지 못한다 — 종료된 타겟은 요약 없이
        // NEVER_SEEN으로 보고된다.
        targetCollector.clearPendingDeactivated();

        // 막히지 않는다 — 연결돼 있으면 송신 스레드가 보내고, 아니면 로컬 버퍼 작업으로 넘어간다.
        client.submit(sysCollector.makeSnapshot(tickTime), procCollector.makeSnapshot(tickTime), targetCollector.getSnapshot());
        if (std::optional<ClientResult> stopped = client.stopped()) {
            shouldContinue(*stopped, "server");   // 종료 사유를 남긴다
            return 1;
        }

        // 보관 시간(local_buffer_hours)이 지난 버퍼 행을 정리한다.
        if (tick % Config::BUFFER_EXPIRE_INTERVAL_TICKS == 0) {
            const size_t expired = buffer.dropExpired(std::chrono::duration_cast<std::chrono::microseconds>(tickTime.time_since_epoch()).count());
            if (expired > 0) {
                spdlog::warn("[SysMonitorAgent] dropped {} buffered snapshot(s) older than {}h", expired, config->localBufferHours);
            }
        }

        ++tick;

        // 수집·전송에 쓴 시간을 빼고 남은 시간만 기다려 1초 주기를 유지한다. 그 사이 타겟 등록/해제 요청이 들어오면
        // 즉시 깨어나 반영한다 (원본 SysMonitor와 같은 방식). 로컬 버퍼 작업은 짧은 간격으로 깨어나 처리한다 —
        // 갭 전송은 묶음마다 이 작업을 기다리므로, 틱 단위로만 처리하면 하루치 갭을 보내는 데 몇 시간이 걸린다.
        const auto deadline = loopStart + std::chrono::seconds(1);
        do {
            client.runBufferTasks(buffer);
            const auto slice = (std::min)(deadline, std::chrono::steady_clock::now() + Config::BUFFER_TASK_POLL);
            if (targetCollector.waitForPendingUntil(slice)) {
                targetCollector.applyPending();
            }
        } while (std::chrono::steady_clock::now() < deadline);
    }
}

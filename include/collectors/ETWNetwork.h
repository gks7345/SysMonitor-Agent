#pragma once
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#define NOMINMAX 
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>
#include <atomic>
#include <memory>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <climits>

#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "secur32.lib")

#pragma comment(lib, "iphlpapi.lib")

// -------------------------------------------------------
// TDH로 파싱한 필드 오프셋 캐시
// 이벤트 ID별로 한 번만 조회 후 재사용
// -------------------------------------------------------
struct NetEventLayout {
    ULONG pidOffset = ULONG_MAX;  // TDH로 찾은 PID 필드 오프셋
    ULONG bytesOffset = ULONG_MAX;  // bytes 필드 오프셋
    ULONG daddrOffset = ULONG_MAX;  // 목적지 IP 오프셋
    ULONG minLength = 0;            // UserData를 읽기 위한 최소 크기
    bool  valid = false;
};

// -------------------------------------------------------
// 누적 엔트리
// -------------------------------------------------------
struct NetAccumEntry {
    std::atomic<ULONGLONG> sentBytes{ 0 };
    std::atomic<ULONGLONG> recvBytes{ 0 };

    // TargetCollector 전용 독립 누적값
    std::atomic<ULONGLONG> targetSentBytes{ 0 };
    std::atomic<ULONGLONG> targetRecvBytes{ 0 };
};

struct NetMbps {
    double sentMbps = 0.0;
    double recvMbps = 0.0;
};

// -------------------------------------------------------
// 프로세스 시작/종료 이벤트 한 건 (Microsoft-Windows-Kernel-Process)
// 프로세스 목록은 1초에 한 번의 단면이라 그 사이에 생겼다 사라진 프로세스를 보지 못한다 — 이벤트는 그것까지 순서대로 알려 준다.
// -------------------------------------------------------
struct ProcessEvent {
    bool  isStart = false;  // false = 종료
    DWORD pid = 0;
    DWORD parentPid = 0;    // 시작 이벤트에만 있다 — 그 시점에 실제로 이 프로세스를 만든 부모
};

// 프로세스 이벤트의 필드 오프셋 (이벤트 ID·버전별로 한 번 조회)
struct ProcEventLayout {
    ULONG pidOffset = ULONG_MAX;
    ULONG parentOffset = ULONG_MAX;
    ULONG minLength = 0;
    bool  valid = false;
};

class ETWNetwork {
public:
    ETWNetwork();
    ~ETWNetwork();

    bool    start();
    void    stop();
    bool    isRunning() const { return running.load(); }
    NetMbps getAndReset(DWORD pid, double elapsedSec);
    NetMbps getAndResetForTarget(DWORD pid, double elapsedSec);

    // 죽은 프로세스 accumulator에서 제거
    void retainOnlyPids(const std::unordered_set<DWORD>& alivePids);

    // 프로세스 시작/종료 이벤트를 받고 있는가. 세션을 열지 못했으면(관리자 권한 없음 등) false —
    // 그때 호출자는 프로세스 목록만으로 동작한다.
    bool processEventsEnabled() const { return procEventsOn.load(); }
    // 지난 호출 이후 쌓인 이벤트를 발생 순서대로 꺼낸다 (꺼낸 것은 비워진다).
    std::vector<ProcessEvent> takeProcessEvents();

private:
    GUID KERNEL_NETWORK_GUID = {};
    GUID KERNEL_PROCESS_GUID = {};

    // Kernel-Process 공급자: 1 = ProcessStart, 2 = ProcessStop.
    // 키워드를 주지 않으면 스레드·이미지 로드 이벤트까지 켜져 양이 크게 늘어난다.
    static constexpr USHORT PROCESS_START_EVENT_ID = 1;
    static constexpr USHORT PROCESS_STOP_EVENT_ID = 2;
    static constexpr ULONGLONG KERNEL_PROCESS_KEYWORD_PROCESS = 0x10;
    // 아무도 꺼내 가지 않을 때 끝없이 쌓이지 않게 하는 상한 — 넘으면 버린다 (호출자는 프로세스 목록으로 계속 동작한다)
    static constexpr size_t MAX_PENDING_PROCESS_EVENTS = 65536;

    std::atomic<bool> procEventsOn{ false };
    std::mutex procEventMtx;
    std::vector<ProcessEvent> procEvents;
    std::unordered_map<ULONG, ProcEventLayout> procLayoutCache;     // (이벤트 ID << 8 | 버전) -> 오프셋, layoutMtx로 보호

    // 이벤트 Id
    // 10 = TcpIp Send,  11 = TcpIp Recv
    // 26 = UdpIp Send,  27 = UdpIp Recv
    static bool isSendEvent(USHORT id) {
        return id == 10 || id == 26;
    }
    static bool isRecvEvent(USHORT id) {
        return id == 11 || id == 27;
    }

    static constexpr char SESSION_NAME[] = "SysMonitor_Network";

    TRACEHANDLE       sessionHandle = INVALID_PROCESSTRACE_HANDLE;
    TRACEHANDLE       traceHandle = INVALID_PROCESSTRACE_HANDLE;
    std::vector<BYTE> sessionProps;

    std::thread       etwThread;
    std::atomic<bool> running{ false };

    std::mutex accumMtx;
    std::unordered_map<DWORD, std::shared_ptr<NetAccumEntry>> accumulator;

    // 루프백 주소 목록 (자동 감지)
    std::unordered_set<ULONG> loopbackAddrs;

    // TDH 이벤트 레이아웃 캐시 (이벤트 ID -> 오프셋)
    std::mutex layoutMtx;
    std::unordered_map<USHORT, NetEventLayout> layoutCache;

    bool startSession();
    void processLoop();

    // GUID 자동 조회
    static GUID findProviderGuid(const std::wstring& providerName);
    // 루프백 주소 자동 수집
    static std::unordered_set<ULONG> getLoopbackAddresses();

    //TDH 파싱
    NetEventLayout buildLayout(PEVENT_RECORD pEvent);
    const NetEventLayout* getOrBuildLayout(PEVENT_RECORD pEvent);

    // 프로세스 이벤트: 필드 이름(ProcessID, ParentProcessID)으로 오프셋을 찾는다 — 이벤트 버전에 따라 사이에 필드가 더 있다
    static ProcEventLayout buildProcLayout(PEVENT_RECORD pEvent);
    const ProcEventLayout* getOrBuildProcLayout(PEVENT_RECORD pEvent);
    void onProcessEvent(PEVENT_RECORD pEvent);

    static VOID WINAPI onEvent(PEVENT_RECORD pEvent);
    std::shared_ptr<NetAccumEntry> getOrCreateEntry(DWORD pid);

    static ETWNetwork* instance;
};

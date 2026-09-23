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

private:
    GUID KERNEL_NETWORK_GUID = {};

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

    static VOID WINAPI onEvent(PEVENT_RECORD pEvent);
    std::shared_ptr<NetAccumEntry> getOrCreateEntry(DWORD pid);

    static ETWNetwork* instance;
};

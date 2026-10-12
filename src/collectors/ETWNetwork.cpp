#include "collectors/ETWNetwork.h"
#include "util/StrUtil.h"
#include <spdlog/spdlog.h>

ETWNetwork* ETWNetwork::instance = nullptr;
constexpr char ETWNetwork::SESSION_NAME[];

ETWNetwork::ETWNetwork() { instance = this; }
ETWNetwork::~ETWNetwork() {
    stop();
    instance = nullptr;
}

// -------------------------------------------------------
// GUID 자동 조회 — TdhEnumerateProviders
// -------------------------------------------------------
GUID ETWNetwork::findProviderGuid(const std::wstring& providerName) {
    ULONG bufSize = 0;
    TdhEnumerateProviders(nullptr, &bufSize);

    if (bufSize == 0) return GUID{};

    std::vector<BYTE> buf(bufSize);
    auto* list = reinterpret_cast<PROVIDER_ENUMERATION_INFO*>(buf.data());

    if (TdhEnumerateProviders(list, &bufSize) != ERROR_SUCCESS)
        return GUID{};

    for (ULONG i = 0; i < list->NumberOfProviders; ++i) {
        auto& entry = list->TraceProviderInfoArray[i];
        auto* name = reinterpret_cast<const wchar_t*>(
            buf.data() + entry.ProviderNameOffset);

        if (providerName == name) {
            spdlog::info("ETWNetwork: Provider '{}' GUID Search Success",
                StrUtil::wideToUtf8(providerName));
            return entry.ProviderGuid;
        }
    }
    return GUID{};
}

// -------------------------------------------------------
// 루프백 주소 자동 수집 — GetAdaptersAddresses
// -------------------------------------------------------
std::unordered_set<ULONG> ETWNetwork::getLoopbackAddresses() {
    std::unordered_set<ULONG> result;

    // 항상 127.0.0.1 포함
    result.insert(htonl(INADDR_LOOPBACK));

    ULONG bufSize = 0;
    GetAdaptersAddresses(AF_INET,
        GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
        nullptr, nullptr, &bufSize);
    if (bufSize == 0) return result;

    std::vector<BYTE> buf(bufSize);
    auto* addrs = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data());

    if (GetAdaptersAddresses(AF_INET,
        GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
        nullptr, addrs, &bufSize) != ERROR_SUCCESS)
        return result;

    for (auto* a = addrs; a; a = a->Next) {
        // 루프백 어댑터만
        if (a->IfType != IF_TYPE_SOFTWARE_LOOPBACK) continue;

        for (auto* ua = a->FirstUnicastAddress; ua; ua = ua->Next) {
            auto* sa = reinterpret_cast<sockaddr_in*>(ua->Address.lpSockaddr);
            if (sa->sin_family == AF_INET) {
                result.insert(sa->sin_addr.s_addr);
                char ipStr[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &sa->sin_addr, ipStr, sizeof(ipStr));
                spdlog::info("ETWNetwork: Loop Back Address Detect {}", ipStr);
            }
        }
    }
    return result;
}

// -------------------------------------------------------
// TDH - 이벤트 레이아웃 파싱 (이벤트 ID당 최초 1회)
// -------------------------------------------------------
NetEventLayout ETWNetwork::buildLayout(PEVENT_RECORD pEvent) {
    NetEventLayout layout;

    // 1단계 - 필요한 버퍼 크기 조회
    ULONG bufSize = 0;
    ULONG status = TdhGetEventInformation(pEvent, 0, nullptr, nullptr, &bufSize);
    if (status != ERROR_INSUFFICIENT_BUFFER || bufSize == 0) return layout;

    // 2단계 - 실제 스키마 조회
    std::vector<BYTE> buf(bufSize);
    auto* pInfo = reinterpret_cast<TRACE_EVENT_INFO*>(buf.data());

    status = TdhGetEventInformation(pEvent, 0, nullptr, pInfo, &bufSize);
    if (status != ERROR_SUCCESS) return layout;

    // 3단계 - 필드 이름으로 오프셋 계산
    ULONG offset = 0;
    for (ULONG i = 0; i < pInfo->TopLevelPropertyCount; ++i) {
        auto& prop = pInfo->EventPropertyInfoArray[i];
        // 필드 이름 (wchar_t*)
        const wchar_t* fieldName = reinterpret_cast<const wchar_t*>(buf.data() + prop.NameOffset);
        // 필드 크기 (byte)
        ULONG fieldSize = prop.length;

        // 찾는 필드: PID, size(bytes), daddr(목적지 IP)
        if (wcscmp(fieldName, L"PID") == 0)
        {
            layout.pidOffset = offset;
            layout.minLength = (std::max)(layout.minLength, offset + fieldSize);
        }
        else if (wcscmp(fieldName, L"size") == 0)
        {
            layout.bytesOffset = offset;
            layout.minLength = (std::max)(layout.minLength, offset + fieldSize);
        }
        else if (wcscmp(fieldName, L"daddr") == 0)
        {
            layout.daddrOffset = offset;
            layout.minLength = (std::max)(layout.minLength, offset + fieldSize);
        }

        // 매칭 여부와 무관하게 항상 오프셋 전진 (필드 순서상 이전 필드들의 크기를 누적해야 함)
        offset += fieldSize;
    }

    // PID와 bytes 오프셋이 유효해야 사용 가능
    layout.valid = (layout.pidOffset != ULONG_MAX && layout.bytesOffset != ULONG_MAX);

    if (!layout.valid) {
        spdlog::warn("ETWNetwork: TDH layout parsing error id={}", pEvent->EventHeader.EventDescriptor.Id);
    }

    spdlog::info("TDH layout id={} valid={} pid@{} bytes@{} daddr@{}",
        pEvent->EventHeader.EventDescriptor.Id,
        layout.valid,
        layout.pidOffset == ULONG_MAX ? -1 : (int)layout.pidOffset,
        layout.bytesOffset == ULONG_MAX ? -1 : (int)layout.bytesOffset,
        layout.daddrOffset == ULONG_MAX ? -1 : (int)layout.daddrOffset);

    return layout;
}

// -------------------------------------------------------
// TDH 레이아웃 캐시 조회 (없으면 buildLayout 호출)
// -------------------------------------------------------
const NetEventLayout* ETWNetwork::getOrBuildLayout(PEVENT_RECORD pEvent) {
    USHORT id = pEvent->EventHeader.EventDescriptor.Id;

    {
        std::lock_guard<std::mutex> lock(layoutMtx);
        auto it = layoutCache.find(id);
        if (it != layoutCache.end()) return &it->second;
    }

    // 캐시 미스 - 스키마 파싱 (최초 1회)
    NetEventLayout layout = buildLayout(pEvent);

    std::lock_guard<std::mutex> lock(layoutMtx);
    layoutCache[id] = layout;
    return &layoutCache[id];
}

bool ETWNetwork::start() {
    if (running.load())  return true;

    // GUID 자동 조회
    KERNEL_NETWORK_GUID = findProviderGuid(L"Microsoft-Windows-Kernel-Network");
    if (KERNEL_NETWORK_GUID == GUID{}) {
        spdlog::error("ETWNetwork: Kernel-Network Provider Not Found");
        return false;
    }

    // 프로세스 시작/종료 이벤트의 공급자 — 못 찾아도 네트워크 수집은 한다 (startSession이 건너뛴다)
    KERNEL_PROCESS_GUID = findProviderGuid(L"Microsoft-Windows-Kernel-Process");
    if (KERNEL_PROCESS_GUID == GUID{}) {
        spdlog::warn("ETWNetwork: Kernel-Process Provider Not Found — process start/stop events are unavailable");
    }

    // 루프백 주소 자동 수집
    loopbackAddrs = getLoopbackAddresses();
    spdlog::info("ETWNetwork: {} loopbackAddrs Detect", loopbackAddrs.size());


    if (!startSession()) return false;
    running.store(true);
    etwThread = std::thread(&ETWNetwork::processLoop, this);
    spdlog::info("ETWNetwork: START");
    return true;
}

void ETWNetwork::stop() {
    if (!running.load()) return;
    running.store(false);
    procEventsOn.store(false);

    if (traceHandle != INVALID_PROCESSTRACE_HANDLE) {
        CloseTrace(traceHandle);
        traceHandle = INVALID_PROCESSTRACE_HANDLE;
    }
    if (sessionHandle != INVALID_PROCESSTRACE_HANDLE) {
        auto* props = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(sessionProps.data());
        ControlTraceA(sessionHandle, SESSION_NAME, props, EVENT_TRACE_CONTROL_STOP);
        sessionHandle = INVALID_PROCESSTRACE_HANDLE;
    }
    if (etwThread.joinable()) etwThread.join();
    spdlog::info("ETWNetwork: STOP");
}

bool ETWNetwork::startSession() {
    // 기존 세션 정리
    {
        size_t sz = sizeof(EVENT_TRACE_PROPERTIES) + (strlen(SESSION_NAME) + 1);
        std::vector<BYTE> tmp(sz, 0);
        auto* p = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(tmp.data());
        p->Wnode.BufferSize = static_cast<ULONG>(sz);
        ControlTraceA(0, SESSION_NAME, p, EVENT_TRACE_CONTROL_STOP);
    }

    size_t sz = sizeof(EVENT_TRACE_PROPERTIES) + (strlen(SESSION_NAME) + 1);
    sessionProps.assign(sz, 0);
    auto* props = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(sessionProps.data());

    props->Wnode.BufferSize = static_cast<ULONG>(sz);
    props->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    props->Wnode.ClientContext = 1;
    props->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

    ULONG status = StartTraceA(&sessionHandle, SESSION_NAME, props);
    if (status != ERROR_SUCCESS && status != ERROR_ALREADY_EXISTS) {
        spdlog::error("ETWNetwork: StartTraceA Error 0x{:X}", status);
        return false;
    }

    ENABLE_TRACE_PARAMETERS params = {};
    params.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;

    status = EnableTraceEx2(
        sessionHandle, &KERNEL_NETWORK_GUID,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        TRACE_LEVEL_INFORMATION,
        0, 0, 0, &params);

    if (status != ERROR_SUCCESS) {
        spdlog::error("ETWNetwork: EnableTraceEx2 Error 0x{:X}", status);
        return false;
    }

    // 프로세스 시작/종료 이벤트 — 같은 세션에 공급자를 하나 더 켠다. 실패해도 네트워크 수집은 계속한다.
    if (!(KERNEL_PROCESS_GUID == GUID{})) {
        status = EnableTraceEx2(
            sessionHandle, &KERNEL_PROCESS_GUID,
            EVENT_CONTROL_CODE_ENABLE_PROVIDER,
            TRACE_LEVEL_INFORMATION,
            KERNEL_PROCESS_KEYWORD_PROCESS, 0, 0, &params);

        if (status == ERROR_SUCCESS) {
            // 세션을 성공적으로 열었다 - true
            procEventsOn.store(true);
        }
        else {
            spdlog::warn("ETWNetwork: EnableTraceEx2 (Kernel-Process) Error 0x{:X} — process start/stop events are unavailable", status);
        }
    }
    return true;
}

void ETWNetwork::processLoop() {
    EVENT_TRACE_LOGFILEA logFile = {};
    logFile.LoggerName = const_cast<LPSTR>(SESSION_NAME);
    logFile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    logFile.EventRecordCallback = onEvent;

    traceHandle = OpenTraceA(&logFile);
    if (traceHandle == INVALID_PROCESSTRACE_HANDLE) {
        spdlog::error("ETWNetwork: OpenTrace Error 0x{:X}", GetLastError());
        running.store(false);
        procEventsOn.store(false);
        return;
    }

    spdlog::info("ETWNetwork: ProcessTrace Start");
    ULONG status = ProcessTrace(&traceHandle, 1, nullptr, nullptr);
    if (status != ERROR_SUCCESS && status != ERROR_CANCELLED)
        spdlog::warn("ETWNetwork: ProcessTrace Close 0x{:X}", status);
}

// -------------------------------------------------------
// onEvent — TDH 캐시 기반 파싱
// -------------------------------------------------------
VOID WINAPI ETWNetwork::onEvent(PEVENT_RECORD pEvent) {
    if (!instance || !instance->running.load()) return;
    if (!pEvent) return;

    if (instance->procEventsOn.load() && IsEqualGUID(pEvent->EventHeader.ProviderId, instance->KERNEL_PROCESS_GUID)) {
        instance->onProcessEvent(pEvent);
        return;
    }

    if (!IsEqualGUID(pEvent->EventHeader.ProviderId, instance->KERNEL_NETWORK_GUID)) return;

    USHORT id = pEvent->EventHeader.EventDescriptor.Id;
    bool isSend;
    if (isSendEvent(id)) isSend = true;
    else if (isRecvEvent(id)) isSend = false;
    else return;

    if (!pEvent->UserData) return;

    // TDH 레이아웃 캐시 조회 (최초 호출 시 TDH 파싱)
    const NetEventLayout* layout = instance->getOrBuildLayout(pEvent);
    if (!layout || !layout->valid) return;
    // UserData 길이 검증
    if (pEvent->UserDataLength < layout->minLength) return;

    const BYTE* data = reinterpret_cast<const BYTE*>(pEvent->UserData);

    // 캐시된 오프셋으로 필드 추출
    DWORD pid = *reinterpret_cast<const ULONG*>(data + layout->pidOffset);
    ULONG bytes = *reinterpret_cast<const ULONG*>(data + layout->bytesOffset);

    if (pid == 0 || pid == 4 || pid == 0xFFFFFFFF) return;
    if (bytes == 0) return;

    // 로컬호스트 트래픽 제외 (daddr 필드가 있을때만)
    // daddr가 존재하면(daddrOffset != ULONG_MAX) buildLayout()이 minLength를 계산할 때 daddrOffset + sizeof(ULONG)까지
    // 반영하므로, 위의 UserDataLength < layout->minLength 검사만으로
    // 경계가 이미 보장된다 — 여기서 길이를 다시 재는 것은 중복이라 존재 여부만 확인한다.
    if (layout->daddrOffset != ULONG_MAX) {
        ULONG daddr = *reinterpret_cast<const ULONG*>(data + layout->daddrOffset);
        if (instance->loopbackAddrs.count(daddr)) return;
    }

    auto entry = instance->getOrCreateEntry(pid);
    if (isSend)
    {
        entry->sentBytes.fetch_add(bytes, std::memory_order_relaxed);
        entry->targetSentBytes.fetch_add(bytes, std::memory_order_relaxed);
    }
    else
    {
        entry->recvBytes.fetch_add(bytes, std::memory_order_relaxed);
        entry->targetRecvBytes.fetch_add(bytes, std::memory_order_relaxed);
    }

}

// -------------------------------------------------------
// 프로세스 시작/종료 이벤트
// -------------------------------------------------------
ProcEventLayout ETWNetwork::buildProcLayout(PEVENT_RECORD pEvent) {
    ProcEventLayout layout;
    const USHORT id = pEvent->EventHeader.EventDescriptor.Id;

    ULONG bufSize = 0;
    ULONG status = TdhGetEventInformation(pEvent, 0, nullptr, nullptr, &bufSize);
    if (status != ERROR_INSUFFICIENT_BUFFER || bufSize == 0) return layout;

    std::vector<BYTE> buf(bufSize);
    auto* pInfo = reinterpret_cast<TRACE_EVENT_INFO*>(buf.data());
    status = TdhGetEventInformation(pEvent, 0, nullptr, pInfo, &bufSize);
    if (status != ERROR_SUCCESS) return layout;

    // 앞에서부터 필드 크기를 더해 오프셋을 구한다. 크기가 고정되지 않은 필드(문자열, SID 등)를 만나면
    // 그 뒤의 오프셋은 이 방법으로 알 수 없으므로 멈춘다 — 찾는 두 필드는 그 앞에 있다.
    ULONG offset = 0;
    for (ULONG i = 0; i < pInfo->TopLevelPropertyCount; ++i) {
        const auto& prop = pInfo->EventPropertyInfoArray[i];
        // 크기를 미리 알 수 없는 필드를 만나면 멈춘다.
        if ((prop.Flags & (PropertyStruct | PropertyParamLength | PropertyParamCount)) || prop.length == 0) break;

        // 필드 이름은 prop에 들어있지 않는다 — NameOffset은 버퍼 시작에서 그 문자열까지의 거리
        const wchar_t* fieldName = reinterpret_cast<const wchar_t*>(buf.data() + prop.NameOffset);
        const ULONG fieldSize = prop.length;

        if (_wcsicmp(fieldName, L"ProcessID") == 0 && fieldSize == sizeof(ULONG)) {
            layout.pidOffset = offset;
            layout.minLength = (std::max)(layout.minLength, offset + fieldSize);
        }
        else if (_wcsicmp(fieldName, L"ParentProcessID") == 0 && fieldSize == sizeof(ULONG)) {
            layout.parentOffset = offset;
            layout.minLength = (std::max)(layout.minLength, offset + fieldSize);
        }
        offset += fieldSize;
    }

    // 시작 이벤트는 부모 PID까지 있어야 쓸 수 있다
    layout.valid = layout.pidOffset != ULONG_MAX && (id != PROCESS_START_EVENT_ID || layout.parentOffset != ULONG_MAX);

    spdlog::info("ETWNetwork: process event layout id={} version={} valid={} pid@{} parent@{}",
        id, pEvent->EventHeader.EventDescriptor.Version, layout.valid,
        layout.pidOffset == ULONG_MAX ? -1 : (int)layout.pidOffset,
        layout.parentOffset == ULONG_MAX ? -1 : (int)layout.parentOffset);
    return layout;
}

const ProcEventLayout* ETWNetwork::getOrBuildProcLayout(PEVENT_RECORD pEvent) {
    // Id는 16비트(USHORT), Version은 8비트(UCHAR)
    // ID를 왼쪽으로 8비트 밀어 아래 8비트를 비우고, 그 자리에 버전을 OR로 채운다.
    // 버전을 키에 넣는 이유: 같은 ID라도 버전이 다르면 필드 구성이 달라 오프셋이 다르다.
    const ULONG key = (static_cast<ULONG>(pEvent->EventHeader.EventDescriptor.Id) << 8) | pEvent->EventHeader.EventDescriptor.Version;

    {
        std::lock_guard<std::mutex> lock(layoutMtx);
        auto it = procLayoutCache.find(key);
        if (it != procLayoutCache.end()) return &it->second;
    }

    ProcEventLayout layout = buildProcLayout(pEvent);

    std::lock_guard<std::mutex> lock(layoutMtx);
    procLayoutCache[key] = layout;
    return &procLayoutCache[key];
}

void ETWNetwork::onProcessEvent(PEVENT_RECORD pEvent) {
    const USHORT id = pEvent->EventHeader.EventDescriptor.Id;
    if (id != PROCESS_START_EVENT_ID && id != PROCESS_STOP_EVENT_ID) return;
    if (!pEvent->UserData) return;

    const ProcEventLayout* layout = getOrBuildProcLayout(pEvent);
    if (!layout) return;
    if (!layout->valid) {
        // 필드를 찾지 못했다 — 시작 이벤트를 읽지 못하면 누가 만든 프로세스인지 알 수 없고, 종료 이벤트를 읽지 못하면
        // 끝난 PID를 제때 지울 수 없다. 어느 쪽이든 이벤트를 순서대로 따라갈 수 없으므로 통째로 끈다.
        // 호출자는 프로세스 목록만으로 계속 동작한다.
        if (procEventsOn.exchange(false)) {
            spdlog::warn("ETWNetwork: process event id={} version={} has no usable ProcessID/ParentProcessID field — process start/stop events are turned off", id, pEvent->EventHeader.EventDescriptor.Version);
        }
        return;
    }
    if (pEvent->UserDataLength < layout->minLength) return;

    const BYTE* data = reinterpret_cast<const BYTE*>(pEvent->UserData);

    ProcessEvent ev;
    ev.isStart = (id == PROCESS_START_EVENT_ID);
    ev.pid = *reinterpret_cast<const ULONG*>(data + layout->pidOffset);
    if (ev.isStart) ev.parentPid = *reinterpret_cast<const ULONG*>(data + layout->parentOffset);

    std::lock_guard<std::mutex> lock(procEventMtx);
    if (procEvents.size() >= MAX_PENDING_PROCESS_EVENTS) procEvents.clear();
    procEvents.push_back(ev);
}

std::vector<ProcessEvent> ETWNetwork::takeProcessEvents() {
    std::vector<ProcessEvent> out;
    std::lock_guard<std::mutex> lock(procEventMtx);
    out.swap(procEvents);
    return out;
}

std::shared_ptr<NetAccumEntry> ETWNetwork::getOrCreateEntry(DWORD pid) {
    std::lock_guard<std::mutex> lock(accumMtx);
    auto it = accumulator.find(pid);
    if (it != accumulator.end()) return it->second;
    auto [inserted, ok] = accumulator.emplace(pid, std::make_shared<NetAccumEntry>());
    return inserted->second;
}

NetMbps ETWNetwork::getAndReset(DWORD pid, double elapsedSec) {
    NetMbps result;
    if (elapsedSec <= 0.0) return result;

    std::lock_guard<std::mutex> lock(accumMtx);
    auto it = accumulator.find(pid);
    if (it == accumulator.end()) return result;

    ULONGLONG s = it->second->sentBytes.exchange(0, std::memory_order_relaxed);
    ULONGLONG r = it->second->recvBytes.exchange(0, std::memory_order_relaxed);

    // bytes → Mbps (1 Mbps = 125,000 bytes/sec)
    constexpr double BYTES_TO_MBPS = 8.0 / 1'000'000.0;
    result.sentMbps = static_cast<double>(s) / elapsedSec * BYTES_TO_MBPS;
    result.recvMbps = static_cast<double>(r) / elapsedSec * BYTES_TO_MBPS;
    return result;
}

NetMbps ETWNetwork::getAndResetForTarget(DWORD pid, double elapsedSec) {
    NetMbps result;
    if (elapsedSec <= 0.0) return result;

    std::lock_guard<std::mutex> lock(accumMtx);
    auto it = accumulator.find(pid);
    if (it == accumulator.end()) return {};

    // 별도 카운터에서 읽고 리셋
    ULONGLONG s = it->second->targetSentBytes.exchange(
        0, std::memory_order_relaxed);
    ULONGLONG r = it->second->targetRecvBytes.exchange(
        0, std::memory_order_relaxed);

    constexpr double BYTES_TO_MBPS = 8.0 / 1'000'000.0;
    result.sentMbps = static_cast<double>(s) / elapsedSec * BYTES_TO_MBPS;
    result.recvMbps = static_cast<double>(r) / elapsedSec * BYTES_TO_MBPS;
    return result;
}

// -------------------------------------------------------
// 죽은 프로세스 제거
// -------------------------------------------------------
void ETWNetwork::retainOnlyPids(const std::unordered_set<DWORD>& alivePids) {
    std::lock_guard<std::mutex> lock(accumMtx);
    for (auto it = accumulator.begin(); it != accumulator.end();) {
        if (!alivePids.count(it->first)) {
            it = accumulator.erase(it);
            continue;
        }
        ++it;
    }
}

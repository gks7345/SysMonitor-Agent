#pragma once

#include <windows.h>
#include <iostream>
#include <algorithm>
#include <pdh.h>
#include <pdhmsg.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <iphlpapi.h>
#include <string>
#include <vector>
#include <unordered_set>
#include <memory>
#include <unordered_map>
#include <chrono>
#include <optional>
#include <spdlog/spdlog.h>

#include "collectors/ETWNetwork.h"
#include "models/SnapshotData.h"
#include "util/ProcessList.h"

#pragma comment(lib, "pdh.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "iphlpapi.lib")

// -------------------------------------------------------
// 정렬 기준
// -------------------------------------------------------
enum class SortCriterion {
    CPU,
    MEMORY,
    DISK,
    NET
};

struct ProcEntry {
    DWORD       pid;
    DWORD       ppid;
    std::string name;
};

// -------------------------------------------------------
// ProcList — 프로세스 단위 데이터 클래스
// -------------------------------------------------------
class ProcList {
public:
    void setProcID(DWORD v) { pid = v; }
    void setProcName(std::string v) { name = v; }
    void setProcCpuUsage(std::optional<double> v) { cpu = v; }
    void setProcMemoryMB(std::optional<double> v) { memMB = v; }
    void setProcPrivateMemoryMB(std::optional<double> v) { privateMemMB = v; }
    void setDiskReadMBs(std::optional<double> v) { diskReadMBs = v; }
    void setDiskWriteMBs(std::optional<double> v) { diskWriteMBs = v; }
    void setNetSentMbps(double v) { netSentMbps = v; }
    void setNetRecvMbps(double v) { netRecvMbps = v; }

    DWORD    getProcID() const { return pid; }
    std::string getProcName() const { return name; }
    std::optional<double> getProcCpuUsage() const { return cpu; }
    std::optional<double> getProcMemoryMB() const { return memMB; }
    std::optional<double> getProcPrivateMemMB() const { return privateMemMB; }
    std::optional<double> getDiskReadMBs() const { return diskReadMBs; }
    std::optional<double> getDiskWriteMBs() const { return diskWriteMBs; }
    double      getNetSentMbps() const { return netSentMbps; }
    double      getNetRecvMbps() const { return netRecvMbps; }

private:
    DWORD    pid = 0;
    std::string name;
    // PDH에서 오는 값 — 비어 있으면 "읽지 못함"이다 (그 카운터의 배열을 읽지 못한 틱, 처음 보인 틱의 비율 값).
    // 0은 실제로 0일 때만 넣는다.
    std::optional<double> cpu;           // %
    std::optional<double> memMB;         // Working Set - Private (MB)
    std::optional<double> privateMemMB;  // Private Bytes (MB, 누수 감지용)
    std::optional<double> diskReadMBs;   // MB/s
    std::optional<double> diskWriteMBs;  // MB/s
    double      netSentMbps = 0.0;  // Mbps (ETW, Phase 5)
    double      netRecvMbps = 0.0;  // Mbps (ETW, Phase 5)
};

// -------------------------------------------------------
// ProcessCollector
//
// PDH 와일드카드(*) 기반으로 전체 프로세스 수집 — 이름으로 걸러 내지 않는다 (PID 0의 의사 항목만 제외).
// 이름은 ".exe"를 뗀 실행 파일 이름 (StrUtil::exeBaseName, 타겟과 같은 표기)
// 같은 이름 프로세스(#N)는 메인에 합산
//
// 수집 항목
//   CPU      : \Process(*)\% Processor Time       (1초)
//   MEM      : \Process(*)\Working Set - Private   (1초)
//   PrivMEM  : \Process(*)\Private Bytes           (1초, 누수용)
//   Disk     : \Process(*)\IO Read Bytes/sec       (2초)
//              \Process(*)\IO Write Bytes/sec
//   Network  : ETW Kernel-Network (Phase 5, 현재 0)
// -------------------------------------------------------

class ProcessCollector {
private:
    std::vector<std::unique_ptr<ProcList>> procList;
    std::vector<std::unique_ptr<ProcList>> aggregatedProcList;
    int topN;

    // 1초 간격
    PDH_HQUERY queryMiddle = nullptr;
    //2초 간격
    PDH_HQUERY querySlow = nullptr;

    // --- PDH COUNTER ---
    PDH_HCOUNTER procIDMiddle = nullptr;
    PDH_HCOUNTER procName = nullptr;
    PDH_HCOUNTER procCpuUsage = nullptr;
    PDH_HCOUNTER procPrivateMem = nullptr;
    PDH_HCOUNTER procMem = nullptr;
    PDH_HCOUNTER procNet = nullptr;
    PDH_HCOUNTER procDiskR = nullptr;
    PDH_HCOUNTER procDiskW = nullptr;

    // 읽기 실패를 이미 알렸는가 (PdhUtil::reportReadState) — 쿼리 수집에 하나, 배열마다 하나
    // (배열 순서: PID, CPU, Working Set - Private, Private Bytes, IO Read, IO Write)
    static constexpr size_t ARRAY_COUNT = 6;
    bool collectWarned = false;
    bool arrayWarned[ARRAY_COUNT] = {};

    ETWNetwork etwNet;

    // ----- 수집 시각 -----
    std::chrono::steady_clock::time_point lastTime;  // ETW NET용

    unsigned int cores = 1;

    // --- 헬퍼 ---
    // Counter 초기화
    void initInfo(PDH_HQUERY& query);

    // 카운터 하나의 배열을 buffer에 읽고 항목 수를 count에 넣는다. 반환: PDH 상태 (ERROR_SUCCESS가 아니면 읽지 못한 것 — count는 0)
    // 매 틱 불리므로 여기서 로그를 찍지 않는다 (알릴지는 호출부가 정한다).
    PDH_STATUS getCountArray(PDH_HCOUNTER hCounter, std::vector<char>& buffer, DWORD& count);

    // 프로세스 목록을 PID -> {부모 PID, 이름(UTF-8)} 표로 바꾼다 (스냅샷을 따로 뜨지 않는다)
    static std::unordered_map<DWORD, ProcEntry> buildProcTree(const ProcessList& procs);

    // 이번 틱의 proc 목록을 만들었는가 — 프로세스 목록을 못 받은 틱은 false (makeSnapshot이 nullopt)
    bool snapshotAvailable = false;

    void aggregateToParents(std::unordered_map<DWORD, ProcEntry>& tree);

public:
    ProcessCollector(int topN = 10);
    ~ProcessCollector();

    // procs: 메인 루프가 이번 틱에 뜬 프로세스 목록 (takeProcessList). PID에 이름과 부모를 붙이는 데 쓴다.
    // nullopt(목록을 못 받음)이면 이번 틱의 proc 목록을 만들지 않는다 — 빈 목록("프로세스 없음")으로 내보내지 않는다.
    // PDH 값을 읽지 못한 틱에도 목록은 만든다: 읽지 못한 지표만 비워 두고(0으로 채우지 않는다), 무엇을 못 읽었는지 한 번 알린다.
    void collectProc(const std::optional<ProcessList>& procs);


    void setTopN(int n);

    ETWNetwork& getEtwNet() { return etwNet; }

    // nullopt = 이번 틱은 proc 목록을 만들지 못함 (보내지 않는다)
    // tickTime: 메인 루프가 정한 이번 틱의 시각 — 스냅샷의 timestamp가 된다
    std::optional<SnapshotProcData> makeSnapshot(std::chrono::system_clock::time_point tickTime);

    // ETWNetwork 프로세스 정리 주기용
    int cleanupTick = 0;
};

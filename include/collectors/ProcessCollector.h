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
#include <spdlog/spdlog.h>

#include "collectors/ETWNetwork.h"
#include "models/SnapshotData.h"

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
    void setProcCpuUsage(double v) { cpu = v; }
    void setProcMemoryMB(double v) { memMB = v; }
    void setProcPrivateMemoryMB(double v) { privateMemMB = v; }
    void setDiskReadMBs(double v) { diskReadMBs = v; }
    void setDiskWriteMBs(double v) { diskWriteMBs = v; }
    void setNetSentMbps(double v) { netSentMbps = v; }
    void setNetRecvMbps(double v) { netRecvMbps = v; }

    DWORD    getProcID() const { return pid; }
    std::string getProcName() const { return name; }
    double      getProcCpuUsage() const { return cpu; }
    double      getProcMemoryMB() const { return memMB; }
    double      getProcPrivateMemMB() const { return privateMemMB; }
    double      getDiskReadMBs() const { return diskReadMBs; }
    double      getDiskWriteMBs() const { return diskWriteMBs; }
    double      getNetSentMbps() const { return netSentMbps; }
    double      getNetRecvMbps() const { return netRecvMbps; }

private:
    DWORD    pid = 0;
    std::string name;
    double      cpu = 0.0;  // %
    double      memMB = 0.0;  // Working Set - Private (MB)
    double      privateMemMB = 0.0;  // Private Bytes (MB, 누수 감지용)
    double      diskReadMBs = 0.0;  // MB/s
    double      diskWriteMBs = 0.0;  // MB/s
    double      netSentMbps = 0.0;  // Mbps (ETW, Phase 5)
    double      netRecvMbps = 0.0;  // Mbps (ETW, Phase 5)
};

// -------------------------------------------------------
// ProcessCollector
//
// PDH 와일드카드(*) 기반으로 전체 프로세스 수집
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
    PDH_HQUERY queryMiddle;
    //2초 간격
    PDH_HQUERY querySlow;

    // --- PDH COUNTER ---
    PDH_HCOUNTER procIDMiddle;
    PDH_HCOUNTER procName;
    PDH_HCOUNTER procCpuUsage;
    PDH_HCOUNTER procPrivateMem;
    PDH_HCOUNTER procMem;
    PDH_HCOUNTER procNet;
    PDH_HCOUNTER procDiskR;
    PDH_HCOUNTER procDiskW;

    ETWNetwork etwNet;

    // ----- 수집 시각 -----
    std::chrono::steady_clock::time_point lastTime;  // ETW NET용

    unsigned int cores = 1;

    // --- 헬퍼 ---
    // Counter 초기화
    void initInfo(PDH_HQUERY& query);

    // 시스템 프로세스 필터
    bool isSystemProcess(const std::string& name) const;

    // 카운터 포맷
    std::vector<char> getCountArray(PDH_HCOUNTER hCounter, DWORD& count);

    std::unordered_map<DWORD, ProcEntry> buildProcTree();

    void aggregateToParents(std::unordered_map<DWORD, ProcEntry>& tree);

public:
    ProcessCollector(int topN = 10);
    ~ProcessCollector();

    void collectProc();


    void setTopN(int n);

    ETWNetwork& getEtwNet() { return etwNet; }

    SnapshotProcData makeSnapshot();

    // ETWNetwork 프로세스 정리 주기용
    int cleanupTick = 0;
};

#pragma once
#include <string>
#include <vector>
#include <chrono>
#include <cstdint> 

// ---------------------------------------------------------------------------
// 시스템
// ---------------------------------------------------------------------------
struct SnapshotSysCpu {
	double cpuTotal = 0.0;
	double cpuFreqGHz = 0.0;

	double cpuUser = 0.0;
	double cpuKernel = 0.0;
	double cpuQueueLength = 0.0;
};

struct SnapshotSysMem {
	double memTotalMB = 0.0;
	double memUsagePercent = 0.0;
	double memUsedMB = 0.0;
	double memAvailMB = 0.0;

	double commitMemPercent = 0.0;
	double committedMemGB = 0.0;
	double commitLimitGB = 0.0;
};

struct SnapshotSysDisk {
	std::chrono::system_clock::time_point lastTime = std::chrono::system_clock::now();
	double diskReadKBs = 0.0;
	double diskWriteKBs = 0.0;
};

struct SnapshotSysNet {
	double netSentKbps = 0.0;
	double netRecvKbps = 0.0;
};

struct SnapshotSysData {
	std::chrono::system_clock::time_point	timestamp;

	SnapshotSysCpu cpu;
	SnapshotSysMem mem;
	SnapshotSysDisk disk;
	SnapshotSysNet net;
};

// ---------------------------------------------------------------------------
// 프로세스
// ---------------------------------------------------------------------------
struct SnapshotProc {
	uint32_t	procID = 0;
	std::string procName;

	double		procCpuUsage = 0.0;

	double		procMemoryMB = 0.0;
	double		procPrivateMemoryMB = 0.0;

	double		procDiskReadMBs = 0.0;
	double		procDiskWriteMBs = 0.0;

	double		procNetSentMbps = 0.0;
	double		procNetRecvMbps = 0.0;
};

struct SnapshotProcData {
	std::chrono::system_clock::time_point	timestamp;
	int										topN = 0;
	std::vector<SnapshotProc>				procs;
};

// ---------------------------------------------------------------------------
// 타겟 프로세스
// ---------------------------------------------------------------------------
struct TargetNetConnection {
	std::string protocol;	 // TCP / UDP
	std::string localAddr;   // 로컬 IP:Port
	std::string remoteAddr;  // 원격 IP:Port
	std::string state;		 // ESTABLISHED, LISTEN 등
};

struct SnapshotChildProcess {
	uint32_t pid = 0;
	std::string processName;

	// 기본 지표
	double cpuUsage = 0.0;
	double memoryMB = 0.0;
	double privateMemoryMB = 0.0;
	double virtualMemoryMB = 0.0;
	double diskReadMBs = 0.0;
	double diskWriteMBs = 0.0;
	double netSentMbps = 0.0;
	double netRecvMbps = 0.0;

	// 리소스
	uint32_t threadCount = 0;
	uint32_t handleCount = 0;
	uint32_t gdiObjectCount = 0;
	double   pageFaultRate = 0.0;

	// 네트워크 연결
	std::vector<TargetNetConnection> connections;
};

struct SnapshotTarget {
	std::string targetName;
	std::string exePath;
	std::string status = "running"; // 메인 루프가 수집 시점에 계산: "running" | "not_running" | "never_seen"

	// status가 "not_running"/"never_seen"일 때만 채워지는 마지막 세션 요약 (running이면 전부 기본값)
	std::string lastSessionDate;
	double lastAvgCpuUsage = 0.0;
	double lastPeakCpuUsage = 0.0;
	double lastAvgMemoryMB = 0.0;
	double lastPeakMemoryMB = 0.0;
	double lastAvgNetMbps = 0.0;
	double lastPeakNetMbps = 0.0;
	uint32_t lastPeakThreadCount = 0;
	uint32_t lastPeakHandleCount = 0;
	double lastTotalRuntimeSec = 0.0;

	// 메인 프로세스
	uint32_t pid = 0;
	double cpuUsage = 0.0;
	double memoryMB = 0.0;
	double privateMemoryMB = 0.0;
	double virtualMemoryMB = 0.0;
	double diskReadMBs = 0.0;
	double diskWriteMBs = 0.0;
	double netSentMbps = 0.0;
	double netRecvMbps = 0.0;
	uint32_t threadCount = 0;
	uint32_t handleCount = 0;
	uint32_t gdiObjectCount = 0;
	double pageFaultRate = 0.0;
	double elapsedSec = 0.0;

	// 네트워크 연결 목록
	std::vector<TargetNetConnection> connections;

	// 자식 프로세스
	std::vector<SnapshotChildProcess> children;

	// 전체 합계 (메인 + 자식)
	double totalCpuUsage = 0.0;
	double totalMemoryMB = 0.0;
	double totalDiskMBs = 0.0;  // Read + Write
	double totalNetMbps = 0.0;  // Sent + Recv
	uint32_t totalThreadCount = 0;
	uint32_t totalHandleCount = 0;
	uint32_t totalProcessCount = 0;    // 메인 + 자식 수

	void calcTotals() {
		totalCpuUsage = cpuUsage;
		totalMemoryMB = memoryMB;
		totalDiskMBs = diskReadMBs + diskWriteMBs;
		totalNetMbps = netSentMbps + netRecvMbps;
		totalThreadCount = threadCount;
		totalHandleCount = handleCount;
		totalProcessCount = 1 + static_cast<uint32_t>(children.size());

		for (const auto& c : children) {
			totalCpuUsage += c.cpuUsage;
			totalMemoryMB += c.memoryMB;
			totalDiskMBs += c.diskReadMBs + c.diskWriteMBs;
			totalNetMbps += c.netSentMbps + c.netRecvMbps;
			totalThreadCount += c.threadCount;
			totalHandleCount += c.handleCount;
		}
	}
};

struct SnapshotTargetData {
	std::chrono::system_clock::time_point	timestamp;
	std::vector<SnapshotTarget> targets;
};

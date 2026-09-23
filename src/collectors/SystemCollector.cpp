#include "collectors/SystemCollector.h"
#include <spdlog/spdlog.h>
#pragma comment(lib, "pdh.lib")

SystemCollector::SystemCollector() : queryMiddle(nullptr), querySlow(nullptr)
{
	PDH_STATUS statusMiddle = PdhOpenQuery(nullptr, 0, &queryMiddle);
	if (statusMiddle != ERROR_SUCCESS) {
		spdlog::error("SystemCollector: PdhOpenQuery(middle) 실패 0x{:X}", statusMiddle);
	}
	PDH_STATUS statusSlow = PdhOpenQuery(nullptr, 0, &querySlow);
	if (statusSlow != ERROR_SUCCESS) {
		spdlog::error("SystemCollector: PdhOpenQuery(slow) 실패 0x{:X}", statusSlow);
	}


	PdhCollectQueryData(queryMiddle);
	PdhCollectQueryData(querySlow);

	cpu.init(queryMiddle);
	mem.init(queryMiddle);
	net.init(queryMiddle);
	disk.init(querySlow);

	//초기 수집
	PdhCollectQueryData(queryMiddle);
	PdhCollectQueryData(querySlow);
	Sleep(1000);
}
SystemCollector::~SystemCollector() {
	PdhCloseQuery(queryMiddle);
	PdhCloseQuery(querySlow);
}
void SystemCollector::collectMiddle() {
	PdhCollectQueryData(queryMiddle);
	mem.collectMemInfo();
}
void SystemCollector::collectSlow() {
	PdhCollectQueryData(querySlow);
	lastTime = std::chrono::system_clock::now();
}

SnapshotSysData SystemCollector::makeSnapshot() {
	SnapshotSysData snapshot;
	snapshot.timestamp = std::chrono::system_clock::now();

	const auto& cpu_ = cpu;
	const auto& mem_ = mem;
	const auto& disk_ = disk;
	const auto& net_ = net;

	snapshot.cpu.cpuTotal = cpu_.getTotalUsage();
	snapshot.cpu.cpuFreqGHz = cpu_.getCpuFreqGHz();
	snapshot.cpu.cpuQueueLength = cpu_.getCpuQueueLength();
	snapshot.cpu.cpuUser = cpu_.getCpuUser();
	snapshot.cpu.cpuKernel = cpu_.getCpuKernel();

	snapshot.mem.memTotalMB = mem_.getMemTotalMB();
	snapshot.mem.memAvailMB = mem_.getAvailMemMB();
	snapshot.mem.memUsagePercent = mem_.getMemUsagedPercent();
	snapshot.mem.memUsedMB = mem_.getMemUsedMB();
	snapshot.mem.commitMemPercent = mem_.getCommitMemPercent();
	snapshot.mem.committedMemGB = mem_.getCommittedMemGB();
	snapshot.mem.commitLimitGB = mem_.getCommitLimitGB();

	snapshot.disk.lastTime = lastTime;
	snapshot.disk.diskReadKBs = disk_.getReadKB();
	snapshot.disk.diskWriteKBs = disk_.getWriteKB();

	snapshot.net.netRecvKbps = net_.getRecvKbps();
	snapshot.net.netSentKbps = net_.getSentKbps();
	return snapshot;
}


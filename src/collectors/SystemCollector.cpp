#include "collectors/SystemCollector.h"
#include <spdlog/spdlog.h>
#pragma comment(lib, "pdh.lib")

namespace {
	// 스냅샷에 넣는 지표 — 읽기 실패를 지표별로 한 번씩 알리는 데 쓴다 (이름은 proto SysSnapshot의 필드 이름)
	enum Metric : size_t {
		CpuTotal, CpuFreq, CpuQueueLength, CpuUser, CpuKernel,
		MemTotal, MemAvail, CommitPercent, CommittedMem, CommitLimit,
		DiskRead, DiskWrite,
		NetRecv, NetSent,
		MetricCount
	};
	constexpr const char* METRIC_NAMES[MetricCount] = {
		"cpu_total", "cpu_freq_ghz", "cpu_queue_length", "cpu_user", "cpu_kernel",
		"mem_total_mb", "mem_avail_mb", "commit_mem_percent", "committed_mem_gb", "commit_limit_gb",
		"disk_read_kbs", "disk_write_kbs",
		"net_recv_kbps", "net_sent_kbps",
	};
}

SystemCollector::SystemCollector() : queryMiddle(nullptr), querySlow(nullptr)
{
	static_assert(MetricCount == METRIC_COUNT, "readWarned needs one entry per metric");

	PDH_STATUS statusMiddle = PdhOpenQuery(nullptr, 0, &queryMiddle);
	if (statusMiddle != ERROR_SUCCESS) {
		spdlog::error("SystemCollector: PdhOpenQuery(middle) 실패 0x{:X}", static_cast<unsigned>(statusMiddle));
	}
	PDH_STATUS statusSlow = PdhOpenQuery(nullptr, 0, &querySlow);
	if (statusSlow != ERROR_SUCCESS) {
		spdlog::error("SystemCollector: PdhOpenQuery(slow) 실패 0x{:X}", static_cast<unsigned>(statusSlow));
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
	const PDH_STATUS status = PdhCollectQueryData(queryMiddle);
	middleCollected = (status == ERROR_SUCCESS);
	PdhUtil::reportReadState(middleCollectWarned, middleCollected, "SystemCollector", "1s query (cpu / memory / network)", status);
	mem.collectMemInfo();
}
void SystemCollector::collectSlow() {
	const PDH_STATUS status = PdhCollectQueryData(querySlow);
	slowCollected = (status == ERROR_SUCCESS);
	PdhUtil::reportReadState(slowCollectWarned, slowCollected, "SystemCollector", "2s query (disk)", status);
	lastTime = std::chrono::system_clock::now();
}

std::optional<double> SystemCollector::take(size_t metric, const PdhUtil::Reading& reading, bool collected) {
	if (!collected) return std::nullopt;
	PdhUtil::reportReadState(readWarned[metric], reading.value.has_value(), "SystemCollector", METRIC_NAMES[metric], reading.status);
	return reading.value;
}

SnapshotSysData SystemCollector::makeSnapshot(std::chrono::system_clock::time_point tickTime) {
	SnapshotSysData snapshot;
	snapshot.timestamp = tickTime;

	const auto& cpu_ = cpu;
	const auto& mem_ = mem;
	const auto& disk_ = disk;
	const auto& net_ = net;

	// 읽지 못한 값은 0으로 채우지 않고 비워 둔다 — 받는 쪽이 "0"과 "읽지 못함"을 구분할 수 있어야 한다
	snapshot.cpu.cpuTotal = take(CpuTotal, cpu_.getTotalUsage(), middleCollected);
	snapshot.cpu.cpuFreqGHz = take(CpuFreq, cpu_.getCpuFreqGHz(), middleCollected);
	snapshot.cpu.cpuQueueLength = take(CpuQueueLength, cpu_.getCpuQueueLength(), middleCollected);
	snapshot.cpu.cpuUser = take(CpuUser, cpu_.getCpuUser(), middleCollected);
	snapshot.cpu.cpuKernel = take(CpuKernel, cpu_.getCpuKernel(), middleCollected);

	// 물리 메모리 총량은 PDH가 아니라 시작할 때 한 번 읽은 값이라 쿼리 수집과 무관하다
	snapshot.mem.memTotalMB = take(MemTotal, mem_.getMemTotalMB(), true);
	snapshot.mem.memAvailMB = take(MemAvail, mem_.getAvailMemMB(), middleCollected);
	// 사용량과 사용률은 총량과 사용 가능 메모리로 계산한다 — 둘 중 하나라도 없으면 없다 (원인은 위 두 값에서 이미 알렸다)
	if (snapshot.mem.memTotalMB && snapshot.mem.memAvailMB) {
		const double usedMB = *snapshot.mem.memTotalMB - *snapshot.mem.memAvailMB;
		snapshot.mem.memUsedMB = usedMB;
		snapshot.mem.memUsagePercent = (usedMB / *snapshot.mem.memTotalMB) * 100.0;	// 총량은 0보다 클 때만 값이 있다
	}
	snapshot.mem.commitMemPercent = take(CommitPercent, mem_.getCommitMemPercent(), middleCollected);
	snapshot.mem.committedMemGB = take(CommittedMem, mem_.getCommittedMemGB(), middleCollected);
	snapshot.mem.commitLimitGB = take(CommitLimit, mem_.getCommitLimitGB(), middleCollected);

	snapshot.disk.lastTime = lastTime;
	snapshot.disk.diskReadKBs = take(DiskRead, disk_.getReadKB(), slowCollected);
	snapshot.disk.diskWriteKBs = take(DiskWrite, disk_.getWriteKB(), slowCollected);

	snapshot.net.netRecvKbps = take(NetRecv, net_.getRecvKbps(), middleCollected);
	snapshot.net.netSentKbps = take(NetSent, net_.getSentKbps(), middleCollected);
	return snapshot;
}

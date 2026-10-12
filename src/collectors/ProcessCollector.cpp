#include "collectors/ProcessCollector.h"
#include "util/PdhUtil.h"
#include "util/StrUtil.h"
#include <spdlog/spdlog.h>
#include <cmath>
#pragma comment(lib, "pdh.lib")

namespace {
	constexpr double BYTES_PER_MB = 1024.0 * 1024.0;

	// 카운터 하나의 배열을 읽은 결과
	struct ArrayRead {
		std::vector<char> buffer;
		DWORD count = 0;
		bool ok = false;	// 읽었고, PID 배열과 같은 순서로 쓸 수 있다

		const PDH_FMT_COUNTERVALUE_ITEM* items() const {
			return reinterpret_cast<const PDH_FMT_COUNTERVALUE_ITEM*>(buffer.data());
		}
		// i번째 항목의 값. 배열을 읽지 못했거나 그 항목이 유효하지 않으면(프로세스가 처음 보인 틱의 비율 값 등) 없다.
		std::optional<double> valueAt(DWORD i) const {
			if (!ok) return std::nullopt;
			const PDH_FMT_COUNTERVALUE& v = items()[i].FmtValue;
			if (v.CStatus != PDH_CSTATUS_VALID_DATA && v.CStatus != PDH_CSTATUS_NEW_DATA) return std::nullopt;
			if (std::isnan(v.doubleValue) || std::isinf(v.doubleValue)) return std::nullopt;
			return v.doubleValue;
		}
	};

	std::optional<double> divided(std::optional<double> value, double divisor) {
		if (!value) return std::nullopt;
		return *value / divisor;
	}

	// 값이 있는 것만 더한다. 둘 다 없으면 합도 없다 — 없는 값을 0으로 쳐서 더하지 않는다.
	std::optional<double> addPresent(std::optional<double> a, std::optional<double> b) {
		if (!a) return b;
		if (!b) return a;
		return *a + *b;
	}
}

ProcessCollector::ProcessCollector(int topN) : topN(topN) {
	PDH_STATUS statusMiddle = PdhOpenQuery(NULL, 0, &queryMiddle);
	if (statusMiddle != ERROR_SUCCESS) {
		spdlog::error("ProcessCollector: PdhOpenQuery(middle) Error 0x{:X}", static_cast<unsigned>(statusMiddle));
	}

	cores = std::thread::hardware_concurrency();
	if (cores == 0) cores = 1;

	initInfo(queryMiddle);

	//초기 수집
	PdhCollectQueryData(queryMiddle);

	if (!etwNet.start()) {
		spdlog::warn("ETWNetwork Start Error");
	}

	lastTime = std::chrono::steady_clock::now();
}
ProcessCollector::~ProcessCollector() {
	PdhCloseQuery(queryMiddle);
}

void ProcessCollector::initInfo(PDH_HQUERY& query) {
	PdhUtil::addCounter(queryMiddle, L"\\Process(*)\\ID Process", procIDMiddle, "ProcessCollector");	//PID
	PdhUtil::addCounter(queryMiddle, L"\\Process(*)\\% Processor Time", procCpuUsage, "ProcessCollector");	//CPU 사용량(%)
	PdhUtil::addCounter(queryMiddle, L"\\Process(*)\\Working Set - Private", procMem, "ProcessCollector");	//실질적인 MEM
	PdhUtil::addCounter(queryMiddle, L"\\Process(*)\\Private Bytes", procPrivateMem, "ProcessCollector");	//Private MEM 메모리 누수 감지용
	PdhUtil::addCounter(queryMiddle, L"\\Process(*)\\IO Read Bytes/sec", procDiskR, "ProcessCollector");
	PdhUtil::addCounter(queryMiddle, L"\\Process(*)\\IO Write Bytes/sec", procDiskW, "ProcessCollector");
}

PDH_STATUS ProcessCollector::getCountArray(PDH_HCOUNTER hCounter, std::vector<char>& buffer, DWORD& count) {
	// PDH_FMT_NOCAP100: 프로세스의 "% Processor Time"은 코어 하나를 다 쓰면 100, 둘이면 200이다.
	// 이 플래그가 없으면 PDH가 100에서 잘라, 여러 코어를 쓰는 프로세스가 (100 / 코어 수)%로 낮게 보고된다.
	// 백분율이 아닌 카운터(바이트, PID 등)에는 영향이 없다.
	constexpr DWORD format = PDH_FMT_DOUBLE | PDH_FMT_NOCAP100;

	buffer.clear();
	count = 0;

	// 크기를 먼저 묻는다 — 정상이면 PDH_MORE_DATA와 함께 필요한 크기가 온다
	DWORD bufferSize = 0;
	PDH_STATUS status = PdhGetFormattedCounterArray(hCounter, format, &bufferSize, &count, NULL);
	if (status != PDH_MORE_DATA || count == 0 || bufferSize == 0) {
		count = 0;
		return (status == PDH_MORE_DATA || status == ERROR_SUCCESS) ? static_cast<PDH_STATUS>(PDH_NO_DATA) : status;
	}

	buffer.resize(bufferSize);
	status = PdhGetFormattedCounterArray(
		hCounter,
		format,
		&bufferSize,
		&count,
		reinterpret_cast<PDH_FMT_COUNTERVALUE_ITEM*>(buffer.data()));

	if (status != ERROR_SUCCESS) {
		count = 0;
		buffer.clear();
	}

	return status;
}

// ---------------------------------------------------------------------------
// 1초 주기 수집
// ---------------------------------------------------------------------------
void ProcessCollector::collectProc(const std::optional<ProcessList>& procs) {
	procList.clear();
	aggregatedProcList.clear();
	// 목록이 없어도 수집은 한다 — 비율 값의 기준점이 끊기지 않게
	const PDH_STATUS collectStatus = PdhCollectQueryData(queryMiddle);
	PdhUtil::reportReadState(collectWarned, collectStatus == ERROR_SUCCESS, "ProcessCollector", "PdhCollectQueryData (every process metric)", collectStatus);

	// 프로세스 목록을 못 받은 틱: PID에 이름을 붙일 수 없으므로 이번 틱의 proc 목록은 만들지 않는다.
	// 빈 목록으로 내보내면 받는 쪽이 "프로세스가 하나도 없다"로 읽는다.
	// lastTime을 그대로 두어, 그동안 쌓인 ETW 네트워크 바이트가 다음 틱에 실제 경과 시간으로 나뉘게 한다.
	snapshotAvailable = procs.has_value();
	if (!procs) return;

	auto now = std::chrono::steady_clock::now();
	double elapsedSec = std::chrono::duration <double>(now - lastTime).count();
	lastTime = now;
	if (elapsedSec <= 0.0) {
		elapsedSec = 1.0;
	}

	// 1단계 - 카운터별 배열 읽기
	// 배열을 읽지 못했다고 목록을 비우지 않는다: 읽지 못한 지표만 비워 둔다. 빈 목록으로 내보내면 받는 쪽이
	// "프로세스가 하나도 없다"로 읽고, 0으로 채우면 실제 0과 구분할 수 없다.
	// 값은 "없음"으로 나가므로 원인은 여기서 한 번 알린다 (실패가 시작될 때 1번, 다시 읽히면 1번).
	enum : size_t { PID, CPU, MEM, PRIVATE_MEM, DISK_READ, DISK_WRITE };
	struct { PDH_HCOUNTER handle; const char* name; } const counters[ARRAY_COUNT] = {
		{ procIDMiddle,   "ID Process" },
		{ procCpuUsage,   "% Processor Time" },
		{ procMem,        "Working Set - Private" },
		{ procPrivateMem, "Private Bytes" },
		{ procDiskR,      "IO Read Bytes/sec" },
		{ procDiskW,      "IO Write Bytes/sec" },
	};

	ArrayRead arrays[ARRAY_COUNT];
	const bool collected = (collectStatus == ERROR_SUCCESS);
	// 수집이 실패한 틱에는 배열을 읽지 않는다 — 이전 수집의 값이 그대로 돌아올 수 있다 (수집 실패는 위에서 알렸다)
	if (collected) {
		for (size_t c = 0; c < ARRAY_COUNT; ++c) {
			PDH_STATUS status = getCountArray(counters[c].handle, arrays[c].buffer, arrays[c].count);
			arrays[c].ok = (status == ERROR_SUCCESS);

			// 다른 배열은 PID 배열과 같은 순서라는 전제로 같은 인덱스를 쓴다 (한 번의 수집에서 나온 배열들).
			// 개수가 다르면 그 전제가 깨진 것이므로 그 지표는 읽지 못한 것으로 본다 — 어긋난 인덱스로 남의 값을 붙이지 않는다.
			if (c != PID && arrays[c].ok && arrays[PID].ok && arrays[c].count != arrays[PID].count) {
				arrays[c].ok = false;
				status = PDH_INVALID_DATA;
			}
			PdhUtil::reportReadState(arrayWarned[c], arrays[c].ok, "ProcessCollector", counters[c].name, status);
		}
	}

	auto tree = buildProcTree(*procs);

	// 2단계 - 목록 구성
	// 이름으로 걸러 내지 않는다 — proc은 전체 목록이고 무엇을 숨길지는 UI가 정한다.
	// 빼는 것은 PID 0뿐이다: PDH의 합계 항목(_Total)과 Idle이 PID 0이고, 프로세스가 아니라 의사 항목이다.
	if (arrays[PID].ok) {
		// PID 배열을 따라가며 같은 인덱스의 값을 붙인다. 이름은 프로세스 목록에서 PID로 찾는다 (PDH의 이름은 중복될 수 있다).
		const PDH_FMT_COUNTERVALUE_ITEM* pidItems = arrays[PID].items();
		for (DWORD i = 0; i < arrays[PID].count; ++i) {
			if (pidItems[i].FmtValue.CStatus != PDH_CSTATUS_VALID_DATA && pidItems[i].FmtValue.CStatus != PDH_CSTATUS_NEW_DATA) continue;

			const DWORD pid = static_cast<DWORD>(pidItems[i].FmtValue.doubleValue);
			if (pid == 0) continue;

			auto entryIt = tree.find(pid);
			if (entryIt == tree.end()) continue;

			auto proc_ = std::make_unique<ProcList>();

			proc_->setProcID(pid);
			proc_->setProcName(entryIt->second.name);

			proc_->setProcCpuUsage(divided(arrays[CPU].valueAt(i), cores));
			proc_->setProcMemoryMB(divided(arrays[MEM].valueAt(i), BYTES_PER_MB));
			proc_->setProcPrivateMemoryMB(divided(arrays[PRIVATE_MEM].valueAt(i), BYTES_PER_MB));
			proc_->setDiskReadMBs(divided(arrays[DISK_READ].valueAt(i), BYTES_PER_MB));
			proc_->setDiskWriteMBs(divided(arrays[DISK_WRITE].valueAt(i), BYTES_PER_MB));

			aggregatedProcList.push_back(std::move(proc_));
		}
	}
	else {
		// PID 배열을 읽지 못했다 — 다른 배열의 값이 어느 프로세스의 것인지 알 수 없다.
		// 목록은 프로세스 목록으로 만들고(PID와 이름), PDH 지표는 모두 비워 둔다.
		for (const auto& p : *procs) {
			if (p.pid == 0) continue;

			auto proc_ = std::make_unique<ProcList>();
			proc_->setProcID(p.pid);
			proc_->setProcName(tree[p.pid].name);
			aggregatedProcList.push_back(std::move(proc_));
		}
	}

	std::unordered_set<DWORD> alivePids;
	for (auto& proc : aggregatedProcList) {
		DWORD pid = proc->getProcID();
		alivePids.insert(pid);
		NetMbps net = etwNet.getAndReset(pid, elapsedSec);
		proc->setNetSentMbps(net.sentMbps);
		proc->setNetRecvMbps(net.recvMbps);
	}

	aggregateToParents(tree);

	// 60초 주기로 현재 죽어있는 프로세스 ETWNetwork에서 정리
	if (++cleanupTick >= 60) {
		etwNet.retainOnlyPids(alivePids);
		cleanupTick = 0;
	}
}

// ---------------------------------------------------------------------------
// 자식 프로세스 값 -> 메인 프로세스에 합산
// ---------------------------------------------------------------------------
void ProcessCollector::aggregateToParents(std::unordered_map<DWORD, ProcEntry>& tree) {
	//auto tree = buildProcTree();

	// PID -> ProcList
	std::unordered_map<DWORD, ProcList*> pidMap;
	for (auto& p : aggregatedProcList) {
		pidMap[p->getProcID()] = p.get();
	}

	// 자식 -> 부모 합산
	std::unordered_set<DWORD> toRemove; // 합산 후 제거할 자식 PID
	std::unordered_set<DWORD> visited;

	// 리프부터 루트 방향으로 합산
	std::function<void(DWORD)> dfs = [&](DWORD pid) {
		if (visited.count(pid)) return;
		visited.insert(pid);

		auto childIt = pidMap.find(pid);
		if (childIt == pidMap.end()) return;

		auto treeIt = tree.find(pid);
		if (treeIt == tree.end()) return;

		DWORD ppid = treeIt->second.ppid;
		if (ppid == pid) return; // 자기 자신 방지

		auto parentIt = pidMap.find(ppid);
		if (parentIt == pidMap.end()) return;

		ProcList* child = childIt->second;
		ProcList* parent = parentIt->second;

		// 이름이 같은 경우만 합산
		if (child->getProcName() != parent->getProcName()) return;

		// 자식을 먼저 처리
		for (const auto& [childPid, childEntry] : tree) {
			if (childEntry.ppid == pid) // pid의 자식들
				dfs(childPid);
		}
		parent->setProcCpuUsage(addPresent(parent->getProcCpuUsage(), child->getProcCpuUsage()));
		parent->setProcMemoryMB(addPresent(parent->getProcMemoryMB(), child->getProcMemoryMB()));
		parent->setProcPrivateMemoryMB(addPresent(parent->getProcPrivateMemMB(), child->getProcPrivateMemMB()));
		parent->setDiskReadMBs(addPresent(parent->getDiskReadMBs(), child->getDiskReadMBs()));
		parent->setDiskWriteMBs(addPresent(parent->getDiskWriteMBs(), child->getDiskWriteMBs()));
		parent->setNetRecvMbps(parent->getNetRecvMbps() + child->getNetRecvMbps());
		parent->setNetSentMbps(parent->getNetSentMbps() + child->getNetSentMbps());

		toRemove.insert(pid);
		};

	for (const auto& [pid, entry] : tree)
		dfs(pid);

	// 자식 제거
	aggregatedProcList.erase(
		std::remove_if(aggregatedProcList.begin(), aggregatedProcList.end(),
			[&](const std::unique_ptr<ProcList>& p) {
				return toRemove.count(p->getProcID()) > 0;
			}),
		aggregatedProcList.end());
}

std::unordered_map<DWORD, ProcEntry> ProcessCollector::buildProcTree(const ProcessList& procs) {
	std::unordered_map<DWORD, ProcEntry> tree;
	tree.reserve(procs.size());
	for (const auto& p : procs) {
		ProcEntry pe;
		pe.pid = p.pid;
		pe.ppid = p.ppid;
		pe.name = StrUtil::wideToUtf8(p.exeName);	// 목록의 이름은 이미 ".exe"를 뗀 것 — 타겟 이름과 같은 표기
		tree[pe.pid] = pe;
	}
	return tree;
}


void ProcessCollector::setTopN(int n) {
	topN = n;
}

std::optional<SnapshotProcData> ProcessCollector::makeSnapshot(std::chrono::system_clock::time_point tickTime) {
	if (!snapshotAvailable) return std::nullopt;

	size_t count = aggregatedProcList.size();

	SnapshotProcData snapshot;
	snapshot.timestamp = tickTime;
	snapshot.topN = topN;

	for (size_t i = 0; i < count; ++i) {
		const auto& proc = aggregatedProcList[i];
		SnapshotProc sp;

		sp.procID = proc->getProcID();
		sp.procName = proc->getProcName();
		sp.procCpuUsage = proc->getProcCpuUsage();
		sp.procMemoryMB = proc->getProcMemoryMB();
		sp.procPrivateMemoryMB = proc->getProcPrivateMemMB();
		sp.procDiskReadMBs = proc->getDiskReadMBs();
		sp.procDiskWriteMBs = proc->getDiskWriteMBs();
		sp.procNetRecvMbps = proc->getNetRecvMbps();
		sp.procNetSentMbps = proc->getNetSentMbps();

		snapshot.procs.push_back(sp);
	}
	return snapshot;
}

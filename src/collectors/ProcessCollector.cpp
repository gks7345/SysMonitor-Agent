#include "collectors/ProcessCollector.h"
#include <spdlog/spdlog.h>
#pragma comment(lib, "pdh.lib")

static const char* SYSTEM_NAMES[] = {
	"_Total", "Idle", "System", "smss", "csrss", "[System Process]",
	"wininit", "winlogon", "services", "lsass",
	"fontdrvhost", "dwm", "Memory Compression", nullptr
};

bool ProcessCollector::isSystemProcess(const std::string& name) const {
	for (int i = 0; SYSTEM_NAMES[i]; ++i)
		if (name == SYSTEM_NAMES[i]) return true;
	return false;
}


ProcessCollector::ProcessCollector(int topN) : topN(topN) {
	PDH_STATUS statusMiddle = PdhOpenQuery(NULL, 0, &queryMiddle);
	if (statusMiddle != ERROR_SUCCESS) {
		spdlog::error("ProcessCollector: PdhOpenQuery(middle) Error 0x{:X}", statusMiddle);
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
	PDH_STATUS pidStatus = PdhAddEnglishCounter(	//PID
		queryMiddle,
		"\\Process(*)\\ID Process",
		0,
		&procIDMiddle
	);
	if (pidStatus != ERROR_SUCCESS) {
		spdlog::error("Counter Error 0x{:X}", pidStatus);
	}

	PDH_STATUS cpuStatus = PdhAddEnglishCounter(	//CPU 사용량(%)
		queryMiddle,
		"\\Process(*)\\% Processor Time",
		0,
		&procCpuUsage
	);
	if (cpuStatus != ERROR_SUCCESS) {
		spdlog::error("Counter Error 0x{:X}", cpuStatus);
	}

	PDH_STATUS memStatus = PdhAddEnglishCounter(	//실질적인 MEM
		queryMiddle,
		"\\Process(*)\\Working Set - Private",
		0,
		&procMem
	);
	if (memStatus != ERROR_SUCCESS) {
		spdlog::error("Counter Error 0x{:X}", memStatus);
	}

	PDH_STATUS priStatus = PdhAddEnglishCounter(	//Private MEM 메모리 누수 감지용
		queryMiddle,
		"\\Process(*)\\Private Bytes",
		0,
		&procPrivateMem
	);
	if (priStatus != ERROR_SUCCESS) {
		spdlog::error("Counter Error 0x{:X}", priStatus);
	}


	// ----------------------------------------
	PDH_STATUS readStatus = PdhAddEnglishCounter(queryMiddle,
		"\\Process(*)\\IO Read Bytes/sec", 0, &procDiskR);
	if (readStatus != ERROR_SUCCESS) {
		spdlog::error("Counter Error 0x{:X}", readStatus);
	}

	PDH_STATUS writeStatus = PdhAddEnglishCounter(queryMiddle,
		"\\Process(*)\\IO Write Bytes/sec", 0, &procDiskW);
	if (writeStatus != ERROR_SUCCESS) {
		spdlog::error("Counter Error 0x{:X}", writeStatus);
	}
	// ----------------------------------------
}

std::vector<char> ProcessCollector::getCountArray(PDH_HCOUNTER hCounter, DWORD& count) {
	DWORD bufferSize = 0;
	PdhGetFormattedCounterArray(hCounter, PDH_FMT_DOUBLE, &bufferSize, &count, NULL);

	std::vector<char> buffer;
	if (count == 0 || bufferSize == 0) return buffer;

	buffer.resize(bufferSize);
	PDH_STATUS status = PdhGetFormattedCounterArray(
		hCounter,
		PDH_FMT_DOUBLE,
		&bufferSize,
		&count,
		reinterpret_cast<PDH_FMT_COUNTERVALUE_ITEM*>(buffer.data()));

	if (status != ERROR_SUCCESS) {
		spdlog::warn("getCountArray Error 0x{:X}", status);
		count = 0;
		buffer.clear();
	}

	return buffer;
}

// ---------------------------------------------------------------------------
// 1초 주기 수집
// ---------------------------------------------------------------------------
void ProcessCollector::collectProc() {
	auto now = std::chrono::steady_clock::now();
	double elapsedSec = std::chrono::duration <double>(now - lastTime).count();
	lastTime = now;
	if (elapsedSec <= 0.0) {
		elapsedSec = 1.0;
	}


	procList.clear();
	aggregatedProcList.clear();
	PdhCollectQueryData(queryMiddle);

	// 1단계 - PID 배열 수집
	DWORD pidItemCount = 0;
	std::vector<char> pidbuffer = getCountArray(procIDMiddle, pidItemCount);
	auto* pidItems = reinterpret_cast<PDH_FMT_COUNTERVALUE_ITEM*>(pidbuffer.data());

	auto tree = buildProcTree();
	// 2단계 - ToolHelp32로 PID -> 이름 맵 구성
	std::unordered_map<DWORD, std::string> pidToName;
	for (const auto& [pid, entry] : tree) {
		pidToName[pid] = entry.name;
	}

	// 3단계 - PID 배열 순회하며 이름으로 나머지 카운터 매핑
	// 같은 query에서 수집 -> 인덱스 일치 보장
	// PID로 이름 검증 -> 이름 중복 문제 없음
	DWORD cpuItemCount = 0;
	DWORD memItemCount = 0, priMemItemCount = 0;
	DWORD diskRCounter = 0, diskWCounter = 0;


	std::vector<char> cpubuffer = getCountArray(procCpuUsage, cpuItemCount);
	std::vector<char> membuffer = getCountArray(procMem, memItemCount);
	std::vector<char> primembuffer = getCountArray(procPrivateMem, priMemItemCount);
	std::vector<char> diskRbuffer = getCountArray(procDiskR, diskRCounter);
	std::vector<char> diskWbuffer = getCountArray(procDiskW, diskWCounter);


	auto* cpuItems = reinterpret_cast<PDH_FMT_COUNTERVALUE_ITEM*>(cpubuffer.data());
	auto* memItems = reinterpret_cast<PDH_FMT_COUNTERVALUE_ITEM*>(membuffer.data());
	auto* privateMemItems = reinterpret_cast<PDH_FMT_COUNTERVALUE_ITEM*>(primembuffer.data());
	auto* diskRItems = reinterpret_cast<PDH_FMT_COUNTERVALUE_ITEM*>(diskRbuffer.data());
	auto* diskWItems = reinterpret_cast<PDH_FMT_COUNTERVALUE_ITEM*>(diskWbuffer.data());

	// 가장 작은 개수로 범위 제한
	DWORD safeCount = (std::min)({
		pidItemCount, cpuItemCount, memItemCount,
		priMemItemCount, diskRCounter, diskWCounter });


	for (DWORD i = 0; i < safeCount; ++i) {
		DWORD pid = static_cast<DWORD>(pidItems[i].FmtValue.doubleValue);

		// ToolHelp32로 얻은 이름으로 검증
		auto nameIt = pidToName.find(pid);
		if (nameIt == pidToName.end()) continue;

		std::string name = nameIt->second;

		//if (name == "_Total" || name == "Idle") continue;
		if (isSystemProcess(name)) continue;

		if (pidItems[i].FmtValue.CStatus != PDH_CSTATUS_VALID_DATA &&
			pidItems[i].FmtValue.CStatus != PDH_CSTATUS_NEW_DATA)
			continue;

		auto proc_ = std::make_unique<ProcList>();

		proc_->setProcID(pid);
		proc_->setProcName(name);

		proc_->setProcCpuUsage(cpuItems[i].FmtValue.doubleValue / cores);
		proc_->setProcMemoryMB(memItems[i].FmtValue.doubleValue / (1024.0 * 1024.0));
		proc_->setProcPrivateMemoryMB(privateMemItems[i].FmtValue.doubleValue / (1024.0 * 1024.0));
		proc_->setDiskReadMBs(diskRItems[i].FmtValue.doubleValue / (1024.0 * 1024.0));
		proc_->setDiskWriteMBs(diskWItems[i].FmtValue.doubleValue / (1024.0 * 1024.0));

		aggregatedProcList.push_back(std::move(proc_));
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
		parent->setProcCpuUsage(parent->getProcCpuUsage() + child->getProcCpuUsage());
		parent->setProcMemoryMB(parent->getProcMemoryMB() + child->getProcMemoryMB());
		parent->setProcPrivateMemoryMB(parent->getProcPrivateMemMB() + child->getProcPrivateMemMB());
		parent->setDiskReadMBs(parent->getDiskReadMBs() + child->getDiskReadMBs());
		parent->setDiskWriteMBs(parent->getDiskWriteMBs() + child->getDiskWriteMBs());
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

std::unordered_map<DWORD, ProcEntry> ProcessCollector::buildProcTree() {
	std::unordered_map<DWORD, ProcEntry> tree;

	HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snap == INVALID_HANDLE_VALUE) return tree;

	PROCESSENTRY32 entry = {};
	entry.dwSize = sizeof(entry);

	if (Process32First(snap, &entry)) {
		do {
			ProcEntry pe;
			pe.pid = entry.th32ProcessID;
			pe.ppid = entry.th32ParentProcessID;
			pe.name = entry.szExeFile;
			tree[pe.pid] = pe;
		} while (Process32Next(snap, &entry));
	}
	CloseHandle(snap);
	return tree;
}


void ProcessCollector::setTopN(int n) {
	topN = n;
}

SnapshotProcData ProcessCollector::makeSnapshot() {
	size_t count = aggregatedProcList.size();

	SnapshotProcData snapshot;
	snapshot.timestamp = std::chrono::system_clock::now();
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

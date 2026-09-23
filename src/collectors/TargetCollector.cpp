#include "collectors/TargetCollector.h"


TargetCollector::TargetCollector(ETWNetwork& sharedEtwNet) : etwNet(sharedEtwNet) {
	cores = std::thread::hardware_concurrency();
	if (cores == 0) cores = 1;

	PDH_STATUS s = PdhOpenQuery(nullptr, 0, &query);
	if (s != ERROR_SUCCESS) {
		spdlog::error("TargetCollector: PdhOpenQuery error 0x{:X}", s);
	}

	lastTime = std::chrono::steady_clock::now();
}
TargetCollector::~TargetCollector() {
	clearRegistered();
	if (query)
		PdhCloseQuery(query);
}

// -------------------------------------------------------
// 타겟 등록 — 실행 여부 무관
// -------------------------------------------------------
void TargetCollector::registerTarget(const std::string& name) {
	// 중복확인
	auto it = std::find(registeredNames.begin(), registeredNames.end(), name);
	if (it != registeredNames.end()) {
		spdlog::warn("TargetCollector: '{}' already registered", name);
		return;
	}

	registeredNames.push_back(name);
	spdlog::info("TargetCollector: '{}' register target", name);
}

// -------------------------------------------------------
// 타겟 해제
// -------------------------------------------------------
void TargetCollector::unregisterTarget(const std::string& name) {
	// registeredNames에서 제거
	registeredNames.erase(std::remove(registeredNames.begin(), registeredNames.end(), name), registeredNames.end());

	// 실행 중이면 deactivate — 사용자가 명시적으로 해제 요청한 경로이므로
	// pendingDeactivated에는 넣지 않는다(아래 lastSessions.erase가 곧바로 뒤집히는 걸 방지).
	deactivateTarget(name, /*notifyPending=*/false);

	// 마지막 세션 제거
	lastSessions.erase(name);
	spdlog::info("TargetCollector: '{}' released", name);
}

// -------------------------------------------------------
// API 스레드에서 호출 — registeredNames/activeTargets/lastSessions는 절대 건드리지 않고
// 커맨드 큐에 넣기만 한다. notify_one()으로 메인 루프가 다음 정규 틱까지 기다리지 않고
// 즉시 깨어나 applyPending()을 처리하도록 한다.
// -------------------------------------------------------
std::future<bool> TargetCollector::requestRegister(const std::string& name, const SessionTargetSummary& lastSession) {
	std::promise<bool> p;
	std::future<bool> fut = p.get_future();
	{
		std::lock_guard<std::mutex> lock(pendingMtx);
		auto& cmd = pendingByName[name];	// 없으면 새로 생성, 있으면 기존 항목에 합쳐짐
		cmd.type = PendingType::Register;	// 가장 나중 요청의 종류로 덮어씀
		cmd.lastSession = lastSession;
		cmd.waiters.push_back(std::move(p));
	}
	pendingCv.notify_one();
	return fut;
}

std::future<bool> TargetCollector::requestUnregister(const std::string& name) {
	std::promise<bool> p;
	std::future<bool> fut = p.get_future();
	{
		std::lock_guard<std::mutex> lock(pendingMtx);
		auto& cmd = pendingByName[name];
		cmd.type = PendingType::Unregister;
		cmd.waiters.push_back(std::move(p));
	}
	pendingCv.notify_one();
	return fut;
}

// -------------------------------------------------------
// 메인 루프 스레드에서 호출 — 큐에 쌓인 요청을 이 스레드 컨텍스트에서 반영한다.
// registerTarget/unregisterTarget/updateLastSession은 여기서만 호출되므로
// 기존처럼 락 없이 안전하게 동작한다.
// -------------------------------------------------------
void TargetCollector::applyPending() {
	std::unordered_map<std::string, PendingCommand> local;
	{
		std::lock_guard<std::mutex> lock(pendingMtx);
		std::swap(local, pendingByName);
	}

	for (auto& [name, cmd] : local) {
		if (cmd.type == PendingType::Register) {
			registerTarget(name);
			if (cmd.lastSession.hasData())
				updateLastSession(name, cmd.lastSession);
		}
		else {
			unregisterTarget(name);
		}
		for (auto& p : cmd.waiters)
			p.set_value(true);
	}
}

bool TargetCollector::waitForPendingUntil(std::chrono::steady_clock::time_point deadline) {
	std::unique_lock<std::mutex> lock(pendingMtx);
	return pendingCv.wait_until(lock, deadline, [this] {
		return !pendingByName.empty();
		});
}

void TargetCollector::clearRegistered() {
	for (auto& e : activeTargets)
	{
		releaseProcessCounters(e.main);
		for (auto& c : e.children)
			releaseProcessCounters(c);
	}

	activeTargets.clear();
	registeredNames.clear();
	lastSessions.clear();
}

// -------------------------------------------------------
// 타겟 상태 조회
// -------------------------------------------------------
TargetStatus TargetCollector::getStatus(const std::string& name) const {
	// 실행 중인지 확인
	auto it = std::find_if(activeTargets.begin(), activeTargets.end(),
		[&](const TargetEntry& e) {return e.targetName == name; });
	if (it != activeTargets.end()) return TargetStatus::RUNNING;

	// 마지막 세션 데이터 확인
	auto sit = lastSessions.find(name);
	if (sit != lastSessions.end() && sit->second.hasData()) return TargetStatus::NOT_RUNNING;

	return TargetStatus::NEVER_SEEN;
}

// -------------------------------------------------------
// 마지막 세션 업데이트
// -------------------------------------------------------
void TargetCollector::updateLastSession(const std::string& name, const SessionTargetSummary& session) {
	lastSessions[name] = session;
}

// -------------------------------------------------------
// PDH 카운터 초기화
// -------------------------------------------------------
bool TargetCollector::initProcessCounters(ProcessCounters& counters) {
	if (!query || counters.name.empty()) return false;
	if (counters.isChild) {
		if (PdhOpenQuery(nullptr, 0, &counters.childQuery) != ERROR_SUCCESS)
			return false;
	}

	auto targetQuery = counters.isChild ? counters.childQuery : query;
	// Process V2 인스턴스 이름 = "name:pid"
	std::string instName = counters.name;
	//spdlog::info("instName: {}", instName);

	auto add = [&](const std::string& path, PDH_HCOUNTER& counter, bool required = false) -> bool {
		std::string full = "\\Process V2(" + instName + ")\\" + path;
		//spdlog::info("initProcessCounters: adding '{}'", full);
		//PDH_STATUS s = PdhAddEnglishCounterA(query, full.c_str(), 0, &counter);
		PDH_STATUS s = PdhAddCounterA(targetQuery, full.c_str(), 0, &counter);
		//spdlog::info("initProcessCounters: '{}' status=0x{:X}", path, (unsigned)s);
		if (s != ERROR_SUCCESS) {
			if (required)
			{
				spdlog::warn("TargetCollector: Essential counter error '{}' 0x{:X}", path, s);
				return false;
			}
			else {
				spdlog::warn("TargetCollector: Selective counter error '{}' 0x{:X}", path, s);
				return true;
			}
		}
		return true;
		};

	// 필수 카운터 — 중간에 실패하면 그때까지 추가된 카운터/childQuery를 정리하고 반환
	if (!add("% Processor Time", counters.cpu, true)) { releaseProcessCounters(counters); return false; }
	if (!add("Working Set - Private", counters.mem, true)) { releaseProcessCounters(counters); return false; }
	if (!add("Private Bytes", counters.privateMem, true)) { releaseProcessCounters(counters); return false; }
	if (!add("IO Read Bytes/sec", counters.diskR, true)) { releaseProcessCounters(counters); return false; }
	if (!add("IO Write Bytes/sec", counters.diskW, true)) { releaseProcessCounters(counters); return false; }

	// 선택 카운터
	add("Virtual Bytes", counters.virtualMem);
	add("Thread Count", counters.threads);
	add("Page Faults/sec", counters.pageFault);
	add("Elapsed Time", counters.elapsed);

	// 기준점 수집
	PdhCollectQueryData(targetQuery);

	return true;
}

// -------------------------------------------------------
// PDH 카운터 해제
// -------------------------------------------------------
void TargetCollector::releaseProcessCounters(ProcessCounters& counters) {
	if (counters.isChild && counters.childQuery) {
		PdhCloseQuery(counters.childQuery);
		counters.childQuery = nullptr;
	}
	auto remove = [](PDH_HCOUNTER& c) {
		if (c) { PdhRemoveCounter(c); c = nullptr; }
		};
	remove(counters.cpu);
	remove(counters.mem);
	remove(counters.privateMem);
	remove(counters.virtualMem);
	remove(counters.diskR);
	remove(counters.diskW);
	remove(counters.threads);
	remove(counters.pageFault);
	remove(counters.elapsed);
}

// -------------------------------------------------------
// 자식 프로세스 수집
// -------------------------------------------------------
SnapshotChildProcess TargetCollector::collectChild(ProcessCounters& counters, double elapsedSec, const ConnectionMap& connMap) {
	if (counters.isChild && counters.childQuery)
		PdhCollectQueryData(counters.childQuery);

	SnapshotChildProcess c;
	c.pid = counters.pid;

	auto nameResult = getProcessNameFromPid(counters.pid);
	if (nameResult.has_value()) {
		// 값이 있으면 신뢰할 수 있는 결과 — 빈 문자열이면 진짜로 종료된 프로세스라는 뜻이고,
		// collectTarget()이 이걸 보고 이번 틱 스냅샷에서 이 자식을 제외한다.
		c.processName = *nameResult;
	}
	else {
		// CreateToolhelp32Snapshot 자체가 일시적으로 실패해 생존 여부를 알 수 없는 경우 —
		// 진짜 유령으로 단정하지 않고, PDH 인스턴스 이름("targetName:pid")에서 pid를 뗀
		// 값을 대체 표시 이름으로 써서 이번 틱에도 계속 포함시킨다.
		auto sep = counters.name.rfind(':');
		c.processName = (sep != std::string::npos) ? counters.name.substr(0, sep) : counters.name;
	}

	c.cpuUsage = getPdhDouble(counters.cpu) / cores;
	c.memoryMB = getPdhDouble(counters.mem) / (1024.0 * 1024.0);
	c.privateMemoryMB = getPdhDouble(counters.privateMem) / (1024.0 * 1024.0);
	c.diskReadMBs = getPdhDouble(counters.diskR) / (1024.0 * 1024.0);
	c.diskWriteMBs = getPdhDouble(counters.diskW) / (1024.0 * 1024.0);
	c.threadCount = static_cast<uint32_t>(getPdhDouble(counters.threads));
	c.pageFaultRate = getPdhDouble(counters.pageFault);

	HANDLE hChild = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, counters.pid);
	if (hChild) {
		DWORD handleCount = 0;
		GetProcessHandleCount(hChild, &handleCount);
		c.handleCount = static_cast<uint32_t>(handleCount);
		c.gdiObjectCount = static_cast<uint32_t>(GetGuiResources(hChild, GR_GDIOBJECTS));

		CloseHandle(hChild);
	}

	NetMbps net = etwNet.getAndResetForTarget(counters.pid, elapsedSec);
	c.netSentMbps = net.sentMbps;
	c.netRecvMbps = net.recvMbps;
	c.connections = lookupConnections(connMap, counters.pid);

	return c;
}

// -------------------------------------------------------
// 단일 타겟 수집
// -------------------------------------------------------
SnapshotTarget TargetCollector::collectTarget(TargetEntry& entry, double elapsedSec, const ConnectionMap& connMap) {
	SnapshotTarget s;
	s.pid = entry.main.pid;
	s.targetName = entry.targetName;
	s.exePath = getExePath(entry.main.pid);

	// 메인 프로세스 수집
	s.cpuUsage = getPdhDouble(entry.main.cpu) / cores;
	s.memoryMB = getPdhDouble(entry.main.mem) / (1024.0 * 1024.0);
	s.privateMemoryMB = getPdhDouble(entry.main.privateMem) / (1024.0 * 1024.0);
	s.virtualMemoryMB = getPdhDouble(entry.main.virtualMem) / (1024.0 * 1024.0);
	s.diskReadMBs = getPdhDouble(entry.main.diskR) / (1024.0 * 1024.0);
	s.diskWriteMBs = getPdhDouble(entry.main.diskW) / (1024.0 * 1024.0);
	s.threadCount = static_cast<uint32_t>(getPdhDouble(entry.main.threads));
	s.pageFaultRate = getPdhDouble(entry.main.pageFault);
	s.elapsedSec = getPdhDouble(entry.main.elapsed);

	HANDLE hMain = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, entry.main.pid);
	// 핸들 수 / GDI 오브젝트
	if (hMain) {
		DWORD handleCount = 0;
		GetProcessHandleCount(hMain, &handleCount);
		s.handleCount = static_cast<uint32_t>(handleCount);
		s.gdiObjectCount = static_cast<uint32_t>(GetGuiResources(hMain, GR_GDIOBJECTS));
		CloseHandle(hMain);
	}

	// ETW 네트워크
	NetMbps net = etwNet.getAndResetForTarget(entry.main.pid, elapsedSec);
	s.netSentMbps = net.sentMbps;
	s.netRecvMbps = net.recvMbps;
	s.connections = lookupConnections(connMap, entry.main.pid);

	// 자식 프로세스 수집
	// syncChildren()이 최대 5초 주기로만 목록을 정리하므로, 그 사이 이미 종료된 자식이
	// entry.children에 남아있을 수 있다 — processName을 못 찾으면(getProcessNameFromPid 실패)
	// 이미 죽은 프로세스로 보고 이번 틱 스냅샷에서 제외한다(이름 빈 문자열/수치 0인 유령 항목이
	// API 응답이나 DB에 그대로 나가는 것을 방지).
	for (auto& child : entry.children) {
		SnapshotChildProcess sc = collectChild(child, elapsedSec, connMap);
		if (sc.processName.empty()) continue;
		s.children.push_back(std::move(sc));
	}

	return s;
}

// -------------------------------------------------------
// 실행 감지 → 수집 시작
// -------------------------------------------------------
PdhInstanceInfo TargetCollector::activateTarget(const std::string& name, DWORD pid) {
	auto info = findMainPdhInstance(name, pid);
	if (!info.isValid()) {
		spdlog::info("TargetCollector: '{}' No Active ", name);
		return {};
	}

	spdlog::debug("activateTarget: '{}' findMain done PID={}", name, info.pid);

	// 이미 active인지 확인
	auto it = std::find_if(activeTargets.begin(), activeTargets.end(),
		[&](const TargetEntry& e) { return e.targetName == name; });
	if (it != activeTargets.end()) return {};

	TargetEntry entry;
	entry.targetName = name;
	entry.main.pid = info.pid;
	entry.main.name = info.instanceName;

	spdlog::debug("activateTarget: '{}' before initProcessCounters", name);

	if (entry.main.name.empty()) {
		spdlog::warn("TargetCollector: '{}' PDH instance is empty", name);
		return {};
	}

	if (!initProcessCounters(entry.main)) {
		spdlog::warn("TargetCollector: '{}' counter init fail", name);
		return {};
	}

	activeTargets.push_back(std::move(entry));
	spdlog::info("TargetCollector: '{}' (PID={}) collect start", name, info.pid);
	return info;
}

// -------------------------------------------------------
// 종료 감지 → 수집 중단
// -------------------------------------------------------
void TargetCollector::deactivateTarget(const std::string& name, bool notifyPending) {
	auto it = std::find_if(activeTargets.begin(), activeTargets.end(), [&](const TargetEntry& e) { return e.targetName == name; });
	if (it == activeTargets.end()) return;

	spdlog::info("TargetCollector: '{}' collect stop", it->targetName);
	releaseProcessCounters(it->main);
	for (auto& c : it->children)
		releaseProcessCounters(c);
	activeTargets.erase(it);

	if (notifyPending)
		pendingDeactivated.push_back(name);
}

// -------------------------------------------------------
// 자식 PID 목록
// -------------------------------------------------------
std::vector<DWORD> TargetCollector::getChildPids(DWORD pid) {
	std::vector<DWORD> result;
	HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snap == INVALID_HANDLE_VALUE) return result;

	PROCESSENTRY32 entry = {};
	entry.dwSize = sizeof(entry);
	if (Process32First(snap, &entry)) {
		do {
			if (entry.th32ParentProcessID == pid && entry.th32ProcessID != pid)
				result.push_back(entry.th32ProcessID);
		} while (Process32Next(snap, &entry));
	}
	CloseHandle(snap);
	return result;
}

// -------------------------------------------------------
// 자식 프로세스 동기화
// -------------------------------------------------------
void TargetCollector::syncChildren(TargetEntry& entry) {
	auto currentChildPids = getChildPids(entry.main.pid);

	// 새 자식 추가
	for (DWORD cpid : currentChildPids) {
		bool exists = std::any_of(entry.children.begin(), entry.children.end(),
			[&](const ProcessCounters& c) { return c.pid == cpid; });
		if (exists) continue;


		//std::string childName = getProcessNameFromPid(cpid);
		auto info = findChildPdhInstance(entry.targetName, cpid);
		if (!info.isValid()) continue;
		if (info.pid != cpid) {
			spdlog::warn("syncChildren: PID Disagreement {} != {}", info.pid, cpid);
			continue;
		}

		ProcessCounters pc;
		pc.pid = cpid;
		pc.name = info.instanceName;
		if (pc.name.empty()) continue;
		pc.isChild = true;

		if (initProcessCounters(pc)) {
			entry.children.push_back(std::move(pc));
			//spdlog::info("TargetCollector: '{}' add child PID={}", entry.targetName, cpid);
		}
	}

	// 종료된 자식 제거
	auto termination = [&](ProcessCounters& c) -> bool {
		bool alive = std::find(currentChildPids.begin(), currentChildPids.end(), c.pid) != currentChildPids.end();
		if (!alive) releaseProcessCounters(c);
		return !alive;
		};
	entry.children.erase(std::remove_if(entry.children.begin(), entry.children.end(),
		termination), entry.children.end());
}

// -------------------------------------------------------
// 전체 수집
// -------------------------------------------------------
void TargetCollector::collect() {
	// 등록된 타겟이 하나도 없어도 snapshot은 항상 "타겟 없음"으로 최신 상태를 반영해야 한다.
	// 이 초기화를 아래 조기 반환보다 뒤에 두면, 마지막 타겟을 해제한 뒤에도 snapshot이
	// 그 직전(심지어 running이었던) 상태로 얼어붙어 버려서 SysMonitor.cpp가 매 틱 그대로
	// DataStore에 재전송하게 된다 — API가 이미 해제된 타겟을 영원히 "실행 중"으로 보고하고,
	// flushTargetToDBInternal()이 동일 타임스탬프 행을 계속 재삽입하는 원인이 된다.
	snapshot.timestamp = std::chrono::system_clock::now();
	snapshot.targets.clear();

	if (registeredNames.empty()) return;

	auto now = std::chrono::steady_clock::now();
	double elapsedSec = std::chrono::duration<double>(now - lastTime).count();
	lastTime = now;
	if (elapsedSec <= 0.0) elapsedSec = 1.0;

	// 등록된 타겟 중 새로 실행된 것 감지 -> activate
	// CreateToolhelp32Snapshot을 이름마다 따로 뜨지 않도록, 아직 활성화되지 않은 이름을
	// 전부 모아 findRunningPids()로 스냅샷 1번에 한꺼번에 대조한다.
	std::vector<std::string> notActiveNames;
	for (const auto& name : registeredNames) {
		bool isActive = std::any_of(activeTargets.begin(), activeTargets.end(), [&](const TargetEntry& e) {return e.targetName == name; });
		if (!isActive) notActiveNames.push_back(name);
	}

	if (!notActiveNames.empty()) {
		auto runningPids = findRunningPids(notActiveNames);
		for (const auto& name : notActiveNames) {
			auto it = runningPids.find(name);
			if (it == runningPids.end()) continue;	// 이번 틱엔 미실행 -> PDH 비용 없이 스킵

			auto info = activateTarget(name, it->second);
			if (info.isValid()) {
				spdlog::info("TargetCollector: '{}' (PID={}) running detect", name, info.pid);
			}
		}
	}

	//// 자식 프로세스 동기화 (매 수집마다)
	//for (auto& entry : activeTargets)
	//	syncChildren(entry);
	 // 자식 동기화 — 5초마다
	if (++cleanupTick >= 5) {
		for (auto& entry : activeTargets)
			syncChildren(entry);
		cleanupTick = 0;
	}

	// PDH 수집
	if (!activeTargets.empty()) PdhCollectQueryData(query);

	// 종료된 프로세스 감지
	std::vector<std::string> deadTargets;

	auto connMap = getAllConnectionsGroupedByPid();
	for (auto& entry : activeTargets) {
		HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, entry.main.pid);

		if (!hProc) {
			spdlog::info("TargetCollector: '{}' shutdown detect", entry.targetName);
			deadTargets.push_back(entry.targetName);
			continue;
		}
		CloseHandle(hProc);
		SnapshotTarget s = collectTarget(entry, elapsedSec, connMap);
		s.calcTotals();
		snapshot.targets.push_back(std::move(s));
	}

	// 종료된 프로세스 deactivate
	for (const auto& name : deadTargets)
		deactivateTarget(name);

	// 실행 중이 아닌 등록 타겟도 상태 + 마지막 세션 요약을 스냅샷에 포함
	// (API가 TargetCollector::getStatus()/lastSessions를 직접 호출하지 않고도
	//  DataStore 경유로 NOT_RUNNING/NEVER_SEEN 타겟을 볼 수 있도록)
	for (const auto& name : registeredNames) {
		bool isRunning = std::any_of(snapshot.targets.begin(), snapshot.targets.end(),
			[&](const SnapshotTarget& t) { return t.targetName == name; });
		if (isRunning) continue;

		SnapshotTarget s;
		s.targetName = name;

		auto sit = lastSessions.find(name);
		if (sit != lastSessions.end() && sit->second.hasData()) {
			s.status = "not_running";
			s.exePath = sit->second.exePath;
			s.lastSessionDate = sit->second.date;
			s.lastAvgCpuUsage = sit->second.avgCpuUsage;
			s.lastPeakCpuUsage = sit->second.peakCpuUsage;
			s.lastAvgMemoryMB = sit->second.avgMemoryMB;
			s.lastPeakMemoryMB = sit->second.peakMemoryMB;
			s.lastAvgNetMbps = sit->second.avgNetMbps;
			s.lastPeakNetMbps = sit->second.peakNetMbps;
			s.lastPeakThreadCount = sit->second.peakThreadCount;
			s.lastPeakHandleCount = sit->second.peakHandleCount;
			s.lastTotalRuntimeSec = sit->second.totalRuntime;
		}
		else {
			s.status = "never_seen";
		}
		snapshot.targets.push_back(std::move(s));
	}
}

// -------------------------------------------------------
// 메인 프로세스 PDH 인스턴스 탐색 — Process V2 적용
// -------------------------------------------------------
// -------------------------------------------------------
// 등록됐지만 아직 활성화되지 않은 이름들을 대상으로 CreateToolhelp32Snapshot을
// 딱 1번만 떠서 전부와 한 번에 대조한다. 이전에는 findMainPdhInstance()가 이름마다
// 개별로 스냅샷을 떠서, 등록된 이름이 K개면 매 틱 스냅샷을 K번 뜨는 중복 비용이 있었다.
// -------------------------------------------------------
std::unordered_map<std::string, DWORD> TargetCollector::findRunningPids(const std::vector<std::string>& notActiveNames) {
	std::unordered_map<std::string, DWORD> result;
	if (notActiveNames.empty()) return result;

	HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snap == INVALID_HANDLE_VALUE) return result;

	PROCESSENTRY32 entry = {};
	entry.dwSize = sizeof(entry);
	if (Process32First(snap, &entry)) {
		do {
			std::string exeName = entry.szExeFile;
			if (exeName.size() > 4 && exeName.substr(exeName.size() - 4) == ".exe")
				exeName = exeName.substr(0, exeName.size() - 4);

			for (const auto& name : notActiveNames) {
				if (result.count(name)) continue;	// 이미 찾음
				if (exeName == name) {
					result[name] = entry.th32ProcessID;
					break;
				}
			}
			if (result.size() == notActiveNames.size()) break;	// 전부 찾았으면 조기 종료
		} while (Process32Next(snap, &entry));
	}
	CloseHandle(snap);

	return result;
}

PdhInstanceInfo TargetCollector::findMainPdhInstance(const std::string& name, DWORD targetPid) {
	if (targetPid == 0) return {};

	// Process V2로 PID 검증
	std::string instName = name + ":" + std::to_string(targetPid);
	std::string path = "\\Process V2(" + instName + ")\\Process ID";
	spdlog::debug("findMainPdhInstance: path='{}'", path);

	PDH_HQUERY tq = nullptr;
	PDH_HCOUNTER tc = nullptr;

	PDH_STATUS openStatus = PdhOpenQuery(nullptr, 0, &tq);
	spdlog::debug("findMainPdhInstance: PdhOpenQuery status=0x{:X} tq={}", (unsigned)openStatus, (void*)tq);
	if (openStatus != ERROR_SUCCESS) {
		PdhCloseQuery(tq);
		spdlog::warn("findMainPdhInstance: PdhOpenQuery failed");
		return {};
	}

	//PDH_STATUS s = PdhAddEnglishCounterA(tq, path.c_str(), 0, &tc);
	PDH_STATUS s = PdhAddCounterA(tq, path.c_str(), 0, &tc);
	if (s != ERROR_SUCCESS) {
		PdhCloseQuery(tq);
		spdlog::warn("findMainPdhInstance: Process V2 counter add failed '{}' error 0x{:X}", instName, (unsigned)s);
		return {};
	}

	PdhCollectQueryData(tq);

	PDH_FMT_COUNTERVALUE val = {};
	if (PdhGetFormattedCounterValue(tc, PDH_FMT_LONG, nullptr, &val) != ERROR_SUCCESS) {
		PdhCloseQuery(tq);
		return {};
	}

	DWORD pid = static_cast<DWORD>(val.longValue);
	PdhCloseQuery(tq);

	if (pid != targetPid) {
		spdlog::warn("findMainPdhInstance: PID mismatch {} != {}", pid, targetPid);
		return {};
	}

	PdhInstanceInfo result;
	result.instanceName = instName;		// "chrome:7500"
	result.pid = pid;
	return result;
}

// -------------------------------------------------------
// 자식 프로세스 PDH 인스턴스 탐색 — Process V2 적용
// -------------------------------------------------------
PdhInstanceInfo TargetCollector::findChildPdhInstance(const std::string& name, DWORD targetPid) {
	// Process V2 인스턴스 이름 = "name:pid"
	std::string instName = name + ":" + std::to_string(targetPid);
	std::string path = "\\Process V2(" + instName + ")\\Process ID";

	PDH_HQUERY tq = nullptr;
	PDH_HCOUNTER tc = nullptr;

	if (PdhOpenQuery(nullptr, 0, &tq) != ERROR_SUCCESS) {
		PdhCloseQuery(tq);
		return {};
	}

	PDH_STATUS s = PdhAddCounterA(tq, path.c_str(), 0, &tc);
	//PDH_STATUS s = PdhAddEnglishCounterA(tq, path.c_str(), 0, &tc);
	if (s != ERROR_SUCCESS) {
		PdhCloseQuery(tq);
		spdlog::warn("findChildPdhInstance: Process V2 counter add failed '{}'", instName);
		return {};
	}

	PdhCollectQueryData(tq);

	PDH_FMT_COUNTERVALUE val = {};
	if (PdhGetFormattedCounterValue(tc, PDH_FMT_LONG, nullptr, &val) != ERROR_SUCCESS) {
		PdhCloseQuery(tq);
		return {};
	}

	DWORD pid = static_cast<DWORD>(val.longValue);
	PdhCloseQuery(tq);

	if (pid != targetPid) {
		spdlog::warn("findChildPdhInstance: PID mismatch {} != {}", pid, targetPid);
		return {};
	}

	PdhInstanceInfo result;

	result.instanceName = instName;
	result.pid = pid;
	return result;
}

// -------------------------------------------------------
// 프로세스 이름 조회
// -------------------------------------------------------
std::optional<std::string> TargetCollector::getProcessNameFromPid(DWORD pid) {
	HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snap == INVALID_HANDLE_VALUE) {
		// 스냅샷 API 자체가 실패 — 이 PID가 살아있는지 죽었는지 전혀 알 수 없는 상태이므로,
		// "없다"는 뜻의 빈 문자열과 구분해서 nullopt로 알린다.
		spdlog::debug("getProcessNameFromPid: CreateToolhelp32Snapshot failed (pid={})", pid);
		return std::nullopt;
	}

	PROCESSENTRY32 entry = {};
	entry.dwSize = sizeof(entry);

	if (Process32First(snap, &entry)) {
		do {
			if (entry.th32ProcessID == pid) {
				CloseHandle(snap);
				std::string name = entry.szExeFile;
				if (name.size() > 4 && name.substr(name.size() - 4) == ".exe")
					name = name.substr(0, name.size() - 4);
				return name;
			}
		} while (Process32Next(snap, &entry));
	}
	// 스냅샷은 성공했는데 그 안에 PID가 없음 — syncChildren()의 5초 정리 주기 사이에
	// 이미 종료된 자식을 조회하는 흔한 경우라 warn이 아니라 debug로 남긴다
	// (collectTarget()이 이 경우를 감지해 스냅샷에서 제외하므로 경고할 실질적 문제는 아님).
	spdlog::debug("getProcessNameFromPid: pid={} not found in snapshot (process likely exited)", pid);
	CloseHandle(snap);
	return "";
}

// -------------------------------------------------------
// 실행 파일 경로
// -------------------------------------------------------
std::string TargetCollector::getExePath(DWORD pid) {
	HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
	if (!hProc) return "";
	char path[MAX_PATH] = {};
	DWORD size = MAX_PATH;
	QueryFullProcessImageNameA(hProc, 0, path, &size);
	CloseHandle(hProc);
	return std::string(path);
}

// -------------------------------------------------------
// PDH 값 double 반환
// -------------------------------------------------------
double TargetCollector::getPdhDouble(PDH_HCOUNTER counter) {
	if (!counter) return 0.0;
	PDH_FMT_COUNTERVALUE val = {};
	PDH_STATUS status = PdhGetFormattedCounterValue(counter, PDH_FMT_DOUBLE, nullptr, &val);
	if (status != ERROR_SUCCESS)
		return 0.0;
	if (val.CStatus != PDH_CSTATUS_VALID_DATA && val.CStatus != PDH_CSTATUS_NEW_DATA)
		return 0.0;
	if (std::isnan(val.doubleValue) || std::isinf(val.doubleValue))
		return 0.0;
	return val.doubleValue;
}

// -------------------------------------------------------
// 네트워크 연결 목록
// -------------------------------------------------------
TargetCollector::ConnectionMap TargetCollector::getAllConnectionsGroupedByPid() {
	ConnectionMap result;

	// TCP
	DWORD size = 0;
	GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
	if (size > 0) {
		std::vector<BYTE> tcpBuf(size);
		auto* table = reinterpret_cast<MIB_TCPTABLE_OWNER_PID*>(tcpBuf.data());
		if (GetExtendedTcpTable(table, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
			for (DWORD i = 0; i < table->dwNumEntries; ++i) {
				auto& row = table->table[i];
				TargetNetConnection conn;
				conn.protocol = "TCP";
				conn.localAddr = addrToString(row.dwLocalAddr, ntohs(static_cast<u_short>(row.dwLocalPort)));
				conn.remoteAddr = addrToString(row.dwRemoteAddr, ntohs(static_cast<u_short>(row.dwRemotePort)));
				conn.state = tcpStateToString(row.dwState);
				result[row.dwOwningPid].push_back(std::move(conn));
			}
		}
	}

	// UDP
	size = 0;
	GetExtendedUdpTable(nullptr, &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
	if (size > 0) {
		std::vector<BYTE> udpBuf(size);
		auto* table = reinterpret_cast<MIB_UDPTABLE_OWNER_PID*>(udpBuf.data());
		if (GetExtendedUdpTable(table, &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
			for (DWORD i = 0; i < table->dwNumEntries; ++i) {
				auto& row = table->table[i];
				TargetNetConnection conn;
				conn.protocol = "UDP";
				conn.localAddr = addrToString(row.dwLocalAddr, ntohs(static_cast<u_short>(row.dwLocalPort)));
				conn.remoteAddr = "-";
				conn.state = "BOUND";	// UDP는 상태가 없음 중립인 바운드로 처리
				result[row.dwOwningPid].push_back(std::move(conn));
			}
		}
	}
	return result;
}

// PID 하나만 빼기
std::vector< TargetNetConnection> TargetCollector::lookupConnections(const TargetCollector::ConnectionMap& map, DWORD pid) {
	auto it = map.find(pid);
	if (it == map.end()) return {};
	return it->second;
}

// -------------------------------------------------------
// IP:Port 문자열
// -------------------------------------------------------
std::string TargetCollector::addrToString(DWORD ip, WORD port) {
	in_addr addr;
	addr.s_addr = ip;
	char buf[INET_ADDRSTRLEN] = {};
	inet_ntop(AF_INET, &addr, buf, sizeof(buf));
	return std::string(buf) + ":" + std::to_string(port);

}

// -------------------------------------------------------
// TCP 상태 문자열
// -------------------------------------------------------
std::string TargetCollector::tcpStateToString(DWORD state) {
	switch (state) {
	case MIB_TCP_STATE_CLOSED:     return "CLOSED";
	case MIB_TCP_STATE_LISTEN:     return "LISTEN";
	case MIB_TCP_STATE_SYN_SENT:   return "SYN_SENT";
	case MIB_TCP_STATE_SYN_RCVD:   return "SYN_RCVD";
	case MIB_TCP_STATE_ESTAB:      return "ESTABLISHED";
	case MIB_TCP_STATE_FIN_WAIT1:  return "FIN_WAIT1";
	case MIB_TCP_STATE_FIN_WAIT2:  return "FIN_WAIT2";
	case MIB_TCP_STATE_CLOSE_WAIT: return "CLOSE_WAIT";
	case MIB_TCP_STATE_CLOSING:    return "CLOSING";
	case MIB_TCP_STATE_LAST_ACK:   return "LAST_ACK";
	case MIB_TCP_STATE_TIME_WAIT:  return "TIME_WAIT";
	case MIB_TCP_STATE_DELETE_TCB: return "DELETE_TCB";
	default:                       return "UNKNOWN";
	}
}


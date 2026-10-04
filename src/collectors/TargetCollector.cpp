#include "collectors/TargetCollector.h"
#include "util/StrUtil.h"

// 문자열 규칙 : 타겟/프로세스 이름·경로는 전부 UTF-8 std::string으로 다룬다.
// ToolHelp32 / QueryFullProcessImageName은 W 버전 결과를 UTF-8로 바꾸고, PDH 카운터 경로처럼
// 이름을 Win32에 되돌려 넘길 때는 utf8ToWide() 후 W 버전에 넘긴다 — A 버전에 UTF-8을 넘기면
// CP949로 해석되어 한글 이름의 인스턴스를 찾지 못한다.

namespace {
	// 타겟 이름 규칙(끝의 ".exe" 제거, 대소문자 무시 비교)은 ProcessCollector와 함께 쓰도록 util/StrUtil에 있다.
	using StrUtil::exeBaseName;
	using StrUtil::sameExeName;

	// 프로세스를 열어야만 얻는 값.
	// 관리자 권한 없이 실행한 Agent는 다른 계정(서비스)의 프로세스를 열지 못한다 — 그때 값을 0으로 채우면
	// 서버에서 "진짜 0"과 구분할 수 없으므로 비워 둔다. 여기의 OpenProcess는 생존 판정이 아니다 (생존은 isAlive()).
	struct OpenedProcessInfo {
		std::optional<uint32_t> gdiObjectCount;	// 열지 못하면 비어 있음
		bool accessDenied = false;				// 못 연 이유가 권한(ERROR_ACCESS_DENIED)인가
	};

	OpenedProcessInfo queryOpenedProcess(DWORD pid) {
		OpenedProcessInfo info;
		HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
		if (!h) {
			info.accessDenied = (GetLastError() == ERROR_ACCESS_DENIED);
			return info;
		}
		// GetGuiResources는 실패해도 0을 돌려준다 — 화면이 없는 프로세스의 "실제 0"과 구분하려면 오류 코드를 봐야 한다.
		// 성공했을 때 오류 코드를 지워 준다는 보장이 없으므로 호출 전에 직접 지운다.
		SetLastError(ERROR_SUCCESS);
		const DWORD gdi = GetGuiResources(h, GR_GDIOBJECTS);
		if (gdi != 0 || GetLastError() == ERROR_SUCCESS)
			info.gdiObjectCount = static_cast<uint32_t>(gdi);
		CloseHandle(h);
		return info;
	}

	// PDH "Working Set - Private"(바이트) → MB. 열 권한이 없는 프로세스는 이 카운터가 0으로 읽히는 경우가 있다
	// (실측: 서비스로 도는 mysqld — 실제 Working Set은 11.6MB). 권한이 없으면서 0이면 "수집하지 못함"으로 본다.
	// 권한이 없어도 0이 아닌 값은 PDH가 실제로 읽은 값이므로 그대로 쓴다.
	std::optional<double> privateWorkingSetMB(double bytes, bool accessDenied) {
		if (accessDenied && bytes == 0.0) return std::nullopt;
		return bytes / (1024.0 * 1024.0);
	}
} // namespace

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
void TargetCollector::registerTarget(const std::string& rawName) {
	const std::string name = StrUtil::wideToUtf8(exeBaseName(StrUtil::utf8ToWide(rawName)));
	if (name.empty()) {
		spdlog::warn("TargetCollector: empty target name '{}' ignored", rawName);
		return;
	}

	// 이름 형식 검사 — 타겟 이름은 실행 파일 이름이다.
	// 파일 이름에 쓸 수 없는 문자가 있으면 어떤 프로세스와도 매칭될 수 없으므로(경로를 넣는 실수가 대표적),
	// 영원히 NEVER_SEEN으로 남게 두지 않고 등록 시점에 거부한다. 전부 ASCII라 UTF-8 바이트로 찾아도 안전하다.
	if (name.find_first_of("\\/:*?\"<>|") != std::string::npos) {
		spdlog::warn("TargetCollector: '{}' rejected: a target is a process name (e.g. notepad), not a path; "
			"it contains a character that a file name cannot have (\\ / : * ? \" < > |)", rawName);
		return;
	}

	// 중복확인 — 대소문자만 다른 이름("notepad" / "Notepad")도 같은 타겟이다
	if (const std::string* existing = findRegistered(name)) {
		spdlog::warn("TargetCollector: '{}' already registered (as '{}')", rawName, *existing);
		return;
	}

	// '#'은 파일 이름으로는 유효하지만 PDH 경로 문법에서 "같은 이름의 N번째 인스턴스" 구분자라,
	// \Process V2(<이름>:<pid>) 경로로 표현할 수 없다 (실측: 카운터 추가는 성공하고 값 읽기가 실패).
	// 그런 프로그램이 실제로 있을 수 있으므로 등록은 받되, 수집되지 않는다는 것을 미리 알린다.
	if (name.find('#') != std::string::npos) {
		spdlog::warn("TargetCollector: '{}' cannot be collected: '#' is the instance-index separator in a PDH counter path, "
			"so its counters cannot be addressed. It will be reported as not running even while it runs", name);
	}

	registeredNames.push_back(name);
	spdlog::info("TargetCollector: '{}' register target", name);
}

const std::string* TargetCollector::findRegistered(const std::string& name) const {
	const std::wstring wname = StrUtil::utf8ToWide(name);
	const std::wstring_view base = exeBaseName(wname);
	for (const auto& r : registeredNames) {
		if (sameExeName(base, StrUtil::utf8ToWide(r))) return &r;
	}
	return nullptr;
}

// -------------------------------------------------------
// 타겟 해제
// -------------------------------------------------------
void TargetCollector::unregisterTarget(const std::string& rawName) {
	// 등록할 때 저장된 철자로 바꾼다 — activeTargets/lastSessions는 그 철자를 키로 쓴다
	const std::string* registered = findRegistered(rawName);
	if (!registered) {
		spdlog::warn("TargetCollector: '{}' is not registered", rawName);
		return;
	}
	const std::string name = *registered;	// 아래 erase로 원본이 사라지므로 복사

	// registeredNames에서 제거
	registeredNames.erase(std::remove(registeredNames.begin(), registeredNames.end(), name), registeredNames.end());

	// 실행 중이면 deactivate — 사용자가 명시적으로 해제 요청한 경로이므로
	// pendingDeactivated에는 넣지 않는다(아래 lastSessions.erase가 곧바로 뒤집히는 걸 방지).
	deactivateTarget(name, /*notifyPending=*/false);

	// 마지막 세션 제거
	lastSessions.erase(name);
	activationFailWarned.erase(name);
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
	activationFailWarned.clear();
}

// -------------------------------------------------------
// 타겟 상태 조회
// -------------------------------------------------------
TargetStatus TargetCollector::getStatus(const std::string& rawName) const {
	const std::string* registered = findRegistered(rawName);
	const std::string& name = registered ? *registered : rawName;

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
	// 등록된 타겟이면 저장된 철자를 키로 쓴다 — collect()가 그 철자로 lastSessions를 찾는다
	const std::string* registered = findRegistered(name);
	lastSessions[registered ? *registered : name] = session;
}

// -------------------------------------------------------
// PDH 카운터 초기화
// -------------------------------------------------------
bool TargetCollector::initProcessCounters(ProcessCounters& counters, std::string* failReason) {
	if (!query || counters.name.empty()) {
		if (failReason) *failReason = "PDH query is not open";
		return false;
	}
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
		PDH_STATUS s = PdhAddCounterW(targetQuery, StrUtil::utf8ToWide(full).c_str(), 0, &counter);
		//spdlog::info("initProcessCounters: '{}' status=0x{:X}", path, (unsigned)s);
		if (s != ERROR_SUCCESS) {
			if (required)
			{
				// failReason을 받는 호출부(activateTarget)는 타겟당 1번만 경고하므로 여기서 따로 찍지 않는다
				if (failReason)
					*failReason = fmt::format("essential counter '{}' could not be added (0x{:X})", path, static_cast<unsigned>(s));
				else
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
	add("Handle Count", counters.handles);	// GetProcessHandleCount 대신 — 프로세스를 열 권한이 없어도 읽힌다
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
	remove(counters.handles);
	remove(counters.pageFault);
	remove(counters.elapsed);
}

// -------------------------------------------------------
// 자식 프로세스 수집
// -------------------------------------------------------
SnapshotChildProcess TargetCollector::collectChild(ProcessCounters& counters, double elapsedSec, const ConnectionMap& connMap, bool& accessDenied) {
	if (counters.isChild && counters.childQuery)
		PdhCollectQueryData(counters.childQuery);

	SnapshotChildProcess c;
	c.pid = counters.pid;
	c.processName = counters.exeName;	// syncChildren()이 프로세스 목록에서 받아 둔 실제 이름 — 매 틱 다시 조회하지 않는다

	const OpenedProcessInfo opened = queryOpenedProcess(counters.pid);
	if (opened.accessDenied) accessDenied = true;

	c.cpuUsage = getPdhDouble(counters.cpu) / cores;
	c.memoryMB = privateWorkingSetMB(getPdhDouble(counters.mem), opened.accessDenied);
	c.privateMemoryMB = getPdhDouble(counters.privateMem) / (1024.0 * 1024.0);
	c.diskReadMBs = getPdhDouble(counters.diskR) / (1024.0 * 1024.0);
	c.diskWriteMBs = getPdhDouble(counters.diskW) / (1024.0 * 1024.0);
	c.threadCount = static_cast<uint32_t>(getPdhDouble(counters.threads));
	c.handleCount = static_cast<uint32_t>(getPdhDouble(counters.handles));
	c.gdiObjectCount = opened.gdiObjectCount;
	c.pageFaultRate = getPdhDouble(counters.pageFault);

	NetMbps net = etwNet.getAndResetForTarget(counters.pid, elapsedSec);
	c.netSentMbps = net.sentMbps;
	c.netRecvMbps = net.recvMbps;
	c.connections = lookupConnections(connMap, counters.pid);

	return c;
}

// -------------------------------------------------------
// 단일 타겟 수집
// -------------------------------------------------------
SnapshotTarget TargetCollector::collectTarget(TargetEntry& entry, double elapsedSec, const ConnectionMap& connMap, const ProcessList* procs) {
	SnapshotTarget s;
	s.pid = entry.main.pid;
	s.targetName = entry.targetName;
	s.processName = entry.exeName;
	s.exePath = getExePath(entry.main.pid);

	const OpenedProcessInfo opened = queryOpenedProcess(entry.main.pid);
	bool accessDenied = opened.accessDenied;	// 메인 또는 자식 중 하나라도 열 권한이 없었는가

	// 메인 프로세스 수집
	s.cpuUsage = getPdhDouble(entry.main.cpu) / cores;
	s.memoryMB = privateWorkingSetMB(getPdhDouble(entry.main.mem), opened.accessDenied);
	s.privateMemoryMB = getPdhDouble(entry.main.privateMem) / (1024.0 * 1024.0);
	s.virtualMemoryMB = getPdhDouble(entry.main.virtualMem) / (1024.0 * 1024.0);
	s.diskReadMBs = getPdhDouble(entry.main.diskR) / (1024.0 * 1024.0);
	s.diskWriteMBs = getPdhDouble(entry.main.diskW) / (1024.0 * 1024.0);
	s.threadCount = static_cast<uint32_t>(getPdhDouble(entry.main.threads));
	s.handleCount = static_cast<uint32_t>(getPdhDouble(entry.main.handles));
	s.gdiObjectCount = opened.gdiObjectCount;
	s.pageFaultRate = getPdhDouble(entry.main.pageFault);
	s.elapsedSec = getPdhDouble(entry.main.elapsed);

	// ETW 네트워크
	NetMbps net = etwNet.getAndResetForTarget(entry.main.pid, elapsedSec);
	s.netSentMbps = net.sentMbps;
	s.netRecvMbps = net.recvMbps;
	s.connections = lookupConnections(connMap, entry.main.pid);

	// 자식 프로세스 수집
	// syncChildren()이 최대 5초 주기로만 목록을 정리하므로, 그 사이 이미 종료된 자식이
	// entry.children에 남아있을 수 있다 — 이번 틱의 프로세스 목록에 없으면 수집하지 않고 스냅샷에서 제외한다
	// (수치 0인 유령 항목이 서버로 나가는 것을 방지). 판정은 메인과 같은 목록, 같은 규칙(PID + 이름)이다
	// (이전에는 자식마다 매 틱 스냅샷을 따로 뜨고 PID만 봤다).
	// 목록을 못 받은 틱(procs == nullptr)은 생존 여부를 알 수 없으므로 유령으로 단정하지 않고 그대로 수집한다.
	for (auto& child : entry.children) {
		if (procs && !isAlive(*procs, child.pid, child.exeName)) continue;
		s.children.push_back(collectChild(child, elapsedSec, connMap, accessDenied));
	}

	// 서버에는 "값 없음"으로 나가지만 원인(권한)과 해결책은 여기서만 알 수 있다 — 활성화당 1번만 남긴다.
	if (accessDenied && !entry.limitedAccessWarned) {
		entry.limitedAccessWarned = true;
		spdlog::warn("TargetCollector: '{}' (PID={}) cannot be opened (access denied): memory / exe path / GDI count may be "
			"unavailable and are sent as N/A, not 0. Run the Agent elevated or as a service to collect them",
			entry.targetName, entry.main.pid);
	}

	return s;
}

// -------------------------------------------------------
// 실행 감지 → 수집 시작
// -------------------------------------------------------
PdhInstanceInfo TargetCollector::activateTarget(const std::string& name, const RunningProcess& proc) {
	// 이미 active인지 확인
	auto it = std::find_if(activeTargets.begin(), activeTargets.end(),
		[&](const TargetEntry& e) { return e.targetName == name; });
	if (it != activeTargets.end()) return {};

	// PDH 인스턴스 경로에는 등록 이름이 아니라 실제 실행 파일 이름을 쓴다 — 매칭이 대소문자를 무시하므로
	// 둘의 대소문자가 다를 수 있고, PDH가 인스턴스 이름을 대소문자 무시로 찾아 준다는 보장에 기대지 않는다.
	std::string failReason;
	auto info = findPdhInstance(proc.exeName, proc.pid, failReason);
	if (info.isValid()) {
		spdlog::debug("activateTarget: '{}' findPdhInstance done PID={}", name, info.pid);

		TargetEntry entry;
		entry.targetName = name;
		entry.exeName = proc.exeName;
		entry.main.pid = info.pid;
		entry.main.name = info.instanceName;

		if (initProcessCounters(entry.main, &failReason)) {
			if (proc.exeName != name) {
				spdlog::info("TargetCollector: '{}' matched process '{}.exe' (names are case-insensitive)", name, proc.exeName);
			}
			activeTargets.push_back(std::move(entry));
			activationFailWarned.erase(name);
			spdlog::info("TargetCollector: '{}' (PID={}) collect start", name, info.pid);
			return info;
		}
	}

	// 여기까지 왔으면 "실행 중인데 수집을 시작하지 못함"이다.
	// 서버에는 미실행 상태로 나가므로 원인은 이 로그에서만 알 수 있다. 활성화는 매 틱 다시 시도하지만
	// 경고는 같은 프로세스(PID)에 대해 1번만 남긴다 — 이전에는 원인 없는 info('No Active')가 매 초 쌓였다.
	auto warned = activationFailWarned.find(name);
	if (warned == activationFailWarned.end() || warned->second != proc.pid) {
		activationFailWarned[name] = proc.pid;
		spdlog::warn("TargetCollector: '{}' (PID={}) is running but could not be activated: {}{}. "
			"It is reported as not running; activation is retried every tick and this warning is logged once",
			name, proc.pid, failReason,
			proc.exeName.find('#') != std::string::npos ? " ('#' in the name cannot be expressed in a PDH counter path)" : "");
	}
	return {};
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
// 자식 프로세스 동기화
// -------------------------------------------------------
void TargetCollector::syncChildren(TargetEntry& entry, const ProcessList& procs) {
	// 종료된 자식 제거 — 목록에 "같은 PID + 같은 이름"이 없으면 종료로 본다 (isAlive 규칙).
	// 추가보다 먼저 한다: PID가 다른 프로세스에 재사용된 경우 옛 항목을 지워야 아래에서 새 프로세스로 다시 볼 수 있다.
	auto termination = [&](ProcessCounters& c) -> bool {
		bool alive = isAlive(procs, c.pid, c.exeName);
		if (!alive) releaseProcessCounters(c);
		return !alive;
		};
	entry.children.erase(std::remove_if(entry.children.begin(), entry.children.end(),
		termination), entry.children.end());

	// 새 자식 추가 — collect()가 뜬 프로세스 목록에서 부모가 이 타겟의 메인인 것을 고른다 (스냅샷을 따로 뜨지 않는다)
	for (const auto& p : procs) {
		if (p.ppid != entry.main.pid || p.pid == entry.main.pid) continue;
		const DWORD cpid = p.pid;

		bool exists = std::any_of(entry.children.begin(), entry.children.end(),
			[&](const ProcessCounters& c) { return c.pid == cpid; });
		if (exists) continue;

		// PDH 인스턴스 이름은 "<그 프로세스의 실행 파일 이름>:<pid>"다 — 자식의 경로는 부모가 아니라 자식 자신의 이름으로 만든다.
		// 부모 이름으로 만들면 실행 파일이 부모와 다른 자식(스크립트가 띄운 프로그램, 콘솔 프로그램의 conhost 등)은
		// 존재하지 않는 인스턴스를 찾게 되어 수집되지 않는다.
		const std::string childExe = StrUtil::wideToUtf8(p.exeName);
		std::string failReason;
		auto info = findPdhInstance(childExe, cpid, failReason);
		if (!info.isValid()) {
			// 여기로 오는 것은 목록을 뜬 뒤 조회 전에 자식이 종료된 경우(다음 동기화에서 사라짐)이거나
			// 이름에 '#'이 있어 PDH 경로로 표현할 수 없는 경우다. 5초마다 다시 시도되므로 debug로 둔다.
			spdlog::debug("TargetCollector: '{}' child '{}' PID={} skipped: {}", entry.targetName, childExe, cpid, failReason);
			continue;
		}

		ProcessCounters pc;
		pc.pid = cpid;
		pc.name = info.instanceName;
		pc.exeName = childExe;
		pc.isChild = true;

		if (initProcessCounters(pc)) {
			entry.children.push_back(std::move(pc));
			//spdlog::info("TargetCollector: '{}' add child PID={}", entry.targetName, cpid);
		}
	}
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
	// 전부 모아 아래의 프로세스 목록 하나와 findRunningPids()로 한꺼번에 대조한다.
	std::vector<std::string> notActiveNames;
	for (const auto& name : registeredNames) {
		bool isActive = std::any_of(activeTargets.begin(), activeTargets.end(), [&](const TargetEntry& e) {return e.targetName == name; });
		if (!isActive) notActiveNames.push_back(name);
	}

	// 프로세스 목록은 틱당 1번 — 비활성 타겟 찾기와 활성 타겟 생존 확인이 함께 쓴다.
	// 실패하면 이번 틱은 시작/종료 판정을 모두 건너뛴다: "목록을 못 받음"을 "목록에 없음"으로 보면
	// 실행 중인 타겟이 전부 종료로 처리돼 세션이 거짓으로 끊긴다 (자식도 같은 원칙 — collectTarget() 참고).
	const std::optional<ProcessList> procs = snapshotProcesses();
	if (!procs) {
		spdlog::warn("TargetCollector: process snapshot failed (error {}) — skipping start/exit detection this tick", GetLastError());
	}

	if (procs && !notActiveNames.empty()) {
		auto runningPids = findRunningPids(*procs, notActiveNames);
		for (const auto& name : notActiveNames) {
			auto it = runningPids.find(name);
			if (it == runningPids.end()) {
				// 이번 틱엔 미실행 -> PDH 비용 없이 스킵. 다음 실행에서 활성화가 또 실패하면 다시 경고하도록 기록을 지운다
				activationFailWarned.erase(name);
				continue;
			}

			auto info = activateTarget(name, it->second);
			if (info.isValid()) {
				spdlog::info("TargetCollector: '{}' (PID={}) running detect", name, info.pid);
			}
		}
	}

	// 자식 동기화 — 5초마다. 위에서 뜬 프로세스 목록을 그대로 쓴다.
	// 목록을 못 받은 틱에는 하지 않고 다음 틱에 다시 시도한다 (cleanupTick을 되돌리지 않음).
	if (++cleanupTick >= 5 && procs) {
		for (auto& entry : activeTargets)
			syncChildren(entry, *procs);
		cleanupTick = 0;
	}

	// PDH 수집
	if (!activeTargets.empty()) PdhCollectQueryData(query);

	// 종료된 프로세스 감지
	std::vector<std::string> deadTargets;

	auto connMap = getAllConnectionsGroupedByPid();
	for (auto& entry : activeTargets) {
		// 생존은 프로세스 목록으로만 판정한다 — OpenProcess 성공은 "실행 중"이 아니고(핸들이 남은 종료 프로세스),
		// 실패는 "종료"가 아니다(권한 부족). 목록을 못 받은 틱(procs 없음)은 직전 상태(실행 중)를 유지한다.
		if (procs && !isAlive(*procs, entry.main.pid, entry.exeName)) {
			spdlog::info("TargetCollector: '{}' shutdown detect", entry.targetName);
			deadTargets.push_back(entry.targetName);
			continue;
		}
		SnapshotTarget s = collectTarget(entry, elapsedSec, connMap, procs ? &*procs : nullptr);
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
			s.status = TargetStatus::NOT_RUNNING;
			if (!sit->second.exePath.empty()) s.exePath = sit->second.exePath;
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
			s.status = TargetStatus::NEVER_SEEN;
		}
		snapshot.targets.push_back(std::move(s));
	}
}

// -------------------------------------------------------
// 실행 중인 프로세스 목록 — collect()가 틱당 1번 떠서 시작 감지와 생존 확인이 함께 쓴다.
// 이전에는 findMainPdhInstance()가 이름마다 개별로 스냅샷을 떠서, 등록된 이름이 K개면
// 매 틱 스냅샷을 K번 뜨는 중복 비용이 있었다.
// -------------------------------------------------------
std::optional<TargetCollector::ProcessList> TargetCollector::snapshotProcesses() {
	HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snap == INVALID_HANDLE_VALUE) return std::nullopt;

	ProcessList procs;
	PROCESSENTRY32W entry = {};
	entry.dwSize = sizeof(entry);
	if (Process32FirstW(snap, &entry)) {
		do {
			procs.push_back(ProcessListEntry{ entry.th32ProcessID, entry.th32ParentProcessID, std::wstring(exeBaseName(entry.szExeFile)) });
		} while (Process32NextW(snap, &entry));
	}
	CloseHandle(snap);
	return procs;
}

std::unordered_map<std::string, TargetCollector::RunningProcess> TargetCollector::findRunningPids(const ProcessList& procs, const std::vector<std::string>& notActiveNames) {
	std::unordered_map<std::string, RunningProcess> result;
	if (notActiveNames.empty()) return result;

	// 비교는 UTF-16끼리 한다 — 등록 이름만 호출당 한 번 변환하고, 프로세스 이름은 매칭됐을 때만 UTF-8로 바꾼다
	std::vector<std::wstring> wideNames;
	wideNames.reserve(notActiveNames.size());
	for (const auto& name : notActiveNames)
		wideNames.push_back(StrUtil::utf8ToWide(name));

	for (const auto& p : procs) {
		for (size_t i = 0; i < notActiveNames.size(); ++i) {
			const std::string& name = notActiveNames[i];
			if (result.count(name)) continue;	// 이미 찾음
			if (sameExeName(p.exeName, wideNames[i])) {
				result[name] = RunningProcess{ p.pid, StrUtil::wideToUtf8(p.exeName) };
				break;
			}
		}
		if (result.size() == notActiveNames.size()) break;	// 전부 찾았으면 조기 종료
	}
	return result;
}

bool TargetCollector::isAlive(const ProcessList& procs, DWORD pid, const std::string& exeName) {
	const std::wstring wideName = StrUtil::utf8ToWide(exeName);
	return std::any_of(procs.begin(), procs.end(), [&](const ProcessListEntry& p) {
		return p.pid == pid && sameExeName(p.exeName, wideName);
	});
}

// -------------------------------------------------------
// PDH 인스턴스 탐색 — Process V2 적용 (메인/자식 공용)
// 이미 알아낸 PID로 "\Process V2(<name>:<pid>)\Process ID"를 읽어 그 인스턴스가 실제로 그 PID인지 확인한다.
// 실패하면 로그를 남기지 않고 failReason에 원인을 담아 돌려준다 — 얼마나 자주 알릴지는 호출부가 정한다
// (activateTarget은 타겟당 1번). 이전에는 값 읽기 실패 분기에 로그가 없어 원인이 드러나지 않았다.
// -------------------------------------------------------
PdhInstanceInfo TargetCollector::findPdhInstance(const std::string& name, DWORD targetPid, std::string& failReason) {
	if (targetPid == 0) {
		failReason = "PID is 0";
		return {};
	}

	// Process V2 인스턴스 이름 = "name:pid"
	std::string instName = name + ":" + std::to_string(targetPid);
	std::string path = "\\Process V2(" + instName + ")\\Process ID";
	spdlog::debug("findPdhInstance: path='{}'", path);

	PDH_HQUERY tq = nullptr;
	PDH_HCOUNTER tc = nullptr;

	PDH_STATUS s = PdhOpenQuery(nullptr, 0, &tq);
	if (s != ERROR_SUCCESS) {
		failReason = fmt::format("PdhOpenQuery failed (0x{:X})", static_cast<unsigned>(s));
		return {};
	}

	s = PdhAddCounterW(tq, StrUtil::utf8ToWide(path).c_str(), 0, &tc);
	if (s != ERROR_SUCCESS) {
		PdhCloseQuery(tq);
		failReason = fmt::format("PDH counter '{}' could not be added (0x{:X})", path, static_cast<unsigned>(s));
		return {};
	}

	const PDH_STATUS collectStatus = PdhCollectQueryData(tq);

	PDH_FMT_COUNTERVALUE val = {};
	s = PdhGetFormattedCounterValue(tc, PDH_FMT_LONG, nullptr, &val);
	PdhCloseQuery(tq);
	if (s != ERROR_SUCCESS) {
		failReason = fmt::format("PDH counter '{}' could not be read (collect 0x{:X}, value 0x{:X})",
			path, static_cast<unsigned>(collectStatus), static_cast<unsigned>(s));
		return {};
	}

	DWORD pid = static_cast<DWORD>(val.longValue);
	if (pid != targetPid) {
		failReason = fmt::format("PDH instance '{}' reports PID {}", instName, pid);
		return {};
	}

	PdhInstanceInfo result;
	result.instanceName = instName;		// "chrome:7500"
	result.pid = pid;
	return result;
}

// -------------------------------------------------------
// 실행 파일 경로
// -------------------------------------------------------
std::optional<std::string> TargetCollector::getExePath(DWORD pid) {
	HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
	if (!hProc) return std::nullopt;

	// 대부분은 MAX_PATH 안에 들어오므로 스택 버퍼로 먼저 시도하고, 긴 경로(\\?\ 등)일 때만 최대 길이로 재시도한다.
	std::optional<std::string> result;
	wchar_t path[MAX_PATH] = {};
	DWORD size = MAX_PATH;
	if (QueryFullProcessImageNameW(hProc, 0, path, &size)) {
		result = StrUtil::wideToUtf8(std::wstring_view(path, size));
	}
	else if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
		std::wstring longPath(32768, L'\0');
		size = static_cast<DWORD>(longPath.size());
		if (QueryFullProcessImageNameW(hProc, 0, longPath.data(), &size))
			result = StrUtil::wideToUtf8(std::wstring_view(longPath.data(), size));
	}
	CloseHandle(hProc);
	return result;
}

// -------------------------------------------------------
// PDH 값 double 반환
// -------------------------------------------------------
double TargetCollector::getPdhDouble(PDH_HCOUNTER counter) {
	if (!counter) return 0.0;
	PDH_FMT_COUNTERVALUE val = {};
	// PDH_FMT_NOCAP100: 프로세스의 "% Processor Time"은 코어 하나를 다 쓰면 100, 둘이면 200이다.
	// 이 플래그가 없으면 PDH가 100에서 잘라, 여러 코어를 쓰는 프로세스가 (100 / 코어 수)%로 낮게 보고된다.
	// 백분율이 아닌 카운터(바이트, 개수 등)에는 영향이 없다.
	PDH_STATUS status = PdhGetFormattedCounterValue(counter, PDH_FMT_DOUBLE | PDH_FMT_NOCAP100, nullptr, &val);
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


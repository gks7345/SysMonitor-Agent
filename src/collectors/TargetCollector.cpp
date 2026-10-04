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

	constexpr double BYTES_PER_MB = 1024.0 * 1024.0;

	std::optional<double> bytesToMB(std::optional<double> bytes) {
		if (!bytes) return std::nullopt;
		return *bytes / BYTES_PER_MB;
	}

	std::optional<uint32_t> toCount(std::optional<double> value) {
		if (!value) return std::nullopt;
		return static_cast<uint32_t>(*value);
	}

	// PDH "Working Set - Private"(바이트) → MB. 열 권한이 없는 프로세스는 이 카운터가 0으로 읽히는 경우가 있다
	// (실측: 서비스로 도는 mysqld — 실제 Working Set은 11.6MB). 권한이 없으면서 0이면 "수집하지 못함"으로 본다.
	// 권한이 없어도 0이 아닌 값은 PDH가 실제로 읽은 값이므로 그대로 쓴다.
	std::optional<double> privateWorkingSetMB(std::optional<double> bytes, bool accessDenied) {
		if (!bytes) return std::nullopt;
		if (accessDenied && *bytes == 0.0) return std::nullopt;
		return *bytes / BYTES_PER_MB;
	}

	// PDH 값을 스냅샷 필드로 옮긴다 — 메인(SnapshotTarget)과 자식(SnapshotChildProcess)이 같은 이름의 필드를 쓴다.
	// perf가 없거나 그 안의 값이 비어 있으면 스냅샷 필드도 비워 둔다 (0으로 채우지 않는다).
	template <typename T>
	void fillPerf(T& dst, const ProcessPerf* perf, bool accessDenied, unsigned int cores) {
		if (!perf) return;
		if (perf->cpuPercent) dst.cpuUsage = *perf->cpuPercent / cores;	// 코어 하나당 100 → 시스템 전체 대비 %
		dst.memoryMB = privateWorkingSetMB(perf->workingSetPrivateBytes, accessDenied);
		dst.privateMemoryMB = bytesToMB(perf->privateBytes);
		dst.virtualMemoryMB = bytesToMB(perf->virtualBytes);
		dst.diskReadMBs = bytesToMB(perf->ioReadBytesPerSec);
		dst.diskWriteMBs = bytesToMB(perf->ioWriteBytesPerSec);
		dst.threadCount = toCount(perf->threadCount);
		dst.handleCount = toCount(perf->handleCount);
		dst.pageFaultRate = perf->pageFaultsPerSec;
	}

	// 수집하는 카운터. isRate: 두 시점의 차이로 계산되는 값 — 직전 수집이 바로 앞 틱이 아니면 쓸 수 없다.
	struct PerfCounterDef {
		const wchar_t* name;
		std::optional<double> ProcessPerf::* field;
		bool isRate;
	};
	constexpr PerfCounterDef PERF_COUNTERS[] = {
		{ L"% Processor Time",      &ProcessPerf::cpuPercent,             true  },
		{ L"Working Set - Private", &ProcessPerf::workingSetPrivateBytes, false },
		{ L"Private Bytes",         &ProcessPerf::privateBytes,           false },
		{ L"Virtual Bytes",         &ProcessPerf::virtualBytes,           false },
		{ L"IO Read Bytes/sec",     &ProcessPerf::ioReadBytesPerSec,      true  },
		{ L"IO Write Bytes/sec",    &ProcessPerf::ioWriteBytesPerSec,     true  },
		{ L"Thread Count",          &ProcessPerf::threadCount,            false },
		{ L"Handle Count",          &ProcessPerf::handleCount,            false },	// 프로세스를 열 권한이 없어도 읽힌다
		{ L"Page Faults/sec",       &ProcessPerf::pageFaultsPerSec,       true  },
		{ L"Elapsed Time",          &ProcessPerf::elapsedSec,             false },
	};
} // namespace

TargetCollector::TargetCollector(ETWNetwork& sharedEtwNet) : etwNet(sharedEtwNet) {
	cores = std::thread::hardware_concurrency();
	if (cores == 0) cores = 1;

	PDH_STATUS s = PdhOpenQuery(nullptr, 0, &query);
	if (s != ERROR_SUCCESS) {
		spdlog::error("TargetCollector: PdhOpenQuery error 0x{:X}", static_cast<unsigned>(s));
		query = nullptr;
	}
	else {
		// 카운터는 여기서 한 번만 등록한다. 영문 이름으로 등록해 다른 언어의 Windows에서도 같은 경로가 통하게 한다.
		perfCounters.resize(std::size(PERF_COUNTERS), nullptr);
		for (size_t i = 0; i < std::size(PERF_COUNTERS); ++i) {
			const std::wstring path = std::wstring(L"\\Process V2(*)\\") + PERF_COUNTERS[i].name;
			s = PdhAddEnglishCounterW(query, path.c_str(), 0, &perfCounters[i]);
			if (s != ERROR_SUCCESS) {
				perfCounters[i] = nullptr;
				spdlog::error("TargetCollector: counter '{}' could not be added (0x{:X}) — that metric will be unavailable",
					StrUtil::wideToUtf8(path), static_cast<unsigned>(s));
			}
		}
	}

	lastTime = std::chrono::steady_clock::now();
}
TargetCollector::~TargetCollector() {
	clearRegistered();
	if (query)
		PdhCloseQuery(query);	// 쿼리에 속한 카운터도 함께 닫힌다
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
	activeTargets.clear();
	registeredNames.clear();
	lastSessions.clear();
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
// PDH 수집 — "\Process V2(*)" 와일드카드
// 프로세스마다 카운터를 등록하지 않는다. 카운터 종류마다 전체 프로세스의 값 배열을 한 번에 받아
// 타겟/자식의 PID에 해당하는 항목만 꺼낸다 — 수집 비용이 타겟·자식 수와 무관하다
// (실측: 이름으로 지정한 카운터는 프로세스 하나에 약 12ms씩 늘고, 와일드카드는 프로세스 300개 전체에 약 13ms).
// 이름으로 경로를 만들지 않으므로 '#'이 든 이름이나 긴 이름의 프로세스도 수집된다.
// -------------------------------------------------------
std::optional<TargetCollector::PerfMap> TargetCollector::collectProcessPerf() {
	PerfMap result;
	if (activeTargets.empty()) {
		// 실행 중인 타겟이 없으면 수집을 쉰다. 다음에 재개하는 수집은 기준점으로만 쓰인다 (아래 ratesValid)
		perfCollectedLastTick = false;
		return result;
	}
	if (!query) return std::nullopt;

	std::unordered_set<DWORD> wanted;
	for (const auto& entry : activeTargets) {
		wanted.insert(entry.pid);
		for (const auto& child : entry.children)
			wanted.insert(child.pid);
	}

	// 비율 값(CPU, 디스크, 페이지 폴트)은 직전 수집과의 차이로 계산된다. 직전 틱에 수집하지 않았으면
	// (첫 수집이거나, 쉬었다가 재개) PDH는 오래된 기준으로 계산한 값을 유효한 것처럼 돌려준다
	// (실측: 8초 쉰 뒤의 첫 수집이 8초 평균을 정상 상태로 반환). 그런 수집은 기준점으로만 쓰고 비율 값은 버린다.
	// 수집 도중 새로 생긴 프로세스의 첫 틱은 PDH가 항목 상태로 알려 주므로 readPerfArray가 걸러 낸다.
	const bool ratesValid = perfCollectedLastTick;

	const PDH_STATUS s = PdhCollectQueryData(query);
	perfCollectedLastTick = (s == ERROR_SUCCESS);
	if (s != ERROR_SUCCESS) {
		spdlog::warn("TargetCollector: PdhCollectQueryData failed (0x{:X}) — target metrics are unavailable this tick", static_cast<unsigned>(s));
		return std::nullopt;
	}

	for (size_t i = 0; i < std::size(PERF_COUNTERS) && i < perfCounters.size(); ++i) {
		if (!perfCounters[i]) continue;
		if (PERF_COUNTERS[i].isRate && !ratesValid) continue;
		readPerfArray(perfCounters[i], PERF_COUNTERS[i].field, wanted, result);
	}
	return result;
}

void TargetCollector::readPerfArray(PDH_HCOUNTER counter, std::optional<double> ProcessPerf::* field, const std::unordered_set<DWORD>& wanted, PerfMap& out) {
	// PDH_FMT_NOCAP100: 프로세스의 "% Processor Time"은 코어 하나를 다 쓰면 100, 둘이면 200이다.
	// 이 플래그가 없으면 PDH가 100에서 잘라, 여러 코어를 쓰는 프로세스가 (100 / 코어 수)%로 낮게 보고된다.
	constexpr DWORD format = PDH_FMT_DOUBLE | PDH_FMT_NOCAP100;

	// 버퍼가 작으면 PDH_MORE_DATA와 함께 필요한 크기를 돌려준다. 크기를 맞춘 뒤 읽는 사이에 프로세스가 늘 수 있으므로 몇 번 다시 시도한다.
	DWORD count = 0;
	PDH_STATUS s = PDH_MORE_DATA;
	for (int attempt = 0; attempt < 3 && s == PDH_MORE_DATA; ++attempt) {
		DWORD size = static_cast<DWORD>(perfBuffer.size());
		s = PdhGetFormattedCounterArrayW(counter, format, &size, &count,
			perfBuffer.empty() ? nullptr : reinterpret_cast<PDH_FMT_COUNTERVALUE_ITEM_W*>(perfBuffer.data()));
		if (s == PDH_MORE_DATA) perfBuffer.resize(size);
	}
	if (s != ERROR_SUCCESS) {
		spdlog::debug("TargetCollector: PdhGetFormattedCounterArray failed (0x{:X})", static_cast<unsigned>(s));
		return;
	}

	const auto* items = reinterpret_cast<const PDH_FMT_COUNTERVALUE_ITEM_W*>(perfBuffer.data());
	for (DWORD i = 0; i < count; ++i) {
		// 항목 이름은 "<실행 파일 이름>:<pid>". 긴 이름은 잘려서 오므로 이름은 보지 않고 PID만 쓴다 (실행 파일 이름에는 ':'가 올 수 없다).
		// ':'가 없는 항목은 합계(_Total)다.
		const wchar_t* colon = wcsrchr(items[i].szName, L':');
		if (!colon) continue;
		const DWORD pid = wcstoul(colon + 1, nullptr, 10);
		if (wanted.find(pid) == wanted.end()) continue;

		ProcessPerf& perf = out[pid];	// 값이 유효하지 않아도 항목은 만든다 — "PDH 배열에 있었다"는 표시
		const DWORD status = items[i].FmtValue.CStatus;
		if (status != PDH_CSTATUS_VALID_DATA && status != PDH_CSTATUS_NEW_DATA) continue;	// 새 프로세스의 첫 틱 비율 값 등
		const double value = items[i].FmtValue.doubleValue;
		if (std::isnan(value) || std::isinf(value)) continue;
		perf.*field = value;
	}
}

// -------------------------------------------------------
// 자식 프로세스 수집
// -------------------------------------------------------
SnapshotChildProcess TargetCollector::collectChild(const TrackedProcess& child, const ProcessPerf* perf, double elapsedSec, const ConnectionMap& connMap, bool& accessDenied) {
	SnapshotChildProcess c;
	c.pid = child.pid;
	c.processName = child.exeName;	// syncChildren()이 프로세스 목록에서 받아 둔 실제 이름 — 매 틱 다시 조회하지 않는다

	const OpenedProcessInfo opened = queryOpenedProcess(child.pid);
	if (opened.accessDenied) accessDenied = true;

	fillPerf(c, perf, opened.accessDenied, cores);
	c.gdiObjectCount = opened.gdiObjectCount;

	NetMbps net = etwNet.getAndResetForTarget(child.pid, elapsedSec);
	c.netSentMbps = net.sentMbps;
	c.netRecvMbps = net.recvMbps;
	c.connections = lookupConnections(connMap, child.pid);

	return c;
}

// -------------------------------------------------------
// 단일 타겟 수집
// -------------------------------------------------------
SnapshotTarget TargetCollector::collectTarget(TargetEntry& entry, double elapsedSec, const ConnectionMap& connMap, const ProcessList* procs, const PerfMap* perf) {
	auto perfOf = [&](DWORD pid) -> const ProcessPerf* {
		if (!perf) return nullptr;
		auto it = perf->find(pid);
		return it == perf->end() ? nullptr : &it->second;
		};

	SnapshotTarget s;
	s.pid = entry.pid;
	s.targetName = entry.targetName;
	s.processName = entry.exeName;
	s.exePath = getExePath(entry.pid);

	const OpenedProcessInfo opened = queryOpenedProcess(entry.pid);
	bool accessDenied = opened.accessDenied;	// 메인 또는 자식 중 하나라도 열 권한이 없었는가

	// 메인 프로세스 — PDH가 이 틱에 값을 주지 않았으면(mainPerf 없음) 지표를 비운 채 보낸다
	const ProcessPerf* mainPerf = perfOf(entry.pid);
	fillPerf(s, mainPerf, opened.accessDenied, cores);
	if (mainPerf) s.elapsedSec = mainPerf->elapsedSec;
	s.gdiObjectCount = opened.gdiObjectCount;

	// ETW 네트워크
	NetMbps net = etwNet.getAndResetForTarget(entry.pid, elapsedSec);
	s.netSentMbps = net.sentMbps;
	s.netRecvMbps = net.recvMbps;
	s.connections = lookupConnections(connMap, entry.pid);

	// 자식 프로세스 수집
	// syncChildren()이 최대 5초 주기로만 목록을 정리하므로, 그 사이 이미 종료된 자식이
	// entry.children에 남아있을 수 있다 — 이번 틱의 프로세스 목록에 없으면 수집하지 않고 스냅샷에서 제외한다
	// (값이 빈 유령 항목이 서버로 나가는 것을 방지). 판정은 메인과 같은 목록, 같은 규칙(PID + 이름)이다.
	// 목록을 못 받은 틱(procs == nullptr)은 생존 여부를 알 수 없으므로 유령으로 단정하지 않고 그대로 수집한다.
	for (const auto& child : entry.children) {
		if (procs && !isAlive(*procs, child.pid, child.exeName)) continue;

		// PDH 수집은 됐는데 배열에 이 자식이 없다 — 프로세스 목록을 뜬 직후 종료된 경우다. 이번 틱은 뺀다.
		// PDH 수집 자체가 실패한 틱(perf == nullptr)은 자식을 지우지 않고 값만 비운 채 보낸다 — 못 받은 것과 없는 것은 다르다.
		const ProcessPerf* childPerf = perfOf(child.pid);
		if (perf && !childPerf) continue;

		s.children.push_back(collectChild(child, childPerf, elapsedSec, connMap, accessDenied));
	}

	// 서버에는 "값 없음"으로 나가지만 원인(권한)과 해결책은 여기서만 알 수 있다 — 활성화당 1번만 남긴다.
	if (accessDenied && !entry.limitedAccessWarned) {
		entry.limitedAccessWarned = true;
		spdlog::warn("TargetCollector: '{}' (PID={}) cannot be opened (access denied): memory / exe path / GDI count may be "
			"unavailable and are sent as N/A, not 0. Run the Agent elevated or as a service to collect them",
			entry.targetName, entry.pid);
	}

	return s;
}

// -------------------------------------------------------
// 실행 감지 → 수집 시작
// 프로세스 목록에서 찾은 프로세스를 수집 대상으로 올린다. PDH 쪽에는 할 일이 없다 —
// 값은 매 틱 와일드카드 배열에서 PID로 찾으므로, 등록에 실패해 "실행 중인데 수집되지 않는" 경우가 없다.
// -------------------------------------------------------
bool TargetCollector::activateTarget(const std::string& name, const RunningProcess& proc) {
	auto it = std::find_if(activeTargets.begin(), activeTargets.end(),
		[&](const TargetEntry& e) { return e.targetName == name; });
	if (it != activeTargets.end()) return false;

	TargetEntry entry;
	entry.targetName = name;
	entry.exeName = proc.exeName;
	entry.pid = proc.pid;

	if (proc.exeName != name) {
		spdlog::info("TargetCollector: '{}' matched process '{}.exe' (names are case-insensitive)", name, proc.exeName);
	}
	activeTargets.push_back(std::move(entry));
	spdlog::info("TargetCollector: '{}' (PID={}) collect start", name, proc.pid);
	return true;
}

// -------------------------------------------------------
// 종료 감지 → 수집 중단
// -------------------------------------------------------
void TargetCollector::deactivateTarget(const std::string& name, bool notifyPending) {
	auto it = std::find_if(activeTargets.begin(), activeTargets.end(), [&](const TargetEntry& e) { return e.targetName == name; });
	if (it == activeTargets.end()) return;

	spdlog::info("TargetCollector: '{}' collect stop", it->targetName);
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
	entry.children.erase(std::remove_if(entry.children.begin(), entry.children.end(),
		[&](const TrackedProcess& c) { return !isAlive(procs, c.pid, c.exeName); }), entry.children.end());

	// 새 자식 추가 — collect()가 뜬 프로세스 목록에서 부모가 이 타겟의 메인인 것을 고른다 (스냅샷을 따로 뜨지 않는다).
	// 실행 파일이 부모와 달라도 자식이다 (스크립트가 띄운 프로그램, 콘솔 프로그램의 conhost 등).
	for (const auto& p : procs) {
		if (p.ppid != entry.pid || p.pid == entry.pid) continue;

		bool exists = std::any_of(entry.children.begin(), entry.children.end(),
			[&](const TrackedProcess& c) { return c.pid == p.pid; });
		if (exists) continue;

		entry.children.push_back(TrackedProcess{ p.pid, StrUtil::wideToUtf8(p.exeName) });
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
			if (it == runningPids.end()) continue;	// 이번 틱엔 미실행
			activateTarget(name, it->second);
		}
	}

	// 자식 동기화 — 5초마다. 위에서 뜬 프로세스 목록을 그대로 쓴다.
	// 목록을 못 받은 틱에는 하지 않고 다음 틱에 다시 시도한다 (cleanupTick을 되돌리지 않음).
	if (++cleanupTick >= 5 && procs) {
		for (auto& entry : activeTargets)
			syncChildren(entry, *procs);
		cleanupTick = 0;
	}

	// PDH 수집 — 실행 중인 타겟이 있을 때만. 전체 프로세스의 값을 한 번에 받아 타겟/자식의 PID만 꺼낸다.
	const std::optional<PerfMap> perf = collectProcessPerf();

	// 종료된 프로세스 감지
	std::vector<std::string> deadTargets;

	auto connMap = getAllConnectionsGroupedByPid();
	for (auto& entry : activeTargets) {
		// 생존은 프로세스 목록으로만 판정한다 — OpenProcess 성공은 "실행 중"이 아니고(핸들이 남은 종료 프로세스),
		// 실패는 "종료"가 아니다(권한 부족). 목록을 못 받은 틱(procs 없음)은 직전 상태(실행 중)를 유지한다.
		if (procs && !isAlive(*procs, entry.pid, entry.exeName)) {
			spdlog::info("TargetCollector: '{}' shutdown detect", entry.targetName);
			deadTargets.push_back(entry.targetName);
			continue;
		}
		SnapshotTarget s = collectTarget(entry, elapsedSec, connMap, procs ? &*procs : nullptr, perf ? &*perf : nullptr);
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


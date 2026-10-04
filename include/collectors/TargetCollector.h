#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <pdh.h>
#include <PdhMsg.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <iphlpapi.h>
#include <string>
#include <vector>
#include <unordered_map>
#include <chrono>
#include <cmath>
#include <thread>
#include <algorithm>
#include <mutex>
#include <condition_variable>
#include <future>
#include <optional>
#include <spdlog/spdlog.h>
#include "collectors/ETWNetwork.h"
#include "models/SnapshotData.h"
#include "models/SessionSummary.h"


#pragma comment(lib, "pdh.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

// 반환: {인스턴스명, PID} 쌍, 실패 시 {"", 0}
struct PdhInstanceInfo {
	std::string instanceName;
	DWORD       pid = 0;
	bool isValid() const { return !instanceName.empty() && pid != 0; }
};

// -------------------------------------------------------
// 단일 프로세스별 PDH 카운터 묶음
// -------------------------------------------------------
struct ProcessCounters {
	DWORD pid = 0;
	std::string name;	// PDH 인스턴스명
	std::string exeName;	// 자식 전용: 실제 실행 파일 이름(.exe 제외) — 스냅샷의 이름과 생존 판정(isAlive)에 쓴다. 메인은 TargetEntry::exeName
	bool         isChild = false;

	// 메인은 공유 query 사용
	// 자식은 개별 childQuery 사용
	PDH_HQUERY childQuery = nullptr;

	PDH_HCOUNTER cpu = nullptr;
	PDH_HCOUNTER mem = nullptr;
	PDH_HCOUNTER privateMem = nullptr;
	PDH_HCOUNTER virtualMem = nullptr;
	PDH_HCOUNTER diskR = nullptr;
	PDH_HCOUNTER diskW = nullptr;
	PDH_HCOUNTER threads = nullptr;
	PDH_HCOUNTER handles = nullptr;
	PDH_HCOUNTER pageFault = nullptr;
	PDH_HCOUNTER elapsed = nullptr;		// 메인 프로세스만

	// 자식 전용 Win32 CPU delta 계산용
	ULONGLONG prevKernelTime = 0;
	ULONGLONG prevUserTime = 0;
	ULONGLONG prevMeasureTime = 0; // 100ns 단위 시스템 시간
};

struct TargetEntry {
	std::string targetName;		// 등록된 이름 — 스냅샷/서버에 나가는 타겟의 정체성
	std::string exeName;		// 실제 실행 파일 이름(.exe 제외, OS가 준 대소문자 그대로) — PDH 인스턴스 경로용.
								// 매칭은 대소문자를 무시하므로 targetName과 대소문자가 다를 수 있다 (예: notepad / Notepad)
	ProcessCounters main;		// 메인 프로세스
	std::vector<ProcessCounters> children;	// 자식 프로세스들
	bool limitedAccessWarned = false;	// "권한이 없어 일부 지표를 수집하지 못함" 경고를 이미 남겼는가 (활성화당 1번)
};

// 타겟 프로세스
class TargetCollector {
private:
	int cleanupTick = 5;
	std::vector<TargetEntry> activeTargets;
	// 등록된 타겟 이름 목록 (실행 여부 무관)
	std::vector<std::string> registeredNames;

	// 마지막 세션 데이터 (이름 -> 마지막 세션)
	std::unordered_map<std::string, SessionTargetSummary> lastSessions;

	// "실행 중인데 활성화 실패" 경고를 이미 남긴 타겟 (등록 이름 -> 그때의 PID).
	// 활성화는 매 틱 재시도하지만 경고는 같은 프로세스에 대해 1번만 남긴다. 활성화 성공/프로세스 종료/등록 해제 시 지운다.
	std::unordered_map<std::string, DWORD> activationFailWarned;

	using ConnectionMap = std::unordered_map<DWORD, std::vector<TargetNetConnection>>;

	PDH_HQUERY query = nullptr;

	ETWNetwork& etwNet;

	std::chrono::steady_clock::time_point lastTime;

	unsigned int cores = 1;

	SnapshotTargetData snapshot;

	// 실행 중 프로세스 종료 감지 -> 안전하게 SessionSummary 전달
	std::vector<std::string> pendingDeactivated;

	// -------------------------------------------------------
	// API 스레드 -> 메인 루프 스레드로 등록/해제 요청을 넘기는 커맨드 큐.
	// registeredNames/activeTargets/lastSessions는 메인 루프 스레드만 변경한다는
	// 불변식을 지키기 위해, API 스레드는 이 큐에만 접근한다.
	//
	// 이름을 키로 하는 맵이라 같은 이름으로 여러 번 요청이 몰려도 항목이 하나로
	// 합쳐지고(register/unregister가 섞여도 가장 나중 요청의 종류로 덮어써짐),
	// 그 사이 요청을 보낸 모든 호출자는 waiters에 각자의 promise로 남아 있다가
	// applyPending()이 실제로 반영할 때 한꺼번에 완료 통보를 받는다.
	// -------------------------------------------------------
	enum class PendingType { Register, Unregister };
	struct PendingCommand {
		PendingType type = PendingType::Register;
		SessionTargetSummary lastSession;	// register 요청에만 사용 (가장 최근 값으로 덮어씀)
		std::vector<std::promise<bool>> waiters;	// 이 이름의 결과를 기다리는 모든 요청자
	};
	std::mutex pendingMtx;
	std::condition_variable pendingCv;
	std::unordered_map<std::string, PendingCommand> pendingByName;

	// snapshotProcesses() 결과 한 건: 이번 틱에 실행 중인 프로세스
	struct ProcessListEntry {
		DWORD pid = 0;
		DWORD ppid = 0;			// 부모 PID — syncChildren()이 타겟의 자식을 고를 때 쓴다
		std::wstring exeName;	// 실행 파일 이름(.exe 제외, OS가 준 그대로)
	};
	using ProcessList = std::vector<ProcessListEntry>;

	// findRunningPids() 결과 한 건: 등록 이름에 매칭된 실행 중 프로세스
	struct RunningProcess {
		DWORD pid = 0;
		std::string exeName;	// 실제 실행 파일 이름(.exe 제외) — TargetEntry::exeName으로 들어간다
	};

	// 헬퍼
	// 이름 규칙 (Windows 파일 이름과 같음): 끝의 ".exe"는 대소문자 무관하게 떼고, 비교는 대소문자를 무시한다.
	// 등록 이름의 정규화/중복 판정과 실행 중 프로세스 매칭이 모두 이 규칙 하나를 쓴다.
	// name과 같은 것으로 판정되는 등록 이름(저장된 철자)을 찾는다. 없으면 nullptr.
	const std::string* findRegistered(const std::string& name) const;

	// proc: findRunningPids()로 이미 찾아둔 PID와 실제 실행 파일 이름 — 호출부가 매 틱 CreateToolhelp32Snapshot을
	// 등록된 이름 개수만큼 중복으로 뜨지 않도록, 여기서는 그 스냅샷을 다시 뜨지 않고
	// PDH 검증(Process V2 카운터로 PID 재확인 + 카운터 초기화)만 수행한다.
	PdhInstanceInfo activateTarget(const std::string& name, const RunningProcess& proc);	// 실행 중 감지 -> 수집 시작
	// notifyPending: true면 pendingDeactivated에 넣어 메인 루프가 세션 요약을 마저 처리하게 한다.
	// collect()가 프로세스 종료를 감지해 호출할 때만 true — unregisterTarget()처럼 사용자가
	// 명시적으로 등록을 해제하는 경로에서는 false로 호출해, 방금 지운 lastSessions 항목이
	// 메인 루프에 의해 되살아나지 않도록 한다.
	void deactivateTarget(const std::string& name, bool notifyPending = true);	// 종료 감지 -> 수집 중단

	// failReason: 주면 필수 카운터 실패를 로그로 찍지 않고 여기에 원인을 담는다 (activateTarget용)
	bool initProcessCounters(ProcessCounters& counters, std::string* failReason = nullptr);
	void releaseProcessCounters(ProcessCounters& counters);

	// procs: collect()가 이번 틱에 뜬 프로세스 목록 — 자식의 생존 판정에 쓴다. nullptr = 이번 틱은 목록을 못 받음(자식을 그대로 수집)
	SnapshotTarget collectTarget(TargetEntry& entry, double elapsedSec, const ConnectionMap& connMap, const ProcessList* procs);
	// accessDenied: 이 자식을 열 권한이 없었으면 true로 바꾼다 (false로 되돌리지는 않음 — 여러 자식의 결과를 모으는 용도)
	SnapshotChildProcess collectChild(ProcessCounters& counters, double elapsedSec, const ConnectionMap& connMap, bool& accessDenied);

	ConnectionMap getAllConnectionsGroupedByPid();
	std::vector<TargetNetConnection> lookupConnections(const ConnectionMap& map, DWORD pid);

	// 자식 목록 동기화 — collect()의 프로세스 목록에서 부모가 타겟 메인인 것을 추가하고, 목록에서 사라진 자식을 제거한다
	void syncChildren(TargetEntry& entry, const ProcessList& procs);

	// 메인/자식 공용. targetPid: 이미 알아낸 PID를 받아 Process V2 카운터로 검증만 한다
	// (자체적으로 CreateToolhelp32Snapshot을 뜨지 않음 — 그 부분은 findRunningPids()로 분리됨).
	// 실패하면 로그 없이 failReason에 원인을 담는다 — 알릴 빈도는 호출부가 정한다.
	static PdhInstanceInfo findPdhInstance(const std::string& name, DWORD targetPid, std::string& failReason);
	// 실행 중인 프로세스 목록 (CreateToolhelp32Snapshot) — collect()가 틱당 1번 떠서
	// 비활성 타겟 찾기(findRunningPids), 메인·자식의 생존 확인(isAlive), 자식 목록 동기화(syncChildren)가 함께 쓴다.
	// TargetCollector 안에서 CreateToolhelp32Snapshot을 부르는 곳은 여기 하나다.
	// 권한이 필요 없고, 종료된 프로세스는 다른 프로세스가 핸들을 쥐고 있어도 목록에서 빠진다
	// (OpenProcess는 두 경우 모두 틀린 답을 준다).
	// nullopt = 스냅샷 자체가 실패(생존 여부 판단 불가) — 빈 목록("아무것도 실행 중이 아님")과 구분한다.
	static std::optional<ProcessList> snapshotProcesses();
	// 등록됐지만 아직 활성화되지 않은 이름들(notActiveNames)을 프로세스 목록 하나와 한 번에 대조한다.
	// 반환값: 이번 틱에 실제로 발견된 이름만 담긴 {등록 이름 -> {PID, 실제 실행 파일 이름}} 맵.
	static std::unordered_map<std::string, RunningProcess> findRunningPids(const ProcessList& procs, const std::vector<std::string>& notActiveNames);
	// 그 프로세스가 목록에 있는지 — PID와 실행 파일 이름이 모두 같아야 한다. 메인과 자식이 같은 규칙을 쓴다
	// (PID만 보면 PID가 다른 프로세스에 재사용됐을 때 그 프로세스를 타겟/자식으로 착각한다).
	static bool isAlive(const ProcessList& procs, DWORD pid, const std::string& exeName);
	// nullopt = 경로를 얻지 못함 (프로세스를 열 권한이 없음 등)
	static std::optional<std::string> getExePath(DWORD pid);
	static double getPdhDouble(PDH_HCOUNTER counter);
	static std::string addrToString(DWORD ip, WORD port);
	static std::string tcpStateToString(DWORD state);
	static ULONGLONG filetimeToULL(const FILETIME& ft);

public:
	explicit TargetCollector(ETWNetwork& sharedEtwNet);
	~TargetCollector();

	// 타겟 등록/해제 (실행 중이 아니어도 등록 가능)
	// 이름은 실행 파일명이며 끝의 ".exe"는 떼고 저장한다 ("notepad.EXE" → "notepad"). 대소문자만 다른 이름은 같은 타겟이다.
	// 메인 루프 스레드 전용 — API 스레드는 절대 직접 호출하면 안 됨 (아래 requestRegister/requestUnregister 참고)
	void registerTarget(const std::string& name);
	void unregisterTarget(const std::string& name);
	void clearRegistered();

	// -------------------------------------------------------
	// API 스레드에서 호출: 등록/해제 요청을 큐에 넣고 즉시 반환.
	// 실제 반영은 메인 루프가 applyPending()을 호출할 때 이루어진다.
	// 반환된 future는 메인 루프가 반영을 마치고 set_value할 때 완료된다.
	// -------------------------------------------------------
	std::future<bool> requestRegister(const std::string& name, const SessionTargetSummary& lastSession);
	std::future<bool> requestUnregister(const std::string& name);

	// 메인 루프 스레드 전용: 큐에 쌓인 요청을 모두 반영한다 (매 틱 시작 시 호출).
	void applyPending();

	// 메인 루프 스레드 전용: deadline까지 대기하되, 큐에 새 요청이 들어오면 즉시 깨어난다.
	// true를 반환하면 처리할 요청이 있다는 뜻(타임아웃이 아니라 notify로 깨어남).
	bool waitForPendingUntil(std::chrono::steady_clock::time_point deadline);

	// 등록된 타겟 목록 조회
	const std::vector<std::string>& getRegisteredNames() const {
		return registeredNames;
	}

	// 타겟 상태 조회
	TargetStatus getStatus(const std::string& name) const;

	// 실행 중 프로세스 종료 감지 -> 안전하게 SessionSummary 전달
	const std::vector<std::string>& getPendingDeactivated() const { return pendingDeactivated; }
	void clearPendingDeactivated() { pendingDeactivated.clear(); }


	void collect();

	// 결과 조회
	const SnapshotTargetData& getSnapshot() const { return snapshot; }

	// 마지막 세션 업데이트 (DataStore에서 주입)
	void updateLastSession(const std::string& name, const SessionTargetSummary& session);
};
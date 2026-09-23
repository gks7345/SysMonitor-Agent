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
	PDH_HCOUNTER pageFault = nullptr;
	PDH_HCOUNTER elapsed = nullptr;		// 메인 프로세스만

	// 자식 전용 Win32 CPU delta 계산용
	ULONGLONG prevKernelTime = 0;
	ULONGLONG prevUserTime = 0;
	ULONGLONG prevMeasureTime = 0; // 100ns 단위 시스템 시간
};

struct TargetEntry {
	std::string targetName;		// 등록된 이름
	ProcessCounters main;		// 메인 프로세스
	std::vector<ProcessCounters> children;	// 자식 프로세스들
};

enum class TargetStatus {
	RUNNING,      // 실행 중 → 실시간 수집
	NOT_RUNNING,  // 꺼져 있음 → 마지막 데이터 표시
	NEVER_SEEN    // 한 번도 수집된 적 없음
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

	// 헬퍼
	// pid: findRunningPids()로 이미 찾아둔 PID — 호출부가 매 틱 CreateToolhelp32Snapshot을
	// 등록된 이름 개수만큼 중복으로 뜨지 않도록, 여기서는 그 스냅샷을 다시 뜨지 않고
	// PDH 검증(Process V2 카운터로 PID 재확인 + 카운터 초기화)만 수행한다.
	PdhInstanceInfo activateTarget(const std::string& name, DWORD pid);	// 실행 중 감지 -> 수집 시작
	// notifyPending: true면 pendingDeactivated에 넣어 메인 루프가 세션 요약을 마저 처리하게 한다.
	// collect()가 프로세스 종료를 감지해 호출할 때만 true — unregisterTarget()처럼 사용자가
	// 명시적으로 등록을 해제하는 경로에서는 false로 호출해, 방금 지운 lastSessions 항목이
	// 메인 루프에 의해 되살아나지 않도록 한다.
	void deactivateTarget(const std::string& name, bool notifyPending = true);	// 종료 감지 -> 수집 중단

	bool initProcessCounters(ProcessCounters& counters);
	void releaseProcessCounters(ProcessCounters& counters);

	SnapshotTarget collectTarget(TargetEntry& entry, double elapsedSec, const ConnectionMap& connMap);
	SnapshotChildProcess collectChild(ProcessCounters& counters, double elapsedSec, const ConnectionMap& connMap);

	ConnectionMap getAllConnectionsGroupedByPid();
	std::vector<TargetNetConnection> lookupConnections(const ConnectionMap& map, DWORD pid);

	// 자식 프로세스 활성화
	void syncChildren(TargetEntry& entry);

	static PdhInstanceInfo findChildPdhInstance(const std::string& name, DWORD targetPid);
	// targetPid: findRunningPids()로 이미 알아낸 PID를 받아 Process V2 카운터로 검증만 한다
	// (자체적으로 CreateToolhelp32Snapshot을 뜨지 않음 — 그 부분은 findRunningPids()로 분리됨).
	static PdhInstanceInfo findMainPdhInstance(const std::string& name, DWORD targetPid);
	// 등록됐지만 아직 활성화되지 않은 이름들(notActiveNames)에 대해 CreateToolhelp32Snapshot을
	// 딱 1번만 떠서 전부와 한 번에 이름을 대조한다 — 이름마다 개별로 스냅샷을 뜨던 중복 비용 제거.
	// 반환값: 이번 틱에 실제로 발견된 이름만 담긴 {이름 -> PID} 맵.
	static std::unordered_map<std::string, DWORD> findRunningPids(const std::vector<std::string>& notActiveNames);
	static std::vector<DWORD> getChildPids(DWORD pid);
	static std::string getExePath(DWORD pid);
	// 반환값 셋을 구분: 값 있음+비어있지 않음 = 정상 조회, 값 있음+빈 문자열 = 스냅샷은 성공했지만
	// 그 PID가 없음(진짜로 종료됨), nullopt = CreateToolhelp32Snapshot 자체가 실패(생존 여부 판단 불가).
	// 후자를 빈 문자열과 뭉뚱그리면, 호출부가 "유령이라 이번 틱 데이터를 버려도 된다"고 잘못
	// 판단해 실제로는 살아있는 프로세스의 정상 데이터를 유실시킬 수 있다.
	static std::optional<std::string> getProcessNameFromPid(DWORD pid);
	static double getPdhDouble(PDH_HCOUNTER counter);
	static std::string addrToString(DWORD ip, WORD port);
	static std::string tcpStateToString(DWORD state);
	static ULONGLONG filetimeToULL(const FILETIME& ft);

public:
	explicit TargetCollector(ETWNetwork& sharedEtwNet);
	~TargetCollector();

	// 타겟 등록/해제 (실행 중이 아니어도 등록 가능)
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
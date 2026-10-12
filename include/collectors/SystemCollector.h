#pragma once
#include <Windows.h>
#include <Pdh.h>
#include <array>
#include <chrono>
#include <optional>

#include "collectors/CpuCollector.h"
#include "collectors/MemCollector.h"
#include "collectors/DiskCollector.h"
#include "collectors/NetCollector.h"
#include "models/SnapshotData.h"
#include "util/PdhUtil.h"

class SystemCollector {
private:
	// 1초 간격
	PDH_HQUERY queryMiddle;
	//2초 간격
	PDH_HQUERY querySlow;

	CpuCollector cpu;
	MemCollector mem;
	NetCollector net;
	DiskCollector disk;

	std::chrono::system_clock::time_point lastTime;

	// 그 쿼리의 가장 최근 PdhCollectQueryData가 성공했는가. 실패했으면 그 쿼리의 지표는 "없음"으로 낸다 —
	// 수집에 실패한 뒤에도 카운터를 읽으면 이전 수집의 값이 그대로 돌아올 수 있다.
	bool middleCollected = false;
	bool slowCollected = false;

	// 읽기 실패를 이미 알렸는가 (PdhUtil::reportReadState) — 쿼리 수집마다 하나, 지표마다 하나
	bool middleCollectWarned = false;
	bool slowCollectWarned = false;
	static constexpr size_t METRIC_COUNT = 14;
	std::array<bool, METRIC_COUNT> readWarned{};

	// 지표 하나의 읽기 결과를 스냅샷에 넣을 값으로 바꾸고, 읽지 못했으면 한 번 알린다.
	// collected: 그 지표가 속한 쿼리의 수집이 성공했는가. 아니면 값을 쓰지 않는다 (수집 실패는 수집할 때 이미 알렸다).
	std::optional<double> take(size_t metric, const PdhUtil::Reading& reading, bool collected);
public:
	SystemCollector();
	~SystemCollector();
	void collectMiddle();
	void collectSlow();

	// tickTime: 메인 루프가 정한 이번 틱의 시각 — 스냅샷의 timestamp가 된다 (수집기가 스스로 시각을 정하지 않는다)
	SnapshotSysData makeSnapshot(std::chrono::system_clock::time_point tickTime);
};

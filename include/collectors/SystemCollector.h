#pragma once
#include <Windows.h>
#include <Pdh.h>
#include <chrono>

#include "collectors/CpuCollector.h"
#include "collectors/MemCollector.h"
#include "collectors/DiskCollector.h"
#include "collectors/NetCollector.h"
#include "models/SnapshotData.h"

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
public:
	SystemCollector();
	~SystemCollector();
	void collectMiddle();
	void collectSlow();

	SnapshotSysData makeSnapshot();
};

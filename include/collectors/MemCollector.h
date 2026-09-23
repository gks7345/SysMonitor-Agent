#pragma once
#include <Windows.h>
#include <Pdh.h>
#include <PdhMsg.h>
#include <iostream>
#include <spdlog/spdlog.h>
#include "util/PdhUtil.h"

class MemCollector {
private:
	PDH_HCOUNTER availableMem;
	PDH_HCOUNTER commitMemPercent;
	PDH_HCOUNTER committedMem;
	PDH_HCOUNTER commitLimit;
	MEMORYSTATUSEX mem;

	double	memTotalMB = 0.0;
	double	memUsedPercent = 0.0;
	double	memUsedMB = 0.0;
	double	memAvailMB = 0.0;

public:
	MemCollector();
	void init(PDH_HQUERY& query);

	double getAvailMemMB() const;
	double getMemUsedMB() const;
	double getMemUsagedPercent() const;
	double getMemTotalMB() const;

	double getCommitMemPercent() const;
	double getCommittedMemGB() const;
	double getCommitLimitGB() const;

	void collectMemInfo();
};

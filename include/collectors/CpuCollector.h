#pragma once
#include <Windows.h>
#include <Pdh.h>
#include <PdhMsg.h>
#include <iostream>
#include <spdlog/spdlog.h>
#include "util/PdhUtil.h"

class CpuCollector {
private:
	PDH_HCOUNTER cpuTotal;
	PDH_HCOUNTER cpuFreqMHz;

	PDH_HCOUNTER cpuUser;
	PDH_HCOUNTER cpuKernel;
	PDH_HCOUNTER cpuQueueLength;

public:
	void init(PDH_HQUERY& query);
	double getTotalUsage() const;
	double getCpuFreqGHz() const;
	double getCpuQueueLength() const;
	double getCpuUser() const;
	double getCpuKernel() const;
};
#pragma once
#include <Windows.h>
#include <Pdh.h>
#include <PdhMsg.h>
#include <iostream>
#include <spdlog/spdlog.h>
#include "util/PdhUtil.h"

class CpuCollector {
private:
	PDH_HCOUNTER cpuTotal = nullptr;
	PDH_HCOUNTER cpuFreqMHz = nullptr;

	PDH_HCOUNTER cpuUser = nullptr;
	PDH_HCOUNTER cpuKernel = nullptr;
	PDH_HCOUNTER cpuQueueLength = nullptr;

public:
	void init(PDH_HQUERY& query);
	// 읽지 못한 값은 0이 아니라 "없음"으로 돌려준다 (PdhUtil::Reading)
	PdhUtil::Reading getTotalUsage() const;
	PdhUtil::Reading getCpuFreqGHz() const;
	PdhUtil::Reading getCpuQueueLength() const;
	PdhUtil::Reading getCpuUser() const;
	PdhUtil::Reading getCpuKernel() const;
};
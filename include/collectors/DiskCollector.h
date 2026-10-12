#pragma once
#include <Windows.h>
#include <Pdh.h>
#include <PdhMsg.h>
#include <iostream>
#include <spdlog/spdlog.h>
#include "util/PdhUtil.h"

class DiskCollector {
private:
	PDH_HCOUNTER readCounter = nullptr;
	PDH_HCOUNTER writeCounter = nullptr;

public:
	void init(PDH_HQUERY& query);
	PdhUtil::Reading getReadKB() const;
	PdhUtil::Reading getWriteKB() const;
};
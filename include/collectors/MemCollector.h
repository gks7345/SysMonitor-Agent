#pragma once
#include <Windows.h>
#include <Pdh.h>
#include <PdhMsg.h>
#include <iostream>
#include <spdlog/spdlog.h>
#include "util/PdhUtil.h"

class MemCollector {
private:
	PDH_HCOUNTER availableMem = nullptr;
	PDH_HCOUNTER commitMemPercent = nullptr;
	PDH_HCOUNTER committedMem = nullptr;
	PDH_HCOUNTER commitLimit = nullptr;
	MEMORYSTATUSEX mem;

	// 물리 메모리 총량(MB) — 시작할 때 한 번 읽는다. 읽지 못했으면 값이 없고 status가 그 이유(Win32 오류 코드)다
	PdhUtil::Reading memTotal;
	// 이번 틱에 읽은 사용 가능 메모리(MB) — collectMemInfo()가 채운다
	PdhUtil::Reading memAvail;

public:
	MemCollector();
	void init(PDH_HQUERY& query);

	// 읽지 못한 값은 0이 아니라 "없음"으로 돌려준다 (PdhUtil::Reading)
	PdhUtil::Reading getAvailMemMB() const;
	PdhUtil::Reading getMemTotalMB() const;

	PdhUtil::Reading getCommitMemPercent() const;
	PdhUtil::Reading getCommittedMemGB() const;
	PdhUtil::Reading getCommitLimitGB() const;

	void collectMemInfo();
};

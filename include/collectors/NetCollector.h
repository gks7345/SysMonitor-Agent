#pragma once
#include <Windows.h>
#include <Pdh.h>
#include <PdhMsg.h>
#include <iostream>
#include <string>
#include <vector>
#include <spdlog/spdlog.h>
#include "util/PdhUtil.h"

class NetCollector {
private:
	PDH_HCOUNTER sentCounter = nullptr;
	PDH_HCOUNTER recvCounter = nullptr;

	// 인터페이스 전체의 값을 더한다. 배열을 읽지 못했으면 0이 아니라 "없음"이다
	static PdhUtil::Reading sumCounterArray(PDH_HCOUNTER counter);

public:
	void init(PDH_HQUERY& query);
	PdhUtil::Reading getSentKbps() const;
	PdhUtil::Reading getRecvKbps() const;
};


#include "collectors/NetCollector.h"

void NetCollector::init(PDH_HQUERY& query) {
	PdhUtil::addCounter(query, L"\\Network Interface(*)\\Bytes Sent/sec", sentCounter, "NetCollector");
	PdhUtil::addCounter(query, L"\\Network Interface(*)\\Bytes Received/sec", recvCounter, "NetCollector");
}

PdhUtil::Reading NetCollector::sumCounterArray(PDH_HCOUNTER counter) {
	DWORD bufSize = 0, count = 0;

	// 크기를 먼저 묻는다 — 정상이면 PDH_MORE_DATA와 함께 필요한 크기가 온다
	PDH_STATUS status = PdhGetFormattedCounterArray(counter,
		PDH_FMT_DOUBLE,
		&bufSize,
		&count,
		nullptr);

	if (status != PDH_MORE_DATA || count == 0 || bufSize == 0)
		return { std::nullopt, status == PDH_MORE_DATA || status == ERROR_SUCCESS ? static_cast<PDH_STATUS>(PDH_NO_DATA) : status };

	std::vector<char> buf(bufSize);

	status = PdhGetFormattedCounterArray(counter, PDH_FMT_DOUBLE,
		&bufSize, &count,
		reinterpret_cast<PDH_FMT_COUNTERVALUE_ITEM*>(buf.data()));

	if (status != ERROR_SUCCESS) return { std::nullopt, status };

	auto* items = reinterpret_cast<PDH_FMT_COUNTERVALUE_ITEM*>(buf.data());

	// 유효한 항목만 더한다. 유효한 항목이 하나도 없으면 합은 0이 아니라 "없음"이다
	double total = 0.0;
	DWORD validCount = 0;
	for (DWORD i = 0; i < count; ++i)
	{
		if (items[i].FmtValue.CStatus != PDH_CSTATUS_VALID_DATA &&
			items[i].FmtValue.CStatus != PDH_CSTATUS_NEW_DATA) {
			continue;
		}
		if (std::isnan(items[i].FmtValue.doubleValue) || std::isinf(items[i].FmtValue.doubleValue)) continue;

		total += items[i].FmtValue.doubleValue;
		++validCount;
	}
	if (validCount == 0) return { std::nullopt, static_cast<PDH_STATUS>(PDH_INVALID_DATA) };

	return { total, ERROR_SUCCESS };
}

PdhUtil::Reading NetCollector::getSentKbps() const {
	return PdhUtil::scaled(sumCounterArray(sentCounter), 8.0 / 1'000.0);
}

PdhUtil::Reading NetCollector::getRecvKbps() const {
	return PdhUtil::scaled(sumCounterArray(recvCounter), 8.0 / 1'000.0);
}

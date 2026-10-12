#include "collectors/MemCollector.h"

MemCollector::MemCollector() {
	mem.dwLength = sizeof(mem);
	if (GlobalMemoryStatusEx(&mem) && mem.ullTotalPhys > 0) {
		memTotal.value = static_cast<double>(mem.ullTotalPhys) / (1024.0 * 1024.0);
	}
	else {
		memTotal.status = static_cast<PDH_STATUS>(GetLastError());
	}
}

//Available Memory↓ commit ↑ 위험
//Available 매우 작음 Commit % 90%+ 위험
void MemCollector::init(PDH_HQUERY& qurey) {
	PdhUtil::addCounter(qurey, L"\\Memory\\Available MBytes", availableMem, "MemCollector");
	PdhUtil::addCounter(qurey, L"\\Memory\\% Committed Bytes In Use", commitMemPercent, "MemCollector");
	PdhUtil::addCounter(qurey, L"\\Memory\\Committed Bytes", committedMem, "MemCollector");
	PdhUtil::addCounter(qurey, L"\\Memory\\Commit Limit", commitLimit, "MemCollector");
}

PdhUtil::Reading MemCollector::getAvailMemMB() const {
	return memAvail;
}
PdhUtil::Reading MemCollector::getMemTotalMB() const {
	return memTotal;
}

PdhUtil::Reading MemCollector::getCommitMemPercent() const {
	return PdhUtil::read(commitMemPercent);
}
PdhUtil::Reading MemCollector::getCommittedMemGB() const {
	return PdhUtil::scaled(PdhUtil::read(committedMem), 1.0 / (1024.0 * 1024.0 * 1024.0));
}
PdhUtil::Reading MemCollector::getCommitLimitGB() const {
	return PdhUtil::scaled(PdhUtil::read(commitLimit), 1.0 / (1024.0 * 1024.0 * 1024.0));
}


void MemCollector::collectMemInfo() {
	memAvail = PdhUtil::read(availableMem);
}

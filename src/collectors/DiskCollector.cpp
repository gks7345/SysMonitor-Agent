#include "collectors/DiskCollector.h"

void DiskCollector::init(PDH_HQUERY& query) {
	PDH_STATUS readStatus = PdhAddEnglishCounterW(
		query,
		L"\\PhysicalDisk(_Total)\\Disk Read Bytes/sec",
		0,
		&readCounter
	);
	if (readStatus != ERROR_SUCCESS) {
		spdlog::error("Counter Error 0x{:X}", readStatus);
	}


	PDH_STATUS writeStatus = PdhAddEnglishCounterW(
		query,
		L"\\PhysicalDisk(_Total)\\Disk Write Bytes/sec",
		0,
		&writeCounter
	);
	if (writeStatus != ERROR_SUCCESS) {
		spdlog::error("Counter Error 0x{:X}", writeStatus);
	}
}

double DiskCollector::getReadKB() const {
	return PdhUtil::getDouble(readCounter) / 1024.0;
}

double DiskCollector::getWriteKB() const {
	return PdhUtil::getDouble(writeCounter) / 1024.0;
}
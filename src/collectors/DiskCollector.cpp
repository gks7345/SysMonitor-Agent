#include "collectors/DiskCollector.h"

void DiskCollector::init(PDH_HQUERY& query) {
	PdhUtil::addCounter(query, L"\\PhysicalDisk(_Total)\\Disk Read Bytes/sec", readCounter, "DiskCollector");
	PdhUtil::addCounter(query, L"\\PhysicalDisk(_Total)\\Disk Write Bytes/sec", writeCounter, "DiskCollector");
}

PdhUtil::Reading DiskCollector::getReadKB() const {
	return PdhUtil::scaled(PdhUtil::read(readCounter), 1.0 / 1024.0);
}

PdhUtil::Reading DiskCollector::getWriteKB() const {
	return PdhUtil::scaled(PdhUtil::read(writeCounter), 1.0 / 1024.0);
}
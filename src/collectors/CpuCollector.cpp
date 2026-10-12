#include "collectors/CpuCollector.h"


void CpuCollector::init(PDH_HQUERY& query) {
	PdhUtil::addCounter(query, L"\\Processor Information(_Total)\\% Processor Utility", cpuTotal, "CpuCollector");	// 전체 사용률
	PdhUtil::addCounter(query, L"\\Processor Information(_Total)\\Actual Frequency", cpuFreqMHz, "CpuCollector");	// 클럭 속도

	// Processor Queue Length 병목 판단용 코어 수 이상 -> 병목 가능
	PdhUtil::addCounter(query, L"\\System\\Processor Queue Length", cpuQueueLength, "CpuCollector");

	//CPU 사용 성격 분석
	//User 높음 -> 프로세스 원인
	//Kernel 높음 -> OS/드라이버 / I/O 문제
	PdhUtil::addCounter(query, L"\\Processor Information(_Total)\\% User Time", cpuUser, "CpuCollector");
	PdhUtil::addCounter(query, L"\\Processor Information(_Total)\\% Privileged Time", cpuKernel, "CpuCollector");
}

PdhUtil::Reading CpuCollector::getTotalUsage() const {
	return PdhUtil::read(cpuTotal);
}
PdhUtil::Reading CpuCollector::getCpuFreqGHz() const {
	PdhUtil::Reading r = PdhUtil::read(cpuFreqMHz);
	if (!r.value) return r;
	const double val = *r.value;

	if (val > 1'000'000'000)  // Hz (10억 이상)
		r.value = val / 1'000'000'000.0;
	else if (val > 1'000'000) // KHz (100만 이상)
		r.value = val / 1'000'000.0;
	else if (val > 100)       // MHz (100 이상)
		r.value = val / 1'000.0;
	// 그 밖은 이미 GHz (1~6 범위)
	return r;
}
PdhUtil::Reading CpuCollector::getCpuQueueLength() const {
	return PdhUtil::read(cpuQueueLength);
}
PdhUtil::Reading CpuCollector::getCpuUser() const {
	return PdhUtil::read(cpuUser);
}
PdhUtil::Reading CpuCollector::getCpuKernel() const {
	return PdhUtil::read(cpuKernel);
}
